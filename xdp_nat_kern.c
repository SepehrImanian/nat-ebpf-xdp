/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDP NAT kernel program — SNAT/DNAT at line rate using eBPF.
 *
 * Packet flow
 * ───────────
 *   Outbound (internal → external)
 *     src_ip:src_port  →  nat_ip:nat_port    (SNAT)
 *     stored in nat_table (forward) and nat_reverse_table.
 *
 *   Inbound (external → internal)
 *     dst_ip:dst_port  →  orig_ip:orig_port  (reverse DNAT)
 *     looked up in nat_reverse_table.
 *
 * Requires Linux ≥ 5.8 (BPF_MAP_TYPE_LRU_HASH + BPF_MAP_TYPE_RINGBUF).
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "nat_common.h"

/* How many port-pool slots to probe per packet before giving up.
 * A random start index is chosen so contention is spread across CPUs. */
#define PORT_SEARCH_WINDOW 32

/* ── Maps ───────────────────────────────────────────────────────────────── */

/* Forward table: internal 5-tuple → nat_entry */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, NAT_TABLE_SIZE);
    __type(key,   struct conn_key);
    __type(value, struct nat_entry);
} nat_table SEC(".maps");

/* Reverse table: external 5-tuple → nat_entry.
 * For ICMP, src_ip/src_port are zeroed — lookup is by (nat_ip, nat_id). */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, NAT_TABLE_SIZE);
    __type(key,   struct conn_key);
    __type(value, struct nat_entry);
} nat_reverse_table SEC(".maps");

/* Port availability bitmap: index → 0 (free) / 1 (used) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PORT_POOL_SIZE);
    __type(key,   __u32);
    __type(value, __u8);
} port_pool SEC(".maps");

/* Per-CPU stats — no locking needed */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct nat_stats);
} stats_map SEC(".maps");

/* Single config slot pushed by userspace */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct nat_config);
} config_map SEC(".maps");

/* Ring buffer for connection lifecycle events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} event_ring SEC(".maps");

/* ── Checksum helpers ───────────────────────────────────────────────────── */

static __always_inline __u16 csum_fold(__u64 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~(__u16)csum;
}

static __always_inline __u16 ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    __u64 csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(*iph), 0);
    return csum_fold(csum);
}

/* Incremental L4 checksum update: replace (old_ip, old_port) with new values.
 * Operates in-place via the checksum pointer in the L4 header. */
static __always_inline void l4_update_csum(void *l4hdr, __u8 proto,
                                            __u32 old_ip,   __u32 new_ip,
                                            __u16 old_port, __u16 new_port) {
    __u16 *ck;
    if (proto == IPPROTO_TCP) {
        ck = &((struct tcphdr *)l4hdr)->check;
    } else if (proto == IPPROTO_UDP) {
        ck = &((struct udphdr *)l4hdr)->check;
        if (*ck == 0)
            return; /* UDP checksum optional (RFC 768) */
    } else {
        return;
    }
    __u64 csum = bpf_csum_diff((__be32 *)&old_ip,   4, (__be32 *)&new_ip,   4, ~(*ck));
    csum       = bpf_csum_diff((__be32 *)&old_port,  2, (__be32 *)&new_port, 2, csum);
    *ck = csum_fold(csum);
}

/* Rewrite the ICMP echo identifier and fix the ICMP checksum in-place. */
static __always_inline void icmp_rewrite_id(struct icmphdr *icmph,
                                            __u16 old_id, __u16 new_id) {
    __u64 csum = bpf_csum_diff((__be32 *)&old_id, 2, (__be32 *)&new_id, 2,
                               ~((__u64)icmph->checksum));
    icmph->checksum    = csum_fold(csum);
    icmph->un.echo.id  = new_id;
}

/* ── Port pool ──────────────────────────────────────────────────────────── */

/* Allocate one port from the pool using a randomised starting index.
 * Returns the port in HOST byte order, or 0 on exhaustion. */
static __always_inline __u16 port_alloc(struct nat_config *cfg) {
    __u16 range = cfg->port_range_end - cfg->port_range_start;
    __u32 start = bpf_get_prandom_u32() % ((__u32)range + 1);
    int i;

    for (i = 0; i < PORT_SEARCH_WINDOW; i++) {
        __u32 idx = start + i;
        if (idx > (__u32)range)
            idx -= (__u32)range + 1;
        if (idx >= PORT_POOL_SIZE)
            continue;

        __u8 *used = bpf_map_lookup_elem(&port_pool, &idx);
        if (used && *used == 0) {
            __u8 one = 1;
            bpf_map_update_elem(&port_pool, &idx, &one, BPF_ANY);
            return cfg->port_range_start + (__u16)idx;
        }
    }
    return 0;
}

static __always_inline void port_free(struct nat_config *cfg, __u16 port) {
    if (port < cfg->port_range_start || port > cfg->port_range_end)
        return;
    __u32 idx = port - cfg->port_range_start;
    if (idx >= PORT_POOL_SIZE)
        return;
    __u8 zero = 0;
    bpf_map_update_elem(&port_pool, &idx, &zero, BPF_ANY);
}

/* ── Utility wrappers ───────────────────────────────────────────────────── */

static __always_inline struct nat_stats *get_stats(void) {
    __u32 k = 0;
    return bpf_map_lookup_elem(&stats_map, &k);
}

static __always_inline struct nat_config *get_config(void) {
    __u32 k = 0;
    return bpf_map_lookup_elem(&config_map, &k);
}

static __always_inline int is_internal(__u32 ip, struct nat_config *cfg) {
    return (ip & cfg->internal_netmask) ==
           (cfg->internal_network & cfg->internal_netmask);
}

/* Advance the TCP state machine based on observed flags byte. */
static __always_inline __u8 tcp_advance(__u8 cur, __u8 flags) {
    if (flags & 0x04) /* RST */
        return TCP_STATE_RST;
    if ((flags & 0x01) && cur == TCP_STATE_ESTAB) /* FIN from either side */
        return TCP_STATE_FIN;
    if ((flags & 0x12) == 0x12 && cur == TCP_STATE_NEW) /* SYN-ACK */
        return TCP_STATE_ESTAB;
    return cur;
}

/* Emit a connection event to the ring buffer (no-op when logging disabled). */
static __always_inline void emit_event(struct nat_entry *e, __u32 remote_ip,
                                        __u16 remote_port, __u8 type,
                                        struct nat_config *cfg) {
    if (!cfg->log_events)
        return;
    struct nat_event *ev = bpf_ringbuf_reserve(&event_ring, sizeof(*ev), 0);
    if (!ev)
        return;
    ev->timestamp     = bpf_ktime_get_ns();
    ev->orig_src_ip   = e->orig_src_ip;
    ev->remote_ip     = remote_ip;
    ev->nat_ip        = e->nat_ip;
    ev->orig_src_port = e->orig_src_port;
    ev->remote_port   = remote_port;
    ev->nat_port      = e->nat_port;
    ev->protocol      = e->protocol;
    ev->event_type    = type;
    bpf_ringbuf_submit(ev, 0);
}

/* ── Main XDP program ───────────────────────────────────────────────────── */

SEC("xdp")
int xdp_nat_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* ── Parse Ethernet ── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ── Parse IP ── */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;
    if (iph->version != 4 || iph->ihl < 5)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP &&
        iph->protocol != IPPROTO_UDP &&
        iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    struct nat_config *cfg = get_config();
    if (!cfg)
        return XDP_PASS;

    struct nat_stats *stats = get_stats();
    if (stats)
        stats->packets_processed++;

    /* ── Parse L4 ── */
    void *l4 = (void *)iph + (iph->ihl << 2);
    if (l4 > data_end)
        return XDP_DROP;

    __u16 src_port = 0, dst_port = 0;
    __u8  tcp_flags = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end)
            return XDP_DROP;
        src_port  = tcph->source;
        dst_port  = tcph->dest;
        tcp_flags = ((__u8 *)tcph)[13]; /* flags byte: URG ACK PSH RST SYN FIN */
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end)
            return XDP_DROP;
        src_port = udph->source;
        dst_port = udph->dest;
    } else { /* ICMP */
        struct icmphdr *icmph = l4;
        if ((void *)(icmph + 1) > data_end)
            return XDP_DROP;
        /* Only translate echo request/reply; pass other ICMP types up. */
        if (icmph->type != ICMP_ECHO && icmph->type != ICMP_ECHOREPLY)
            return XDP_PASS;
        /* Treat the ICMP identifier as the "port" for lookup purposes. */
        src_port = dst_port = icmph->un.echo.id;
    }

    int outbound = is_internal(iph->saddr, cfg);

    /* ═══════════════════════════════════════════════════════════════════
     * OUTBOUND PATH — SNAT: rewrite source IP and port.
     * ═══════════════════════════════════════════════════════════════════ */
    if (outbound) {
        struct conn_key fwd_key = {
            .src_ip   = iph->saddr,
            .dst_ip   = iph->daddr,
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = iph->protocol,
        };

        struct nat_entry *entry = bpf_map_lookup_elem(&nat_table, &fwd_key);
        struct nat_entry  tmp;

        if (!entry) {
            /* ── New connection: allocate a port and create both entries ── */
            __u16 nat_port = port_alloc(cfg);
            if (nat_port == 0) {
                if (stats) {
                    stats->port_exhausted++;
                    stats->packets_dropped++;
                }
                struct nat_entry exhaust_ev = {
                    .orig_src_ip = iph->saddr,
                    .nat_ip      = cfg->external_ip,
                    .protocol    = iph->protocol,
                };
                emit_event(&exhaust_ev, iph->daddr, dst_port,
                           NAT_EVT_PORT_EXHAUST, cfg);
                return XDP_DROP;
            }

            tmp = (struct nat_entry){
                .orig_src_ip   = iph->saddr,
                .orig_src_port = src_port,
                .nat_ip        = cfg->external_ip,
                .nat_port      = bpf_htons(nat_port),
                .last_seen     = bpf_ktime_get_ns(),
                .protocol      = iph->protocol,
                .tcp_state     = TCP_STATE_NEW,
            };

            /* Forward entry */
            bpf_map_update_elem(&nat_table, &fwd_key, &tmp, BPF_NOEXIST);

            /* Reverse entry key: (remote_ip, nat_ip, remote_port, nat_port).
             * ICMP uses zero for remote_ip/remote_port — lookup by nat_id only. */
            struct conn_key rev_key = {
                .src_ip   = (iph->protocol == IPPROTO_ICMP) ? 0 : iph->daddr,
                .dst_ip   = cfg->external_ip,
                .src_port = (iph->protocol == IPPROTO_ICMP) ? 0 : dst_port,
                .dst_port = bpf_htons(nat_port),
                .protocol = iph->protocol,
            };
            bpf_map_update_elem(&nat_reverse_table, &rev_key, &tmp, BPF_ANY);

            if (stats) stats->new_connections++;
            emit_event(&tmp, iph->daddr, dst_port, NAT_EVT_NEW_CONN, cfg);

            entry = &tmp;
        } else {
            /* Existing connection: refresh timestamp and TCP state. */
            entry->last_seen = bpf_ktime_get_ns();
            if (iph->protocol == IPPROTO_TCP)
                entry->tcp_state = tcp_advance(entry->tcp_state, tcp_flags);
        }

        /* ── Apply SNAT ── */
        __u32 old_sip   = iph->saddr;
        __u16 old_sport = src_port;

        iph->saddr = entry->nat_ip;
        iph->check = ip_checksum(iph);

        if (iph->protocol == IPPROTO_TCP) {
            ((struct tcphdr *)l4)->source = entry->nat_port;
            l4_update_csum(l4, IPPROTO_TCP,
                           old_sip, entry->nat_ip, old_sport, entry->nat_port);
        } else if (iph->protocol == IPPROTO_UDP) {
            ((struct udphdr *)l4)->source = entry->nat_port;
            l4_update_csum(l4, IPPROTO_UDP,
                           old_sip, entry->nat_ip, old_sport, entry->nat_port);
        } else { /* ICMP */
            icmp_rewrite_id(l4, old_sport, entry->nat_port);
            if (stats) stats->icmp_translated++;
        }

    /* ═══════════════════════════════════════════════════════════════════
     * INBOUND PATH — reverse DNAT: rewrite destination IP and port.
     * ═══════════════════════════════════════════════════════════════════ */
    } else {
        struct conn_key rev_key = {
            .src_ip   = (iph->protocol == IPPROTO_ICMP) ? 0 : iph->saddr,
            .dst_ip   = iph->daddr,
            .src_port = (iph->protocol == IPPROTO_ICMP) ? 0 : src_port,
            .dst_port = dst_port,
            .protocol = iph->protocol,
        };

        struct nat_entry *entry = bpf_map_lookup_elem(&nat_reverse_table, &rev_key);
        if (!entry)
            return XDP_PASS; /* not a NATted flow — let kernel handle it */

        entry->last_seen = bpf_ktime_get_ns();
        if (iph->protocol == IPPROTO_TCP)
            entry->tcp_state = tcp_advance(entry->tcp_state, tcp_flags);

        /* ── Apply reverse DNAT ── */
        __u32 old_dip   = iph->daddr;
        __u16 old_dport = dst_port;

        iph->daddr = entry->orig_src_ip;
        iph->check = ip_checksum(iph);

        if (iph->protocol == IPPROTO_TCP) {
            ((struct tcphdr *)l4)->dest = entry->orig_src_port;
            l4_update_csum(l4, IPPROTO_TCP,
                           old_dip, entry->orig_src_ip, old_dport, entry->orig_src_port);
        } else if (iph->protocol == IPPROTO_UDP) {
            ((struct udphdr *)l4)->dest = entry->orig_src_port;
            l4_update_csum(l4, IPPROTO_UDP,
                           old_dip, entry->orig_src_ip, old_dport, entry->orig_src_port);
        } else { /* ICMP */
            icmp_rewrite_id(l4, old_dport, entry->orig_src_port);
            if (stats) stats->icmp_translated++;
        }
    }

    if (stats) stats->packets_translated++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
