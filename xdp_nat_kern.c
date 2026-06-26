/* SPDX-License-Identifier: GPL-2.0 */

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

/* probe window when scanning for a free port */
#define PORT_SEARCH_WINDOW 32

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, NAT_TABLE_SIZE);
    __type(key,   struct conn_key);
    __type(value, struct nat_entry);
} nat_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, NAT_TABLE_SIZE);
    __type(key,   struct conn_key);
    __type(value, struct nat_entry);
} nat_reverse_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PORT_POOL_SIZE);
    __type(key,   __u32);
    __type(value, __u8);
} port_pool SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct nat_stats);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct nat_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} event_ring SEC(".maps");

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

static __always_inline void l4_update_csum(void *l4hdr, __u8 proto,
                                            __u32 old_ip,   __u32 new_ip,
                                            __u16 old_port, __u16 new_port) {
    __u16 *ck;
    if (proto == IPPROTO_TCP) {
        ck = &((struct tcphdr *)l4hdr)->check;
    } else if (proto == IPPROTO_UDP) {
        ck = &((struct udphdr *)l4hdr)->check;
        if (*ck == 0)
            return;
    } else {
        return;
    }
    __u64 csum = bpf_csum_diff((__be32 *)&old_ip,   4, (__be32 *)&new_ip,   4, ~(*ck));
    csum       = bpf_csum_diff((__be32 *)&old_port,  2, (__be32 *)&new_port, 2, csum);
    *ck = csum_fold(csum);
}

static __always_inline void icmp_rewrite_id(struct icmphdr *icmph,
                                            __u16 old_id, __u16 new_id) {
    __u64 csum = bpf_csum_diff((__be32 *)&old_id, 2, (__be32 *)&new_id, 2,
                               ~((__u64)icmph->checksum));
    icmph->checksum    = csum_fold(csum);
    icmph->un.echo.id  = new_id;
}

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

static __always_inline __u8 tcp_advance(__u8 cur, __u8 flags) {
    if (flags & 0x04)
        return TCP_STATE_RST;
    if ((flags & 0x01) && cur == TCP_STATE_ESTAB)
        return TCP_STATE_FIN;
    if ((flags & 0x12) == 0x12 && cur == TCP_STATE_NEW)
        return TCP_STATE_ESTAB;
    return cur;
}

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

SEC("xdp")
int xdp_nat_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

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
        tcp_flags = ((__u8 *)tcph)[13];
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end)
            return XDP_DROP;
        src_port = udph->source;
        dst_port = udph->dest;
    } else {
        struct icmphdr *icmph = l4;
        if ((void *)(icmph + 1) > data_end)
            return XDP_DROP;
        if (icmph->type != ICMP_ECHO && icmph->type != ICMP_ECHOREPLY)
            return XDP_PASS;
        src_port = dst_port = icmph->un.echo.id;
    }

    int outbound = is_internal(iph->saddr, cfg);

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

            bpf_map_update_elem(&nat_table, &fwd_key, &tmp, BPF_NOEXIST);

            /* ICMP reverse key uses zero for remote fields — keyed by nat_id only */
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
            entry->last_seen = bpf_ktime_get_ns();
            if (iph->protocol == IPPROTO_TCP)
                entry->tcp_state = tcp_advance(entry->tcp_state, tcp_flags);
        }

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
        } else {
            icmp_rewrite_id(l4, old_sport, entry->nat_port);
            if (stats) stats->icmp_translated++;
        }

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
            return XDP_PASS;

        entry->last_seen = bpf_ktime_get_ns();
        if (iph->protocol == IPPROTO_TCP)
            entry->tcp_state = tcp_advance(entry->tcp_state, tcp_flags);

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
        } else {
            icmp_rewrite_id(l4, old_dport, entry->orig_src_port);
            if (stats) stats->icmp_translated++;
        }
    }

    if (stats) stats->packets_translated++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
