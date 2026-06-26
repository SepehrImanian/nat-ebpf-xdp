/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

/*
 * Shared struct definitions between the eBPF kernel program and the
 * userspace control tool.  Both sides must agree on layout; explicit
 * pad fields guarantee no compiler-inserted holes that would differ
 * between toolchains.
 */

#ifndef __KERNEL__
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* ── Map sizing ─────────────────────────────────────────────────────────── */

#define NAT_TABLE_SIZE      65536   /* forward + reverse LRU hash entries    */
#define PORT_POOL_SIZE      10000   /* max width of NAT port range           */
#define RINGBUF_SIZE        (256 * 1024) /* 256 KB event ring                */

/* ── TCP connection states ──────────────────────────────────────────────── */

#define TCP_STATE_NEW       0
#define TCP_STATE_ESTAB     1
#define TCP_STATE_FIN       2
#define TCP_STATE_RST       3

/* ── Ring-buffer event types ────────────────────────────────────────────── */

#define NAT_EVT_NEW_CONN    0   /* new SNAT mapping created                  */
#define NAT_EVT_DEL_CONN    1   /* mapping expired / deleted by userspace    */
#define NAT_EVT_PORT_EXHAUST 2  /* port pool exhausted, packet dropped       */

/* ── Hash-map key: 5-tuple ──────────────────────────────────────────────── */
/*
 * Explicit pad[3] ensures the 3 bytes after `protocol` are always zero,
 * so the kernel hash treats two logically-equal keys as byte-equal.
 */
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};                              /* 16 bytes, naturally aligned */

/* ── NAT table entry ────────────────────────────────────────────────────── */
/*
 * Stored in both the forward (internal→external) and reverse
 * (external→internal) LRU hash maps.
 *
 * All port values are in **network byte order** (big-endian) so they can
 * be written directly into packet headers without conversion.
 */
struct nat_entry {
    __u32 orig_src_ip;      /* original internal source IP                  */
    __u16 orig_src_port;    /* original internal source port / ICMP id      */
    __u16 nat_port;         /* allocated NAT port / ICMP id (network order) */
    __u32 nat_ip;           /* external IP used for translation              */
    __u32 _pad0;            /* align last_seen to 8 bytes                   */
    __u64 last_seen;        /* bpf_ktime_get_ns() at last matching packet   */
    __u8  protocol;         /* IPPROTO_TCP / UDP / ICMP                     */
    __u8  tcp_state;        /* TCP_STATE_* above (ignored for UDP/ICMP)     */
    __u8  pad[6];
};                          /* 32 bytes */

/* ── Per-CPU statistics ─────────────────────────────────────────────────── */

struct nat_stats {
    __u64 packets_processed;
    __u64 packets_translated;
    __u64 packets_dropped;
    __u64 new_connections;
    __u64 expired_connections;  /* removed by userspace cleanup              */
    __u64 port_exhausted;
    __u64 icmp_translated;
};

/* ── Runtime configuration ──────────────────────────────────────────────── */

struct nat_config {
    __u32 internal_network;     /* host network address (e.g. 192.168.1.0)  */
    __u32 internal_netmask;     /* prefix mask in network byte order         */
    __u32 external_ip;          /* SNAT target IP                            */
    __u16 port_range_start;     /* inclusive, host byte order                */
    __u16 port_range_end;       /* inclusive, host byte order                */
    __u32 tcp_timeout;          /* seconds before idle TCP flow expires      */
    __u32 udp_timeout;          /* seconds before idle UDP flow expires      */
    __u32 icmp_timeout;         /* seconds before idle ICMP flow expires     */
    __u8  log_events;           /* 1 = emit ring-buffer events               */
    __u8  pad[3];
};

/* ── Ring-buffer event record ───────────────────────────────────────────── */

struct nat_event {
    __u64 timestamp;            /* bpf_ktime_get_ns()                        */
    __u32 orig_src_ip;
    __u32 remote_ip;
    __u32 nat_ip;
    __u16 orig_src_port;
    __u16 remote_port;
    __u16 nat_port;
    __u8  protocol;
    __u8  event_type;           /* NAT_EVT_* above                           */
};                              /* 32 bytes */
