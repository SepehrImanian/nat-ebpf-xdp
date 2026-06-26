/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#ifndef __KERNEL__
#ifdef __linux__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t            __u8;
typedef uint16_t           __u16;
typedef uint32_t           __u32;
typedef unsigned long long __u64;
#endif
#endif

#define NAT_TABLE_SIZE      65536
#define PORT_POOL_SIZE      10000
#define RINGBUF_SIZE        (256 * 1024)

#define TCP_STATE_NEW       0
#define TCP_STATE_ESTAB     1
#define TCP_STATE_FIN       2
#define TCP_STATE_RST       3

#define NAT_EVT_NEW_CONN     0
#define NAT_EVT_DEL_CONN     1
#define NAT_EVT_PORT_EXHAUST 2

struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};

/* all port fields are network byte order */
struct nat_entry {
    __u32 orig_src_ip;
    __u16 orig_src_port;
    __u16 nat_port;
    __u32 nat_ip;
    __u32 _pad0;
    __u64 last_seen;
    __u8  protocol;
    __u8  tcp_state;
    __u8  pad[6];
};

struct nat_stats {
    __u64 packets_processed;
    __u64 packets_translated;
    __u64 packets_dropped;
    __u64 new_connections;
    __u64 expired_connections;
    __u64 port_exhausted;
    __u64 icmp_translated;
};

struct nat_config {
    __u32 internal_network;
    __u32 internal_netmask;
    __u32 external_ip;
    __u16 port_range_start;
    __u16 port_range_end;
    __u32 tcp_timeout;
    __u32 udp_timeout;
    __u32 icmp_timeout;
    __u8  log_events;
    __u8  pad[3];
};

struct nat_event {
    __u64 timestamp;
    __u32 orig_src_ip;
    __u32 remote_ip;
    __u32 nat_ip;
    __u16 orig_src_port;
    __u16 remote_port;
    __u16 nat_port;
    __u8  protocol;
    __u8  event_type;
};
