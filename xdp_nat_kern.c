#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_CONNECTIONS 1000000
#define PORT_POOL_SIZE 10000
#define NAT_TABLE_SIZE 65536

// NAT connection entry
struct nat_entry {
    __u32 orig_src_ip;
    __u16 orig_src_port;
    __u32 nat_ip;
    __u16 nat_port;
    __u64 timestamp;
    __u8 protocol;
};

// Connection key for hash lookup
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
};

// Statistics structure
struct nat_stats {
    __u64 packets_processed;
    __u64 packets_translated;
    __u64 packets_dropped;
    __u64 new_connections;
    __u64 port_exhausted;
};

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NAT_TABLE_SIZE);
    __type(key, struct conn_key);
    __type(value, struct nat_entry);
} nat_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PORT_POOL_SIZE);
    __type(key, __u32);
    __type(value, __u8);  // 0 = free, 1 = used
} port_pool SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct nat_stats);
} stats_map SEC(".maps");

// Configuration map
struct nat_config {
    __u32 internal_network;
    __u32 internal_netmask;
    __u32 external_ip;
    __u16 port_range_start;
    __u16 port_range_end;
    __u32 tcp_timeout;
    __u32 udp_timeout;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct nat_config);
} config_map SEC(".maps");

// Helper functions
static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
#pragma unroll
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 ipv4_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

static __always_inline void update_l4_checksum(struct iphdr *iph, void *l4hdr, __u8 protocol,
                                              __u32 old_addr, __u32 new_addr,
                                              __u16 old_port, __u16 new_port) {
    __u16 *checksum;
    
    if (protocol == IPPROTO_TCP) {
        checksum = &((struct tcphdr *)l4hdr)->check;
    } else if (protocol == IPPROTO_UDP) {
        checksum = &((struct udphdr *)l4hdr)->check;
        if (*checksum == 0) return; // UDP checksum is optional
    } else {
        return;
    }
    
    // Update checksum for address change
    unsigned long long csum = bpf_csum_diff((__be32 *)&old_addr, 4, (__be32 *)&new_addr, 4, ~(*checksum));
    
    // Update checksum for port change
    csum = bpf_csum_diff((__be32 *)&old_port, 2, (__be32 *)&new_port, 2, csum);
    
    *checksum = csum_fold_helper(csum);
}

static __always_inline __u16 allocate_port(void) {
    __u32 key = 0;
    struct nat_config *config = bpf_map_lookup_elem(&config_map, &key);
    if (!config) return 0;
    
    // Simple port allocation - could be improved with better algorithm
    for (__u16 port = config->port_range_start; port <= config->port_range_end; port++) {
        __u32 port_key = port - config->port_range_start;
        __u8 *status = bpf_map_lookup_elem(&port_pool, &port_key);
        if (status && *status == 0) {
            __u8 used = 1;
            bpf_map_update_elem(&port_pool, &port_key, &used, BPF_ANY);
            return port;
        }
    }
    return 0; // No ports available
}

static __always_inline void free_port(__u16 port) {
    __u32 key = 0;
    struct nat_config *config = bpf_map_lookup_elem(&config_map, &key);
    if (!config) return;
    
    if (port >= config->port_range_start && port <= config->port_range_end) {
        __u32 port_key = port - config->port_range_start;
        __u8 free = 0;
        bpf_map_update_elem(&port_pool, &port_key, &free, BPF_ANY);
    }
}

static __always_inline void update_stats(__u64 *counter) {
    __u32 key = 0;
    struct nat_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        (*counter)++;
    }
}

static __always_inline int is_internal_ip(__u32 ip) {
    __u32 key = 0;
    struct nat_config *config = bpf_map_lookup_elem(&config_map, &key);
    if (!config) return 0;
    
    return (ip & config->internal_netmask) == (config->internal_network & config->internal_netmask);
}

// Main XDP program
SEC("xdp")
int xdp_nat_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;
    
    if (iph->version != 4)
        return XDP_PASS;
    
    // Only handle TCP, UDP, and ICMP
    if (iph->protocol != IPPROTO_TCP && 
        iph->protocol != IPPROTO_UDP && 
        iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;
    
    void *l4_header = (void *)iph + (iph->ihl << 2);
    __u16 src_port = 0, dst_port = 0;
    
    // Extract port information
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4_header;
        if ((void *)(tcph + 1) > data_end)
            return XDP_DROP;
        src_port = tcph->source;
        dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4_header;
        if ((void *)(udph + 1) > data_end)
            return XDP_DROP;
        src_port = udph->source;
        dst_port = udph->dest;
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = l4_header;
        if ((void *)(icmph + 1) > data_end)
            return XDP_DROP;
        src_port = dst_port = 0; // ICMP doesn't have ports
    }
    
    // Create connection key
    struct conn_key key = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = iph->protocol,
    };
    
    // Update packet counter
    __u32 stats_key = 0;
    struct nat_stats *stats = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (stats) {
        stats->packets_processed++;
    }
    
    // Check if this is outbound traffic (from internal network)
    int outbound = is_internal_ip(iph->saddr);
    
    if (outbound) {
        // Outbound traffic - apply SNAT
        struct nat_entry *entry = bpf_map_lookup_elem(&nat_table, &key);
        
        if (!entry) {
            // New connection - create NAT entry
            struct nat_entry new_entry = {0};
            __u16 nat_port = allocate_port();
            
            if (nat_port == 0) {
                // Port pool exhausted
                if (stats) stats->port_exhausted++;
                return XDP_DROP;
            }
            
            __u32 config_key = 0;
            struct nat_config *config = bpf_map_lookup_elem(&config_map, &config_key);
            if (!config) return XDP_DROP;
            
            new_entry.orig_src_ip = iph->saddr;
            new_entry.orig_src_port = src_port;
            new_entry.nat_ip = config->external_ip;
            new_entry.nat_port = bpf_htons(nat_port);
            new_entry.timestamp = bpf_ktime_get_ns();
            new_entry.protocol = iph->protocol;
            
            bpf_map_update_elem(&nat_table, &key, &new_entry, BPF_NOEXIST);
            entry = &new_entry;
            
            if (stats) stats->new_connections++;
        }
        
        // Apply SNAT translation
        __u32 old_saddr = iph->saddr;
        __u16 old_sport = src_port;
        
        iph->saddr = entry->nat_ip;
        
        if (iph->protocol == IPPROTO_TCP) {
            ((struct tcphdr *)l4_header)->source = entry->nat_port;
        } else if (iph->protocol == IPPROTO_UDP) {
            ((struct udphdr *)l4_header)->source = entry->nat_port;
        }
        
        // Update checksums
        iph->check = ipv4_csum(iph);
        if (iph->protocol != IPPROTO_ICMP) {
            update_l4_checksum(iph, l4_header, iph->protocol,
                             old_saddr, entry->nat_ip,
                             old_sport, entry->nat_port);
        }
        
    } else {
        // Inbound traffic - look for reverse NAT entry
        struct conn_key reverse_key = {
            .src_ip = iph->daddr,  // Swap src/dst for reverse lookup
            .dst_ip = iph->saddr,
            .src_port = dst_port,
            .dst_port = src_port,
            .protocol = iph->protocol,
        };
        
        struct nat_entry *entry = bpf_map_lookup_elem(&nat_table, &reverse_key);
        if (!entry) {
            // No NAT entry found - pass through
            return XDP_PASS;
        }
        
        // Apply reverse NAT translation
        __u32 old_daddr = iph->daddr;
        __u16 old_dport = dst_port;
        
        iph->daddr = entry->orig_src_ip;
        
        if (iph->protocol == IPPROTO_TCP) {
            ((struct tcphdr *)l4_header)->dest = entry->orig_src_port;
        } else if (iph->protocol == IPPROTO_UDP) {
            ((struct udphdr *)l4_header)->dest = entry->orig_src_port;
        }
        
        // Update checksums
        iph->check = ipv4_csum(iph);
        if (iph->protocol != IPPROTO_ICMP) {
            update_l4_checksum(iph, l4_header, iph->protocol,
                             old_daddr, entry->orig_src_ip,
                             old_dport, entry->orig_src_port);
        }
    }
    
    if (stats) stats->packets_translated++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
