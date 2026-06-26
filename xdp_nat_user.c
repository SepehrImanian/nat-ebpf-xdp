/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "nat_common.h"

static int    ifindex        = -1;
static __u32  xdp_flags_used = 0;
static struct bpf_object *obj  = NULL;
static int nat_table_fd        = -1;
static int nat_rev_fd          = -1;
static int port_pool_fd        = -1;
static int stats_fd            = -1;
static int config_fd           = -1;
static int event_ring_fd       = -1;
static volatile sig_atomic_t keep_running = 1;
static int json_output = 0;

static void signal_handler(int sig) { (void)sig; keep_running = 0; }

static __u64 mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static int load_config(const char *internal_net, const char *external_ip,
                       int port_start, int port_end,
                       int tcp_timeout, int udp_timeout, int icmp_timeout,
                       int log_events) {
    struct nat_config cfg = {0};

    char net_str[32];
    strncpy(net_str, internal_net, sizeof(net_str) - 1);
    char *slash = strchr(net_str, '/');
    if (!slash) {
        fprintf(stderr, "Network must be in CIDR notation, e.g. 192.168.1.0/24\n");
        return -1;
    }
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) {
        fprintf(stderr, "Invalid prefix length %d\n", prefix);
        return -1;
    }

    struct in_addr addr;
    if (!inet_aton(net_str, &addr)) {
        fprintf(stderr, "Invalid network address: %s\n", net_str);
        return -1;
    }
    cfg.internal_network = addr.s_addr;
    cfg.internal_netmask = (prefix == 0) ? 0 :
        htonl(~((1u << (32 - prefix)) - 1));

    if (!inet_aton(external_ip, &addr)) {
        fprintf(stderr, "Invalid external IP: %s\n", external_ip);
        return -1;
    }
    cfg.external_ip = addr.s_addr;

    if (port_start < 1024 || port_end > 65535 || port_start >= port_end) {
        fprintf(stderr, "Invalid port range %d-%d\n", port_start, port_end);
        return -1;
    }
    if (port_end - port_start > PORT_POOL_SIZE - 1) {
        fprintf(stderr, "Port range too wide; max %d ports\n", PORT_POOL_SIZE);
        return -1;
    }
    cfg.port_range_start = (__u16)port_start;
    cfg.port_range_end   = (__u16)port_end;
    cfg.tcp_timeout      = (__u32)tcp_timeout;
    cfg.udp_timeout      = (__u32)udp_timeout;
    cfg.icmp_timeout     = (__u32)icmp_timeout;
    cfg.log_events       = (__u8)log_events;

    int key = 0;
    if (bpf_map_update_elem(config_fd, &key, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to write config: %s\n", strerror(errno));
        return -1;
    }

    if (!json_output) {
        printf("Configuration:\n");
        printf("  Internal network : %s\n", internal_net);
        printf("  External IP      : %s\n", external_ip);
        printf("  Port range       : %d-%d\n", port_start, port_end);
        printf("  TCP timeout      : %d s\n", tcp_timeout);
        printf("  UDP timeout      : %d s\n", udp_timeout);
        printf("  ICMP timeout     : %d s\n", icmp_timeout);
        printf("  Event logging    : %s\n", log_events ? "on" : "off");
    }
    return 0;
}

static int read_stats(struct nat_stats *out) {
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return -1;

    struct nat_stats *percpu = calloc(ncpus, sizeof(*percpu));
    if (!percpu)
        return -1;

    memset(out, 0, sizeof(*out));
    int key = 0;
    if (bpf_map_lookup_elem(stats_fd, &key, percpu) == 0) {
        for (int i = 0; i < ncpus; i++) {
            out->packets_processed   += percpu[i].packets_processed;
            out->packets_translated  += percpu[i].packets_translated;
            out->packets_dropped     += percpu[i].packets_dropped;
            out->new_connections     += percpu[i].new_connections;
            out->expired_connections += percpu[i].expired_connections;
            out->port_exhausted      += percpu[i].port_exhausted;
            out->icmp_translated     += percpu[i].icmp_translated;
        }
    }
    free(percpu);
    return 0;
}

static void print_stats(void) {
    struct nat_stats s;
    if (read_stats(&s) != 0)
        return;

    if (json_output) {
        printf("{"
               "\"packets_processed\":%llu,"
               "\"packets_translated\":%llu,"
               "\"packets_dropped\":%llu,"
               "\"new_connections\":%llu,"
               "\"expired_connections\":%llu,"
               "\"port_exhausted\":%llu,"
               "\"icmp_translated\":%llu"
               "}\n",
               (unsigned long long)s.packets_processed,
               (unsigned long long)s.packets_translated,
               (unsigned long long)s.packets_dropped,
               (unsigned long long)s.new_connections,
               (unsigned long long)s.expired_connections,
               (unsigned long long)s.port_exhausted,
               (unsigned long long)s.icmp_translated);
    } else {
        printf("\n=== NAT Statistics ===\n");
        printf("  Packets processed   : %llu\n",
               (unsigned long long)s.packets_processed);
        printf("  Packets translated  : %llu\n",
               (unsigned long long)s.packets_translated);
        printf("  Packets dropped     : %llu\n",
               (unsigned long long)s.packets_dropped);
        printf("  New connections     : %llu\n",
               (unsigned long long)s.new_connections);
        printf("  Expired (cleaned)   : %llu\n",
               (unsigned long long)s.expired_connections);
        printf("  Port exhausted      : %llu\n",
               (unsigned long long)s.port_exhausted);
        printf("  ICMP translated     : %llu\n",
               (unsigned long long)s.icmp_translated);
        printf("======================\n");
    }
}

static const char *proto_name(__u8 proto) {
    if (proto == IPPROTO_TCP)  return "TCP";
    if (proto == IPPROTO_UDP)  return "UDP";
    if (proto == IPPROTO_ICMP) return "ICMP";
    return "?";
}

static const char *tcp_state_name(__u8 state) {
    switch (state) {
    case TCP_STATE_NEW:   return "NEW";
    case TCP_STATE_ESTAB: return "ESTAB";
    case TCP_STATE_FIN:   return "FIN";
    case TCP_STATE_RST:   return "RST";
    default:              return "?";
    }
}

static void dump_connections(void) {
    struct conn_key key, next;
    struct nat_entry entry;
    __u64 now = mono_ns();
    int count = 0;

    memset(&key, 0, sizeof(key));

    if (json_output) {
        printf("[");
    } else {
        printf("%-21s %-5s %-21s %-21s %-5s %-5s %s\n",
               "Int.IP:Port", "Proto", "NAT IP:Port",
               "Remote IP:Port", "State", "Age(s)", "Protocol");
        printf("%-21s %-5s %-21s %-21s %-5s %-5s %s\n",
               "-------------------", "-----", "-------------------",
               "-------------------", "-----", "------", "--------");
    }

    while (bpf_map_get_next_key(nat_table_fd, &key, &next) == 0) {
        if (bpf_map_lookup_elem(nat_table_fd, &next, &entry) == 0) {
            char int_ip[INET_ADDRSTRLEN], nat_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &next.src_ip,     int_ip,  sizeof(int_ip));
            inet_ntop(AF_INET, &entry.nat_ip,    nat_ip,  sizeof(nat_ip));
            inet_ntop(AF_INET, &next.dst_ip,     dst_ip,  sizeof(dst_ip));

            double age = (now > entry.last_seen)
                         ? (double)(now - entry.last_seen) / 1e9 : 0.0;

            if (json_output) {
                if (count > 0) printf(",");
                printf("{\"int_ip\":\"%s\",\"int_port\":%u,"
                       "\"nat_ip\":\"%s\",\"nat_port\":%u,"
                       "\"remote_ip\":\"%s\",\"remote_port\":%u,"
                       "\"proto\":\"%s\",\"state\":\"%s\",\"age_s\":%.1f}",
                       int_ip,  ntohs(next.src_port),
                       nat_ip,  ntohs(entry.nat_port),
                       dst_ip,  ntohs(next.dst_port),
                       proto_name(next.protocol),
                       tcp_state_name(entry.tcp_state),
                       age);
            } else {
                char int_ep[32], nat_ep[32], dst_ep[32];
                snprintf(int_ep, sizeof(int_ep), "%s:%u",
                         int_ip, ntohs(next.src_port));
                snprintf(nat_ep, sizeof(nat_ep), "%s:%u",
                         nat_ip, ntohs(entry.nat_port));
                snprintf(dst_ep, sizeof(dst_ep), "%s:%u",
                         dst_ip, ntohs(next.dst_port));
                printf("%-21s %-5s %-21s %-21s %-5s %5.0f\n",
                       int_ep, proto_name(next.protocol),
                       nat_ep, dst_ep,
                       tcp_state_name(entry.tcp_state), age);
            }
            count++;
        }
        key = next;
    }

    if (json_output) {
        printf("]\n");
    } else {
        printf("\n%d active connection(s)\n", count);
    }
}

/* TODO: bump CLEANUP_BATCH or run multiple passes for large tables */
#define CLEANUP_BATCH 256

static int cleanup_expired(void) {
    int key_fd = config_fd;
    int cfg_key = 0;
    struct nat_config cfg;
    if (bpf_map_lookup_elem(key_fd, &cfg_key, &cfg) != 0)
        return 0;

    __u64 now = mono_ns();
    struct conn_key keys[CLEANUP_BATCH];
    struct nat_entry entries[CLEANUP_BATCH];
    int n = 0;

    struct conn_key cur, next;
    memset(&cur, 0, sizeof(cur));

    while (n < CLEANUP_BATCH &&
           bpf_map_get_next_key(nat_table_fd, &cur, &next) == 0) {
        struct nat_entry e;
        if (bpf_map_lookup_elem(nat_table_fd, &next, &e) == 0) {
            __u64 timeout_ns;
            if (e.protocol == IPPROTO_TCP)
                timeout_ns = (__u64)cfg.tcp_timeout  * 1000000000ULL;
            else if (e.protocol == IPPROTO_UDP)
                timeout_ns = (__u64)cfg.udp_timeout  * 1000000000ULL;
            else
                timeout_ns = (__u64)cfg.icmp_timeout * 1000000000ULL;

            if (e.tcp_state == TCP_STATE_RST || e.tcp_state == TCP_STATE_FIN)
                timeout_ns = 10ULL * 1000000000ULL;

            if (now - e.last_seen > timeout_ns) {
                keys[n]    = next;
                entries[n] = e;
                n++;
            }
        }
        cur = next;
    }

    int ncpus = libbpf_num_possible_cpus();
    struct nat_stats *percpu = calloc(ncpus, sizeof(*percpu));

    for (int i = 0; i < n; i++) {
        struct conn_key *k = &keys[i];
        struct nat_entry *e = &entries[i];

        bpf_map_delete_elem(nat_table_fd, k);

        struct conn_key rev = {
            .src_ip   = (e->protocol == IPPROTO_ICMP) ? 0 : k->dst_ip,
            .dst_ip   = e->nat_ip,
            .src_port = (e->protocol == IPPROTO_ICMP) ? 0 : k->dst_port,
            .dst_port = e->nat_port,
            .protocol = e->protocol,
        };
        bpf_map_delete_elem(nat_rev_fd, &rev);

        __u16 port = ntohs(e->nat_port);
        if (port >= cfg.port_range_start && port <= cfg.port_range_end) {
            __u32 idx = port - cfg.port_range_start;
            __u8 zero = 0;
            bpf_map_update_elem(port_pool_fd, &idx, &zero, BPF_ANY);
        }

        if (percpu) {
            int stats_key = 0;
            if (bpf_map_lookup_elem(stats_fd, &stats_key, percpu) == 0) {
                percpu[0].expired_connections++;
                bpf_map_update_elem(stats_fd, &stats_key, percpu, BPF_ANY);
            }
        }
    }

    free(percpu);

    if (n > 0)
        printf("Cleaned up %d expired connection(s)\n", n);

    return n;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx; (void)data_sz;
    struct nat_event *ev = data;

    char src[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN], nat[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ev->orig_src_ip, src,    sizeof(src));
    inet_ntop(AF_INET, &ev->remote_ip,   remote, sizeof(remote));
    inet_ntop(AF_INET, &ev->nat_ip,      nat,    sizeof(nat));

    const char *type;
    switch (ev->event_type) {
    case NAT_EVT_NEW_CONN:     type = "NEW";     break;
    case NAT_EVT_DEL_CONN:     type = "DEL";     break;
    case NAT_EVT_PORT_EXHAUST: type = "EXHAUST"; break;
    default:                   type = "?";       break;
    }

    if (json_output) {
        printf("{\"event\":\"%s\",\"proto\":\"%s\","
               "\"src\":\"%s\",\"src_port\":%u,"
               "\"nat\":\"%s\",\"nat_port\":%u,"
               "\"remote\":\"%s\",\"remote_port\":%u}\n",
               type, proto_name(ev->protocol),
               src,    ntohs(ev->orig_src_port),
               nat,    ntohs(ev->nat_port),
               remote, ntohs(ev->remote_port));
    } else {
        printf("[%s] %s  %s:%u -> %s:%u -> %s:%u\n",
               type, proto_name(ev->protocol),
               src,    ntohs(ev->orig_src_port),
               nat,    ntohs(ev->nat_port),
               remote, ntohs(ev->remote_port));
    }
    fflush(stdout);
    return 0;
}

static void usage(const char *prog) {
    printf(
        "Usage: %s -i IFACE -n NETWORK -e EXT_IP [OPTIONS]\n"
        "\n"
        "Mandatory (unless --stats / --conns):\n"
        "  -i, --interface IFACE      Network interface to attach XDP program\n"
        "  -n, --network   NETWORK    Internal network in CIDR (e.g. 192.168.1.0/24)\n"
        "  -e, --external-ip IP       External IP for SNAT\n"
        "\n"
        "Port pool:\n"
        "  -s, --port-start PORT      First NAT port (default: 10000)\n"
        "  -E, --port-end   PORT      Last  NAT port (default: 20000)\n"
        "\n"
        "Timeouts (seconds):\n"
        "  -t, --tcp-timeout  SECS    TCP idle timeout  (default: 7440)\n"
        "  -u, --udp-timeout  SECS    UDP idle timeout  (default: 300)\n"
        "  -I, --icmp-timeout SECS    ICMP idle timeout (default: 30)\n"
        "\n"
        "Modes:\n"
        "  -S, --stats                Print aggregated statistics and exit\n"
        "  -c, --conns                Dump active connection table and exit\n"
        "  -m, --monitor              Stream connection events (ring buffer)\n"
        "  -d, --daemon               Run cleanup loop as daemon\n"
        "\n"
        "Output:\n"
        "  -j, --json                 Output in JSON format\n"
        "  -L, --log-events           Enable kernel-side ring buffer logging\n"
        "  -h, --help                 Show this help\n"
        "\n"
        "Examples:\n"
        "  sudo %s -i eth0 -n 192.168.1.0/24 -e 203.0.113.1\n"
        "  sudo %s -i eth0 -n 192.168.1.0/24 -e 203.0.113.1 -L -m\n"
        "  sudo %s -i eth0 -c -j\n",
        prog, prog, prog, prog);
}

static int get_map_fd(const char *name) {
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    if (!m) {
        fprintf(stderr, "Map '%s' not found in BPF object\n", name);
        return -1;
    }
    return bpf_map__fd(m);
}

static void detach_xdp(void) {
    if (ifindex > 0) {
        bpf_set_link_xdp_fd(ifindex, -1, xdp_flags_used);
        ifindex = -1;
    }
}

static void cleanup(void) {
    detach_xdp();
    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
}

int main(int argc, char **argv) {
    const char *interface    = NULL;
    const char *internal_net = NULL;
    const char *external_ip  = NULL;
    int port_start    = 10000;
    int port_end      = 20000;
    int tcp_timeout   = 7440;
    int udp_timeout   = 300;
    int icmp_timeout  = 30;
    int show_stats    = 0;
    int show_conns    = 0;
    int monitor_mode  = 0;
    int daemon_mode   = 0;
    int log_events    = 0;

    static struct option opts[] = {
        {"interface",    required_argument, 0, 'i'},
        {"network",      required_argument, 0, 'n'},
        {"external-ip",  required_argument, 0, 'e'},
        {"port-start",   required_argument, 0, 's'},
        {"port-end",     required_argument, 0, 'E'},
        {"tcp-timeout",  required_argument, 0, 't'},
        {"udp-timeout",  required_argument, 0, 'u'},
        {"icmp-timeout", required_argument, 0, 'I'},
        {"stats",        no_argument,       0, 'S'},
        {"conns",        no_argument,       0, 'c'},
        {"monitor",      no_argument,       0, 'm'},
        {"daemon",       no_argument,       0, 'd'},
        {"json",         no_argument,       0, 'j'},
        {"log-events",   no_argument,       0, 'L'},
        {"help",         no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:n:e:s:E:t:u:I:ScmdjLh",
                              opts, NULL)) != -1) {
        switch (opt) {
        case 'i': interface    = optarg;       break;
        case 'n': internal_net = optarg;       break;
        case 'e': external_ip  = optarg;       break;
        case 's': port_start   = atoi(optarg); break;
        case 'E': port_end     = atoi(optarg); break;
        case 't': tcp_timeout  = atoi(optarg); break;
        case 'u': udp_timeout  = atoi(optarg); break;
        case 'I': icmp_timeout = atoi(optarg); break;
        case 'S': show_stats   = 1;            break;
        case 'c': show_conns   = 1;            break;
        case 'm': monitor_mode = 1;            break;
        case 'd': daemon_mode  = 1;            break;
        case 'j': json_output  = 1;            break;
        case 'L': log_events   = 1;            break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (!interface) {
        fprintf(stderr, "Error: --interface is required\n");
        usage(argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(interface);
    if (!ifindex) {
        fprintf(stderr, "Interface '%s' not found: %s\n",
                interface, strerror(errno));
        return 1;
    }

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
        fprintf(stderr, "setrlimit(RLIMIT_MEMLOCK): %s\n", strerror(errno));
        return 1;
    }

    obj = bpf_object__open_file("xdp_nat_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open xdp_nat_kern.o\n");
        return 1;
    }
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    nat_table_fd  = get_map_fd("nat_table");
    nat_rev_fd    = get_map_fd("nat_reverse_table");
    port_pool_fd  = get_map_fd("port_pool");
    stats_fd      = get_map_fd("stats_map");
    config_fd     = get_map_fd("config_map");
    event_ring_fd = get_map_fd("event_ring");

    if (nat_table_fd < 0 || nat_rev_fd < 0 || port_pool_fd < 0 ||
        stats_fd < 0     || config_fd < 0   || event_ring_fd < 0) {
        bpf_object__close(obj);
        return 1;
    }

    if (show_stats) {
        print_stats();
        bpf_object__close(obj);
        return 0;
    }
    if (show_conns) {
        dump_connections();
        bpf_object__close(obj);
        return 0;
    }

    if (!internal_net || !external_ip) {
        fprintf(stderr, "Error: --network and --external-ip are required\n");
        usage(argv[0]);
        cleanup();
        return 1;
    }

    if (load_config(internal_net, external_ip, port_start, port_end,
                    tcp_timeout, udp_timeout, icmp_timeout, log_events) != 0) {
        cleanup();
        return 1;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "xdp_nat_prog");
    if (!prog) {
        fprintf(stderr, "BPF program 'xdp_nat_prog' not found\n");
        cleanup();
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    /* try native driver mode first; fall back to generic SKB mode */
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_DRV_MODE) == 0) {
        xdp_flags_used = XDP_FLAGS_DRV_MODE;
        printf("XDP attached in native driver mode\n");
    } else if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE) == 0) {
        xdp_flags_used = XDP_FLAGS_SKB_MODE;
        printf("XDP attached in generic (SKB) mode\n");
    } else {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        cleanup();
        return 1;
    }

    printf("XDP NAT running on %s (pid %d)\n", interface, getpid());
    printf("Press Ctrl-C to stop\n\n");

    if (monitor_mode) {
        if (!log_events) {
            fprintf(stderr, "Warning: --log-events not set; no events will fire."
                            " Add -L to enable.\n");
        }
        struct ring_buffer *rb =
            ring_buffer__new(event_ring_fd, handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
            cleanup();
            return 1;
        }
        while (keep_running) {
            int err = ring_buffer__poll(rb, 100);
            if (err < 0 && err != -EINTR)
                break;
        }
        ring_buffer__free(rb);
        print_stats();
        cleanup();
        return 0;
    }

    if (daemon_mode) {
        printf("Running in daemon mode (cleanup every 30 s)\n");
        while (keep_running) {
            sleep(30);
            cleanup_expired();
        }
    } else {
        while (keep_running) {
            sleep(5);
            print_stats();
        }
    }

    print_stats();
    cleanup();
    printf("Stopped.\n");
    return 0;
}
