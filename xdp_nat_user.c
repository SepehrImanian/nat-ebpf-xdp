#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

static int ifindex = -1;
static struct bpf_object *obj = NULL;
static int prog_fd = -1;
static int nat_table_fd = -1;
static int port_pool_fd = -1;
static int stats_fd = -1;
static int config_fd = -1;

static volatile sig_atomic_t keep_running = 1;

void signal_handler(int sig) {
    keep_running = 0;
}

static int load_config(const char *internal_net, const char *external_ip,
                      int port_start, int port_end) {
    struct nat_config config = {0};
    
    // Parse internal network (e.g., "192.168.1.0/24")
    char net_str[32];
    strncpy(net_str, internal_net, sizeof(net_str));
    char *slash = strchr(net_str, '/');
    if (!slash) {
        fprintf(stderr, "Invalid network format. Use CIDR notation (e.g., 192.168.1.0/24)\n");
        return -1;
    }
    
    *slash = 0;
    int prefix_len = atoi(slash + 1);
    
    struct in_addr addr;
    if (inet_aton(net_str, &addr) == 0) {
        fprintf(stderr, "Invalid network address\n");
        return -1;
    }
    
    config.internal_network = addr.s_addr;
    config.internal_netmask = htonl(~((1 << (32 - prefix_len)) - 1));
    
    if (inet_aton(external_ip, &addr) == 0) {
        fprintf(stderr, "Invalid external IP address\n");
        return -1;
    }
    config.external_ip = addr.s_addr;
    
    config.port_range_start = port_start;
    config.port_range_end = port_end;
    config.tcp_timeout = 7440; // 2 hours
    config.udp_timeout = 300;  // 5 minutes
    
    int key = 0;
    if (bpf_map_update_elem(config_fd, &key, &config, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update config: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Configuration loaded:\n");
    printf("  Internal network: %s\n", internal_net);
    printf("  External IP: %s\n", external_ip);
    printf("  Port range: %d-%d\n", port_start, port_end);
    
    return 0;
}

static void print_stats(void) {
    int key = 0;
    struct nat_stats stats = {0};
    
    if (bpf_map_lookup_elem(stats_fd, &key, &stats) == 0) {
        printf("\n=== NAT Statistics ===\n");
        printf("Packets processed:  %llu\n", stats.packets_processed);
        printf("Packets translated: %llu\n", stats.packets_translated);
        printf("Packets dropped:    %llu\n", stats.packets_dropped);
        printf("New connections:    %llu\n", stats.new_connections);
        printf("Port exhausted:     %llu\n", stats.port_exhausted);
        printf("======================\n");
    }
}

static void cleanup_connections(void) {
    // Simple connection cleanup - remove old entries
    // In production, this should be more sophisticated
    printf("Cleaning up old connections...\n");
    // Implementation would iterate through nat_table and remove old entries
}

static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("Options:\n");
    printf("  -i, --interface IFACE    Network interface to attach XDP program\n");
    printf("  -n, --network NETWORK    Internal network in CIDR format (e.g., 192.168.1.0/24)\n");
    printf("  -e, --external-ip IP     External IP address for NAT\n");
    printf("  -s, --port-start PORT    Starting port for NAT pool (default: 10000)\n");
    printf("  -E, --port-end PORT      Ending port for NAT pool (default: 20000)\n");
    printf("  -S, --stats              Print statistics and exit\n");
    printf("  -d, --daemon             Run as daemon\n");
    printf("  -h, --help               Show this help\n");
    printf("\nExample:\n");
    printf("  %s -i eth0 -n 192.168.1.0/24 -e 203.0.113.1\n", prog);
}

int main(int argc, char **argv) {
    const char *interface = NULL;
    const char *internal_network = NULL;
    const char *external_ip = NULL;
    int port_start = 10000;
    int port_end = 20000;
    int show_stats = 0;
    int daemon_mode = 0;
    
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"network", required_argument, 0, 'n'},
        {"external-ip", required_argument, 0, 'e'},
        {"port-start", required_argument, 0, 's'},
        {"port-end", required_argument, 0, 'E'},
        {"stats", no_argument, 0, 'S'},
        {"daemon", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:n:e:s:E:Sdh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'n':
                internal_network = optarg;
                break;
            case 'e':
                external_ip = optarg;
                break;
            case 's':
                port_start = atoi(optarg);
                break;
            case 'E':
                port_end = atoi(optarg);
                break;
            case 'S':
                show_stats = 1;
                break;
            case 'd':
                daemon_mode = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
        }
    }
    
    if (!interface) {
        fprintf(stderr, "Interface is required\n");
        usage(argv[0]);
        return 1;
    }
    
    ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface: %s\n", interface);
        return 1;
    }
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Increase RLIMIT_MEMLOCK to allow BPF
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        return 1;
    }
    
    // Load and attach BPF program
    obj = bpf_object__open_file("xdp_nat_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }
    
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        goto cleanup;
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_nat_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        goto cleanup;
    }
    
    prog_fd = bpf_program__fd(prog);
    
    // Get map file descriptors
    struct bpf_map *map;
    map = bpf_object__find_map_by_name(obj, "nat_table");
    nat_table_fd = map ? bpf_map__fd(map) : -1;
    
    map = bpf_object__find_map_by_name(obj, "port_pool");
    port_pool_fd = map ? bpf_map__fd(map) : -1;
    
    map = bpf_object__find_map_by_name(obj, "stats_map");
    stats_fd = map ? bpf_map__fd(map) : -1;
    
    map = bpf_object__find_map_by_name(obj, "config_map");
    config_fd = map ? bpf_map__fd(map) : -1;
    
    if (nat_table_fd < 0 || port_pool_fd < 0 || stats_fd < 0 || config_fd < 0) {
        fprintf(stderr, "Failed to get map file descriptors\n");
        goto cleanup;
    }
    
    if (show_stats) {
        print_stats();
        goto cleanup;
    }
    
    if (!internal_network || !external_ip) {
        fprintf(stderr, "Internal network and external IP are required\n");
        usage(argv[0]);
        goto cleanup;
    }
    
    // Load configuration
    if (load_config(internal_network, external_ip, port_start, port_end) != 0) {
        goto cleanup;
    }
    
    // Attach XDP program
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL) < 0) {
        fprintf(stderr, "Failed to attach XDP program in native mode, trying generic mode\n");
        if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
            fprintf(stderr, "Failed to attach XDP program\n");
            goto cleanup;
        }
    }
    
    printf("XDP NAT program loaded on interface %s\n", interface);
    
    if (daemon_mode) {
        printf("Running in daemon mode...\n");
        while (keep_running) {
            sleep(30);
            cleanup_connections();
        }
    } else {
        printf("Press Ctrl+C to exit and show final statistics\n");
        while (keep_running) {
            sleep(5);
            print_stats();
        }
    }
    
    print_stats();

cleanup:
    // Detach XDP program
    if (ifindex > 0) {
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    }
    
    if (obj) {
        bpf_object__close(obj);
    }
    
    printf("Cleanup completed\n");
    return 0;
}