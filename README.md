# nat-ebpf-xdp

[![CI](https://github.com/SepehrImanian/nat-ebpf-xdp/actions/workflows/ci.yml/badge.svg)](https://github.com/SepehrImanian/nat-ebpf-xdp/actions/workflows/ci.yml)
[![License: GPL-2.0](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)

A NAT implementation using eBPF XDP. It does SNAT on outbound packets and reverse DNAT on the way back, all at the XDP hook before the kernel stack touches anything. Supports TCP, UDP, and ICMP echo.

Tested on Ubuntu 22.04 with kernel 5.15. Needs at least 5.8 for LRU hash maps and the ring buffer.

## How it works

Two LRU hash maps — one for the forward direction (internal 5-tuple → NAT entry) and one for reverse (external 5-tuple → NAT entry). When a new outbound packet arrives, a port is picked from the pool, both map entries are written, and the packet headers are rewritten in place. Return traffic hits the reverse map and gets rewritten back to the original client.

Port allocation uses a random starting index and scans up to 32 slots, which keeps things fast without needing locks across CPUs. Stats are per-CPU to avoid contention there too.

Userspace handles the stuff that doesn't belong in the kernel: loading the BPF object, writing the config, and periodically cleaning up stale connections. The cleanup walks the forward table every 30 seconds (in daemon mode) and removes entries that have been idle longer than their protocol timeout.

## Building

```bash
# Ubuntu/Debian
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) libelf-dev zlib1g-dev

# Fedora/RHEL
sudo dnf install clang llvm libbpf-devel kernel-devel elfutils-libelf-devel

make
sudo make install
```

Or with Docker if you don't want to mess with kernel headers:

```bash
docker build -t nat-ebpf-xdp .
docker run --rm --privileged --network host nat-ebpf-xdp \
    --interface eth0 --network 192.168.1.0/24 --external-ip 203.0.113.1
```

One-liner installer (Ubuntu/Debian/Fedora):

```bash
curl -fsSL https://raw.githubusercontent.com/SepehrImanian/nat-ebpf-xdp/main/install.sh | sudo bash
```

## Running

```bash
# basic usage
sudo xdp_nat_user -i eth0 -n 192.168.1.0/24 -e 203.0.113.1

# run in the background as a cleanup daemon
sudo xdp_nat_user -i eth0 -n 192.168.1.0/24 -e 203.0.113.1 -d &

# watch new connections as they come in
sudo xdp_nat_user -i eth0 -n 192.168.1.0/24 -e 203.0.113.1 -L -m

# see what's currently NATed
sudo xdp_nat_user -i eth0 -c

# check counters
sudo xdp_nat_user -i eth0 -S
```

The tool tries to attach in native driver mode first and falls back to generic SKB mode if the NIC driver doesn't support XDP. Native mode is significantly faster but requires driver support (mlx5, i40e, ixgbe, etc.).

### Options

```
-i / --interface     interface to attach to (required)
-n / --network       internal subnet in CIDR notation
-e / --external-ip   IP to SNAT to
-s / --port-start    start of NAT port range (default 10000)
-E / --port-end      end of NAT port range (default 20000)
-t / --tcp-timeout   TCP idle timeout in seconds (default 7440)
-u / --udp-timeout   UDP idle timeout (default 300)
-I / --icmp-timeout  ICMP idle timeout (default 30)
-S / --stats         print counters and exit
-c / --conns         dump active connections and exit
-m / --monitor       stream ring buffer events to stdout
-d / --daemon        background cleanup loop mode
-L / --log-events    enable kernel-side event emission (needed for -m)
-j / --json          JSON output for all modes
```

## Testing

```bash
# full integration test with network namespaces (needs root)
make test

# just check the BPF program passes the verifier
sudo make test-load
```

The integration test (`test_nat.sh`) spins up three network namespaces — internal, router, external — attaches XDP in generic mode, and runs ICMP/TCP/UDP tests plus stats and connection dump checks.

## Troubleshooting

**xdp_nat_kern.o not found** — you need to `make` first, the `.o` has to be in the working directory when you run the userspace tool.

**port pool exhausted** — either too many concurrent connections for the pool size or stale entries not getting cleaned up. Widen the range with `-s`/`-E`, or lower the timeouts so connections expire faster.

**-m shows nothing** — you need `-L` as well to tell the kernel side to actually write events to the ring buffer. They're two separate flags by design since the ring buffer write has a small cost per packet.

**XDP not attaching in native mode** — not all NIC drivers support XDP. The fallback to SKB mode is automatic, just slower. Check `ip link show <iface>` for `xdp` in the output to confirm it attached at all.

## License

GPL-2.0 — eBPF programs that use GPL-only kernel helpers have to be GPL licensed.
