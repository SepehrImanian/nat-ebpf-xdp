# eBPF XDP NAT Implementation

High-performance Network Address Translation using eBPF XDP for line-rate packet processing.

## Features

- **Zero-copy packet processing** at XDP hook point
- **Hash-based connection tracking** for O(1) lookups  
- **Configurable port pool** management
- **TCP, UDP, and ICMP** protocol support
- **Real-time statistics** and monitoring
- **Automatic connection cleanup**

## Requirements

- Linux kernel 4.18+ with XDP support
- libbpf and kernel headers installed
- Root privileges (CAP_SYS_ADMIN)
- Network interface with XDP driver support

## Installation

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Compile
make clean && make

# Install (optional)
sudo make install
```

## Usage

### Basic NAT Setup
```bash
# Set up NAT for internal network 192.168.1.0/24
# External IP: 203.0.113.1, Interface: eth0
sudo ./xdp_nat_user -i eth0 -n 192.168.1.0/24 -e 203.0.113.1

# Custom port range
sudo ./xdp_nat_user -i eth0 -n 192.168.1.0/24 -e 203.0.113.1 -s 15000 -E 25000

# Run as daemon
sudo ./xdp_nat_user -i eth0 -n 192.168.1.0/24 -e 203.0.113.1 -d
```

### Statistics and Monitoring
```bash
# View current statistics
sudo ./xdp_nat_user -i eth0 -S

# Monitor in real-time
sudo ./xdp_nat_user -i eth0 -n 192.168.1.0/24 -e 203.0.113.1
```

## Configuration Options

| Option              | Description             | Default     |
| ------------------- | ----------------------- | ----------- |
| `-i, --interface`   | Network interface       | Required    |
| `-n, --network`     | Internal network (CIDR) | Required    |
| `-e, --external-ip` | External NAT IP         | Required    |
| `-s, --port-start`  | Port pool start         | 10000       |
| `-E, --port-end`    | Port pool end           | 20000       |
| `-d, --daemon`      | Run as daemon           | Interactive |
| `-S, --stats`       | Show statistics         | -           |

## Performance Tuning

### Kernel Parameters
```bash
# Increase connection tracking table size
echo 1000000 > /proc/sys/net/