# Makefile for eBPF XDP NAT
CC := clang
CFLAGS := -O2 -g -Wall -Werror

# Kernel headers and libbpf
LIBBPF_DIR := /usr/include
KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)

# eBPF compilation flags  
BPF_CFLAGS := -target bpf -D__KERNEL__ -Wno-unused-value -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end \
              -Wno-address-of-packed-member -Wno-tautological-compare \
              -Wno-unknown-warning-option -O2 -emit-llvm

# Userspace compilation flags
USER_CFLAGS := -lbpf -lelf -lz

.PHONY: all clean install

all: xdp_nat_kern.o xdp_nat_user

xdp_nat_kern.o: xdp_nat_kern.c
	$(CC) $(BPF_CFLAGS) -I$(LIBBPF_DIR) -I$(KERNEL_HEADERS)/include \
		-c $< -o - | llc -march=bpf -filetype=obj -o $@

xdp_nat_user: xdp_nat_user.c
	$(CC) $(CFLAGS) $(USER_CFLAGS) -I$(LIBBPF_DIR) $< -o $@

clean:
	rm -f xdp_nat_kern.o xdp_nat_user

install: all
	sudo cp xdp_nat_user /usr/local/bin/
	sudo cp xdp_nat_kern.o /usr/local/lib/

# Example usage targets
example-setup:
	@echo "Setting up NAT on eth0 for 192.168.1.0/24 -> 203.0.113.1"
	sudo ./xdp_nat_user -i eth0 -n 192.168.1.0/24 -e 203.0.113.1

stats:
	sudo ./xdp_nat_user -i eth0 -S