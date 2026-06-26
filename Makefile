# Makefile — eBPF XDP NAT
CC      := clang
CFLAGS  := -O2 -g -Wall -Werror

# Detect kernel headers path
KVER            := $(shell uname -r)
KERNEL_HEADERS  := /usr/src/linux-headers-$(KVER)
LIBBPF_DIR      := /usr/include

# eBPF kernel program flags
BPF_CFLAGS := \
    -target bpf \
    -D__KERNEL__ \
    -O2 \
    -g \
    -Wno-unused-value \
    -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Wno-gnu-variable-sized-type-not-at-end \
    -Wno-address-of-packed-member \
    -Wno-tautological-compare \
    -Wno-unknown-warning-option \
    -emit-llvm

# Userspace link flags
USER_LIBS := -lbpf -lelf -lz

SRCS_KERN := xdp_nat_kern.c nat_common.h
SRCS_USER := xdp_nat_user.c nat_common.h

.PHONY: all clean install test fmt

all: xdp_nat_kern.o xdp_nat_user

xdp_nat_kern.o: $(SRCS_KERN)
	$(CC) $(BPF_CFLAGS) \
	    -I$(LIBBPF_DIR) \
	    -I$(KERNEL_HEADERS)/include \
	    -c xdp_nat_kern.c -o - \
	    | llc -march=bpf -filetype=obj -o $@

xdp_nat_user: $(SRCS_USER)
	$(CC) $(CFLAGS) -I$(LIBBPF_DIR) $(USER_LIBS) xdp_nat_user.c -o $@

clean:
	rm -f xdp_nat_kern.o xdp_nat_user

install: all
	install -m 755 xdp_nat_user  /usr/local/bin/
	install -m 644 xdp_nat_kern.o /usr/local/lib/

# Run integration tests using Linux network namespaces (requires root)
test: all
	@echo "Running integration tests (requires root)..."
	sudo bash test_nat.sh

# Quick smoke-test: just verify the BPF object passes the verifier
test-load: xdp_nat_kern.o
	@echo "Verifying BPF program loads cleanly..."
	@ip link add dummy_nat_test type dummy 2>/dev/null || true
	@ip link set dummy_nat_test up
	@ip link xdp dev dummy_nat_test off 2>/dev/null || true
	@if bpftool prog load xdp_nat_kern.o /sys/fs/bpf/nat_test_prog 2>&1; then \
	    echo "PASS: BPF program verifier accepted"; \
	    rm -f /sys/fs/bpf/nat_test_prog; \
	else \
	    echo "FAIL: BPF verifier rejected program"; \
	fi
	@ip link del dummy_nat_test 2>/dev/null || true

# Example: attach to eth0, 192.168.1.0/24 → 203.0.113.1
example-setup:
	sudo ./xdp_nat_user -i eth0 -n 192.168.1.0/24 -e 203.0.113.1

stats:
	sudo ./xdp_nat_user -i eth0 -S

conns:
	sudo ./xdp_nat_user -i eth0 -c

monitor:
	sudo ./xdp_nat_user -i eth0 -n 192.168.1.0/24 -e 203.0.113.1 -L -m
