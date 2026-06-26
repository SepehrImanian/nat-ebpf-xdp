# Makefile — eBPF XDP NAT
SHELL   := /bin/bash
CC      := clang
CFLAGS  := -O2 -g -Wall -Werror

# Detect kernel headers path.
# KERNEL_HEADERS can be overridden on the command line, e.g.:
#   make KERNEL_HEADERS=/usr    (Dockerfile build against linux-libc-dev)
KVER            := $(shell uname -r)
KERNEL_HEADERS  ?= /usr/src/linux-headers-$(KVER)
LIBBPF_DIR      := /usr/include

# Architecture-specific kernel header subdirectory (x86_64 → x86, aarch64 → arm64)
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

# On Debian/Ubuntu, architecture-specific headers (asm/types.h etc.) live in
# /usr/include/<machine>-linux-gnu/ rather than /usr/include/asm/ directly.
# $(wildcard ...) returns empty string if the path does not exist, so this is
# safe even on non-Debian systems.
ARCH_TRIPLE   := $(shell uname -m)-linux-gnu
MULTIARCH_INC := $(wildcard /usr/include/$(ARCH_TRIPLE))

# On Ubuntu the flavor-specific package (linux-headers-X.X.X-YY-azure) does not
# ship arch/ headers; those live in the common package (linux-headers-X.X.X-YY).
# Strip the trailing flavor word (anything matching -[alpha][alnum]*) to find it.
# If that directory does not exist, fall back to KERNEL_HEADERS.
KVER_COMMON   := $(shell echo $(KVER) | sed 's/-[a-zA-Z][a-zA-Z0-9]*$$//')
KERNEL_COMMON := $(shell \
    test -d /usr/src/linux-headers-$(KVER_COMMON) \
    && echo /usr/src/linux-headers-$(KVER_COMMON) \
    || echo $(KERNEL_HEADERS))

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
	set -o pipefail; $(CC) $(BPF_CFLAGS) \
	    -I$(LIBBPF_DIR) \
	    $(if $(MULTIARCH_INC),-I$(MULTIARCH_INC)) \
	    -I$(KERNEL_HEADERS)/include \
	    -I$(KERNEL_COMMON)/arch/$(ARCH)/include \
	    -I$(KERNEL_COMMON)/arch/$(ARCH)/include/generated \
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
