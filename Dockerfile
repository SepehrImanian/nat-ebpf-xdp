# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev \
    linux-headers-generic \
    libelf-dev zlib1g-dev \
    make ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Use generic kernel headers for the eBPF build (the .o runs on the host kernel)
ENV KERNEL_HEADERS=/usr/src/linux-headers-generic

WORKDIR /src
COPY . .

RUN make

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    libbpf0 libelf1 zlib1g \
    iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/nat-ebpf-xdp

COPY --from=builder /src/xdp_nat_kern.o .
COPY --from=builder /src/xdp_nat_user  .

# The tool requires CAP_SYS_ADMIN and access to the host network.
# Run with: docker run --privileged --network host nat-ebpf-xdp
ENTRYPOINT ["/opt/nat-ebpf-xdp/xdp_nat_user"]
CMD ["--help"]
