# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev \
    linux-libc-dev \
    libelf-dev zlib1g-dev \
    make ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# linux-libc-dev installs /usr/include/linux/, /usr/include/asm/ etc.
# Pass KERNEL_HEADERS=/usr so the Makefile searches /usr/include directly,
# avoiding any dependency on the host kernel version during the Docker build.
RUN make KERNEL_HEADERS=/usr

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
