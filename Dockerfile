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

# linux-libc-dev ships /usr/include/linux/ so we point KERNEL_HEADERS there
# instead of needing the host kernel headers at build time.
RUN make KERNEL_HEADERS=/usr

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    libbpf0 libelf1 zlib1g \
    iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/nat-ebpf-xdp

COPY --from=builder /src/xdp_nat_kern.o .
COPY --from=builder /src/xdp_nat_user  .

# requires --privileged and --network host to load into the host kernel
ENTRYPOINT ["/opt/nat-ebpf-xdp/xdp_nat_user"]
CMD ["--help"]
