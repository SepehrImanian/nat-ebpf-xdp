#!/usr/bin/env bash
# install.sh — one-shot installer for eBPF XDP NAT
# Usage:  curl -fsSL https://raw.githubusercontent.com/SepehrImanian/nat-ebpf-xdp/main/install.sh | sudo bash
set -euo pipefail

REPO="https://github.com/SepehrImanian/nat-ebpf-xdp.git"
INSTALL_BIN="/usr/local/bin"
INSTALL_LIB="/usr/local/lib"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ── Privilege check ──────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || error "This script must be run as root (sudo)."

# ── Kernel version check ─────────────────────────────────────────────────────
KVER_MAJOR=$(uname -r | cut -d. -f1)
KVER_MINOR=$(uname -r | cut -d. -f2)
if [[ $KVER_MAJOR -lt 5 ]] || { [[ $KVER_MAJOR -eq 5 ]] && [[ $KVER_MINOR -lt 8 ]]; }; then
    error "Kernel $(uname -r) is too old. Minimum required: 5.8 (LRU hash + ring buffer)."
fi
info "Kernel $(uname -r) — OK"

# ── Detect package manager and install deps ───────────────────────────────────
install_deps_apt() {
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev \
        "linux-headers-$(uname -r)" \
        libelf-dev zlib1g-dev git
}

install_deps_dnf() {
    dnf install -y clang llvm libbpf-devel kernel-devel \
        elfutils-libelf-devel git
}

install_deps_pacman() {
    pacman -Sy --noconfirm clang llvm libbpf linux-headers git
}

if command -v apt-get &>/dev/null; then
    info "Installing dependencies (apt)..."
    install_deps_apt
elif command -v dnf &>/dev/null; then
    info "Installing dependencies (dnf)..."
    install_deps_dnf
elif command -v pacman &>/dev/null; then
    info "Installing dependencies (pacman)..."
    install_deps_pacman
else
    warn "Unknown package manager — assuming build tools are already installed."
fi

# ── Clone & build ─────────────────────────────────────────────────────────────
info "Cloning repository..."
git clone --depth=1 "$REPO" "$TMP_DIR/nat-ebpf-xdp"
cd "$TMP_DIR/nat-ebpf-xdp"

info "Building..."
make -j"$(nproc)"

# ── Install ────────────────────────────────────────────────────────────────────
info "Installing to ${INSTALL_BIN} and ${INSTALL_LIB}..."
install -m 755 xdp_nat_user  "$INSTALL_BIN/"
install -m 644 xdp_nat_kern.o "$INSTALL_LIB/"

# ── Smoke test ─────────────────────────────────────────────────────────────────
if xdp_nat_user --help &>/dev/null; then
    info "Installation complete — xdp_nat_user is ready."
else
    error "Installed binary does not execute correctly."
fi

echo ""
echo -e "${GREEN}Quick start:${NC}"
echo "  sudo xdp_nat_user -i eth0 -n 192.168.1.0/24 -e <your-public-ip>"
echo ""
echo -e "${GREEN}Daemon mode:${NC}"
echo "  sudo xdp_nat_user -i eth0 -n 192.168.1.0/24 -e <your-public-ip> -d &"
echo ""
echo -e "${GREEN}Stats:${NC}"
echo "  sudo xdp_nat_user -i eth0 --stats"
