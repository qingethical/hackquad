#!/usr/bin/env bash
# hacklith init.sh — first-run environment setup.
# Run with: sudo bash init.sh
set -euo pipefail

INIT_DONE=".init_done"
TOOLS=(
  nmap curl wget git whois openssl unzip python3
  nikto gobuster sqlmap wpscan whatweb ferret
  sublist3r amass gau waybackurls httpx nuclei katana
)

log()  { echo -e "[*] $*"; }
ok()   { echo -e "[+] $*"; }
warn() { echo -e "[!] $*"; }
fail() { echo -e "[x] $*"; exit 1; }

if [ -f "$INIT_DONE" ]; then
  log "init already completed ($INIT_DONE exists). Remove it to re-run."
  exit 0
fi

need_apt() {
  command -v apt-get >/dev/null 2>&1
}

install_apt() {
  log "Updating package lists..."
  apt-get update -qq
  log "Installing missing kali tools..."
  apt-get install -y -qq "$@"
}

install_go() {
  GO_VERSION="1.23.4"
  GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
  GO_URL="https://go.dev/dl/${GO_TARBALL}"
  log "Downloading Go ${GO_VERSION}..."
  wget -q --show-progress "$GO_URL" -O "/tmp/${GO_TARBALL}" || fail "wget $GO_URL failed"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
  rm "/tmp/${GO_TARBALL}"
  export PATH="/usr/local/go/bin:$PATH"
  if ! command -v go >/dev/null 2>&1; then
    echo 'export PATH="/usr/local/go/bin:$PATH"' >> /etc/profile.d/go.sh
  fi
  ok "Go installed: $(go version)"
}

check_go() {
  if command -v go >/dev/null 2>&1; then
    ok "Go found: $(go version)"
    return 0
  fi
  warn "Go not found."
  if [ "$(id -u)" -eq 0 ] && need_apt; then
    install_apt golang-go || true
    if command -v go >/dev/null 2>&1; then
      ok "Go installed via apt: $(go version)"
      return 0
    fi
  fi
  warn "Installing Go from official binaries..."
  install_go
}

check_tool() {
  local tool="$1"
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool: $(command -v "$tool")"
  else
    warn "$tool: missing"
    return 1
  fi
}

log "=== hacklith init ==="
log "Checking environment..."

MISSING=()
for tool in "${TOOLS[@]}"; do
  check_tool "$tool" || MISSING+=("$tool")
done

if [ "${#MISSING[@]}" -gt 0 ]; then
  if [ "$(id -u)" -eq 0 ] && need_apt; then
    log "Installing ${MISSING[*]} via apt..."
    install_apt "${MISSING[@]}"
  else
    warn "Missing tools: ${MISSING[*]}"
    warn "Run as root (sudo) for auto-install, or install manually:"
    echo "    sudo apt install ${MISSING[*]}"
  fi
fi

check_go

log "Compiling hacklith backend..."
SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f go.mod ]; then
  fail "go.mod not found in $SCRIPT_DIR"
fi

log "Running go mod tidy..."
go mod tidy

log "Building single backend binary..."
go build -ldflags "-s -w" -o build/hacklith .

if [ ! -x build/hacklith ]; then
  fail "Build failed — check the Go sources"
fi

ok "Build complete: $(du -h build/hacklith | cut -f1)"

chmod +x build/hacklith
chmod +x modules/shell/*.sh 2>/dev/null || true

touch "$INIT_DONE"
ok "Init complete. Run: sudo bash hacklith.sh"
