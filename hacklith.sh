#!/usr/bin/env bash
# hacklith.sh — launcher for the hacklith offensive web-testing toolkit.
# Usage:
#   sudo bash hacklith.sh                 interactive terminal UI
#   sudo bash hacklith.sh --run <module> --target <url> [flags]
set -u

# --- resolve the real project root (handles symlinks and relative paths)
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
ROOT="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
export HACKLITH_ROOT="$ROOT"

BIN="$ROOT/build/hacklith"
SRC="$ROOT/main.go"
MODULES_DIR="$ROOT/modules/shell"
INIT_DONE="$ROOT/.init_done"

# --- first-run init -------------------------------------------------------
if [ ! -f "$INIT_DONE" ]; then
  echo "[*] first run detected — running init.sh"
  if [ -x "$ROOT/init.sh" ]; then
    bash "$ROOT/init.sh"
  else
    echo "[x] init.sh not found at $ROOT/init.sh"
    exit 1
  fi
fi

# --- dependency check -----------------------------------------------------
need_go=0
if ! command -v go >/dev/null 2>&1; then
  need_go=1
fi

if [ "$need_go" -eq 1 ]; then
  echo "[!] go is required to build hacklith"
  if [ "$(id -u)" -eq 0 ] && command -v apt-get >/dev/null 2>&1; then
    echo "[*] installing golang-go via apt..."
    apt-get update -qq && apt-get install -y -qq golang-go
    if command -v go >/dev/null 2>&1; then
      echo "[+] go installed: $(go version)"
      need_go=0
    fi
  else
    echo "[x] run as root (sudo) to auto-install, or install golang first:"
    echo "    apt install golang-go"
    exit 1
  fi
fi

echo "[*] hacklith root: $ROOT"
echo "[*] go: $(go version)"

# --- optional tool report ------------------------------------------------
missing=()
for tool in curl nmap git openssl whois; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "[~] optional tools not found: ${missing[*]}"
  echo "    (apt install ${missing[*]})  — core modules work without them"
fi

# --- dependency sync (for bubbletea and other go modules) ------------------
if [ -f "$ROOT/go.mod" ]; then
  echo "[*] syncing go modules..."
  (cd "$ROOT" && go mod tidy)
fi

# --- stale-source rebuild ------------------------------------------------
need_build=0
if [ ! -x "$BIN" ]; then
  need_build=1
else
  if find "$ROOT" -name '*.go' -newer "$BIN" -not -path '*/build/*' 2>/dev/null | grep -q .; then
    need_build=1
  fi
fi

if [ "$need_build" -eq 1 ]; then
  echo "[*] building hacklith (go build)..."
  mkdir -p "$ROOT/build"
  (cd "$ROOT" && go build -ldflags "-s -w" -o "$BIN" .)
  if [ $? -ne 0 ] || [ ! -x "$BIN" ]; then
    echo "[x] build failed — check the Go sources"
    exit 1
  fi
  echo "[+] build ok: $BIN ($(du -h "$BIN" | cut -f1))"
fi

# --- shell module availability -------------------------------------------
if [ -d "$MODULES_DIR" ] && ls "$MODULES_DIR"/*.sh >/dev/null 2>&1; then
  chmod +x "$MODULES_DIR"/*.sh
fi

# --- run ------------------------------------------------------------------
exec "$BIN" "$@"
