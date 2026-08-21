#!/usr/bin/env bash
# hacklith shell module: nmap_quick
# usage: nmap_quick.sh <host> [ports]
set -u

TARGET="${1:-}"
PORTS="${2:-21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443}"
if [ -z "$TARGET" ]; then
  echo "usage: nmap_quick.sh <host> [ports]"
  exit 1
fi

HOST="$TARGET"
case "$HOST" in
  *://*) HOST="$(printf '%s' "$HOST" | sed -E 's|^[a-z]+://||; s|/.*$||')" ;;
esac

if ! command -v nmap >/dev/null 2>&1; then
  echo "nmap: not installed (apt install nmap)"
  exit 1
fi

echo "=== nmap_quick: $HOST ports=$PORTS ==="
exec timeout 120 nmap -Pn -sV -T4 -p "$PORTS" --open "$HOST"

