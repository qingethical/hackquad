#!/usr/bin/env bash
# hacklith shell module: recon_all
# usage: recon_all.sh <target>
# Layered recon with whatever tools exist on the system. Each tool is
# optional; missing tools are skipped with a note.
set -u

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "usage: recon_all.sh <host|url>"
  exit 1
fi

HOST="$TARGET"
case "$HOST" in
  *://*) HOST="$(printf '%s' "$HOST" | sed -E 's|^[a-z]+://||; s|/.*$||')" ;;
esac

echo "=== recon_all: $HOST ==="

if command -v ping >/dev/null 2>&1; then
  echo "--- ping ---"
  ping -c 2 -W 2 "$HOST" 2>&1 | tail -n +1
else
  echo "ping: not installed"
fi

if command -v whois >/dev/null 2>&1; then
  echo "--- whois (first 25 lines) ---"
  timeout 15 whois "$HOST" 2>&1 | head -n 25
else
  echo "whois: not installed (apt install whois)"
fi

if command -v nslookup >/dev/null 2>&1; then
  echo "--- dns: A/MX/NS ---"
  nslookup -type=A  "$HOST" 2>&1 | grep -E 'Address|Name' | head -n 10
  nslookup -type=MX "$HOST" 2>&1 | grep -E 'mail exchanger' | head -n 10
  nslookup -type=NS "$HOST" 2>&1 | grep -E 'nameserver' | head -n 10
else
  echo "nslookup: not installed"
fi

if command -v nmap >/dev/null 2>&1; then
  echo "--- nmap top-1000 ports ---"
  timeout 90 nmap -Pn --top-ports 100 -T4 --open "$HOST" 2>&1 | grep -E '^[0-9]+/tcp|Nmap scan report' | head -n 40
else
  echo "nmap: not installed (apt install nmap) — use the portscan module instead"
fi

if command -v curl >/dev/null 2>&1; then
  echo "--- http headers (root) ---"
  timeout 15 curl -s -I -L --max-redirs 3 "http://$HOST/" 2>&1 | head -n 25
else
  echo "curl: not installed"
fi

echo "=== recon_all done: $HOST ==="

