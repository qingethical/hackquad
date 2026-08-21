#!/usr/bin/env bash
# hacklith shell module: ssl_check
# usage: ssl_check.sh <host> [port]
# Inspects the TLS certificate and cipher of a host with openssl.
set -u

TARGET="${1:-}"
PORT="${2:-443}"
if [ -z "$TARGET" ]; then
  echo "usage: ssl_check.sh <host> [port]"
  exit 1
fi

HOST="$TARGET"
case "$HOST" in
  *://*) HOST="$(printf '%s' "$HOST" | sed -E 's|^[a-z]+://||; s|/.*$||')" ;;
esac

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl: not installed"
  exit 1
fi

echo "=== ssl_check: $HOST:$PORT ==="
timeout 15 openssl s_client -connect "$HOST:$PORT" -servername "$HOST" </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 2>&1 \
  | head -n 20

echo "--- cipher ---"
timeout 15 openssl s_client -connect "$HOST:$PORT" -servername "$HOST" </dev/null 2>/dev/null \
  | grep -E 'Cipher is|Protocol  :|New, TLS' | head -n 5
echo "=== ssl_check done ==="

