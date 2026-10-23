#!/usr/bin/env bash
# Runner automático do Cargo para o Sentinela
# Verifica se o binário compilado já tem a capacidade CAP_NET_RAW; se não tiver, aplica-a.

BIN="$1"
shift

if [ -f "$BIN" ]; then
    if ! getcap "$BIN" 2>/dev/null | grep -q "cap_net_raw"; then
        sudo setcap cap_net_raw+eip "$BIN"
    fi
fi

exec "$BIN" "$@"
