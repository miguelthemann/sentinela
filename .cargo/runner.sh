#!/usr/bin/env bash
# Runner automático do Cargo para o Sentinela
# Tenta atribuir CAP_NET_RAW se tiver privilégios; caso contrário, executa diretamente sem bloquear.

BIN="$1"
shift

if [ -f "$BIN" ]; then
    if ! getcap "$BIN" 2>/dev/null | grep -q "cap_net_raw"; then
        if [ "$(id -u)" -eq 0 ]; then
            setcap cap_net_raw+eip "$BIN" 2>/dev/null || true
        elif sudo -n true 2>/dev/null; then
            sudo -n setcap cap_net_raw+eip "$BIN" 2>/dev/null || true
        fi
    fi
fi

exec "$BIN" "$@"
