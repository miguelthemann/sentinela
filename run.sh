#!/usr/bin/env bash
# Script rápido de execução do Sentinela com CAP_NET_RAW automático

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

MODE="release"
CARGO_FLAGS="--release"

if [ "$1" = "--debug" ]; then
    MODE="debug"
    CARGO_FLAGS=""
    shift
fi

echo "==> A compilar Sentinela ($MODE)..."
cargo build $CARGO_FLAGS

BIN="target/$MODE/sentinela"

if ! getcap "$BIN" 2>/dev/null | grep -q "cap_net_raw"; then
    echo "==> A atribuir permissão CAP_NET_RAW..."
    sudo setcap cap_net_raw+eip "$BIN"
fi

echo "==> A iniciar Sentinela..."
exec "$BIN" "$@"
