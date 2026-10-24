#!/usr/bin/env sh
# ==============================================================================
# Sentinela HIDS - Script de Instalação Automatizado (Linux & macOS)
# Repositório: https://github.com/teizinh/sentinela
# Licença: MIT
# ==============================================================================

set -e

REPO="teizinh/sentinela"
BINARY_NAME="sentinela"

# Cores para o terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

printf "${CYAN}"
cat << 'EOF'
   ___           _   _            _       
  / __| ___ _ _ | |_(_)_ _  ___  | | __ _ 
  \__ \/ -_) ' \|  _| | ' \/ -_) | |/ _` |
  |___/\___|_||_|\__|_|_||_\___| |_|\__,_|
      Honeypot & Intrusion Detection System
EOF
printf "${NC}\n"

echo "${BOLD}==> A iniciar a instalação do Sentinela...${NC}"

# 1. Deteta o Sistema Operativo e Arquitetura
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        OS_TAG="linux"
        ;;
    Darwin)
        OS_TAG="macos"
        ;;
    *)
        echo "${RED}Erro: Sistema Operativo não suportado: $OS${NC}"
        echo "O Sentinela suporta oficialmente Linux e macOS através deste script (e Windows via install.ps1)."
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH_TAG="x86_64"
        ;;
    aarch64|arm64)
        ARCH_TAG="arm64"
        ;;
    *)
        echo "${RED}Erro: Arquitetura não suportada: $ARCH${NC}"
        exit 1
        ;;
esac

ASSET_NAME="sentinela-${OS_TAG}-${ARCH_TAG}.tar.gz"
echo "  • Sistema detetado: ${BLUE}${OS} (${ARCH})${NC} -> Pacote: ${CYAN}${ASSET_NAME}${NC}"

# 2. Localiza ou Descarrega o Binário
TMP_DIR="$(mktemp -d /tmp/sentinela-install-XXXXXX)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

TARGET_BIN=""

# Verifica se o binário já está no diretório atual (extração local de tarball)
if [ -f "./sentinela" ] && [ -x "./sentinela" ]; then
    echo "  • Binário local encontrado no diretório atual."
    TARGET_BIN="./sentinela"
elif [ -f "./target/release/sentinela" ]; then
    echo "  • Binário compilado encontrado em ./target/release/sentinela."
    TARGET_BIN="./target/release/sentinela"
else
    echo "  • A descarregar o último lançamento oficial do GitHub..."
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
    
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${ASSET_NAME}" || {
            echo "${RED}Erro: Falha ao descarregar ${DOWNLOAD_URL}${NC}"
            echo "Verifique a sua ligação ou se existe uma release com o asset: ${ASSET_NAME}"
            exit 1
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$DOWNLOAD_URL" -O "${TMP_DIR}/${ASSET_NAME}" || {
            echo "${RED}Erro: Falha ao descarregar ${DOWNLOAD_URL}${NC}"
            exit 1
        }
    else
        echo "${RED}Erro: Nem 'curl' nem 'wget' foram encontrados no sistema.${NC}"
        exit 1
    fi

    tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "$TMP_DIR"
    TARGET_BIN="${TMP_DIR}/sentinela"
fi

if [ ! -f "$TARGET_BIN" ]; then
    echo "${RED}Erro: Não foi possível obter o binário executável do Sentinela.${NC}"
    exit 1
fi

# 3. Determina o diretório de destino
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    SUDO=""
else
    if command -v sudo >/dev/null 2>&1; then
        INSTALL_DIR="/usr/local/bin"
        SUDO="sudo"
    else
        INSTALL_DIR="$HOME/.local/bin"
        SUDO=""
        mkdir -p "$INSTALL_DIR"
    fi
fi

DEST_PATH="${INSTALL_DIR}/${BINARY_NAME}"
echo "  • A instalar o binário em: ${CYAN}${DEST_PATH}${NC}..."

if [ -n "$SUDO" ]; then
    $SUDO cp "$TARGET_BIN" "$DEST_PATH"
    $SUDO chmod 755 "$DEST_PATH"
else
    cp "$TARGET_BIN" "$DEST_PATH"
    chmod 755 "$DEST_PATH"
fi

# 4. No Linux: Aplica Permissões Raw Sockets e Gestão de Rede (CAP_NET_RAW + CAP_NET_ADMIN)
if [ "$OS" = "Linux" ]; then
    if command -v setcap >/dev/null 2>&1; then
        echo "  • A configurar capacidades de rede (CAP_NET_RAW + CAP_NET_ADMIN)..."
        if [ -n "$SUDO" ]; then
            $SUDO setcap cap_net_raw,cap_net_admin+eip "$DEST_PATH" 2>/dev/null && \
                echo "    ${GREEN}✓ Permissões CAP_NET_RAW e CAP_NET_ADMIN atribuídas (Deteção SYN scan e Killswitch ativos sem root!)${NC}" || \
                echo "    ${YELLOW}! Aviso: Não foi possível atribuir capacidades completas. O Sentinela funcionará como honeypot TCP.${NC}"
        else
            setcap cap_net_raw,cap_net_admin+eip "$DEST_PATH" 2>/dev/null || true
        fi
    fi
fi

# 5. Validação de PATH
case ":$PATH:" in
    *":${INSTALL_DIR}:"*)
        PATH_OK=1
        ;;
    *)
        PATH_OK=0
        ;;
esac

echo ""
echo "${GREEN}======================================================================${NC}"
echo "${GREEN}${BOLD}       ✓ SENTINELA INSTALADO COM SUCESSO!                             ${NC}"
echo "${GREEN}======================================================================${NC}"
echo "  Binário: ${DEST_PATH}"

if [ "$PATH_OK" -eq 0 ]; then
    echo "${YELLOW}! ATENÇÃO: ${INSTALL_DIR} não está na sua variável PATH.${NC}"
    echo "  Adicione a seguinte linha ao seu ~/.bashrc ou ~/.zshrc:"
    echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
fi

echo "Para iniciar a monitorização:"
echo "  ${CYAN}${BINARY_NAME}${NC}                      # Portas padrão (22, 80, 443, 3306, 8080...)"
echo "  ${CYAN}${BINARY_NAME} 2222 8000 9000${NC}       # Portas personalizadas"
echo ""
echo "Atalhos rápidos dentro da TUI:"
echo "  [K] Ativar/Desativar Killswitch | [W] Auditar Portas Abertas | [Q] Sair"
echo ""
