# 🛡️ Sentinela

<p align="center">
  <strong>Sistema Leve de Deteção de Intrusões (NIDS), Monitorização de Portas e Armadilhas de Rede em Rust</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Interface-Ratatui%20TUI-purple.svg" alt="Ratatui">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg" alt="Platforms">
  <img src="https://img.shields.io/badge/Version-0.3.0-green.svg" alt="Version">
</p>

---

## ⚡ Instalação Rápida (Releases Oficiais)

O Sentinela dispõe de instaladores automatizados e binários portáteis pré-compilados para os principais sistemas operativos:

### 🐧 Linux & 🍎 macOS (Terminal)
Executa o comando de instalação num terminal (deteta a arquitetura `x86_64` ou `arm64`, instala em `/usr/local/bin` e configura `CAP_NET_RAW` no Linux automaticamente):
```bash
curl -fsSL https://raw.githubusercontent.com/teizinh/sentinela/main/install.sh | bash
```

### 🪟 Windows 10/11 (PowerShell)
Executa na PowerShell (instala em `%LOCALAPPDATA%\Programs\Sentinela`, adiciona ao `PATH` e cria atalho no Ambiente de Trabalho):
```powershell
irm https://raw.githubusercontent.com/teizinh/sentinela/main/scripts/install.ps1 | iex
```

### 📦 Descarregamento Direto das Releases

| Sistema Operativo | Arquitetura | Pacote Oficial |
| :--- | :--- | :--- |
| **Linux** | x86_64 (64-bit Intel/AMD) | [`sentinela-linux-x86_64.tar.gz`](https://github.com/teizinh/sentinela/releases/latest/download/sentinela-linux-x86_64.tar.gz) |
| **Linux** | ARM64 / aarch64 (Raspberry Pi / Servidores ARM) | [`sentinela-linux-arm64.tar.gz`](https://github.com/teizinh/sentinela/releases/latest/download/sentinela-linux-arm64.tar.gz) |
| **Windows** | x86_64 (Windows 10/11) | [`sentinela-windows-x64.zip`](https://github.com/teizinh/sentinela/releases/latest/download/sentinela-windows-x64.zip) |
| **macOS** | Apple Silicon (M1 / M2 / M3 / M4) | [`sentinela-macos-arm64.tar.gz`](https://github.com/teizinh/sentinela/releases/latest/download/sentinela-macos-arm64.tar.gz) |
| **macOS** | Intel (x86_64) | [`sentinela-macos-x64.tar.gz`](https://github.com/teizinh/sentinela/releases/latest/download/sentinela-macos-x64.tar.gz) |

---

## 📖 Visão Geral

O **Sentinela** é uma ferramenta de cibersegurança e monitorização de tráfego de rede concebida em **Rust**. Opera em tempo real através de uma interface interativa de terminal (**TUI - Terminal User Interface**) desenvolvida com a biblioteca **Ratatui**.

O sistema atua como sentinela passiva e ativa na interface de rede da máquina, identificando varrimentos de portas suspeitos (incluindo *SYN stealth scans* do Nmap), disponibilizando armadilhas de rede (*honeypot trap ports*) e permitindo o isolamento imediato da rede através de um *Emergency Killswitch*.

---

## ✨ Funcionalidades Principais

* 🔍 **Deteção de Port Scans em Tempo Real:** Captura pacotes brutos (*raw sockets*) via `pnet` ao nível da camada de rede, detetando varrimentos furtivos (`nmap -sS`, masscan) antes de a ligação TCP de 3 vias se completar.
* 🪤 **Armadilhas de Rede Configuráveis (*Honeypot Trap Ports*):** Permite abrir portas armadilhadas (ex: SSH em `2222`, HTTP em `8080`, RDP em `3389`). Qualquer ligação a estas portas gera de imediato um alerta de severidade elevada com identificação do IP intruso.
* 🖥️ **Dashboard Interativo em Terminal (Ratatui TUI):** Visualização estética e responsiva em tempo real com taxas de pacotes/segundo, lista cronológica de incidentes com códigos de cores, estado das portas e interfaces ativas.
* 🛑 **Emergency Network Killswitch:** Permite cortar ou reativar instantaneamente as interfaces de rede através de um único atalho de teclado (`k`), útil para conter exfiltração de dados ou varrimentos agressivos.
* 📊 **Classificação Semântica de Incidentes:** Alertas distribuídos por 4 patamares de gravidade: `Baixa`, `Média`, `Alta` e `Crítica`.
* 📝 **Registo e Auditoria Persistente:** Criação automática de ficheiros de log diários com carimbo temporal (`sentinela_YYYY-MM-DD.log`).
* 🌐 **Suporte Bilingue:** Alternância instantânea entre **Português (PT)** e **Inglês (EN)** premindo a tecla `l`.
* ⚡ **Performance e Baixo Consumo:** Desenvolvido 100% em Rust assíncrono com o runtime `tokio`, com consumo mínimo de memória RAM e CPU.

---

## 🛠️ Arquitetura do Código

A estrutura modular do projeto em `src/` divide-se nas seguintes responsabilidades:

| Módulo | Ficheiro | Responsabilidade |
| :--- | :--- | :--- |
| **Ponto de Entrada** | [`src/main.rs`](src/main.rs) | Ciclo principal de eventos, escuta de sinais (SIGINT/Ctrl+C), gestão de argumentos e coordenação assíncrona. |
| **Modelos de Dados** | [`src/models.rs`](src/models.rs) | Estruturas de `Incident`, `SeverityFilter`, `PortWarning` e definições multilíngue (`Language`). |
| **Captura de Rede** | [`src/network.rs`](src/network.rs) | Sniffer de pacotes brutos via `pnet`, deteção de interfaces ativas e controlador de ligações. |
| **Análise Heurística** | [`src/scanner.rs`](src/scanner.rs) | Deteção de padrões de varrimento (Nmap, múltiplos IPs, taxas de pacotes por segundo). |
| **Armadilhas (Traps)** | [`src/traps.rs`](src/traps.rs) | Gestão de sockets de escuta nas portas armadilha e geração de alertas intrusivos. |
| **Interface Visual** | [`src/ui.rs`](src/ui.rs) | Renderização dos widgets Ratatui, blocos, tabelas, modais de ajuda e avisos. |

---

## 🚀 Como Compilar e Executar

### Pré-requisitos
* **Rust & Cargo** (versão 1.70 ou superior recomendada):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
* **Dependências de Rede em Linux (Fedora / Debian / Ubuntu / Arch):**
  * Em Fedora: `sudo dnf install libpcap-devel libcap`
  * Em Ubuntu/Debian: `sudo apt install libpcap-dev libcap2-bin`

### Permissões de Rede (`CAP_NET_RAW`)
Para capturar pacotes de rede crus sem necessitar de correr o binário completo como `root`, o Sentinela utiliza a capacidade Linux `CAP_NET_RAW`. O script incluído `run.sh` configura isto automaticamente:

```bash
# Dar permissão de execução ao script
chmod +x run.sh

# Executar em modo Release com portas padrão
./run.sh
```

### Argumentos Opcionais (Portas Personalizadas)
Podes especificar portas armadilhadas adicionais como argumentos de linha de comando:

```bash
# Monitorizar armadilhas personalizadas nas portas 2222, 8080 e 9999
./run.sh 2222 8080 9999
```

Ou compilar diretamente com o Cargo:
```bash
cargo build --release
sudo setcap cap_net_raw+eip target/release/sentinela
./target/release/sentinela
```

---

## ⌨️ Atalhos de Teclado no Dashboard

| Tecla | Ação |
| :---: | :--- |
| `q` / `Ctrl+C` | **Sair** do Sentinela e restaurar o terminal com segurança |
| `i` | Abrir / Fechar janela de **Ajuda** (*Help Modal*) |
| `w` | Consultar **Auditor de Avisos** de Portas Abertas (*Port Warnings*) |
| `l` | Alternar idioma entre **Português** e **Inglês** |
| `k` | Ativar / Desativar **Emergency Network Killswitch** |
| `f` | Alternar filtro de severidade (**Todos** $\rightarrow$ **Baixa** $\rightarrow$ **Média** $\rightarrow$ **Alta** $\rightarrow$ **Crítica**) |
| `r` | Reiniciar contadores de tráfego e limpar filtros ativos |
| `↑` / `↓` | Percorrer a lista de incidentes detetados |
| `Home` / `End` | Saltar para o início ou fim da lista de incidentes |
| `Esc` | Fechar qualquer janela modal aberta |

---

## 📄 Licença

Este projeto está licenciado sob a Licença **MIT** — consulta o ficheiro [LICENSE](LICENSE) para mais detalhes.

---

<p align="center">
  Desenvolvido por <strong>teizinh</strong> • Cibersegurança & Engenharia de Sistemas Informáticos
</p>
