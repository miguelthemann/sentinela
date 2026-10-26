# Sentinela

<p align="center">
  <strong>Network Intrusion Detection, Honeypot Traps and Traffic Monitor — written in Rust</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/Interface-Ratatui%20TUI-purple.svg" alt="Ratatui TUI">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg" alt="Platforms">
  <img src="https://img.shields.io/badge/Version-0.3.3-green.svg" alt="Version 0.3.3">
</p>

---

Sentinela runs on your machine and watches your network interfaces in real time. It detects port scans (including Nmap SYN stealth, NULL, FIN and XMAS scans), catches anything that connects to configurable honeypot ports, and lets you cut all network access instantly if needed. Everything is visible through a terminal dashboard that works from a desktop down to an SSH session on a phone.

It does not require a separate server, database or cloud account. It runs as a single binary.

---

## Install

**Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/teizinh/sentinela/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/teizinh/sentinela/main/scripts/install.ps1 | iex
```

### Pre-built packages

| Platform | Format | File |
|---|---|---|
| Linux (Debian / Ubuntu / Mint) | `.deb` | `sentinela-linux-x86_64.deb` |
| Linux (Fedora / RHEL / openSUSE) | `.rpm` | `sentinela-linux-x86_64.rpm` |
| Linux (universal) | `.tar.gz` | `sentinela-linux-x86_64.tar.gz` |
| Windows | Installer | `sentinela-windows-x64-setup.exe` |
| Windows | Portable zip | `sentinela-windows-x64.zip` |

All releases are on the [Releases page](https://github.com/teizinh/sentinela/releases). Each file has a corresponding `.sha256` checksum. A combined `SHA256SUMS.txt` is included in every release.

---

## What it does

### Port scan detection
On Linux, Sentinela reads raw packets directly from the network interface using `pnet` (requires `CAP_NET_RAW`). This lets it catch SYN stealth scans before the TCP handshake completes — the kind that `nmap -sS` and `masscan` use specifically to avoid leaving traces in application logs. It also detects NULL, FIN and XMAS scans. If a single IP hits five or more distinct ports within five seconds, it is flagged as a port sweep.

On Windows and macOS — or on Linux without the raw socket capability — the scanner degrades gracefully. Honeypot traps continue to work normally.

### Honeypot trap ports
Sentinela binds a set of ports and waits. Any incoming connection triggers an alert. Default trap ports: `2121`, `2222`, `2323`, `8080`, `8443`. You can pass your own list at startup:
```bash
sentinela 22 3306 5432 9200
```

### Emergency killswitch
Press `k` to drop all network traffic instantly. On Linux this inserts blocking rules into `iptables`/`ip6tables` and calls `rfkill block all`. Press `k` again to restore everything. If Sentinela exits while the killswitch is active, it cleans up automatically.

### Deep incident forensic inspection & reverse DNS
Press `Enter` on any highlighted incident to open a full forensic modal showing detailed telemetry: source IP, async Reverse DNS (rDNS / PTR hostname), threat severity, hit counts, geolocation (country and city), ISP entity, target port, captured payload/banner, and recommended mitigation command.

### Honeypot payload & banner sniffing
When an attacker connects to an active honeypot port, Sentinela asynchronously reads the initial bytes (HTTP paths like `GET /admin`, SSH client identification strings, Redis probes, or raw exploit payloads) without blocking the accept loop. Payloads are sanitized and displayed inside the inspection modal and saved into exported reports.

### Real-time traffic pulse & sparkline
On wider terminal screens, Sentinela renders a live unicode `Sparkline` graph in the header displaying attack intensity and frequency over rolling 24-second windows.

### Surgical per-IP firewall ban & unban
Press `b` in the dashboard or within the inspection modal to immediately block the attacker IP with an active firewall rule (`iptables -I INPUT 1 -s <IP> -j DROP` on Linux or `netsh advfirewall` on Windows). Banned addresses are marked with a distinct `[BAN]` badge in the incident table. Pressing `b` again unbans the IP. All surgical bans are cleaned up automatically on exit to prevent orphaned rules.

### Audio & desktop alert toggle
Press `a` to toggle immediate audio terminal bell (`\x07`) sounds and high-urgency OS desktop notifications for incoming Critical and Port Sweep alerts.

### Threat intelligence export
Press `e` at any time to dump the complete session threat intelligence to both `sentinela_report_YYYY-MM-DD_HH-MM-SS.json` and `.csv` files. Includes system metadata, active trap ports, unique attacker count, banned IPs, threat scores, captured payloads, and full incident histories.

### GeoIP lookup
Every detected IP is looked up against the [ip-api.com](http://ip-api.com) service. Country, city and ISP are shown in the dashboard and written to the log. Results are cached for the session; failed lookups retry after two minutes.

### Audit logs
Incidents are written to daily log files (`sentinela_YYYY-MM-DD.log`) in the working directory. The format is plain text, one line per event. When an IP is seen again, the hit counter on its log line is updated in place.

### Session report
When you quit, Sentinela prints a summary to the terminal: uptime, total alerts, unique IPs seen, the most active source, the most targeted port, and a breakdown by severity.

---

## Incident severity levels

| Level | Colour | Triggered by |
|---|---|---|
| Critical | Red | Connections to SSH (22, 2222), Telnet (23, 2323), Redis (6379), MongoDB (27017) traps |
| Sweep | Red | ≥ 5 distinct ports from the same IP within 5 seconds |
| Medium | Yellow | Connections to FTP, SMTP, MySQL, PostgreSQL, RDP traps |
| Scan | Magenta | Raw SYN / NULL / FIN / XMAS packet detected |
| Alert | Cyan | Connections to DNS, HTTP, HTTPS or custom traps |

---

## Dashboard

The terminal UI adapts to the available width:

| Terminal width | Columns shown |
|---|---|
| Under 70 columns | Time, Risk, Source, Target |
| 70 – 94 columns | + Location |
| 95 columns and above | + Hits, ISP |

The header shows current network interface IPs, raw scanner status, and system info. An asterisk next to an IP (`192.168.1.1*`) means that address has triggered more than one alert this session.

The UI language switches between Portuguese and English at runtime. It is auto-detected from your `$LANG` / `$LC_ALL` environment variable at startup and can be toggled at any time with `l`.

### Keyboard shortcuts

| Key | Action |
|---|---|
| `q` / `Ctrl+C` | Exit (cleans up any active killswitch and temporary bans) |
| `Enter` | Open deep forensic inspection modal for selected incident |
| `b` | Surgically ban / unban selected attacker IP (DROP firewall rule) |
| `e` | Export session Threat Intel report to JSON and CSV |
| `a` | Toggle audio bell alarm and desktop notifications |
| `i` | Open / close help modal |
| `w` | Open / close port security audit |
| `l` | Toggle language (PT / EN) |
| `k` | Toggle emergency network killswitch |
| `f` | Cycle severity filter: All → Critical → Medium and above |
| `r` | Restore network (undo killswitch) |
| `↑` / `↓` / `j` / `k` | Scroll incident list |
| `PgUp` / `PgDn` | Scroll 5 lines at a time |
| `Home` / `End` | Jump to top / bottom |
| `Esc` | Close any open modal |

Scrolling works the same way inside the help and port audit modals.

---

## Build from source

**Dependencies:**
- Rust and Cargo 1.70 or later
- On Linux: `libpcap` and `libcap`

```bash
# Fedora / RHEL
sudo dnf install libpcap-devel libcap

# Debian / Ubuntu
sudo apt install libpcap-dev libcap2-bin
```

**Using the included script (recommended):**
```bash
chmod +x run.sh
./run.sh

# With custom trap ports:
./run.sh 22 3306 9200
```

The script builds a release binary, applies `CAP_NET_RAW` automatically, and runs it.

**Manual:**
```bash
cargo build --release
sudo setcap cap_net_raw,cap_net_admin+eip target/release/sentinela
./target/release/sentinela
```

---

## Code structure

| File | Role |
|---|---|
| `src/main.rs` | Entry point, event loop, CLI argument parsing, async coordination |
| `src/models.rs` | Core data types: `Incident`, `PortWarning`, `SeverityFilter`, `Language` |
| `src/network.rs` | Raw packet capture, GeoIP, killswitch, local port scanner, desktop notifications |
| `src/scanner.rs` | Heuristic scan detection (SYN stealth, NULL, FIN, XMAS, port sweeps) |
| `src/traps.rs` | Honeypot TCP listeners, connection handling, alert generation |
| `src/ui.rs` | Ratatui rendering, responsive layout, modals |

The scanner module (`src/scanner.rs`) is Linux-only and compiled conditionally. On other platforms, the rest of the application continues to work through the trap-based detection in `src/traps.rs`.

---

## Notes on permissions

Raw packet capture on Linux requires `CAP_NET_RAW`. The install script and `run.sh` set this capability on the binary automatically using `setcap`. If you run the binary without it, Sentinela will still start and the honeypot traps will still work — only the raw scanner will be inactive, which is shown in the header.

The killswitch also needs `CAP_NET_ADMIN` (or root) to insert `iptables` rules. Without it, it falls back to bringing interfaces down via `ip link`.

---

## Platform support

| Feature | Linux | Windows |
|---|---|---|
| Honeypot traps | ✓ | ✓ |
| Raw scan detection | ✓ | — |
| Killswitch | ✓ (iptables + rfkill) | ✓ (PowerShell) |
| Desktop notifications | ✓ (notify-send) | ✓ (PowerShell) |
| GeoIP lookup | ✓ | ✓ |
| Audit logs | ✓ | ✓ |

---

## License

MIT — see [LICENSE](LICENSE).

---

*Developed by [teizinh](https://github.com/teizinh)*
