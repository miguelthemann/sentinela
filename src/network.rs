use crate::models::{GeoResponse, Incident, Language, PortWarning, SysInfo};
use get_if_addrs::get_if_addrs;
#[cfg(target_os = "linux")]
use std::fs;
use std::{
    collections::{HashMap, HashSet},
    env,
    net::IpAddr,
    process::{Command, Stdio},
    sync::{OnceLock, RwLock as StdRwLock},
    time::Duration,
};
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct GeoCacheEntry {
    pub geo: (String, String, String),
    /// Data/hora de expiração para entradas de cache negativas (falhas de lookup).
    /// Se `None`, a entrada é positiva (sucesso) e permanece válida durante toda a sessão.
    pub expires_at: Option<std::time::Instant>,
}

static GEO_CACHE: OnceLock<RwLock<HashMap<IpAddr, GeoCacheEntry>>> = OnceLock::new();

pub fn get_geo_cache() -> &'static RwLock<HashMap<IpAddr, GeoCacheEntry>> {
    GEO_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Cliente HTTP partilhado por todos os lookups GeoIP.
/// Criado uma vez — reutiliza pool de ligações e sessão TLS em vez de
/// abrir uma nova ligação TCP+TLS a cada pedido.
static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn get_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .user_agent("sentinela/0.3.2")
            .build()
            .expect("Falha ao construir cliente HTTP")
    })
}

pub fn detect_language() -> Language {
    let lang_var = env::var("LANG")
        .or_else(|_| env::var("LC_ALL"))
        .unwrap_or_default()
        .to_lowercase();

    if lang_var.starts_with("pt") {
        Language::Pt
    } else {
        Language::En
    }
}

struct HostIpsCache {
    ips: HashSet<IpAddr>,
    expires_at: std::time::Instant,
}

static HOST_IPS_CACHE: StdRwLock<Option<HostIpsCache>> = StdRwLock::new(None);

pub fn is_host_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }

    let now = std::time::Instant::now();

    // Fast path: leitura da cache sem contenção caso ainda esteja válida (TTL de 10 segundos)
    if let Ok(guard) = HOST_IPS_CACHE.read() {
        if let Some(cache) = &*guard {
            if now < cache.expires_at {
                return cache.ips.contains(&ip);
            }
        }
    }

    // Refresh path: atualiza as interfaces locais evitando tempestades de chamadas netlink
    if let Ok(mut guard) = HOST_IPS_CACHE.write() {
        // Double-check após adquirir o lock de escrita
        if let Some(cache) = &*guard {
            if now < cache.expires_at {
                return cache.ips.contains(&ip);
            }
        }

        let mut fresh_ips = HashSet::new();
        if let Ok(interfaces) = get_if_addrs() {
            for iface in interfaces {
                fresh_ips.insert(iface.ip());
            }
        }

        let is_host = fresh_ips.contains(&ip);
        *guard = Some(HostIpsCache {
            ips: fresh_ips,
            expires_at: now + Duration::from_secs(10),
        });
        return is_host;
    }

    // Fallback de segurança se o lock estiver corrompido
    if let Ok(interfaces) = get_if_addrs() {
        for iface in interfaces {
            if iface.ip() == ip {
                return true;
            }
        }
    }

    false
}

#[cfg(target_os = "linux")]
pub fn get_system_info() -> SysInfo {
    let distro = fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return Some(
                        line.trim_start_matches("PRETTY_NAME=")
                            .trim_matches(|c| c == '"' || c == '\'')
                            .to_string(),
                    );
                }
            }
            None
        })
        .unwrap_or_else(|| "Linux Genérico".to_string());

    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|k| k.trim().to_string())
        .unwrap_or_else(|_| "Desconhecido".to_string());

    let arch = env::consts::ARCH.to_string();

    SysInfo {
        distro,
        kernel,
        arch,
    }
}

#[cfg(target_os = "windows")]
pub fn get_system_info() -> SysInfo {
    let distro = "Windows".to_string();
    let kernel = match Command::new("cmd").args(["/c", "ver"]).output() {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() {
                "Windows 10/11".to_string()
            } else {
                s
            }
        }
        Err(_) => "Windows".to_string(),
    };
    let arch = env::consts::ARCH.to_string();

    SysInfo {
        distro,
        kernel,
        arch,
    }
}

#[cfg(target_os = "macos")]
pub fn get_system_info() -> SysInfo {
    let distro = match Command::new("sw_vers").arg("-productVersion").output() {
        Ok(out) => format!("macOS {}", String::from_utf8_lossy(&out.stdout).trim()),
        Err(_) => "macOS".to_string(),
    };
    let kernel = match Command::new("uname").arg("-r").output() {
        Ok(out) => format!("Darwin {}", String::from_utf8_lossy(&out.stdout).trim()),
        Err(_) => "Darwin".to_string(),
    };
    let arch = env::consts::ARCH.to_string();

    SysInfo {
        distro,
        kernel,
        arch,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn get_system_info() -> SysInfo {
    SysInfo {
        distro: env::consts::OS.to_string(),
        kernel: "Unix".to_string(),
        arch: env::consts::ARCH.to_string(),
    }
}

pub fn get_all_local_ips() -> String {
    match get_if_addrs() {
        Ok(interfaces) => {
            let mut list = Vec::new();
            for iface in interfaces {
                if let IpAddr::V4(ipv4) = iface.addr.ip() {
                    if !ipv4.is_loopback() {
                        list.push(format!("{}: {}", iface.name, ipv4));
                    }
                }
            }
            if list.is_empty() {
                "Sem IPs".into()
            } else {
                list.join(" | ")
            }
        }
        Err(_) => "Erro de IP".into(),
    }
}

/// Devolve (country, city, isp) para o IP fornecido.
/// Usa cache em memória com TTL de 5 minutos para falhas para permitir novas tentativas.
pub async fn inspect_ip(ip: IpAddr) -> (String, String, String) {
    if ip.is_loopback() {
        return (
            "Loopback".to_string(),
            "".to_string(),
            "Host Interno".to_string(),
        );
    }

    match ip {
        IpAddr::V4(ipv4) if ipv4.is_private() => (
            "Rede Local (LAN)".to_string(),
            "".to_string(),
            "Dispositivo Interno".to_string(),
        ),
        _ => {
            // 1. Verifica cache em memória primeiro (respeitando TTL para entradas negativas)
            {
                let now = std::time::Instant::now();
                let cache = get_geo_cache().read().await;
                if let Some(entry) = cache.get(&ip) {
                    match entry.expires_at {
                        Some(exp) if now < exp => return entry.geo.clone(),
                        Some(_) => {} // Cache negativa expirada (passaram > 5 min): tentar novamente
                        None => return entry.geo.clone(), // Cache positiva válida
                    }
                }
            }

            // 2. Efetua pedido HTTP se não estiver na cache ou se a cache negativa tiver expirado
            let url = format!(
                "http://ip-api.com/json/{}?fields=status,country,city,isp",
                ip
            );
            let (result, is_negative) = match get_http_client().get(&url).send().await {
                Ok(resp) => {
                    if let Ok(geo) = resp.json::<GeoResponse>().await {
                        if geo.status.as_deref() == Some("success") {
                            (
                                (
                                    geo.country.unwrap_or_else(|| "Desconhecido".to_string()),
                                    geo.city.unwrap_or_default(),
                                    geo.isp.unwrap_or_else(|| "Desconhecido".to_string()),
                                ),
                                false, // Sucesso: resposta positiva
                            )
                        } else {
                            (
                                (
                                    "Internet (WAN)".to_string(),
                                    "".to_string(),
                                    "Consulta Externa".to_string(),
                                ),
                                true,
                            )
                        }
                    } else {
                        (
                            (
                                "Internet (WAN)".to_string(),
                                "".to_string(),
                                "Consulta Externa".to_string(),
                            ),
                            true,
                        )
                    }
                }
                Err(_) => (
                    (
                        "Internet (WAN)".to_string(),
                        "".to_string(),
                        "Sem resposta GeoIP".to_string(),
                    ),
                    true,
                ),
            };

            // 3. Guarda em cache: respostas com falha recebem TTL curto (2 min) para retentativa futura
            // Reduzido de 5 min para 2 min: economiza memória e permite retry mais rápido
            {
                let expires_at = if is_negative {
                    Some(std::time::Instant::now() + Duration::from_secs(120)) // 2 minutos
                } else {
                    None
                };
                let mut cache = get_geo_cache().write().await;
                cache.insert(
                    ip,
                    GeoCacheEntry {
                        geo: result.clone(),
                        expires_at,
                    },
                );
            }

            result
        }
    }
}

#[cfg(target_os = "linux")]
fn run_cmd(cmd: &str, args: &[&str]) -> bool {
    // 1. Tenta execução direta (processo com privilégios de root ou capabilities)
    if let Ok(output) = Command::new(cmd).args(args).output() {
        if output.status.success() {
            return true;
        }
    }

    // 2. Tenta via sudo não-interativo (-n) caso o utilizador tenha permissões sudoers
    let mut sudo_args = vec!["-n", cmd];
    sudo_args.extend_from_slice(args);
    if let Ok(output) = Command::new("sudo").args(&sudo_args).output() {
        if output.status.success() {
            return true;
        }
    }

    false
}

#[cfg(target_os = "linux")]
pub fn get_all_linux_interfaces() -> Vec<String> {
    let mut ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "lo" {
                ifaces.push(name);
            }
        }
    }
    // Fallback para get_if_addrs caso /sys não esteja acessível
    if ifaces.is_empty() {
        if let Ok(addrs) = get_if_addrs() {
            for iface in addrs {
                if !iface.is_loopback() && !ifaces.contains(&iface.name) {
                    ifaces.push(iface.name);
                }
            }
        }
    }
    ifaces
}

#[cfg(target_os = "linux")]
pub fn cleanup_firewall_rules() {
    for _ in 0..5 {
        let d1 = run_cmd("iptables", &["-D", "INPUT", "!", "-i", "lo", "-j", "DROP"]);
        let d2 = run_cmd("iptables", &["-D", "OUTPUT", "!", "-o", "lo", "-j", "DROP"]);
        let d3 = run_cmd("ip6tables", &["-D", "INPUT", "!", "-i", "lo", "-j", "DROP"]);
        let d4 = run_cmd(
            "ip6tables",
            &["-D", "OUTPUT", "!", "-o", "lo", "-j", "DROP"],
        );
        if !d1 && !d2 && !d3 && !d4 {
            break;
        }
    }
}

/// Altera o estado da rede (isolamento / restauro).
/// No Linux, utiliza prioritariamente regras Netfilter (iptables / ip6tables) para bloquear 100%
/// do tráfego de entrada e saída. Isto garante o isolamento absoluto sem desligar as interfaces
/// físicas, preservando as concessões DHCP, rotas predeterminadas (gateway) e endereços IP.
/// Caso o iptables não esteja disponível, recorre ao desligamento dos links físicos (ip link set down).
/// No restauro, remove as regras de firewall, garante que todas as interfaces de /sys/class/net/
/// estão UP, e sinaliza a renovação de DHCP/rotas (compatível com OpenRC/Gentoo, systemd e NetworkManager).
#[cfg(target_os = "linux")]
pub fn toggle_network(isolate: bool) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let mut successes = 0;

    if isolate {
        // --- 1. ISOLAMENTO VIA FIREWALL (MÉTODO PRIMÁRIO) ---
        // Bloqueia todo o tráfego que não seja loopback local (lo)
        let ipt_in = run_cmd(
            "iptables",
            &["-I", "INPUT", "1", "!", "-i", "lo", "-j", "DROP"],
        );
        let ipt_out = run_cmd(
            "iptables",
            &["-I", "OUTPUT", "1", "!", "-o", "lo", "-j", "DROP"],
        );
        let _ = run_cmd(
            "ip6tables",
            &["-I", "INPUT", "1", "!", "-i", "lo", "-j", "DROP"],
        );
        let _ = run_cmd(
            "ip6tables",
            &["-I", "OUTPUT", "1", "!", "-o", "lo", "-j", "DROP"],
        );

        let mut fw_active = false;
        if ipt_in || ipt_out {
            fw_active = true;
            successes += 1;
        }

        // Bloqueia rádio Wi-Fi/Bluetooth via rfkill
        let _ = run_cmd("rfkill", &["block", "all"]);

        // --- 2. FALLBACK FÍSICO: SE O FIREWALL NÃO PUDER SER ATIVADO ---
        if !fw_active {
            let ifaces = get_all_linux_interfaces();
            for iface in &ifaces {
                if run_cmd("ip", &["link", "set", "dev", iface, "down"]) {
                    successes += 1;
                } else {
                    errors.push(format!(
                        "Interface {}: permissão negada ao desativar link (requer sudo)",
                        iface
                    ));
                }
            }
            let _ = run_cmd("nmcli", &["networking", "off"]);
            let _ = run_cmd("nmcli", &["radio", "all", "off"]);
        }

        if successes == 0 {
            if errors.is_empty() {
                errors.push(
                    "Nenhuma interface de rede ou firewall disponível para isolamento".to_string(),
                );
            } else {
                errors.push("O Killswitch requer privilégios de root para isolar a rede (executa com: sudo ./sentinela)".to_string());
            }

            let filename = crate::traps::get_log_filename();
            let err_log = format!(
                "[{}] [FALHA  ] Killswitch: Falha ao isolar rede!\nErros detalhados:\n• {}\n",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                errors.join("\n• ")
            );
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&filename)
            {
                let _ = std::io::Write::write_all(&mut f, err_log.as_bytes());
            }

            return Err(errors);
        }
    } else {
        // --- RESTAURO COMPLETO DA REDE ---
        // 1. Remove quaisquer regras DROP adicionadas pelo Sentinela
        cleanup_firewall_rules();

        // 2. Levanta links de todas as interfaces listadas em /sys/class/net/
        // CRÍTICO: Nunca usar get_if_addrs() porque interfaces DOWN perdem os IPs e são ignoradas!
        let ifaces = get_all_linux_interfaces();
        for iface in &ifaces {
            let _ = run_cmd("ip", &["link", "set", "dev", iface, "up"]);
        }

        // 3. Desbloqueia rádio Wi-Fi/Bluetooth via rfkill
        let _ = run_cmd("rfkill", &["unblock", "all"]);

        // 4. Reativa conectividade no NetworkManager (se instalado)
        let _ = run_cmd("nmcli", &["radio", "all", "on"]);
        let _ = run_cmd("nmcli", &["networking", "on"]);

        // 5. Restauração de IP e rotas (Gentoo / OpenRC / systemd / dhcpcd)
        let _ = run_cmd("dhcpcd", &["-n"]);
        for iface in &ifaces {
            let _ = run_cmd(
                "rc-service",
                &["--ifexists", &format!("net.{}", iface), "restart"],
            );
        }
        let _ = run_cmd("rc-service", &["--ifexists", "dhcpcd", "restart"]);
        let _ = run_cmd("networkctl", &["renew"]);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn toggle_network(isolate: bool) -> Result<(), Vec<String>> {
    let ps_cmd = if isolate {
        "Get-NetAdapter | Disable-NetAdapter -Confirm:$false"
    } else {
        "Get-NetAdapter | Enable-NetAdapter -Confirm:$false"
    };

    match Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_cmd])
        .output()
    {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let msg = if err.is_empty() {
                "PowerShell falhou ao alterar estado das placas de rede (requer privilégios de Administrador)".to_string()
            } else {
                err
            };
            Err(vec![msg])
        }
        Err(e) => Err(vec![format!("Falha ao invocar PowerShell: {}", e)]),
    }
}

#[cfg(target_os = "macos")]
pub fn toggle_network(isolate: bool) -> Result<(), Vec<String>> {
    let state = if isolate { "off" } else { "on" };
    match Command::new("networksetup")
        .args(["-setairportpower", "en0", state])
        .output()
    {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if err.is_empty() {
                Ok(())
            } else {
                Err(vec![err])
            }
        }
        Err(e) => Err(vec![format!("Falha ao invocar networksetup: {}", e)]),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn toggle_network(_isolate: bool) -> Result<(), Vec<String>> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_local_only_binding(ip_hex: &str) -> bool {
    if ip_hex.len() == 8 {
        if let Ok(val) = u32::from_str_radix(ip_hex, 16) {
            // Em /proc/net/tcp (little-endian em x86):
            // 127.x.x.x tem 0x7F no byte menos significativo lido em u32
            if (val & 0xFF) == 127 {
                return true;
            }
        }
    } else if ip_hex.len() == 32 {
        // Em /proc/net/tcp6, ::1 loopback é codificado como 00000000000000000000000001000000
        if ip_hex == "00000000000000000000000001000000" {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn get_listening_ports() -> Vec<u16> {
    let mut listening_ports = Vec::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[3] == "0A" {
                    if let Some((ip_hex, port_hex)) = parts[1].split_once(':') {
                        // Ignora serviços locais seguros (bind exclusivo em 127.0.0.1 / ::1)
                        if is_local_only_binding(ip_hex) {
                            continue;
                        }
                        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                            if !listening_ports.contains(&port) {
                                listening_ports.push(port);
                            }
                        }
                    }
                }
            }
        }
    }
    listening_ports
}

#[cfg(target_os = "windows")]
fn get_listening_ports() -> Vec<u16> {
    let mut listening_ports = Vec::new();
    if let Ok(output) = Command::new("netstat").args(["-ano", "-p", "tcp"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Formato típico Windows: TCP    0.0.0.0:8080    0.0.0.0:0    LISTENING    1234
            if parts.len() >= 4
                && parts[0].eq_ignore_ascii_case("TCP")
                && parts[3].eq_ignore_ascii_case("LISTENING")
            {
                let local_addr = parts[1];
                if local_addr.starts_with("127.") || local_addr.starts_with("[::1]") {
                    continue;
                }
                if let Some((_ip, port_str)) = local_addr.rsplit_once(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        if !listening_ports.contains(&port) {
                            listening_ports.push(port);
                        }
                    }
                }
            }
        }
    }
    listening_ports
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn get_listening_ports() -> Vec<u16> {
    let mut listening_ports = Vec::new();
    if let Ok(output) = Command::new("netstat").args(["-an", "-p", "tcp"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if line.contains("LISTEN") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for part in parts {
                    if let Some((_ip, port_str)) = part.rsplit_once('.') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            if !listening_ports.contains(&port) {
                                listening_ports.push(port);
                            }
                        }
                    }
                }
            }
        }
    }
    listening_ports
}

pub fn scan_open_ports_warnings(trap_ports: &[u16], lang: Language) -> Vec<PortWarning> {
    let mut warnings = Vec::new();
    let listening_ports = get_listening_ports();

    for port in listening_ports {
        if trap_ports.contains(&port) {
            continue;
        }

        let (service, risk, pt_msg, en_msg, fix) = match port {
            21 => (
                "FTP",
                "ALTO",
                "Credenciais e ficheiros transmitidos em texto claro (inseguro).",
                "Cleartext credentials & files exposed over network.",
                "sudo /etc/init.d/vsftpd stop  |  sudo systemctl stop vsftpd",
            ),
            23 => (
                "Telnet",
                "CRÍTICO",
                "Shell remota sem qualquer cifra! Palavras-passe visíveis a sniffers.",
                "Unencrypted remote shell! Plaintext passwords on wire.",
                "sudo killall in.telnetd  |  sudo iptables -A INPUT -p tcp --dport 23 -j DROP",
            ),
            139 | 445 => (
                "SMB / Samba",
                "ALTO",
                "Partilha de ficheiros exposta. Alvo clássico de ransomware.",
                "Exposed Windows file sharing. Frequent ransomware vector.",
                "sudo /etc/init.d/samba stop  |  sudo systemctl stop smb",
            ),
            3306 => (
                "MySQL / MariaDB",
                "MÉDIO",
                "Base de dados acessível na rede. Deve escutar apenas em 127.0.0.1.",
                "Database listening publicly. Restrict bind to 127.0.0.1.",
                "Mudar 'bind-address = 127.0.0.1' no my.cnf",
            ),
            5432 => (
                "PostgreSQL",
                "MÉDIO",
                "Porta PostgreSQL exposta a ligações de fora.",
                "PostgreSQL port exposed to external probes.",
                "Configurar listen_addresses = 'localhost' no postgresql.conf",
            ),
            6379 => (
                "Redis",
                "CRÍTICO",
                "Base de dados em cache exposta e habitualmente sem autenticação.",
                "In-memory Redis exposed with no authentication.",
                "Configurar 'bind 127.0.0.1' no redis.conf",
            ),
            27017 => (
                "MongoDB",
                "CRÍTICO",
                "MongoDB exposto sem autenticação por defeito em versões antigas.",
                "MongoDB exposed — older versions have no auth by default.",
                "Configurar 'bindIp: 127.0.0.1' no mongod.conf",
            ),
            3389 => (
                "RDP",
                "MÉDIO",
                "Ambiente de trabalho remoto exposto a força bruta.",
                "Remote desktop open to brute-force dictionaries.",
                "sudo systemctl stop xrdp  |  Isolar na firewall",
            ),
            5900..=5905 => (
                "VNC",
                "ALTO",
                "Acesso gráfico remoto vulnerável se não passar por túnel seguro.",
                "VNC desktop exposed without TLS/SSH encapsulation.",
                "sudo killall x11vnc  |  Usar apenas por túnel SSH",
            ),
            9200 | 9300 => (
                "Elasticsearch",
                "CRÍTICO",
                "Elasticsearch exposto sem autenticação — dados acessíveis publicamente.",
                "Elasticsearch with no auth — full data exposure risk.",
                "Configurar 'network.host: localhost' no elasticsearch.yml",
            ),
            _ => continue,
        };

        let reason = match lang {
            Language::Pt => pt_msg.to_string(),
            Language::En => en_msg.to_string(),
        };

        warnings.push(PortWarning {
            port,
            service: service.to_string(),
            risk_level: risk,
            reason,
            fix_command: fix.to_string(),
        });
    }

    warnings
}

use std::sync::atomic::{AtomicU64, Ordering};
static LAST_NOTIFICATION_MILLIS: AtomicU64 = AtomicU64::new(0);

pub fn send_desktop_alert(incident: &Incident) {
    let now_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Rate limit atómico: no máximo 1 notificação desktop a cada 3 segundos (sem race conditions)
    let mut current = LAST_NOTIFICATION_MILLIS.load(Ordering::Relaxed);
    loop {
        if now_millis.saturating_sub(current) < 3000 {
            return;
        }
        match LAST_NOTIFICATION_MILLIS.compare_exchange_weak(
            current,
            now_millis,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }

    let _urgency = match incident.severity.as_str() {
        "CRÍTICO" => "critical".to_string(),
        _ => "normal".to_string(),
    };

    let location = if incident.city.is_empty() {
        incident.country.clone()
    } else {
        format!("{}, {}", incident.city, incident.country)
    };

    let title = format!("🚨 Sentinela: Intrusão [{}]", incident.severity);
    let body = format!(
        "IP: {} ({}x)\nAlvo: Porta {} ({})\nOrigem: {}",
        incident.ip, incident.hit_count, incident.port, incident.service, location
    );

    // Executa notificação em thread separada para nunca bloquear o loop principal da TUI
    #[cfg(target_os = "linux")]
    std::thread::spawn(move || {
        let _ = Command::new("notify-send")
            .args([
                "-u",
                &_urgency,
                "-a",
                "Sentinela HIDS",
                "-i",
                "security-high",
                &title,
                &body,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    });

    #[cfg(target_os = "windows")]
    std::thread::spawn(move || {
        let ps_script = format!(
            r#"[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');
$notify = New-Object System.Windows.Forms.NotifyIcon;
$notify.Icon = [System.Drawing.SystemIcons]::Warning;
$notify.BalloonTipIcon = 'Warning';
$notify.BalloonTipTitle = '{}';
$notify.BalloonTipText = '{}';
$notify.Visible = $True;
$notify.ShowBalloonTip(4000);
Start-Sleep -Seconds 4;
$notify.Dispose();"#,
            title.replace('\'', "''"),
            body.replace('\'', "''")
        );

        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-WindowStyle",
                "Hidden",
                "-Command",
                &ps_script,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    });

    #[cfg(target_os = "macos")]
    std::thread::spawn(move || {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            body.replace('"', "\\\""),
            title.replace('"', "\\\"")
        );
        let _ = Command::new("osascript")
            .args(["-e", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    });

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        // Outros SOs sem interface gráfica direta
    }
}

pub fn send_desktop_notification_raw(title: &str, body: &str, urgency: &str) {
    let t = title.to_string();
    let b = body.to_string();
    let _u = urgency.to_string();

    #[cfg(target_os = "linux")]
    std::thread::spawn(move || {
        let _ = Command::new("notify-send")
            .args([
                "-u",
                &_u,
                "-a",
                "Sentinela HIDS",
                "-i",
                "dialog-error",
                &t,
                &b,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    });

    #[cfg(target_os = "windows")]
    std::thread::spawn(move || {
        let ps_script = format!(
            r#"[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');
$notify = New-Object System.Windows.Forms.NotifyIcon;
$notify.Icon = [System.Drawing.SystemIcons]::Error;
$notify.BalloonTipIcon = 'Error';
$notify.BalloonTipTitle = '{}';
$notify.BalloonTipText = '{}';
$notify.Visible = $True;
$notify.ShowBalloonTip(4000);
Start-Sleep -Seconds 4;
$notify.Dispose();"#,
            t.replace('\'', "''"),
            b.replace('\'', "''")
        );

        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-WindowStyle",
                "Hidden",
                "-Command",
                &ps_script,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    });

    #[cfg(target_os = "macos")]
    std::thread::spawn(move || {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            b.replace('"', "\\\""),
            t.replace('"', "\\\"")
        );
        let _ = Command::new("osascript")
            .args(["-e", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    });

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        // No-op
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_geo_cache_negative_ttl() {
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)); // RFC 5737 TEST-NET-2

        // Insere entrada negativa que já expirou
        {
            let mut cache = get_geo_cache().write().await;
            cache.insert(
                ip,
                GeoCacheEntry {
                    geo: (
                        "Internet (WAN)".to_string(),
                        "".to_string(),
                        "Sem resposta GeoIP".to_string(),
                    ),
                    expires_at: Some(std::time::Instant::now() - Duration::from_secs(1)), // já expirado
                },
            );
        }

        // Ao ler a cache, a entrada expirada deve ser considerada inválida
        {
            let now = std::time::Instant::now();
            let cache = get_geo_cache().read().await;
            let entry = cache.get(&ip).unwrap();
            let is_valid = match entry.expires_at {
                Some(exp) => now < exp,
                None => true,
            };
            assert!(
                !is_valid,
                "Entrada negativa expirada não deve ser considerada válida!"
            );
        }

        // Insere entrada negativa válida (dentro dos 5 min de TTL)
        {
            let mut cache = get_geo_cache().write().await;
            cache.insert(
                ip,
                GeoCacheEntry {
                    geo: (
                        "Internet (WAN)".to_string(),
                        "".to_string(),
                        "Sem resposta GeoIP".to_string(),
                    ),
                    expires_at: Some(std::time::Instant::now() + Duration::from_secs(300)),
                },
            );
        }

        {
            let now = std::time::Instant::now();
            let cache = get_geo_cache().read().await;
            let entry = cache.get(&ip).unwrap();
            let is_valid = match entry.expires_at {
                Some(exp) => now < exp,
                None => true,
            };
            assert!(
                is_valid,
                "Entrada negativa dentro do TTL deve ser considerada válida!"
            );
        }

        // Insere entrada positiva permanente (expires_at == None)
        {
            let mut cache = get_geo_cache().write().await;
            cache.insert(
                ip,
                GeoCacheEntry {
                    geo: (
                        "Portugal".to_string(),
                        "Lisbon".to_string(),
                        "MEO".to_string(),
                    ),
                    expires_at: None,
                },
            );
        }

        {
            let cache = get_geo_cache().read().await;
            let entry = cache.get(&ip).unwrap();
            assert!(
                entry.expires_at.is_none(),
                "Entrada positiva deve ter expires_at == None"
            );
            assert_eq!(entry.geo.0, "Portugal");
        }
    }

    #[test]
    fn test_is_host_ip_loopback() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        assert!(is_host_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_host_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_host_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    }
}
