use crate::models::{GeoResponse, Incident, Language, PortWarning, SysInfo};
use get_if_addrs::get_if_addrs;
use std::{
    collections::HashMap,
    env, fs,
    net::IpAddr,
    process::{Command, Stdio},
    sync::OnceLock,
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

pub fn is_host_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    if let Ok(interfaces) = get_if_addrs() {
        for iface in interfaces {
            if iface.ip() == ip {
                return true;
            }
        }
    }
    false
}

pub fn get_system_info() -> SysInfo {
    let distro = fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|content| {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return Some(
                        line.trim_start_matches("PRETTY_NAME=")
                            .trim_matches('"')
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

    SysInfo { distro, kernel, arch }
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
        return ("Loopback".to_string(), "".to_string(), "Host Interno".to_string());
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
                            (("Internet (WAN)".to_string(), "".to_string(), "Consulta Externa".to_string()), true)
                        }
                    } else {
                        (("Internet (WAN)".to_string(), "".to_string(), "Consulta Externa".to_string()), true)
                    }
                }
                Err(_) => (("Internet (WAN)".to_string(), "".to_string(), "Sem resposta GeoIP".to_string()), true),
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
                cache.insert(ip, GeoCacheEntry { geo: result.clone(), expires_at });
            }

            result
        }
    }
}

/// Altera o estado da rede (isolamento / restauro).
/// Captura os códigos de retorno dos comandos de sistema. Se o isolamento falhar,
/// regista os erros específicos no ficheiro de log e devolve `Err(erros)` para que
/// a interface gráfica e o utilizador sejam notificados de que o isolamento falhou.
pub fn toggle_network(isolate: bool) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let mut successes = 0;

    if isolate {
        // 1. Tenta desativar conexões via NetworkManager
        match Command::new("nmcli")
            .args(["networking", "off"])
            .output()
        {
            Ok(output) if output.status.success() => successes += 1,
            Ok(output) => {
                let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
                errors.push(format!("nmcli networking off falhou: {}", err));
            }
            Err(e) => errors.push(format!("nmcli networking off falhou ao iniciar: {}", e)),
        }

        match Command::new("nmcli")
            .args(["radio", "all", "off"])
            .output()
        {
            Ok(output) if output.status.success() => successes += 1,
            Ok(output) => {
                let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
                errors.push(format!("nmcli radio all off falhou: {}", err));
            }
            Err(e) => errors.push(format!("nmcli radio off falhou ao iniciar: {}", e)),
        }

        // 2. Tenta desligar links de rede físicos e lógicos via iproute2
        if let Ok(interfaces) = get_if_addrs() {
            let mut iface_count = 0;
            for iface in interfaces {
                if !iface.is_loopback() {
                    iface_count += 1;
                    match Command::new("ip")
                        .args(["link", "set", "dev", &iface.name, "down"])
                        .output()
                    {
                        Ok(output) if output.status.success() => successes += 1,
                        Ok(output) => {
                            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
                            errors.push(format!("ip link set {} down falhou: {}", iface.name, err));
                        }
                        Err(e) => errors.push(format!("ip link set {} down falhou ao iniciar: {}", iface.name, e)),
                    }
                }
            }
            if iface_count == 0 {
                errors.push("Nenhuma interface externa detetada para isolamento".to_string());
            }
        } else {
            errors.push("Falha ao enumerar interfaces de rede".to_string());
        }

        // Se nenhuma camada teve sucesso ou se ocorreram erros críticos (ex.: falta de privilégios de root)
        if successes == 0 || !errors.is_empty() {
            let filename = crate::traps::get_log_filename();
            let err_log = format!(
                "[{}] [FALHA  ] Killswitch: Isolamento de rede não é fiável!\nErros detalhados:\n• {}\n",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                errors.join("\n• ")
            );
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&filename) {
                let _ = std::io::Write::write_all(&mut f, err_log.as_bytes());
            }

            return Err(errors);
        }
    } else {
        // Restauração completa de todas as camadas de rede:
        // 1. Levanta os links das placas de rede
        if let Ok(interfaces) = get_if_addrs() {
            for iface in interfaces {
                if !iface.is_loopback() {
                    match Command::new("ip")
                        .args(["link", "set", "dev", &iface.name, "up"])
                        .output()
                    {
                        Ok(output) if !output.status.success() => {
                            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
                            errors.push(format!("ip link set {} up falhou: {}", iface.name, err));
                        }
                        Err(e) => errors.push(format!("ip link set {} up falhou: {}", iface.name, e)),
                        _ => {}
                    }
                }
            }
        }

        // 2. Desbloqueia rfkill (Wi-Fi e Bluetooth)
        let _ = Command::new("rfkill")
            .args(["unblock", "all"])
            .output();

        // 3. Ativa rádio Wi-Fi no NetworkManager
        let _ = Command::new("nmcli")
            .args(["radio", "all", "on"])
            .output();

        // 4. Ativa o subsistema de rede
        let _ = Command::new("nmcli")
            .args(["networking", "on"])
            .output();

        if !errors.is_empty() {
            return Err(errors);
        }
    }

    Ok(())
}

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

pub fn scan_open_ports_warnings(trap_ports: &[u16], lang: Language) -> Vec<PortWarning> {
    let mut warnings = Vec::new();
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

    let last = LAST_NOTIFICATION_MILLIS.load(Ordering::Relaxed);
    // Limite: no máximo 1 notificação desktop a cada 3 segundos para evitar bloquear ou floodar
    if now_millis.saturating_sub(last) < 3000 {
        return;
    }
    LAST_NOTIFICATION_MILLIS.store(now_millis, Ordering::Relaxed);

    let urgency = match incident.severity.as_str() {
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

    // Executa em thread separada com spawn() SEM esperar por status()
    // para nunca bloquear a UI, mesmo se notify-send encravar ou não tiver DBUS
    std::thread::spawn(move || {
        let _ = Command::new("notify-send")
            .args([
                "-u",
                &urgency,
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
}

pub fn send_desktop_notification_raw(title: &str, body: &str, urgency: &str) {
    let t = title.to_string();
    let b = body.to_string();
    let u = urgency.to_string();
    std::thread::spawn(move || {
        let _ = Command::new("notify-send")
            .args([
                "-u",
                &u,
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
                    geo: ("Internet (WAN)".to_string(), "".to_string(), "Sem resposta GeoIP".to_string()),
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
            assert!(!is_valid, "Entrada negativa expirada não deve ser considerada válida!");
        }

        // Insere entrada negativa válida (dentro dos 5 min de TTL)
        {
            let mut cache = get_geo_cache().write().await;
            cache.insert(
                ip,
                GeoCacheEntry {
                    geo: ("Internet (WAN)".to_string(), "".to_string(), "Sem resposta GeoIP".to_string()),
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
            assert!(is_valid, "Entrada negativa dentro do TTL deve ser considerada válida!");
        }

        // Insere entrada positiva permanente (expires_at == None)
        {
            let mut cache = get_geo_cache().write().await;
            cache.insert(
                ip,
                GeoCacheEntry {
                    geo: ("Portugal".to_string(), "Lisbon".to_string(), "MEO".to_string()),
                    expires_at: None,
                },
            );
        }

        {
            let cache = get_geo_cache().read().await;
            let entry = cache.get(&ip).unwrap();
            assert!(entry.expires_at.is_none(), "Entrada positiva deve ter expires_at == None");
            assert_eq!(entry.geo.0, "Portugal");
        }
    }
}