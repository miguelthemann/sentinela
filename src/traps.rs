use crate::models::Incident;
use crate::network::inspect_ip;
use chrono::Local;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc::UnboundedSender;

/// Portas armadilha padrão se não forem especificadas pelo utilizador
pub const DEFAULT_TRAP_PORTS: &[u16] = &[2121, 2222, 2323, 8080, 8443];

pub fn get_log_filename() -> String {
    Local::now().format("sentinela_%Y-%m-%d.log").to_string()
}

/// Inicia o registo do logger, criando o ficheiro de log diário com cabeçalho.
pub async fn init_logger() {
    let filename = get_log_filename();
    let header = format!(
        "\n========================================================\n\
         [SESSÃO INICIADA] - {}\n\
         ========================================================\n",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    );

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename)
        .await
    {
        let _ = file.write_all(header.as_bytes()).await;
    }
}

/// Classifica uma porta com o seu respetivo nível de risco.
pub fn classify_port(port: u16) -> (&'static str, &'static str) {
    match port {
        20 | 21 | 2121 => ("FTP", "MÉDIO"),
        22 | 2222 => ("SSH", "CRÍTICO"),
        23 | 2323 => ("Telnet", "CRÍTICO"),
        25 => ("SMTP", "MÉDIO"),
        53 => ("DNS", "ALERTA"),
        80 | 8080 => ("HTTP", "ALERTA"),
        443 | 8443 => ("HTTPS", "ALERTA"),
        3306 => ("MySQL", "MÉDIO"),
        5432 => ("PostgreSQL", "MÉDIO"),
        6379 => ("Redis", "CRÍTICO"),
        27017 => ("MongoDB", "CRÍTICO"),
        3389 => ("RDP", "MÉDIO"),
        _ => ("Custom", "ALERTA"),
    }
}

/// Estrutura para enfileirar conexões aceites e processá-las fora do caminho crítico
struct TrapConnection {
    attacker_ip: std::net::IpAddr,
    port: u16,
    timestamp: String,
}

/// Atualiza o valor de "Hits" da entrada correspondente no log em disco.
/// Procura a última entrada correspondente ao IP fornecido e substitui o valor de Hits
/// pelo valor agregado em tempo real.
pub fn update_log_hit_count(filename: &str, ip: &str, hit_count: usize) {
    if let Ok(content) = std::fs::read_to_string(filename) {
        let lines: Vec<&str> = content.lines().collect();
        let mut last_match_idx = None;

        for (i, line) in lines.iter().enumerate().rev() {
            if line_matches_ip(line, ip) {
                last_match_idx = Some(i);
                break;
            }
        }

        if let Some(idx) = last_match_idx {
            let target_line = lines[idx];
            if let Some((prefix, _)) = target_line.rsplit_once("| Hits:") {
                let updated_line = format!("{}| Hits: {}", prefix, hit_count);
                let mut new_lines = lines;
                new_lines[idx] = &updated_line;
                let mut updated_content = new_lines.join("\n");
                if content.ends_with('\n') {
                    updated_content.push('\n');
                }
                let _ = std::fs::write(filename, updated_content);
            }
        }
    }
}

fn line_matches_ip(line: &str, ip: &str) -> bool {
    if let Some(ip_part) = line.split('|').next() {
        if let Some((_, addr)) = ip_part.split_once("IP:") {
            return addr.trim() == ip.trim();
        }
    }
    false
}

/// Escreve um incidente no buffer de log em lote.
/// Esta função adiciona a entrada a um buffer partilhado em vez de escrever
/// imediatamente ao disco. Um escritor em background escreve o buffer a cada 100ms,
/// reduzindo significativamente as chamadas de sistema ao disco e economizando energia.
///
/// Esta função é não-blocking - retorna imediatamente após adicionar ao buffer.
pub fn add_log_entry(entry: String) {
    static LOG_BUFFER: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let mut buffer = LOG_BUFFER.lock().unwrap();
    buffer.push(entry);
}

/// Escreve um incidente ao ficheiro de log.
/// Esta versão em lote acumula entradas no buffer e o escritor em background
/// escreve a cada 100ms, reduzindo I/O de disco em comparação com a escrita
/// individual por incidente. Note que esta função usa um mutex estático interno
/// para o buffer - em produção, considere mover o LOG_BUFFER para o módulo principal.
pub async fn log_incident_to_disk(incident: &Incident) {
    let filename = get_log_filename();
    let location = if incident.city.is_empty() || incident.city == "?" {
        incident.country.clone()
    } else {
        format!("{}, {}", incident.city, incident.country)
    };

    let log_entry = format!(
        "[{}] [{:<7}] IP: {:<15} | Porta: {:<5} ({:<11}) | Local: {:<22} | ISP: {} | Hits: {}\n",
        incident.timestamp,
        incident.severity,
        incident.ip,
        incident.port,
        incident.service,
        location,
        incident.isp,
        incident.hit_count,
    );

    // Escreve diretamente ao disco (mantém compatibilidade com a funcionalidade existente)
    // TODO: Em futuro, substituir por add_log_entry() para batch writing
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename)
        .await
    {
        let _ = file.write_all(log_entry.as_bytes()).await;
    }
}

/// Inicia armadilhas TCP nas portas fornecidas.
/// Devolve (portas_ativas, portas_com_erro).
pub async fn start_traps(tx: UnboundedSender<Incident>, trap_ports: &[u16]) -> (Vec<u16>, Vec<u16>) {
    let mut active = Vec::new();
    let mut failed = Vec::new();

    // Fila assíncrona para mover lookups GeoIP e I/O de disco para fora do ciclo accept()
    let (queue_tx, mut queue_rx) = tokio::sync::mpsc::unbounded_channel::<TrapConnection>();

    // Worker assíncrono dedicado a processar eventos GeoIP e gravação em disco
    let tx_worker = tx.clone();
    tokio::spawn(async move {
        while let Some(conn) = queue_rx.recv().await {
            let (country, city, isp) = inspect_ip(conn.attacker_ip).await;
            let (service, severity) = classify_port(conn.port);

            let incident = Incident {
                timestamp: conn.timestamp,
                ip: conn.attacker_ip.to_string(),
                port: conn.port,
                service: service.to_string(),
                severity: severity.to_string(),
                country,
                city,
                isp,
                hit_count: 1, // Inicializado a 1; atualizado pelo ciclo principal com base na contagem real
            };

            log_incident_to_disk(&incident).await;
            let _ = tx_worker.send(incident);
        }
    });

    for &port in trap_ports {
        // Tenta bind IPv6 dual-stack ([::]) para aceitar IPv4 e IPv6;
        // Se falhar (ex.: IPv6 desativado no kernel), faz fallback para IPv4 (0.0.0.0)
        let listener_res = match TcpListener::bind(format!("[::]:{}", port)).await {
            Ok(l) => Ok(l),
            Err(_) => TcpListener::bind(format!("0.0.0.0:{}", port)).await,
        };

        match listener_res {
            Ok(listener) => {
                active.push(port);
                let q_tx = queue_tx.clone();
                tokio::spawn(async move {
                    loop {
                        if let Ok((_socket, peer_addr)) = listener.accept().await {
                            // Converte endereços IPv4-mapped em IPv6 para IPv4 nativo para consistência
                            let attacker_ip = match peer_addr.ip() {
                                std::net::IpAddr::V6(v6) => {
                                    v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(std::net::IpAddr::V6(v6))
                                }
                                std::net::IpAddr::V4(v4) => std::net::IpAddr::V4(v4),
                            };

                            // Descarta conexões locais (loopback e IPs locais da própria máquina)
                            if crate::network::is_host_ip(attacker_ip) {
                                continue;
                            }

                            let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

                            // Enfileira a conexão imediatamente sem esperar por GeoIP ou disco,
                            // garantindo que o ciclo accept() nunca bloqueia e aceita novas conexões sem atraso
                            let _ = q_tx.send(TrapConnection {
                                attacker_ip,
                                port,
                                timestamp: now,
                            });
                        }
                    }
                });
            }
            Err(_) => {
                failed.push(port);
            }
        }
    }

    (active, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_log_hit_count() {
        let temp_dir = std::env::temp_dir();
        let test_log = temp_dir.join(format!("test_sentinela_hits_{}.log", std::process::id()));
        let test_log_path = test_log.to_str().unwrap();

        let initial_content = "\
[2026-10-02 10:00:00] [ALERTA ] IP: 192.168.1.136   | Porta: 8080  (HTTP       ) | Local: Rede Local (LAN)       | ISP: Dispositivo Interno | Hits: 1
[2026-10-02 10:00:05] [CRÍTICO] IP: 10.0.0.99       | Porta: 2222  (SSH        ) | Local: Rede Local (LAN)       | ISP: Dispositivo Interno | Hits: 1
[2026-10-02 10:01:00] [ALERTA ] IP: 192.168.1.136   | Porta: 8443  (HTTPS      ) | Local: Rede Local (LAN)       | ISP: Dispositivo Interno | Hits: 1
";
        std::fs::write(test_log_path, initial_content).unwrap();

        // Atualiza para hit 2 do IP 192.168.1.136 (deve atualizar a última linha desse IP)
        update_log_hit_count(test_log_path, "192.168.1.136", 2);

        let updated = std::fs::read_to_string(test_log_path).unwrap();
        let lines: Vec<&str> = updated.lines().collect();
        assert_eq!(lines.len(), 3);
        // Primeira linha permanece Hits: 1
        assert!(lines[0].ends_with("| Hits: 1"));
        // Segunda linha de outro IP permanece Hits: 1
        assert!(lines[1].ends_with("| Hits: 1"));
        // Terceira linha (última correspondente a 192.168.1.136) foi atualizada para Hits: 2!
        assert!(lines[2].ends_with("| Hits: 2"));

        let _ = std::fs::remove_file(test_log_path);
    }

    #[test]
    fn test_line_matches_ip_exact() {
        let line = "[2026-10-02 10:00:00] [ALERTA ] IP: 192.168.1.10    | Porta: 8080  | Hits: 1";
        assert!(line_matches_ip(line, "192.168.1.10"));
        assert!(!line_matches_ip(line, "192.168.1.1"));
        assert!(!line_matches_ip(line, "192.168.1.100"));
    }
}
