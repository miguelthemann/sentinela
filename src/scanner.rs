/// Módulo de deteção de varrimentos (port scans) por captura de pacotes raw.
///
/// O TcpListener padrão só dispara quando o handshake TCP está completo (SYN→SYN-ACK→ACK).
/// O nmap -sS (scan furtivo) envia SYN, recebe SYN-ACK e manda RST imediatamente,
/// nunca completando o handshake — por isso o honeypot normal não o apanha.
///
/// Este módulo usa sockets raw (AF_PACKET no Linux via pnet) para capturar os pacotes
/// SYN antes de qualquer handshake, detectando:
///   1. Hits directos nas portas armadilha → alerta imediato
///   2. Port sweep: mesmo IP bate N portos distintos em T segundos → alerta SWEEP
///
/// REQUISITO: CAP_NET_RAW ou sudo. Sem essa permissão, falha graciosamente.
use crate::models::Incident;
use crate::network::inspect_ip;
use crate::traps::classify_port;
use chrono::Local;
use pnet::datalink::{self, Channel};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet,
};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::runtime::Handle;
use tokio::sync::mpsc::UnboundedSender;

/// Janela de dedup por (IP, porto) — evita duplicar retransmissões do mesmo pacote.
/// Curta o suficiente para não bloquear scans consecutivos.
const DEDUP_WINDOW: Duration = Duration::from_secs(2);

/// Configuração para deteção de Port Sweep.
/// A deteção recorre a uma janela deslizante (sliding window) que monitoriza
/// a sequência temporal de portos tocados por cada endereço IP.
#[derive(Clone, Copy, Debug)]
pub struct SweepConfig {
    /// Número mínimo de portos distintos necessários dentro da janela para disparar SWEEP.
    /// Racional: Ligações legítimas normais (browsers HTTP/HTTPS, DNS, NTP, etc.) tocam
    /// habitualmente em 1 a 3 portos distintos. Um ataque de varrimento horizontal/port sweep
    /// tenta contactar ativamente vários serviços à procura de portas abertas.
    /// Um limiar de 5 portos distintos dentro da janela reduz drasticamente falsos positivos
    /// causados por rajadas de tráfego legítimo, mantendo a sensibilidade contra ferramentas de scan.
    pub threshold: usize,
    /// Duração da janela deslizante temporal (sliding window).
    pub window: Duration,
}

impl Default for SweepConfig {
    fn default() -> Self {
        // Configurável através de variáveis de ambiente com valores padrão seguros
        let threshold = std::env::var("SENTINELA_SWEEP_THRESHOLD")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(5);

        let window_secs = std::env::var("SENTINELA_SWEEP_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5);

        SweepConfig {
            threshold,
            window: Duration::from_secs(window_secs),
        }
    }
}

/// Limpa periodicamente entradas antigas de todos os 3 mapas do scanner:
/// 1. `trap_dedup`: remove entradas de portas trap com mais de 30s.
/// 2. `sweep_tracker`: descarta toques fora da janela deslizante e remove IPs sem histórico.
/// 3. `sweep_alert_dedup`: remove cooldowns de alertas com mais de 30s.
pub fn cleanup_scanner_maps(
    trap_dedup: &mut HashMap<(IpAddr, u16), Instant>,
    sweep_tracker: &mut HashMap<IpAddr, Vec<(u16, Instant)>>,
    sweep_alert_dedup: &mut HashMap<IpAddr, Instant>,
    now: Instant,
    sweep_window: Duration,
) {
    // 1. Limpa dedup de portas trap
    trap_dedup.retain(|_, t| now.duration_since(*t) < Duration::from_secs(30));

    // 2. Limpa tracker de sweep (purga toques antigos e remove IPs vazios)
    sweep_tracker.retain(|_, history| {
        history.retain(|(_, t)| now.duration_since(*t) <= sweep_window);
        !history.is_empty()
    });

    // 3. Limpa dedup de alertas de sweep
    sweep_alert_dedup.retain(|_, t| now.duration_since(*t) < Duration::from_secs(30));
}

/// Tenta iniciar o scanner de pacotes raw em todas as interfaces não-loopback.
/// Devolve `true` se pelo menos uma interface foi capturada com sucesso.
pub fn start_packet_scanner(tx: UnboundedSender<Incident>, trap_ports: Vec<u16>) -> bool {
    let interfaces = datalink::interfaces();
    let handle = Handle::current();
    let sweep_config = SweepConfig::default();
    let mut started = false;

    for iface in interfaces {
        if iface.is_loopback() || !iface.is_up() || iface.ips.is_empty() {
            continue;
        }

        let config = datalink::Config {
            read_timeout: Some(Duration::from_millis(200)),
            ..Default::default()
        };

        match datalink::channel(&iface, config) {
            Ok(Channel::Ethernet(_, mut rx)) => {
                started = true;
                let tx_clone = tx.clone();
                let ports = trap_ports.clone();
                let rt = handle.clone();

                std::thread::spawn(move || {
                    // Dedup para alertas imediatos de portos trap: (IP, porto) → last_seen
                    let mut trap_dedup: HashMap<(IpAddr, u16), Instant> = HashMap::new();

                    // Rastreio de port sweep com janela deslizante: IP → sequência de (porto, timestamp)
                    let mut sweep_tracker: HashMap<IpAddr, Vec<(u16, Instant)>> = HashMap::new();
                    // Cooldown para envio de alertas SWEEP: IP → last_alert_sent
                    let mut sweep_alert_dedup: HashMap<IpAddr, Instant> = HashMap::new();

                    // Marca de tempo da última limpeza dos mapas
                    let mut last_cleanup = Instant::now();

                    loop {
                        match rx.next() {
                            Ok(raw) => {
                                if let Some(eth) = EthernetPacket::new(raw) {
                                    if let Some((src_ip, dst_port, tcp_flags)) =
                                        extract_tcp_info(&eth)
                                    {
                                        // Só SYN puro ou scans furtivos (FIN, NULL, XMAS)
                                        let is_syn = tcp_flags & TcpFlags::SYN != 0
                                            && tcp_flags & TcpFlags::ACK == 0;
                                        let is_stealth = is_unusual_scan(tcp_flags);
                                        if !is_syn && !is_stealth {
                                            continue;
                                        }

                                        // Ignora o próprio host
                                        if crate::network::is_host_ip(src_ip) {
                                            continue;
                                        }

                                        let now = Instant::now();

                                        // ─── 1. Alerta imediato para portos armadilha ────────────
                                        if ports.contains(&dst_port) {
                                            let key = (src_ip, dst_port);
                                            let fresh = trap_dedup
                                                .get(&key)
                                                .map(|t| now.duration_since(*t) >= DEDUP_WINDOW)
                                                .unwrap_or(true);

                                            if fresh {
                                                trap_dedup.insert(key, now);

                                                let scan_type = if is_stealth {
                                                    describe_scan_type(tcp_flags)
                                                } else {
                                                    "SYN"
                                                };

                                                let tx2 = tx_clone.clone();
                                                let label = scan_type.to_string();
                                                rt.spawn(async move {
                                                    let (country, city, isp) =
                                                        inspect_ip(src_ip).await;
                                                    let _ = tx2.send(Incident {
                                                        timestamp: Local::now()
                                                            .format("%Y-%m-%d %H:%M:%S")
                                                            .to_string(),
                                                        ip: src_ip.to_string(),
                                                        port: dst_port,
                                                        service: format!(
                                                            "SCAN {}→{}",
                                                            label,
                                                            classify_port(dst_port).0
                                                        ),
                                                        severity: "SCAN".to_string(),
                                                        country,
                                                        city,
                                                        isp,
                                                        hit_count: 1,
                                                    });
                                                });
                                            }
                                        }

                                        // ─── 2. Deteção inteligente de port sweep (janela deslizante) ───
                                        {
                                            let history = sweep_tracker.entry(src_ip).or_default();

                                            // 1. Remove toques fora da janela deslizante (sliding window)
                                            history.retain(|(_, ts)| now.duration_since(*ts) <= sweep_config.window);

                                            // 2. Adiciona o porto e instante atual à sequência
                                            history.push((dst_port, now));

                                            // 3. Calcula quantos portos DISTINTOS foram tocados na janela ativa
                                            let distinct_ports: HashSet<u16> = history.iter().map(|(p, _)| *p).collect();

                                            // 4. Dispara alerta apenas se o limiar de portos distintos for atingido
                                            if distinct_ports.len() >= sweep_config.threshold {
                                                let should_alert = sweep_alert_dedup
                                                    .get(&src_ip)
                                                    .map(|t| now.duration_since(*t) >= sweep_config.window)
                                                    .unwrap_or(true);

                                                if should_alert {
                                                    sweep_alert_dedup.insert(src_ip, now);
                                                    let mut swept: Vec<u16> = distinct_ports.into_iter().collect();
                                                    swept.sort_unstable();
                                                    // Limpa histórico para evitar repetições contínuas a cada pacote seguinte
                                                    history.clear();

                                                    let tx2 = tx_clone.clone();
                                                    rt.spawn(async move {
                                                        let (country, city, isp) =
                                                            inspect_ip(src_ip).await;
                                                        let ports_str = if swept.len() > 6 {
                                                            let sample = swept[..6]
                                                                .iter()
                                                                .map(|p| p.to_string())
                                                                .collect::<Vec<_>>()
                                                                .join(",");
                                                            format!("{},+{}p", sample, swept.len() - 6)
                                                        } else {
                                                            swept
                                                                .iter()
                                                                .map(|p| p.to_string())
                                                                .collect::<Vec<_>>()
                                                                .join(",")
                                                        };
                                                        let _ = tx2.send(Incident {
                                                            timestamp: Local::now()
                                                                .format("%Y-%m-%d %H:%M:%S")
                                                                .to_string(),
                                                            ip: src_ip.to_string(),
                                                            port: 0, // sweep = múltiplos portos
                                                            service: format!(
                                                                "SWEEP [{}]",
                                                                ports_str
                                                            ),
                                                            severity: "SWEEP".to_string(),
                                                            country,
                                                            city,
                                                            isp,
                                                            hit_count: 1,
                                                        });
                                                    });
                                                }
                                            }
                                        }

                                        // Limpeza periódica dos 3 mapas a cada 10 segundos
                                        if now.duration_since(last_cleanup) >= Duration::from_secs(10) {
                                            last_cleanup = now;
                                            cleanup_scanner_maps(
                                                &mut trap_dedup,
                                                &mut sweep_tracker,
                                                &mut sweep_alert_dedup,
                                                now,
                                                sweep_config.window,
                                            );
                                        }
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                });
            }
            Ok(_) | Err(_) => {}
        }
    }

    started
}

/// Extrai (IP origem, porto destino, flags TCP) de um frame Ethernet.
fn extract_tcp_info(eth: &EthernetPacket) -> Option<(IpAddr, u16, u8)> {
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ip = Ipv4Packet::new(eth.payload())?;
            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                return None;
            }
            let tcp = TcpPacket::new(ip.payload())?;
            Some((IpAddr::V4(ip.get_source()), tcp.get_destination(), tcp.get_flags()))
        }
        EtherTypes::Ipv6 => {
            let ip = Ipv6Packet::new(eth.payload())?;
            if ip.get_next_header() != IpNextHeaderProtocols::Tcp {
                return None;
            }
            let tcp = TcpPacket::new(ip.payload())?;
            Some((IpAddr::V6(ip.get_source()), tcp.get_destination(), tcp.get_flags()))
        }
        _ => None,
    }
}

/// Deteta scans furtivos por combinações invulgares de flags TCP.
fn is_unusual_scan(flags: u8) -> bool {
    flags == 0                                                          // NULL scan
        || flags == TcpFlags::FIN                                       // FIN scan
        || (flags & TcpFlags::FIN != 0                                  // XMAS scan
            && flags & TcpFlags::PSH != 0
            && flags & TcpFlags::URG != 0)
}

fn describe_scan_type(flags: u8) -> &'static str {
    if flags == 0 {
        "NULL"
    } else if flags == TcpFlags::FIN {
        "FIN"
    } else if flags & TcpFlags::FIN != 0 && flags & TcpFlags::PSH != 0 && flags & TcpFlags::URG != 0 {
        "XMAS"
    } else {
        "SYN"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_cleanup_scanner_maps() {
        let mut trap_dedup = HashMap::new();
        let mut sweep_tracker = HashMap::new();
        let mut sweep_alert_dedup = HashMap::new();

        let now = Instant::now();
        let old_time = now - Duration::from_secs(35);
        let recent_time = now - Duration::from_secs(5);

        let ip_old = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_recent = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // trap_dedup
        trap_dedup.insert((ip_old, 80), old_time);
        trap_dedup.insert((ip_recent, 80), recent_time);

        // sweep_tracker
        sweep_tracker.insert(ip_old, vec![(80, old_time), (443, old_time)]);
        sweep_tracker.insert(ip_recent, vec![(80, old_time), (443, recent_time)]);

        // sweep_alert_dedup
        sweep_alert_dedup.insert(ip_old, old_time);
        sweep_alert_dedup.insert(ip_recent, recent_time);

        cleanup_scanner_maps(
            &mut trap_dedup,
            &mut sweep_tracker,
            &mut sweep_alert_dedup,
            now,
            Duration::from_secs(5),
        );

        // trap_dedup: ip_old removido, ip_recent mantido
        assert_eq!(trap_dedup.len(), 1);
        assert!(trap_dedup.contains_key(&(ip_recent, 80)));

        // sweep_tracker: ip_old removido porque todos os toques expiraram (>5s); ip_recent mantido com 1 toque recente
        assert_eq!(sweep_tracker.len(), 1);
        assert_eq!(sweep_tracker.get(&ip_recent).unwrap().len(), 1);
        assert_eq!(sweep_tracker.get(&ip_recent).unwrap()[0].0, 443);

        // sweep_alert_dedup: ip_old removido, ip_recent mantido
        assert_eq!(sweep_alert_dedup.len(), 1);
        assert!(sweep_alert_dedup.contains_key(&ip_recent));
    }

    #[test]
    fn test_sweep_sliding_window_threshold() {
        let config = SweepConfig {
            threshold: 4,
            window: Duration::from_secs(5),
        };

        let now = Instant::now();
        let mut history: Vec<(u16, Instant)> = Vec::new();

        // 3 portos distintos tocados recentemente (abaixo do limiar de 4)
        history.push((80, now - Duration::from_secs(3)));
        history.push((443, now - Duration::from_secs(2)));
        history.push((8080, now - Duration::from_secs(1)));

        // Remove toques fora da janela
        history.retain(|(_, ts)| now.duration_since(*ts) <= config.window);
        let distinct: HashSet<u16> = history.iter().map(|(p, _)| *p).collect();
        assert_eq!(distinct.len(), 3);
        assert!(distinct.len() < config.threshold);

        // Adiciona um 4º porto distinto
        history.push((8443, now));
        history.retain(|(_, ts)| now.duration_since(*ts) <= config.window);
        let distinct: HashSet<u16> = history.iter().map(|(p, _)| *p).collect();
        assert_eq!(distinct.len(), 4);
        assert!(distinct.len() >= config.threshold, "Deve atingir o limiar de SWEEP!");

        // Adiciona um porto repetido (ex.: retransmissão de 80)
        history.push((80, now));
        let distinct_repeated: HashSet<u16> = history.iter().map(|(p, _)| *p).collect();
        assert_eq!(distinct_repeated.len(), 4, "Portos repetidos não devem aumentar a contagem de portos distintos!");
    }
}
