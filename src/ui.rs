use crate::models::{Incident, Language, PortWarning, SeverityFilter, SysInfo};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};
use std::collections::HashMap;

pub struct UiContext<'a> {
    pub incidents: &'a [Incident],
    pub killswitch_active: bool,
    pub killswitch_failed: bool,
    pub local_ips: &'a str,
    pub log_name: &'a str,
    pub sys_info: &'a SysInfo,
    pub lang: Language,
    pub show_help: bool,
    pub show_warnings: bool,
    pub warnings: &'a [PortWarning],
    pub failed_traps: &'a [u16],
    pub scroll_offset: usize,
    pub modal_scroll: u16,
    pub severity_filter: SeverityFilter,
    pub severity_stats: &'a HashMap<String, usize>,
    pub port_stats: &'a HashMap<u16, usize>,
    pub trap_ports: &'a [u16],
    pub scanner_active: bool,
}

pub fn format_modal_title(base_title: &str, scroll_offset: u16) -> String {
    if scroll_offset > 0 {
        format!("{} [+{}] ", base_title.trim_end(), scroll_offset)
    } else {
        format!("{} ", base_title.trim_end())
    }
}

pub fn extract_time_str(timestamp: &str) -> &str {
    timestamp.split_whitespace().nth(1).unwrap_or(timestamp)
}

pub fn abbreviate_severity(severity: &str) -> &'static str {
    match severity {
        "CRÍTICO" => "CRIT",
        "MÉDIO" => "MED",
        "ALERTA" => "ALRT",
        "SWEEP" => "SWP",
        "SCAN" => "SCAN",
        _ => "INFO",
    }
}

pub fn get_table_columns(width: u16, lang: Language) -> (Vec<&'static str>, Vec<Constraint>) {
    if width < 70 {
        // Modo Ultra-Compacto para Termux / ecrãs móveis em modo retrato (~40-65 colunas)
        let h = match lang {
            Language::Pt => vec!["Hora", "Risco", "Origem", "Alvo"],
            Language::En => vec!["Time", "Risk", "Source", "Target"],
        };
        let c = vec![
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(16),
            Constraint::Min(8),
        ];
        (h, c)
    } else if width < 95 {
        // Modo compacto para tablets / terminais estreitos
        let h = match lang {
            Language::Pt => vec!["Hora", "Risco", "IP Origem", "Alvo", "Localização"],
            Language::En => vec!["Time", "Risk", "Source IP", "Target", "Location"],
        };
        let c = vec![
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(15),
            Constraint::Min(12),
        ];
        (h, c)
    } else {
        // Modo alargado desktop completo
        let h = match lang {
            Language::Pt => vec![
                "Timestamp",
                "Risco",
                "IP Origem",
                "Hits",
                "Alvo / Serviço",
                "Localização",
                "ISP",
            ],
            Language::En => vec![
                "Timestamp",
                "Risk",
                "Source IP",
                "Hits",
                "Target / Service",
                "Location",
                "ISP",
            ],
        };
        let c = vec![
            Constraint::Length(19),
            Constraint::Length(8),
            Constraint::Length(17),
            Constraint::Length(5),
            Constraint::Length(18),
            Constraint::Length(20),
            Constraint::Min(16),
        ];
        (h, c)
    }
}

pub fn render_ui(f: &mut Frame, ctx: &UiContext) {
    let screen_width = f.area().width;
    let screen_height = f.area().height;
    let is_mobile = screen_width < 75;
    let is_ultra_compact = screen_width < 70;

    let UiContext {
        incidents,
        killswitch_active,
        killswitch_failed,
        local_ips,
        log_name,
        sys_info,
        lang,
        show_help,
        show_warnings,
        warnings,
        failed_traps,
        scroll_offset,
        modal_scroll,
        severity_filter,
        severity_stats,
        port_stats,
        trap_ports,
        scanner_active,
    } = *ctx;

    // Em modo mobile ou ecrãs curtos (como Termux no telemóvel), remove margens externas
    // para maximizar o espaço útil do terminal
    let margin = if is_mobile || screen_height < 24 {
        0
    } else {
        1
    };
    let header_height = if screen_height < 18 {
        3
    } else if is_mobile {
        4
    } else {
        5
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(margin)
        .constraints([
            Constraint::Length(header_height),
            Constraint::Min(4),
            Constraint::Length(3),
        ])
        .split(f.area());

    // 1. Cabeçalho Responsivo (Divide horizontalmente apenas em ecrãs largos desktop)
    let top_constraints = if screen_width < 100 {
        [Constraint::Percentage(60), Constraint::Percentage(40)]
    } else {
        [Constraint::Percentage(70), Constraint::Percentage(30)]
    };

    let top_chunks = if !is_mobile {
        Some(
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints(top_constraints)
                .split(chunks[0]),
        )
    } else {
        None
    };

    let top_port = port_stats
        .iter()
        .max_by_key(|&(_, count)| *count)
        .map(|(p, c)| format!(":{} ({}x)", p, c))
        .unwrap_or_else(|| match lang {
            Language::Pt => "Nenhuma".to_string(),
            Language::En => "None".to_string(),
        });

    let (status_color, status_label) = if killswitch_failed {
        (
            Color::LightRed,
            match lang {
                Language::Pt => "[!] FALHA ISOLAMENTO (SEM ROOT)",
                Language::En => "[!] ISOLATION FAILED (NO ROOT)",
            },
        )
    } else if killswitch_active {
        (
            Color::Red,
            match lang {
                Language::Pt => "[X] ISOLADO (KILLSWITCH)",
                Language::En => "[X] ISOLATED (KILLSWITCH)",
            },
        )
    } else {
        (
            Color::Green,
            match lang {
                Language::Pt => "[OK] EM GUARDA",
                Language::En => "[OK] GUARD ACTIVE",
            },
        )
    };

    let traps_status = if failed_traps.is_empty() {
        match lang {
            Language::Pt => format!("Armadilhas: {} ativas", trap_ports.len()),
            Language::En => format!("Traps: {} active", trap_ports.len()),
        }
    } else {
        match lang {
            Language::Pt => format!("[!] Erro portas: {:?}", failed_traps),
            Language::En => format!("[!] Port errors: {:?}", failed_traps),
        }
    };

    // Contadores de severidade em tempo real
    let crit = severity_stats.get("CRÍTICO").copied().unwrap_or(0);
    let med = severity_stats.get("MÉDIO").copied().unwrap_or(0);
    let alrt = severity_stats.get("ALERTA").copied().unwrap_or(0);
    let scans = severity_stats.get("SCAN").copied().unwrap_or(0)
        + severity_stats.get("SWEEP").copied().unwrap_or(0);

    let scanner_label = match (scanner_active, lang) {
        (true, Language::Pt) => "RAW: ativo",
        (true, Language::En) => "RAW: active",
        (false, Language::Pt) => "RAW: sem root",
        (false, Language::En) => "RAW: no root",
    };

    let filter_label = severity_filter.label(lang);
    let title_status = if is_mobile {
        format!(" Sentinela v{} ", env!("CARGO_PKG_VERSION"))
    } else {
        format!(" Sentinela SOC v{} ", env!("CARGO_PKG_VERSION"))
    };

    let local_ips_compact = if is_mobile {
        local_ips.split(" | ").next().unwrap_or(local_ips)
    } else {
        local_ips
    };

    let header_info = if screen_height < 18 {
        format!(
            " {} | IPs: {} | C:{} M:{} S:{}",
            status_label, local_ips_compact, crit, med, scans
        )
    } else if is_mobile {
        match lang {
            Language::Pt => format!(
                " Estado: {} | {} | {}\n IPs: {} | C:{} M:{} A:{} S:{} | +Vis: {}",
                status_label,
                traps_status,
                scanner_label,
                local_ips_compact,
                crit,
                med,
                alrt,
                scans,
                top_port
            ),
            Language::En => format!(
                " Status: {} | {} | {}\n IPs: {} | C:{} M:{} A:{} S:{} | Top: {}",
                status_label,
                traps_status,
                scanner_label,
                local_ips_compact,
                crit,
                med,
                alrt,
                scans,
                top_port
            ),
        }
    } else {
        match lang {
            Language::Pt => format!(
                " IPs: {} | Log: {}\n Estado: {} | {} | {} | CRIT:{} MED:{} ALRT:{} SCAN:{} | Filtro: {} | +Visada: {}",
                local_ips, log_name, status_label, traps_status, scanner_label,
                crit, med, alrt, scans, filter_label, top_port
            ),
            Language::En => format!(
                " IPs: {} | Log: {}\n Status: {} | {} | {} | CRIT:{} MED:{} ALRT:{} SCAN:{} | Filter: {} | Top: {}",
                local_ips, log_name, status_label, traps_status, scanner_label,
                crit, med, alrt, scans, filter_label, top_port
            ),
        }
    };

    let header_p = Paragraph::new(header_info)
        .style(
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL).title(title_status));

    if let Some(ref top) = top_chunks {
        f.render_widget(header_p, top[0]);

        // Caixa de Sistema (Kernel encurtado para caber sem truncar)
        let short_kernel = if sys_info.kernel.len() > 18 {
            format!("{}...", &sys_info.kernel[..15])
        } else {
            sys_info.kernel.clone()
        };

        let sys_box_text = format!(
            " SO: {}\n Kernel: {}\n Arch: {}",
            sys_info.distro, short_kernel, sys_info.arch
        );
        let sys_title = match lang {
            Language::Pt => " Sistema ",
            Language::En => " System ",
        };
        let sys_p = Paragraph::new(sys_box_text)
            .style(Style::default().fg(Color::Cyan))
            .block(Block::default().borders(Borders::ALL).title(sys_title));
        f.render_widget(sys_p, top[1]);
    } else {
        f.render_widget(header_p, chunks[0]);
    }

    // 2. Tabela com colunas dinâmicas (Mobile Termux / Tablet / Desktop)
    let (headers_text, col_constraints) = get_table_columns(screen_width, lang);

    let header_cells = headers_text.into_iter().map(|h| {
        Cell::from(h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header_row = Row::new(header_cells).height(1).bottom_margin(1);

    // Aplica filtro de severidade e scroll
    let filtered: Vec<&Incident> = incidents
        .iter()
        .filter(|i| severity_filter.matches(&i.severity))
        .collect();

    let rows = filtered.iter().skip(scroll_offset).map(|item| {
        let risk_color = match item.severity.as_str() {
            "CRÍTICO" => Color::Red,
            "SWEEP" => Color::Red, // varrimento amplo = tão sério quanto crítico
            "MÉDIO" => Color::Yellow,
            "SCAN" => Color::Magenta,
            _ => Color::Cyan,
        };

        let time_str = if screen_width < 95 {
            extract_time_str(item.timestamp.as_str())
        } else {
            item.timestamp.as_str()
        };

        let severity_display = if is_ultra_compact {
            abbreviate_severity(item.severity.as_str())
        } else {
            item.severity.as_str()
        };

        // Localização: "Cidade, País" se disponível, senão só país
        let location_str = if item.city.is_empty() {
            item.country.clone()
        } else {
            format!("{}, {}", item.city, item.country)
        };

        let target_str = if item.port == 0 {
            item.service.clone()
        } else {
            format!(":{} ({})", item.port, item.service)
        };

        let mobile_target = if item.port == 0 {
            item.service.clone()
        } else {
            format!(":{}", item.port)
        };

        // Indica consistentemente com * os IPs com múltiplos hits (tanto em modo compacto como expandido)
        let ip_display = if item.hit_count > 1 {
            format!("{}*", item.ip)
        } else {
            item.ip.clone()
        };

        let cells = if is_ultra_compact {
            vec![
                Cell::from(time_str),
                Cell::from(severity_display)
                    .style(Style::default().fg(risk_color).add_modifier(Modifier::BOLD)),
                Cell::from(ip_display),
                Cell::from(mobile_target),
            ]
        } else if screen_width < 95 {
            vec![
                Cell::from(time_str),
                Cell::from(item.severity.as_str())
                    .style(Style::default().fg(risk_color).add_modifier(Modifier::BOLD)),
                Cell::from(ip_display),
                Cell::from(target_str),
                Cell::from(location_str),
            ]
        } else {
            let hits_str = if item.hit_count > 1 {
                format!("×{}", item.hit_count)
            } else {
                String::from("1")
            };
            vec![
                Cell::from(item.timestamp.as_str()),
                Cell::from(item.severity.as_str())
                    .style(Style::default().fg(risk_color).add_modifier(Modifier::BOLD)),
                Cell::from(ip_display),
                Cell::from(hits_str).style(Style::default().fg(if item.hit_count > 1 {
                    Color::Magenta
                } else {
                    Color::White
                })),
                Cell::from(target_str),
                Cell::from(location_str),
                Cell::from(item.isp.as_str()),
            ]
        };

        Row::new(cells).style(Style::default().fg(Color::White))
    });

    let filter_label_display = severity_filter.label(lang);
    let scroll_info = if filtered.len() > scroll_offset {
        format!(" [{}/{}]", scroll_offset + 1, filtered.len())
    } else {
        String::new()
    };

    let table_title = if is_ultra_compact {
        match lang {
            Language::Pt => format!(" Deteções [{filter_label_display}] "),
            Language::En => format!(" Detections [{filter_label_display}] "),
        }
    } else {
        match lang {
            Language::Pt => format!(" Deteções em Direto [{filter_label_display}]{scroll_info} "),
            Language::En => format!(" Live Detections [{filter_label_display}]{scroll_info} "),
        }
    };

    let table = Table::new(rows, col_constraints)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(table_title));

    f.render_widget(table, chunks[1]);

    // 3. Rodapé Responsivo com Atalhos
    let footer_text = if screen_width < 55 {
        match lang {
            Language::Pt => " [Q]Sair [K]Kill [F]Filtro [W]Avisos [↑↓]Nav",
            Language::En => " [Q]Quit [K]Kill [F]Filter [W]Warn [↑↓]Nav",
        }
    } else if screen_width < 75 {
        match lang {
            Language::Pt => " [Q]Sair [K]Kill [F]Filtro [W]Avisos [I]Ajuda [↑↓]Nav",
            Language::En => " [Q]Quit [K]Kill [F]Filter [W]Warn [I]Help [↑↓]Nav",
        }
    } else {
        match lang {
            Language::Pt => " [K] Killswitch (Liga/Desliga) | [R] Repor | [W] Avisos | [I] Manual | [F] Filtro | [↑↓/Pg] Scroll | [L] Idioma | [Q] Sair ",
            Language::En => " [K] Killswitch (Toggle) | [R] Restore | [W] Warnings | [I] Manual | [F] Filter | [↑↓/Pg] Scroll | [L] Language | [Q] Quit ",
        }
    };

    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[2]);

    let (modal_w, modal_h) = if is_mobile { (96, 92) } else { (88, 85) };

    // 4. Modal de Avisos de Portas Vulneráveis (Tecla W)
    if show_warnings {
        let area = centered_rect(modal_w, modal_h, f.area());
        f.render_widget(Clear, area);

        let (w_title, w_body) = if warnings.is_empty() {
            let (title, text) = match lang {
                Language::Pt => (
                    " [#] AUDITORIA DE SEGURANÇA LOCAL ",
                    "\n[OK] NENHUMA PORTA CRÍTICA DESPROTEGIDA DETETADA!\n\n\
                     O kernel não encontrou serviços inseguros (Telnet, SMB, Redis, BDs externas)\n\
                     a escutar abertamente em 0.0.0.0.\n\n\
                     As tuas portas armadilha estão isoladas e a funcionar como honeypot.\n\n\
                     [Prime 'W' ou 'ESC' para regressar ao painel]",
                ),
                Language::En => (
                    " [#] LOCAL SECURITY AUDIT ",
                    "\n[OK] NO CRITICAL EXPOSED PORTS DETECTED!\n\n\
                     Kernel inspection found no unencrypted services (Telnet, SMB, Redis, external DBs)\n\
                     listening openly on 0.0.0.0.\n\n\
                     Your trap ports are functioning securely as honeypots.\n\n\
                     [Press 'W' or 'ESC' to return]",
                ),
            };
            (title, text.to_string())
        } else {
            let mut report = match lang {
                Language::Pt => String::from("[!] PORTAS EM RISCO DETETADAS NESTE SISTEMA:\n-------------------------------------------------------------\n"),
                Language::En => String::from("[!] VULNERABLE OPEN PORTS DETECTED ON HOST:\n-------------------------------------------------------------\n"),
            };

            for w in warnings {
                report.push_str(&format!(
                    "• Porta: {} | Serviço: {} | Risco: {}\n  Motivo: {}\n  Como Fechar: {}\n\n",
                    w.port, w.service, w.risk_level, w.reason, w.fix_command
                ));
            }

            match lang {
                Language::Pt => report.push_str("[j/k ou ↑↓ scroll | W/ESC voltar]"),
                Language::En => report.push_str("[j/k or ↑↓ scroll | W/ESC return]"),
            }

            let t = match lang {
                Language::Pt => " [!] RELATÓRIO DE AUDITORIA DE PORTAS ",
                Language::En => " [!] PORT AUDIT WARNINGS ",
            };
            (t, report)
        };

        let final_title = format_modal_title(w_title, modal_scroll);

        let modal_p = Paragraph::new(w_body)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true })
            .scroll((modal_scroll, 0))
            .alignment(Alignment::Left)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(final_title)
                    .style(Style::default().bg(Color::Black).fg(Color::Yellow)),
            );

        f.render_widget(modal_p, area);
    }

    // 5. Modal de Manual / Info (Tecla I)
    if show_help {
        let area = centered_rect(modal_w, modal_h, f.area());
        f.render_widget(Clear, area);

        let trap_ports_str = trap_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let (modal_title, modal_body) = match lang {
            Language::Pt => (
                " [#] MANUAL DE OPERAÇÃO - SENTINELA ",
                format!(
                    "SENTINELA HIDS & HONEYPOT v{}\n\
                     -------------------------------------------------------------\n\
                     • OBJETIVO:\n\
                       Monitorizar e intercetar varrimentos de portas (nmap, bots)\n\
                       na máquina anfitriã, funcionando como alerta precoce de invasão.\n\n\
                     • COMO FUNCIONA:\n\
                       Cria armadilhas TCP assíncronas. Qualquer conexão é identificada,\n\
                       geolocalizada (país + cidade) e gravada em disco.\n\
                       Portas ativas: {}\n\n\
                     • ATALHOS:\n\
                       [↑↓ / j/k] Scroll: Navegar nos incidentes ou neste manual.\n\
                       [F]   Filtro: Alternar filtro de severidade (Todos / Críticos / Médio+).\n\
                       [W]   Avisos: Lista portas perigosas abertas e como fechá-las.\n\
                       [K]   Killswitch: Isola o PC da rede imediatamente.\n\
                       [R]   Repor: Restaura as interfaces de rede normais.\n\
                       [L]   Idioma: Alterna entre Português e Inglês.\n\
                       [I]   Manual: Abre e fecha este ecrã de ajuda.\n\
                       [Q]   Sair: Termina e imprime o relatório estatístico.\n\n\
                     • PORTAS CUSTOM:\n\
                       Podes iniciar com portas à escolha:\n\
                       ./sentinela 2222 8080 9999\n\n\
                     • INDICADORES:\n\
                       * após o IP = mesmo atacante visto múltiplas vezes (coluna Hits).\n\
                       CRIT: Crítico  |  MED: Médio  |  ALRT: Alerta  |  SCAN: Varrimento\n\n\
                     [j/k ou ↑↓ scroll | I/ESC voltar]",
                    env!("CARGO_PKG_VERSION"),
                    trap_ports_str
                ),
            ),
            Language::En => (
                " [#] OPERATION MANUAL - SENTINELA ",
                format!(
                    "SENTINELA HIDS & HONEYPOT v{}\n\
                     -------------------------------------------------------------\n\
                     • PURPOSE:\n\
                       Monitors and flags unauthorized port scans and probes,\n\
                       acting as an early host-based intrusion detection sensor.\n\n\
                     • HOW IT WORKS:\n\
                       Spawns async TCP traps. Every probe is logged, geolocated\n\
                       (country + city) and classified with risk badges.\n\
                       Active trap ports: {}\n\n\
                     • SHORTCUTS:\n\
                       [↑↓ / j/k] Scroll: Navigate incident history or this manual.\n\
                       [F]   Filter: Cycle severity filter (All / Critical / Medium+).\n\
                       [W]   Warnings: Checks risky listening ports and fix commands.\n\
                       [K]   Killswitch: Disconnects the system from all networks.\n\
                       [R]   Restore: Re-enables networking adapters.\n\
                       [L]   Language: Toggles between Portuguese and English.\n\
                       [I]   Manual: Opens and closes this manual window.\n\
                       [Q]   Quit: Closes Sentinela and displays audit summary.\n\n\
                     • CUSTOM PORTS:\n\
                       Launch with your own trap ports:\n\
                       ./sentinela 2222 8080 9999\n\n\
                     • INDICATORS:\n\
                       * after IP = same attacker seen multiple times (Hits column).\n\
                       CRIT: Critical  |  MED: Medium  |  ALRT: Alert  |  SCAN: Scan/Sweep\n\n\
                     [j/k or ↑↓ scroll | I/ESC return]",
                    env!("CARGO_PKG_VERSION"),
                    trap_ports_str
                ),
            ),
        };

        let final_title = format_modal_title(modal_title, modal_scroll);

        let modal_p = Paragraph::new(modal_body)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true })
            .scroll((modal_scroll, 0))
            .alignment(Alignment::Left)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(final_title)
                    .style(Style::default().bg(Color::Black).fg(Color::Cyan)),
            );

        f.render_widget(modal_p, area);
    }
}

// Centra os modais cobrindo a área de forma homogénea sem deixar sobras feias de lado
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let px = percent_x.min(100);
    let py = percent_y.min(100);
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - py) / 2),
            Constraint::Percentage(py),
            Constraint::Percentage((100 - py) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - px) / 2),
            Constraint::Percentage(px),
            Constraint::Percentage((100 - px) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_centered_rect_bounds() {
        let area = Rect::new(0, 0, 100, 50);
        let r1 = centered_rect(50, 50, area);
        assert!(r1.width <= 100);
        assert!(r1.height <= 50);

        // Previne underflow de inteiros caso sejam passadas percentagens > 100
        let r2 = centered_rect(150, 200, area);
        assert!(r2.width <= 100);
        assert!(r2.height <= 50);
    }

    #[test]
    fn test_extract_time_str() {
        assert_eq!(extract_time_str("2026-10-26 12:34:56"), "12:34:56");
        assert_eq!(extract_time_str("12:34:56"), "12:34:56");
        assert_eq!(extract_time_str(""), "");
    }

    #[test]
    fn test_abbreviate_severity() {
        assert_eq!(abbreviate_severity("CRÍTICO"), "CRIT");
        assert_eq!(abbreviate_severity("MÉDIO"), "MED");
        assert_eq!(abbreviate_severity("ALERTA"), "ALRT");
        assert_eq!(abbreviate_severity("SWEEP"), "SWP");
        assert_eq!(abbreviate_severity("SCAN"), "SCAN");
        assert_eq!(abbreviate_severity("OUTRO"), "INFO");
    }

    #[test]
    fn test_get_table_columns_mobile_and_desktop() {
        // Modo Ultra-Compacto Termux (< 70 colunas)
        let (mobile_h, mobile_c) = get_table_columns(60, Language::Pt);
        assert_eq!(mobile_h.len(), 4);
        assert_eq!(mobile_c.len(), 4);
        assert_eq!(mobile_h, vec!["Hora", "Risco", "Origem", "Alvo"]);

        // Modo Compacto (70..95 colunas)
        let (compact_h, compact_c) = get_table_columns(80, Language::Pt);
        assert_eq!(compact_h.len(), 5);
        assert_eq!(compact_c.len(), 5);
        assert_eq!(
            compact_h,
            vec!["Hora", "Risco", "IP Origem", "Alvo", "Localização"]
        );

        // Modo Desktop Alargado (>= 95 colunas)
        let (desktop_h, desktop_c) = get_table_columns(120, Language::Pt);
        assert_eq!(desktop_h.len(), 7);
        assert_eq!(desktop_c.len(), 7);
        assert_eq!(
            desktop_h,
            vec![
                "Timestamp",
                "Risco",
                "IP Origem",
                "Hits",
                "Alvo / Serviço",
                "Localização",
                "ISP",
            ]
        );
    }

    #[test]
    fn test_format_modal_title() {
        assert_eq!(format_modal_title(" [#] MANUAL ", 0), " [#] MANUAL ");
        assert_eq!(format_modal_title(" [#] MANUAL ", 5), " [#] MANUAL [+5] ");
    }

    #[test]
    fn test_sentinela_soc_version_title() {
        let mobile = format!(" Sentinela v{} ", env!("CARGO_PKG_VERSION"));
        let desktop = format!(" Sentinela SOC v{} ", env!("CARGO_PKG_VERSION"));
        assert!(mobile.contains(env!("CARGO_PKG_VERSION")));
        assert!(desktop.contains("SOC"));
        assert!(desktop.contains(env!("CARGO_PKG_VERSION")));
    }
}
