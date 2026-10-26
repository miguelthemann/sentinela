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
    pub severity_filter: SeverityFilter,
    pub severity_stats: &'a HashMap<String, usize>,
    pub port_stats: &'a HashMap<u16, usize>,
    pub trap_ports: &'a [u16],
    pub scanner_active: bool,
}

pub fn render_ui(f: &mut Frame, ctx: &UiContext) {
    let screen_width = f.area().width;
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
        severity_filter,
        severity_stats,
        port_stats,
        trap_ports,
        scanner_active,
    } = *ctx;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(f.area());

    // 1. Cabeçalho Responsivo
    let top_constraints = if screen_width < 100 {
        [Constraint::Percentage(60), Constraint::Percentage(40)]
    } else {
        [Constraint::Percentage(70), Constraint::Percentage(30)]
    };

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(top_constraints)
        .split(chunks[0]);

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

    let title_status = " Sentinela SOC ";

    let header_info = match lang {
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
    };

    let header_p = Paragraph::new(header_info)
        .style(
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL).title(title_status));
    f.render_widget(header_p, top_chunks[0]);

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
    f.render_widget(sys_p, top_chunks[1]);

    // 2. Tabela com colunas dinâmicas segundo a largura do ecrã
    let (headers_text, col_constraints): (Vec<&str>, Vec<Constraint>) = if screen_width < 95 {
        // Modo compacto para terminais estreitos
        let h = match lang {
            Language::Pt => vec!["Hora", "Risco", "IP Origem", "Alvo", "Localização"],
            Language::En => vec!["Time", "Risk", "Source IP", "Target", "Location"],
        };
        let c = vec![
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Length(15),
            Constraint::Min(12),
        ];
        (h, c)
    } else {
        // Modo alargado — inclui ISP e hits
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
            Constraint::Length(20),
            Constraint::Length(8),
            Constraint::Length(17),
            Constraint::Length(5),
            Constraint::Length(18),
            Constraint::Length(20),
            Constraint::Min(16),
        ];
        (h, c)
    };

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

        // Localização: "Cidade, País" se disponível, senão só país
        let location_str = if item.city.is_empty() {
            item.country.clone()
        } else {
            format!("{}, {}", item.city, item.country)
        };

        let target_str = format!(":{} ({})", item.port, item.service);

        // Indica consistentemente com * os IPs com múltiplos hits (tanto em modo compacto como expandido)
        let ip_display = if item.hit_count > 1 {
            format!("{}*", item.ip)
        } else {
            item.ip.clone()
        };

        let cells = if screen_width < 95 {
            vec![
                Cell::from(item.timestamp.as_str()),
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

    let table_title = match lang {
        Language::Pt => format!(
            " Deteções em Direto [{}]{} ",
            filter_label_display, scroll_info
        ),
        Language::En => format!(
            " Live Detections [{}]{} ",
            filter_label_display, scroll_info
        ),
    };

    let table = Table::new(rows, col_constraints)
        .header(header_row)
        .block(Block::default().borders(Borders::ALL).title(table_title));

    f.render_widget(table, chunks[1]);

    // 3. Rodapé com Atalhos
    let footer_text = match lang {
        Language::Pt => " [K] Killswitch (Liga/Desliga) | [R] Repor | [W] Avisos | [I] Manual | [F] Filtro | [↑↓] Scroll | [L] Idioma | [Q] Sair ",
        Language::En => " [K] Killswitch (Toggle) | [R] Restore | [W] Warnings | [I] Manual | [F] Filter | [↑↓] Scroll | [L] Language | [Q] Quit ",
    };

    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, chunks[2]);

    // 4. Modal de Avisos de Portas Vulneráveis (Tecla W)
    if show_warnings {
        let area = centered_rect(88, 85, f.area());
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
                Language::Pt => report.push_str("[Prime 'W' ou 'ESC' para voltar ao painel]"),
                Language::En => report.push_str("[Press 'W' or 'ESC' to return]"),
            }

            let t = match lang {
                Language::Pt => " [!] RELATÓRIO DE AUDITORIA DE PORTAS ",
                Language::En => " [!] PORT AUDIT WARNINGS ",
            };
            (t, report)
        };

        let modal_p = Paragraph::new(w_body)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(w_title)
                    .style(Style::default().bg(Color::Black).fg(Color::Yellow)),
            );

        f.render_widget(modal_p, area);
    }

    // 5. Modal de Manual / Info (Tecla I)
    if show_help {
        let area = centered_rect(88, 85, f.area());
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
                    "SENTINELA HIDS & HONEYPOT\n\
                     -------------------------------------------------------------\n\
                     • OBJETIVO:\n\
                       Monitorizar e intercetar varrimentos de portas (nmap, bots)\n\
                       na máquina anfitriã, funcionando como alerta precoce de invasão.\n\n\
                     • COMO FUNCIONA:\n\
                       Cria armadilhas TCP assíncronas. Qualquer conexão é identificada,\n\
                       geolocalizada (país + cidade) e gravada em disco.\n\
                       Portas ativas: {}\n\n\
                     • ATALHOS:\n\
                       [↑↓]  Scroll: Navegar nos incidentes (mantém histórico de 100).\n\
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
                     [Prime 'I' ou 'ESC' para voltar ao painel]",
                    trap_ports_str
                ),
            ),
            Language::En => (
                " [#] OPERATION MANUAL - SENTINELA ",
                format!(
                    "SENTINELA HIDS & HONEYPOT\n\
                     -------------------------------------------------------------\n\
                     • PURPOSE:\n\
                       Monitors and flags unauthorized port scans and probes,\n\
                       acting as an early host-based intrusion detection sensor.\n\n\
                     • HOW IT WORKS:\n\
                       Spawns async TCP traps. Every probe is logged, geolocated\n\
                       (country + city) and classified with risk badges.\n\
                       Active trap ports: {}\n\n\
                     • SHORTCUTS:\n\
                       [↑↓]  Scroll: Navigate incident history (keeps last 100).\n\
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
                     [Press 'I' or 'ESC' to return]",
                    trap_ports_str
                ),
            ),
        };

        let modal_p = Paragraph::new(modal_body)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(modal_title)
                    .style(Style::default().bg(Color::Black).fg(Color::Cyan)),
            );

        f.render_widget(modal_p, area);
    }
}

// Centra os modais cobrindo a área de forma homogénea sem deixar sobras feias de lado
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
