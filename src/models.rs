use serde::Deserialize;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Pt,
    En,
}

#[derive(Clone, Debug)]
pub struct SysInfo {
    pub distro: String,
    pub kernel: String,
    pub arch: String,
}

/// Representa uma conexão capturada por uma armadilha (honeypot)
#[derive(Clone, Debug)]
pub struct Incident {
    pub timestamp: String,
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub severity: String,
    pub country: String,
    pub city: String,
    pub isp: String,
    /// Número total de vezes que este IP foi visto na sessão atual
    pub hit_count: usize,
}

/// Aviso sobre uma porta localmente vulnerável
#[derive(Clone, Debug)]
pub struct PortWarning {
    pub port: u16,
    pub service: String,
    pub risk_level: &'static str,
    pub reason: String,
    pub fix_command: String,
}

/// Filtro de severidade aplicado à tabela de deteções
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SeverityFilter {
    All,
    CriticalOnly,
    MediumAndAbove,
}

impl SeverityFilter {
    /// Alterna para o próximo filtro em ciclo
    pub fn next(self) -> Self {
        match self {
            SeverityFilter::All => SeverityFilter::CriticalOnly,
            SeverityFilter::CriticalOnly => SeverityFilter::MediumAndAbove,
            SeverityFilter::MediumAndAbove => SeverityFilter::All,
        }
    }

    pub fn label(self, lang: Language) -> &'static str {
        match (self, lang) {
            (SeverityFilter::All, Language::Pt) => "Todos",
            (SeverityFilter::All, Language::En) => "All",
            (SeverityFilter::CriticalOnly, Language::Pt) => "Críticos",
            (SeverityFilter::CriticalOnly, Language::En) => "Critical",
            (SeverityFilter::MediumAndAbove, Language::Pt) => "Médio+",
            (SeverityFilter::MediumAndAbove, Language::En) => "Medium+",
        }
    }

    /// Devolve true se o incidente passa este filtro
    pub fn matches(self, severity: &str) -> bool {
        match self {
            SeverityFilter::All => true,
            SeverityFilter::CriticalOnly => severity == "CRÍTICO" || severity == "SWEEP",
            SeverityFilter::MediumAndAbove => {
                severity == "CRÍTICO" || severity == "SWEEP" || severity == "MÉDIO"
            }
        }
    }
}

/// Resposta da API GeoIP (ip-api.com)
#[derive(Deserialize)]
pub struct GeoResponse {
    pub country: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub status: Option<String>,
}