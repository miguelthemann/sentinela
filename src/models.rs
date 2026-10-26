use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    Pt,
    En,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SysInfo {
    pub distro: String,
    pub kernel: String,
    pub arch: String,
}

/// Representa uma conexão capturada por uma armadilha (honeypot)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Incident {
    pub timestamp: String,
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub severity: String,
    pub country: String,
    pub city: String,
    pub isp: String,
    /// Hostname DNS reverso obtido assincronamente (se disponível)
    pub rdns: Option<String>,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, Deserialize)]
pub struct GeoResponse {
    pub country: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_filter_cycle() {
        let filter = SeverityFilter::All;
        assert_eq!(filter.next(), SeverityFilter::CriticalOnly);
        assert_eq!(filter.next().next(), SeverityFilter::MediumAndAbove);
        assert_eq!(filter.next().next().next(), SeverityFilter::All);
    }

    #[test]
    fn test_severity_filter_matching() {
        let all = SeverityFilter::All;
        assert!(all.matches("CRÍTICO"));
        assert!(all.matches("SWEEP"));
        assert!(all.matches("MÉDIO"));
        assert!(all.matches("ALERTA"));
        assert!(all.matches("SCAN"));

        let crit = SeverityFilter::CriticalOnly;
        assert!(crit.matches("CRÍTICO"));
        assert!(crit.matches("SWEEP"));
        assert!(!crit.matches("MÉDIO"));
        assert!(!crit.matches("ALERTA"));
        assert!(!crit.matches("SCAN"));

        let med_plus = SeverityFilter::MediumAndAbove;
        assert!(med_plus.matches("CRÍTICO"));
        assert!(med_plus.matches("SWEEP"));
        assert!(med_plus.matches("MÉDIO"));
        assert!(!med_plus.matches("ALERTA"));
        assert!(!med_plus.matches("SCAN"));
    }

    #[test]
    fn test_severity_filter_labels() {
        assert_eq!(SeverityFilter::All.label(Language::Pt), "Todos");
        assert_eq!(SeverityFilter::All.label(Language::En), "All");
        assert_eq!(SeverityFilter::CriticalOnly.label(Language::Pt), "Críticos");
        assert_eq!(SeverityFilter::CriticalOnly.label(Language::En), "Critical");
        assert_eq!(SeverityFilter::MediumAndAbove.label(Language::Pt), "Médio+");
        assert_eq!(
            SeverityFilter::MediumAndAbove.label(Language::En),
            "Medium+"
        );
    }
}
