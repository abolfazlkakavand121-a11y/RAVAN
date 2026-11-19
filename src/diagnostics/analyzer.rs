use super::{dns, http, normalized_host, safe_target, tcp, tls};
use crate::report::DiagnosticReport;
use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde::Serialize;
use serde_json::json;
use std::{
    net::{IpAddr, SocketAddr},
    time::Instant,
};
use url::Url;

const MAX_REPEATS: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum IpFamily {
    All,
    Ipv4,
    Ipv6,
}

impl IpFamily {
    fn includes(self, address: IpAddr) -> bool {
        match self {
            Self::All => true,
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AddressAttemptReport {
    pub attempt: u8,
    pub success: bool,
    pub stages: Vec<DiagnosticReport>,
}

#[derive(Debug, Serialize)]
pub struct AddressAnalysisReport {
    pub address: String,
    pub family: String,
    pub success: bool,
    pub successful_attempts: u8,
    pub attempts: Vec<AddressAttemptReport>,
}

#[derive(Debug, Serialize)]
pub struct ProtocolAnalysisReport {
    pub check: String,
    pub target: String,
    pub success: bool,
    pub ip_family: IpFamily,
    pub repeats: u8,
    pub dns: DiagnosticReport,
    pub addresses: Vec<AddressAnalysisReport>,
    pub summary: String,
}

pub async fn run(url: Url, ip_family: IpFamily, repeats: u8) -> ProtocolAnalysisReport {
    let target = safe_target(&url);
    let repeats = repeats.clamp(1, MAX_REPEATS);

    match run_inner(url, target.clone(), ip_family, repeats).await {
        Ok(report) => report,
        Err(error) => ProtocolAnalysisReport {
            check: "PROTOCOL_ANALYSIS".to_owned(),
            target: target.clone(),
            success: false,
            ip_family,
            repeats,
            dns: DiagnosticReport::failure(
                "DNS",
                target,
                0,
                format!("analysis could not start: {error:#}"),
            ),
            addresses: Vec::new(),
            summary: format!("Analysis could not start: {error:#}"),
        },
    }
}

async fn run_inner(
    url: Url,
    target: String,
    ip_family: IpFamily,
    repeats: u8,
) -> Result<ProtocolAnalysisReport> {
    if !matches!(url.scheme(), "http" | "https") {
        bail!("only http:// and https:// URLs are supported");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("URL credentials are not allowed");
    }

    let host = normalized_host(&url).context("URL has no hostname")?;
    let port = url
        .port_or_known_default()
        .context("URL has no known port")?;

    let dns_started = Instant::now();
    let resolved_addresses = match dns::resolve(&host).await {
        Ok(addresses) => addresses,
        Err(error) => {
            let dns_report =
                DiagnosticReport::failure("DNS", &host, dns_started.elapsed().as_millis(), &error);
            return Ok(ProtocolAnalysisReport {
                check: "PROTOCOL_ANALYSIS".to_owned(),
                target,
                success: false,
                ip_family,
                repeats,
                dns: dns_report,
                addresses: Vec::new(),
                summary: "DNS resolution failed; no address-level tests were attempted.".to_owned(),
            });
        }
    };

    let selected_addresses: Vec<IpAddr> = resolved_addresses
        .iter()
        .copied()
        .filter(|address| ip_family.includes(*address))
        .collect();

    let dns_report = DiagnosticReport::success(
        "DNS",
        &host,
        dns_started.elapsed().as_millis(),
        json!({
            "addresses": resolved_addresses,
            "selected_addresses": selected_addresses,
            "requested_family": ip_family.as_str()
        }),
    );

    if selected_addresses.is_empty() {
        return Ok(ProtocolAnalysisReport {
            check: "PROTOCOL_ANALYSIS".to_owned(),
            target,
            success: false,
            ip_family,
            repeats,
            dns: dns_report,
            addresses: Vec::new(),
            summary: format!(
                "DNS succeeded, but it returned no addresses matching the requested family '{}'.",
                ip_family.as_str()
            ),
        });
    }

    let mut address_reports = Vec::with_capacity(selected_addresses.len());
    for ip in selected_addresses {
        let socket_address = SocketAddr::new(ip, port);
        let mut attempts = Vec::with_capacity(repeats as usize);
        let mut successful_attempts = 0_u8;

        for attempt in 1..=repeats {
            let result = run_address_attempt(&url, &target, socket_address, attempt).await;
            if result.success {
                successful_attempts += 1;
            }
            attempts.push(result);
        }

        address_reports.push(AddressAnalysisReport {
            address: ip.to_string(),
            family: if ip.is_ipv4() { "ipv4" } else { "ipv6" }.to_owned(),
            success: successful_attempts > 0,
            successful_attempts,
            attempts,
        });
    }

    let total_attempts = address_reports
        .iter()
        .map(|address| address.attempts.len())
        .sum::<usize>();
    let successful_attempts = address_reports
        .iter()
        .map(|address| usize::from(address.successful_attempts))
        .sum::<usize>();
    let successful_addresses = address_reports
        .iter()
        .filter(|address| address.success)
        .count();

    let success = successful_attempts > 0;
    let summary = if success {
        format!(
            "{successful_addresses}/{} IP addresses completed at least one full protocol attempt; {successful_attempts}/{total_attempts} attempts succeeded. Every TCP, TLS, and HTTP probe used its address's pinned IP.",
            address_reports.len()
        )
    } else {
        format!(
            "DNS succeeded, but none of the {total_attempts} pinned-IP protocol attempts completed successfully."
        )
    };

    Ok(ProtocolAnalysisReport {
        check: "PROTOCOL_ANALYSIS".to_owned(),
        target,
        success,
        ip_family,
        repeats,
        dns: dns_report,
        addresses: address_reports,
        summary,
    })
}

async fn run_address_attempt(
    url: &Url,
    target: &str,
    address: SocketAddr,
    attempt: u8,
) -> AddressAttemptReport {
    let mut stages = Vec::with_capacity(3);

    let tcp_report = tcp::run_pinned(target, address).await;
    if !tcp_report.success {
        stages.push(tcp_report);
        return AddressAttemptReport {
            attempt,
            success: false,
            stages,
        };
    }
    stages.push(tcp_report);

    if url.scheme() == "https" {
        let host = normalized_host(url).unwrap_or_default();
        let tls_report = tls::run_pinned(&host, address).await;
        if !tls_report.success {
            stages.push(tls_report);
            return AddressAttemptReport {
                attempt,
                success: false,
                stages,
            };
        }
        stages.push(tls_report);
    }

    let http_report = http::run_pinned(url.clone(), address).await;
    let success = http_report.success;
    stages.push(http_report);

    AddressAttemptReport {
        attempt,
        success,
        stages,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_filter_selects_only_matching_ip_addresses() {
        let addresses = vec![
            "192.0.2.10".parse::<IpAddr>().unwrap(),
            "2001:db8::10".parse::<IpAddr>().unwrap(),
            "192.0.2.11".parse::<IpAddr>().unwrap(),
        ];

        let ipv4 = addresses
            .iter()
            .copied()
            .filter(|address| IpFamily::Ipv4.includes(*address))
            .collect::<Vec<_>>();
        let ipv6 = addresses
            .iter()
            .copied()
            .filter(|address| IpFamily::Ipv6.includes(*address))
            .collect::<Vec<_>>();

        assert_eq!(ipv4.len(), 2);
        assert!(ipv4.iter().all(IpAddr::is_ipv4));
        assert_eq!(ipv6.len(), 1);
        assert!(ipv6.iter().all(IpAddr::is_ipv6));
        assert!(addresses
            .iter()
            .copied()
            .all(|address| IpFamily::All.includes(address)));
    }

    #[test]
    fn analysis_report_serializes_per_address_attempts() {
        let report = ProtocolAnalysisReport {
            check: "PROTOCOL_ANALYSIS".to_owned(),
            target: "https://example.com/".to_owned(),
            success: true,
            ip_family: IpFamily::Ipv4,
            repeats: 2,
            dns: DiagnosticReport::success(
                "DNS",
                "example.com",
                5,
                json!({ "addresses": ["192.0.2.10"] }),
            ),
            addresses: vec![AddressAnalysisReport {
                address: "192.0.2.10".to_owned(),
                family: "ipv4".to_owned(),
                success: true,
                successful_attempts: 1,
                attempts: vec![AddressAttemptReport {
                    attempt: 1,
                    success: true,
                    stages: vec![DiagnosticReport::success(
                        "TCP",
                        "example.com via 192.0.2.10:443",
                        10,
                        json!({ "peer": "192.0.2.10:443" }),
                    )],
                }],
            }],
            summary: "test summary".to_owned(),
        };

        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["ip_family"], "ipv4");
        assert_eq!(value["repeats"], 2);
        assert_eq!(value["addresses"][0]["address"], "192.0.2.10");
        assert_eq!(
            value["addresses"][0]["attempts"][0]["stages"][0]["check"],
            "TCP"
        );
        assert!(value["success"].as_bool().unwrap());
    }
}
