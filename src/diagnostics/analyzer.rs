use super::{dns, http, normalized_host, safe_target, tcp, tls};
use crate::report::DiagnosticReport;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use url::Url;

#[derive(Debug, Serialize)]
pub struct ProtocolAnalysisReport {
    pub check: String,
    pub target: String,
    pub success: bool,
    pub stages: Vec<DiagnosticReport>,
    pub summary: String,
}

pub async fn run(url: Url) -> ProtocolAnalysisReport {
    run_with_family(url, "both").await
}

pub async fn run_with_family(url: Url, family: &str) -> ProtocolAnalysisReport {
    let target = safe_target(&url);
    match run_inner(url, target.clone(), family).await {
        Ok(report) => report,
        Err(error) => ProtocolAnalysisReport {
            check: "PROTOCOL_ANALYSIS".to_owned(),
            target,
            success: false,
            stages: Vec::new(),
            summary: format!("Analysis could not start: {error:#}"),
        },
    }
}

async fn run_inner(url: Url, target: String, family: &str) -> Result<ProtocolAnalysisReport> {
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
    let dns_started = std::time::Instant::now();
    let addresses = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => dns::resolve(&host).await.context("DNS resolution failed")?,
    };

    let addresses = addresses
        .into_iter()
        .filter(|ip| match family {
            "ipv4" => ip.is_ipv4(),
            "ipv6" => ip.is_ipv6(),
            _ => true,
        })
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        bail!("DNS returned no addresses matching --ip-family {family}");
    }

    let dns_report = DiagnosticReport::success(
        "DNS",
        &host,
        dns_started.elapsed().as_millis(),
        serde_json::json!({ "addresses": addresses.iter().map(ToString::to_string).collect::<Vec<_>>() }),
    );
    let mut stages = vec![dns_report];
    let mut successful_addresses = Vec::new();

    for ip in addresses {
        let socket = SocketAddr::new(ip, port);
        let endpoint = format!("{host}:{} via {ip}", port);
        let tcp_report = tcp::run_pinned(&endpoint, socket).await;
        let tcp_ok = tcp_report.success;
        stages.push(tcp_report);
        if !tcp_ok {
            continue;
        }

        if url.scheme() == "https" {
            let tls_report = tls::run_pinned(&endpoint, &host, socket).await;
            let tls_ok = tls_report.success;
            stages.push(tls_report);
            if !tls_ok {
                continue;
            }
        }

        let http_report = http::run_pinned(url.clone(), ip, family).await;
        let http_ok = http_report.success;
        stages.push(http_report);
        if http_ok {
            successful_addresses.push(ip.to_string());
        }
    }

    let success = !successful_addresses.is_empty();
    let summary = if success {
        format!(
            "Analysis completed successfully through pinned address(es): {}. Each initial TCP/TLS/HTTP connection used the same selected IP; redirect destinations are resolved independently.",
            successful_addresses.join(", ")
        )
    } else {
        "No resolved address completed all applicable stages. See per-address TCP/TLS/HTTP results for details.".to_owned()
    };

    Ok(ProtocolAnalysisReport {
        check: "PROTOCOL_ANALYSIS".to_owned(),
        target,
        success,
        stages,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_ipv6_tcp_target_with_brackets() {
        let url = Url::parse("https://[2001:db8::1]:8443/").unwrap();
        let host = normalized_host(&url).unwrap();
        let port = url.port_or_known_default().unwrap();
        assert_eq!(format!("[{host}]:{port}"), "[2001:db8::1]:8443");
    }

    #[test]
    fn analysis_report_serializes_stage_details() {
        let report = ProtocolAnalysisReport {
            check: "PROTOCOL_ANALYSIS".to_owned(),
            target: "https://example.com/".to_owned(),
            success: true,
            stages: vec![DiagnosticReport::success(
                "DNS",
                "example.com",
                1,
                serde_json::json!({"addresses":["192.0.2.1"]}),
            )],
            summary: "completed".to_owned(),
        };
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["check"], "PROTOCOL_ANALYSIS");
        assert_eq!(value["success"], true);
        assert_eq!(value["stages"][0]["check"], "DNS");
        assert_eq!(value["summary"], "completed");
    }
}
