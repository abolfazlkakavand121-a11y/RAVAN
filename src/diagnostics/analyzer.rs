use super::{dns, http, normalized_host, safe_target, tcp, tls};
use crate::report::DiagnosticReport;
use anyhow::{bail, Context, Result};
use serde::Serialize;
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
    let target = safe_target(&url);
    match run_inner(url, target.clone()).await {
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

async fn run_inner(url: Url, target: String) -> Result<ProtocolAnalysisReport> {
    if !matches!(url.scheme(), "http" | "https") {
        bail!("only http:// and https:// URLs are supported");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("URL credentials are not allowed");
    }

    let host = normalized_host(&url).context("URL has no hostname")?;
    let port = url.port_or_known_default().context("URL has no known port")?;
    let tcp_target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut stages = Vec::with_capacity(4);

    let dns_report = dns::run(&host).await;
    if !dns_report.success {
        stages.push(dns_report);
        return Ok(failed(target, stages, "DNS resolution failed; TCP, TLS, and HTTP stages were not attempted."));
    }
    stages.push(dns_report);

    let tcp_report = tcp::run(&tcp_target).await;
    if !tcp_report.success {
        stages.push(tcp_report);
        return Ok(failed(target, stages, "DNS succeeded, but TCP connection failed; higher protocol stages were not attempted."));
    }
    stages.push(tcp_report);

    if url.scheme() == "https" {
        let tls_report = tls::run(&tcp_target).await;
        if !tls_report.success {
            stages.push(tls_report);
            return Ok(failed(target, stages, "DNS and TCP succeeded, but TLS negotiation or certificate validation failed."));
        }
        stages.push(tls_report);
    }

    let http_report = http::run(url).await;
    if !http_report.success {
        stages.push(http_report);
        return Ok(failed(target, stages, "DNS and transport setup succeeded, but the HTTP exchange failed."));
    }
    stages.push(http_report);

    Ok(ProtocolAnalysisReport {
        check: "PROTOCOL_ANALYSIS".to_owned(),
        target,
        success: true,
        stages,
        summary: "All applicable stages completed. An HTTP status such as 403 or 404 still confirms that an HTTP server responded; it is not a transport failure.".to_owned(),
    })
}

fn failed(target: String, stages: Vec<DiagnosticReport>, summary: &str) -> ProtocolAnalysisReport {
    ProtocolAnalysisReport {
        check: "PROTOCOL_ANALYSIS".to_owned(),
        target,
        success: false,
        stages,
        summary: summary.to_owned(),
    }
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
        let report = failed(
            "https://example.com/".to_owned(),
            vec![DiagnosticReport::failure("DNS", "example.com", 12, "test failure")],
            "DNS failed",
        );
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["check"], "PROTOCOL_ANALYSIS");
        assert_eq!(value["success"], false);
        assert_eq!(value["stages"][0]["check"], "DNS");
        assert_eq!(value["summary"], "DNS failed");
    }
}
