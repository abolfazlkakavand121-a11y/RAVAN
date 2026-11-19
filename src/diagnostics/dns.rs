use crate::report::DiagnosticReport;
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::{
    collections::BTreeSet,
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::{net::lookup_host, time::timeout};

/// Resolve a hostname once and return the concrete IP addresses that later
/// diagnostic stages can pin their sockets to.
pub async fn resolve(host: &str) -> Result<Vec<IpAddr>> {
    if host.trim().is_empty() || host.contains('/') || host.chars().any(char::is_whitespace) {
        bail!("expected a hostname or IP literal");
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let addresses = timeout(Duration::from_secs(10), lookup_host((host, 0)))
        .await
        .context("system DNS lookup timed out after 10 seconds")??
        .map(|address| address.ip())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if addresses.is_empty() {
        bail!("system resolver returned no addresses");
    }

    Ok(addresses)
}

pub async fn run(host: &str) -> DiagnosticReport {
    let started = Instant::now();
    match resolve(host).await {
        Ok(addresses) => {
            let addresses = addresses
                .into_iter()
                .map(|address| address.to_string())
                .collect::<Vec<_>>();
            DiagnosticReport::success(
                "DNS",
                host,
                started.elapsed().as_millis(),
                json!({ "addresses": addresses }),
            )
        }
        Err(error) => DiagnosticReport::failure("DNS", host, started.elapsed().as_millis(), error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_rejects_invalid_host_input() {
        assert!(resolve("bad host/name").await.is_err());
    }

    #[tokio::test]
    async fn resolve_accepts_ip_literals_without_dns_lookup() {
        let addresses = resolve("127.0.0.1").await.unwrap();
        assert_eq!(addresses, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }
}
