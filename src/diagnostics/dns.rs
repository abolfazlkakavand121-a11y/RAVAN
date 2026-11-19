use crate::report::DiagnosticReport;
use anyhow::{bail, ensure, Context, Result};
use serde_json::json;
use std::{
    collections::BTreeSet,
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::{net::lookup_host, time::timeout};

pub async fn resolve(host: &str) -> Result<Vec<IpAddr>> {
    if host.trim().is_empty() || host.contains('/') || host.chars().any(char::is_whitespace) {
        bail!("expected a hostname or IP literal");
    }

    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![address]);
    }

    let resolved = timeout(Duration::from_secs(10), lookup_host((host, 0)))
        .await
        .context("system DNS lookup timed out after 10 seconds")??;

    let addresses: BTreeSet<IpAddr> = resolved.map(|address| address.ip()).collect();
    ensure!(!addresses.is_empty(), "system resolver returned no addresses");

    Ok(addresses.into_iter().collect())
}

pub async fn run(host: &str) -> DiagnosticReport {
    let started = Instant::now();

    match resolve(host).await {
        Ok(addresses) => DiagnosticReport::success(
            "DNS",
            host,
            started.elapsed().as_millis(),
            json!({ "addresses": addresses }),
        ),
        Err(error) => DiagnosticReport::failure(
            "DNS",
            host,
            started.elapsed().as_millis(),
            error,
        ),
    }
}
