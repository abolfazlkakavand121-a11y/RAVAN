use crate::report::DiagnosticReport;
use serde_json::json;
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
use tokio::{net::lookup_host, time::timeout};

pub async fn run(host: &str) -> DiagnosticReport {
    let started = Instant::now();
    if host.trim().is_empty() || host.contains('/') || host.chars().any(char::is_whitespace) {
        return DiagnosticReport::failure(
            "DNS",
            host,
            started.elapsed().as_millis(),
            "expected a hostname or IP literal",
        );
    }

    match timeout(Duration::from_secs(10), lookup_host((host, 0))).await {
        Ok(Ok(addresses)) => {
            let addresses: BTreeSet<String> =
                addresses.map(|address| address.ip().to_string()).collect();
            let elapsed = started.elapsed().as_millis();
            if addresses.is_empty() {
                DiagnosticReport::failure(
                    "DNS",
                    host,
                    elapsed,
                    "system resolver returned no addresses",
                )
            } else {
                DiagnosticReport::success("DNS", host, elapsed, json!({ "addresses": addresses }))
            }
        }
        Ok(Err(error)) => {
            DiagnosticReport::failure("DNS", host, started.elapsed().as_millis(), error)
        }
        Err(_) => DiagnosticReport::failure(
            "DNS",
            host,
            started.elapsed().as_millis(),
            "system DNS lookup timed out after 10 seconds",
        ),
    }
}
