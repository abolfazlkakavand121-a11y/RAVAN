use crate::report::DiagnosticReport;
use serde_json::json;
use std::{collections::BTreeSet, time::Instant};
use tokio::net::lookup_host;

pub async fn run(host: &str) -> DiagnosticReport {
    let started = Instant::now();
    if host.trim().is_empty() || host.contains('/') || host.chars().any(char::is_whitespace) {
        return DiagnosticReport::failure("DNS", host, started.elapsed().as_millis(), "expected a hostname or IP literal");
    }

    match lookup_host((host, 0)).await {
        Ok(addresses) => {
            let addresses: BTreeSet<String> = addresses.map(|address| address.ip().to_string()).collect();
            let elapsed = started.elapsed().as_millis();
            if addresses.is_empty() {
                DiagnosticReport::failure("DNS", host, elapsed, "system resolver returned no addresses")
            } else {
                DiagnosticReport::success("DNS", host, elapsed, json!({ "addresses": addresses }))
            }
        }
        Err(error) => DiagnosticReport::failure("DNS", host, started.elapsed().as_millis(), error),
    }
}
