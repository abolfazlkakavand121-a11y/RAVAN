use super::parse_host_port;
use crate::report::DiagnosticReport;
use serde_json::json;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, time::timeout};

pub async fn run(target: &str) -> DiagnosticReport {
    let started = Instant::now();
    let (host, port) = match parse_host_port(target) {
        Ok(value) => value,
        Err(error) => {
            return DiagnosticReport::failure("TCP", target, started.elapsed().as_millis(), error)
        }
    };

    match timeout(
        Duration::from_secs(10),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(stream)) => {
            let peer = stream
                .peer_addr()
                .map(|address| address.to_string())
                .unwrap_or_default();
            drop(stream);
            DiagnosticReport::success(
                "TCP",
                target,
                started.elapsed().as_millis(),
                json!({ "peer": peer }),
            )
        }
        Ok(Err(error)) => {
            DiagnosticReport::failure("TCP", target, started.elapsed().as_millis(), error)
        }
        Err(_) => DiagnosticReport::failure(
            "TCP",
            target,
            started.elapsed().as_millis(),
            "connection timed out after 10 seconds",
        ),
    }
}

/// Connects directly to one previously resolved IP address without another DNS lookup.
pub async fn run_pinned(target: &str, address: SocketAddr) -> DiagnosticReport {
    let started = Instant::now();

    match timeout(Duration::from_secs(10), TcpStream::connect(address)).await {
        Ok(Ok(stream)) => {
            let peer = stream
                .peer_addr()
                .map(|peer| peer.to_string())
                .unwrap_or_else(|_| address.to_string());
            drop(stream);
            DiagnosticReport::success(
                "TCP",
                format!("{target} via {address}"),
                started.elapsed().as_millis(),
                json!({
                    "peer": peer,
                    "pinned_ip": address.ip().to_string(),
                    "ip_family": if address.is_ipv4() { "ipv4" } else { "ipv6" }
                }),
            )
        }
        Ok(Err(error)) => DiagnosticReport::failure(
            "TCP",
            format!("{target} via {address}"),
            started.elapsed().as_millis(),
            error,
        ),
        Err(_) => DiagnosticReport::failure(
            "TCP",
            format!("{target} via {address}"),
            started.elapsed().as_millis(),
            "connection to pinned IP timed out after 10 seconds",
        ),
    }
}
