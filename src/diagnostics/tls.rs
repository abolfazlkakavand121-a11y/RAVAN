use super::parse_host_port;
use crate::report::DiagnosticReport;
use anyhow::{Context, Result};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde_json::json;
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{client::TlsStream, TlsConnector};

pub(crate) fn connector() -> Result<TlsConnector> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>> {
    match host.parse::<IpAddr>() {
        Ok(ip) => Ok(ServerName::IpAddress(ip.into())),
        Err(_) => ServerName::try_from(host.to_owned()).context("invalid TLS server name"),
    }
}

pub(crate) async fn connect_tls(host: &str, port: u16) -> Result<TlsStream<TcpStream>> {
    let stream = timeout(Duration::from_secs(10), TcpStream::connect((host, port)))
        .await
        .context("TCP connection timed out")??;
    let tls = timeout(Duration::from_secs(10), connector()?.connect(server_name(host)?, stream))
        .await
        .context("TLS handshake timed out")?
        .context("TLS handshake failed")?;
    Ok(tls)
}

pub async fn run(target: &str) -> DiagnosticReport {
    let started = std::time::Instant::now();
    let (host, port) = match parse_host_port(target) {
        Ok(value) => value,
        Err(error) => return DiagnosticReport::failure("TLS", target, started.elapsed().as_millis(), error),
    };

    match connect_tls(&host, port).await {
        Ok(stream) => {
            let connection = stream.get_ref().1;
            let version = connection.protocol_version().map(|value| format!("{value:?}")).unwrap_or_else(|| "unknown".to_owned());
            let cipher = connection.negotiated_cipher_suite().map(|value| format!("{:?}", value.suite())).unwrap_or_else(|| "unknown".to_owned());
            DiagnosticReport::success("TLS", target, started.elapsed().as_millis(), json!({
                "handshake": "completed",
                "tls_version": version,
                "cipher_suite": cipher,
                "certificate_validation": "enabled"
            }))
        }
        Err(error) => DiagnosticReport::failure("TLS", target, started.elapsed().as_millis(), error),
    }
}
