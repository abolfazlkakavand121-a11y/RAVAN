use super::parse_host_port;
use crate::report::DiagnosticReport;
use anyhow::{Context, Result};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde_json::json;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{client::TlsStream, TlsConnector};

pub(crate) fn connector() -> Result<TlsConnector> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(connector_with_roots(roots))
}

fn connector_with_roots(roots: RootCertStore) -> TlsConnector {
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
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
    connect_tls_stream(host, stream).await
}

/// Performs TLS over a socket connected to an explicit IP while validating the original host.
pub(crate) async fn connect_tls_to(
    host: &str,
    address: SocketAddr,
) -> Result<TlsStream<TcpStream>> {
    let stream = timeout(Duration::from_secs(10), TcpStream::connect(address))
        .await
        .context("TCP connection to pinned IP timed out")??;
    connect_tls_stream(host, stream).await
}

async fn connect_tls_stream(host: &str, stream: TcpStream) -> Result<TlsStream<TcpStream>> {
    let tls = timeout(
        Duration::from_secs(10),
        connector()?.connect(server_name(host)?, stream),
    )
    .await
    .context("TLS handshake timed out")?
    .context("TLS handshake failed")?;
    Ok(tls)
}

pub async fn run(target: &str) -> DiagnosticReport {
    let started = Instant::now();
    let (host, port) = match parse_host_port(target) {
        Ok(value) => value,
        Err(error) => {
            return DiagnosticReport::failure("TLS", target, started.elapsed().as_millis(), error)
        }
    };

    match connect_tls(&host, port).await {
        Ok(stream) => report_tls_success(target, started.elapsed().as_millis(), &stream, None),
        Err(error) => {
            DiagnosticReport::failure("TLS", target, started.elapsed().as_millis(), error)
        }
    }
}

/// Performs a TLS handshake to a pinned IP but keeps the URL hostname for SNI and
/// certificate hostname verification.
pub async fn run_pinned(host: &str, address: SocketAddr) -> DiagnosticReport {
    let started = Instant::now();
    let target = format!("{host} via {address}");

    match connect_tls_to(host, address).await {
        Ok(stream) => report_tls_success(
            &target,
            started.elapsed().as_millis(),
            &stream,
            Some(address),
        ),
        Err(error) => {
            DiagnosticReport::failure("TLS", target, started.elapsed().as_millis(), error)
        }
    }
}

fn report_tls_success(
    target: &str,
    elapsed_ms: u128,
    stream: &TlsStream<TcpStream>,
    pinned_address: Option<SocketAddr>,
) -> DiagnosticReport {
    let connection = stream.get_ref().1;
    let version = connection
        .protocol_version()
        .map(|value| format!("{value:?}"))
        .unwrap_or_else(|| "unknown".to_owned());
    let cipher = connection
        .negotiated_cipher_suite()
        .map(|value| format!("{:?}", value.suite()))
        .unwrap_or_else(|| "unknown".to_owned());

    let mut details = json!({
        "handshake": "completed",
        "tls_version": version,
        "cipher_suite": cipher,
        "certificate_validation": "enabled"
    });
    if let Some(address) = pinned_address {
        details["pinned_ip"] = json!(address.ip().to_string());
        details["ip_family"] = json!(if address.is_ipv4() { "ipv4" } else { "ipv6" });
    }

    DiagnosticReport::success("TLS", target, elapsed_ms, details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    };
    use std::{net::SocketAddr, sync::Arc};
    use tokio::{net::TcpListener, task::JoinHandle, time::timeout};
    use tokio_rustls::TlsAcceptor;

    fn test_certificate() -> CertificateDer<'static> {
        CertificateDer::from(include_bytes!("../../tests/fixtures/tls-test-cert.der").to_vec())
    }

    fn trusted_test_roots() -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(test_certificate()).unwrap();
        roots
    }

    async fn spawn_test_tls_server() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let certificate = test_certificate();
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../../tests/fixtures/tls-test-key.pk8").to_vec(),
        ));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key)
            .expect("test certificate and key must match");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });
        (address, task)
    }

    #[tokio::test]
    async fn accepts_a_test_certificate_when_chain_and_hostname_are_trusted() {
        let (address, server) = spawn_test_tls_server().await;
        let stream = TcpStream::connect(address).await.unwrap();
        let connector = connector_with_roots(trusted_test_roots());
        let result = timeout(
            Duration::from_secs(3),
            connector.connect(server_name("localhost").unwrap(), stream),
        )
        .await
        .expect("TLS test handshake should finish");
        let _tls = result.expect("trusted certificate and hostname should be accepted");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_a_certificate_from_an_untrusted_root() {
        let (address, server) = spawn_test_tls_server().await;
        let stream = TcpStream::connect(address).await.unwrap();
        let connector = connector_with_roots(RootCertStore::empty());
        let result = timeout(
            Duration::from_secs(3),
            connector.connect(server_name("localhost").unwrap(), stream),
        )
        .await
        .expect("TLS test handshake should finish");
        assert!(result.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_a_hostname_that_does_not_match_the_trusted_certificate() {
        let (address, server) = spawn_test_tls_server().await;
        let stream = TcpStream::connect(address).await.unwrap();
        let connector = connector_with_roots(trusted_test_roots());
        let result = timeout(
            Duration::from_secs(3),
            connector.connect(server_name("not-localhost.invalid").unwrap(), stream),
        )
        .await
        .expect("TLS test handshake should finish");
        assert!(result.is_err());
        server.await.unwrap();
    }
}
