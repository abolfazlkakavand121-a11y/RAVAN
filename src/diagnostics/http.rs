use super::{dns, normalized_host, safe_target, tls};
use crate::report::DiagnosticReport;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use url::Url;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_REDIRECTS: usize = 3;
const MAX_ADDRESS_ATTEMPT: Duration = Duration::from_secs(8);

pub async fn run(url: Url) -> DiagnosticReport {
    run_with_ip(url, None, "both").await
}

pub async fn run_pinned(url: Url, ip: IpAddr, family: &str) -> DiagnosticReport {
    run_with_ip(url, Some(ip), family).await
}

async fn run_with_ip(
    mut url: Url,
    mut pinned_ip: Option<IpAddr>,
    family: &str,
) -> DiagnosticReport {
    let started = Instant::now();
    let original_target = safe_target(&url);
    if !matches!(url.scheme(), "http" | "https") {
        return DiagnosticReport::failure(
            "HTTP",
            &original_target,
            started.elapsed().as_millis(),
            "only http:// and https:// URLs are supported",
        );
    }
    if !url.username().is_empty() || url.password().is_some() {
        return DiagnosticReport::failure(
            "HTTP",
            &original_target,
            started.elapsed().as_millis(),
            "URL credentials are not allowed",
        );
    }

    let mut redirects_followed = 0;
    let mut connections: Vec<Value> = Vec::new();

    loop {
        let current_target = safe_target(&url);
        let remaining = Duration::from_secs(15).saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return DiagnosticReport::failure(
                "HTTP",
                &current_target,
                started.elapsed().as_millis(),
                "request timed out after 15 seconds",
            );
        }

        let host = match normalized_host(&url) {
            Some(host) => host,
            None => {
                return DiagnosticReport::failure(
                    "HTTP",
                    &current_target,
                    started.elapsed().as_millis(),
                    "URL has no hostname",
                )
            }
        };
        let port = match url.port_or_known_default() {
            Some(port) => port,
            None => {
                return DiagnosticReport::failure(
                    "HTTP",
                    &current_target,
                    started.elapsed().as_millis(),
                    "URL has no known port",
                )
            }
        };

        // The first hop may be pinned by the analyzer. Every later hop is
        // resolved independently and then connected through a concrete IP.
        let addresses = match pinned_ip.take() {
            Some(ip) => vec![ip],
            None => match timeout(remaining, dns::resolve(&host)).await {
                Err(_) => {
                    return DiagnosticReport::failure(
                        "HTTP",
                        &current_target,
                        started.elapsed().as_millis(),
                        format!("DNS resolution timed out for redirect/request host {host}"),
                    )
                }
                Ok(Err(error)) => {
                    return DiagnosticReport::failure(
                        "HTTP",
                        &current_target,
                        started.elapsed().as_millis(),
                        format!("DNS resolution failed for {host}: {error:#}"),
                    )
                }
                Ok(Ok(addresses)) => addresses,
            },
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
            return DiagnosticReport::failure(
                "HTTP",
                &current_target,
                started.elapsed().as_millis(),
                format!("no resolved address matched --ip-family {family} for {host}"),
            );
        }

        let resolved_ips = addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let mut successful_response = None;
        let mut address_errors = Vec::new();

        for ip in addresses {
            let remaining = Duration::from_secs(15).saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return DiagnosticReport::failure(
                    "HTTP",
                    &current_target,
                    started.elapsed().as_millis(),
                    "request timed out after 15 seconds",
                );
            }

            let attempt_timeout = remaining.min(MAX_ADDRESS_ATTEMPT);
            match timeout(
                attempt_timeout,
                request_once(&url, SocketAddr::new(ip, port)),
            )
            .await
            {
                Err(_) => address_errors.push(format!(
                    "{ip}: request attempt timed out after {} seconds",
                    attempt_timeout.as_secs()
                )),
                Ok(Err(error)) => address_errors.push(format!("{ip}: {error:#}")),
                Ok(Ok((status, location, connected_ip))) => {
                    successful_response = Some((status, location, connected_ip));
                    break;
                }
            }
        }

        let Some((status, location, connected_ip)) = successful_response else {
            return DiagnosticReport::failure(
                "HTTP",
                &current_target,
                started.elapsed().as_millis(),
                format!(
                    "all resolved addresses failed for {host}:{port}: {}",
                    address_errors.join("; ")
                ),
            );
        };

        connections.push(json!({
            "target": current_target,
            "host": host,
            "port": port,
            "resolved_ips": resolved_ips,
            "connected_ip": connected_ip.to_string(),
            "status": status
        }));

        if (300..400).contains(&status) {
            if let Some(location) = location {
                if redirects_followed >= MAX_REDIRECTS {
                    return DiagnosticReport::failure(
                        "HTTP",
                        &current_target,
                        started.elapsed().as_millis(),
                        "redirect limit exceeded",
                    );
                }

                let next = match url.join(&location) {
                    Ok(next) => next,
                    Err(error) => {
                        return DiagnosticReport::failure(
                            "HTTP",
                            &current_target,
                            started.elapsed().as_millis(),
                            error,
                        )
                    }
                };
                if !matches!(next.scheme(), "http" | "https") {
                    return DiagnosticReport::failure(
                        "HTTP",
                        &current_target,
                        started.elapsed().as_millis(),
                        "redirect used an unsupported URL scheme",
                    );
                }
                if !next.username().is_empty() || next.password().is_some() {
                    return DiagnosticReport::failure(
                        "HTTP",
                        &current_target,
                        started.elapsed().as_millis(),
                        "redirect URL credentials are not allowed",
                    );
                }
                if url.scheme() == "https" && next.scheme() != "https" {
                    return DiagnosticReport::failure(
                        "HTTP",
                        &current_target,
                        started.elapsed().as_millis(),
                        "refused HTTPS-to-HTTP redirect downgrade",
                    );
                }

                // Do not carry the previous host's pin to a different redirect
                // target. The next loop resolves that target and pins its socket.
                pinned_ip = None;
                url = next;
                redirects_followed += 1;
                continue;
            }
        }

        return DiagnosticReport::success(
            "HTTP",
            &current_target,
            started.elapsed().as_millis(),
            json!({
                "status": status,
                "method": "HEAD",
                "redirects_followed": redirects_followed,
                "connections": connections
            }),
        );
    }
}

async fn request_once(url: &Url, address: SocketAddr) -> Result<(u16, Option<String>, IpAddr)> {
    let host = normalized_host(url).context("URL has no hostname")?;
    let port = url
        .port_or_known_default()
        .context("URL has no known port")?;
    anyhow::ensure!(
        address.port() == port,
        "pinned endpoint port does not match URL port"
    );

    let stream = TcpStream::connect(address)
        .await
        .with_context(|| format!("connect to pinned endpoint {address}"))?;
    let connected_ip = stream
        .peer_addr()
        .context("read connected peer address")?
        .ip();

    let response = if url.scheme() == "https" {
        let tls_stream = tls::connector()?
            .connect(tls::server_name(&host)?, stream)
            .await
            .context("TLS handshake failed")?;
        send_head(tls_stream, url, &host, port).await?
    } else {
        send_head(stream, url, &host, port).await?
    };

    Ok((response.0, response.1, connected_ip))
}

async fn send_head<S>(
    mut stream: S,
    url: &Url,
    host: &str,
    port: u16,
) -> Result<(u16, Option<String>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let request_target = match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    let host_header = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let default_port =
        (url.scheme() == "http" && port == 80) || (url.scheme() == "https" && port == 443);
    let host_header = if default_port {
        host_header
    } else {
        format!("{host_header}:{port}")
    };
    let request = format!(
        "HEAD {request_target} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: RAVAN/0.1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("send HTTP HEAD request")?;

    let mut response = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        if let Some(position) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if response.len() >= MAX_HEADER_BYTES {
            bail!("HTTP response headers exceeded 16 KiB");
        }
        let remaining = MAX_HEADER_BYTES.saturating_sub(response.len());
        let read_len = remaining.min(chunk.len());
        let count = stream
            .read(&mut chunk[..read_len])
            .await
            .context("read HTTP response headers")?;
        if count == 0 {
            bail!("connection closed before HTTP response headers were complete");
        }
        response.extend_from_slice(&chunk[..count]);
    };

    parse_response_headers(&response[..header_end])
}

fn parse_response_headers(bytes: &[u8]) -> Result<(u16, Option<String>)> {
    let headers = String::from_utf8_lossy(bytes);
    let mut lines = headers.lines();
    let status_line = lines.next().context("HTTP response has no status line")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .context("malformed HTTP status line")?
        .parse::<u16>()
        .context("invalid HTTP status code")?;
    let location = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("location") {
            Some(value.trim().to_owned())
        } else {
            None
        }
    });
    Ok((status, location))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn parses_status_and_location_headers() {
        let response = b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_response_headers(response).unwrap(),
            (302, Some("/next".to_owned()))
        );
    }

    #[test]
    fn tolerates_non_utf8_bytes_in_unrelated_headers() {
        let response = b"HTTP/1.1 204 No Content\r\nX-Opaque: \xff\r\n\r\n";
        assert_eq!(parse_response_headers(response).unwrap().0, 204);
    }

    #[test]
    fn rejects_malformed_status_line() {
        let response = b"NOT-HTTP\r\n\r\n";
        assert!(parse_response_headers(response).is_err());
    }

    #[tokio::test]
    async fn pins_and_reports_each_redirect_hop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let redirect_location = format!("http://127.0.0.1:{}/final", address.port());

        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let count = first.read(&mut request).await.unwrap();
            let first_request = String::from_utf8_lossy(&request[..count]).to_string();
            assert!(first_request.starts_with("HEAD /start HTTP/1.1"));
            first
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {redirect_location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            let (mut second, _) = listener.accept().await.unwrap();
            let count = second.read(&mut request).await.unwrap();
            let second_request = String::from_utf8_lossy(&request[..count]).to_string();
            assert!(second_request.starts_with("HEAD /final HTTP/1.1"));
            second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let url = Url::parse(&format!("http://localhost:{}/start", address.port())).unwrap();
        let report = run_pinned(url, IpAddr::V4(Ipv4Addr::LOCALHOST), "ipv4").await;
        assert!(
            report.success,
            "HTTP redirect chain failed: {:?}",
            report.error
        );
        assert_eq!(report.details["redirects_followed"], 1);
        let connections = report.details["connections"].as_array().unwrap();
        assert_eq!(connections.len(), 2);
        assert_eq!(connections[0]["host"], "localhost");
        assert_eq!(connections[0]["connected_ip"], "127.0.0.1");
        assert_eq!(connections[1]["host"], "127.0.0.1");
        assert_eq!(connections[1]["resolved_ips"][0], "127.0.0.1");
        assert_eq!(connections[1]["connected_ip"], "127.0.0.1");
        server.await.unwrap();
    }
}
