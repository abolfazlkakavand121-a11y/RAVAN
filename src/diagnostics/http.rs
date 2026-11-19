use super::{normalized_host, safe_target, tls};
use crate::report::DiagnosticReport;
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::{
    net::SocketAddr,
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

pub async fn run(mut url: Url) -> DiagnosticReport {
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

        match timeout(remaining, request_once(&url)).await {
            Err(_) => {
                return DiagnosticReport::failure(
                    "HTTP",
                    &current_target,
                    started.elapsed().as_millis(),
                    "request timed out after 15 seconds",
                )
            }
            Ok(Err(error)) => {
                return DiagnosticReport::failure(
                    "HTTP",
                    &current_target,
                    started.elapsed().as_millis(),
                    error,
                )
            }
            Ok(Ok((status, location))) => {
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
                        "redirects_followed": redirects_followed
                    }),
                );
            }
        }
    }
}

/// Sends one HEAD request to an explicit IP. Redirects are reported but not followed,
/// because a redirect may name a different host and would break the single-IP trial.
pub async fn run_pinned(url: Url, address: SocketAddr) -> DiagnosticReport {
    let started = Instant::now();
    let target = safe_target(&url);

    if !matches!(url.scheme(), "http" | "https") {
        return DiagnosticReport::failure(
            "HTTP",
            target,
            started.elapsed().as_millis(),
            "only http:// and https:// URLs are supported",
        );
    }
    if !url.username().is_empty() || url.password().is_some() {
        return DiagnosticReport::failure(
            "HTTP",
            target,
            started.elapsed().as_millis(),
            "URL credentials are not allowed",
        );
    }

    let port = match url.port_or_known_default() {
        Some(port) => port,
        None => {
            return DiagnosticReport::failure(
                "HTTP",
                target,
                started.elapsed().as_millis(),
                "URL has no known port",
            )
        }
    };
    if address.port() != port {
        return DiagnosticReport::failure(
            "HTTP",
            target,
            started.elapsed().as_millis(),
            "pinned socket address port does not match the URL",
        );
    }

    match timeout(Duration::from_secs(15), request_once_at(&url, Some(address))).await {
        Err(_) => DiagnosticReport::failure(
            "HTTP",
            format!("{target} via {address}"),
            started.elapsed().as_millis(),
            "request to pinned IP timed out after 15 seconds",
        ),
        Ok(Err(error)) => DiagnosticReport::failure(
            "HTTP",
            format!("{target} via {address}"),
            started.elapsed().as_millis(),
            error,
        ),
        Ok(Ok((status, location))) => DiagnosticReport::success(
            "HTTP",
            format!("{target} via {address}"),
            started.elapsed().as_millis(),
            json!({
                "status": status,
                "method": "HEAD",
                "redirects_followed": 0,
                "redirect_present": location.is_some(),
                "peer": address.to_string(),
                "pinned_ip": address.ip().to_string(),
                "ip_family": if address.is_ipv4() { "ipv4" } else { "ipv6" }
            }),
        ),
    }
}

async fn request_once(url: &Url) -> Result<(u16, Option<String>)> {
    request_once_at(url, None).await
}

async fn request_once_at(
    url: &Url,
    pinned_address: Option<SocketAddr>,
) -> Result<(u16, Option<String>)> {
    let host = normalized_host(url).context("URL has no hostname")?;
    let port = url
        .port_or_known_default()
        .context("URL has no known port")?;
    let stream = match pinned_address {
        Some(address) => TcpStream::connect(address)
            .await
            .with_context(|| format!("connect to pinned IP {address}"))?,
        None => TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("connect to {host}:{port}"))?,
    };

    if url.scheme() == "https" {
        let tls_stream = tls::connector()?
            .connect(tls::server_name(&host)?, stream)
            .await
            .context("TLS handshake failed")?;
        send_head(tls_stream, url, &host, port).await
    } else {
        send_head(stream, url, &host, port).await
    }
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
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener, task::JoinHandle};

    #[tokio::test]
    async fn pinned_probe_uses_the_supplied_ip_without_resolving_the_url_host() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server: JoinHandle<()> = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let url = Url::parse(&format!("http://host-that-does-not-resolve.invalid:{}/probe", address.port()))
            .unwrap();
        let report = run_pinned(url, address).await;

        assert!(report.success, "unexpected HTTP probe failure: {:?}", report.error);
        assert_eq!(report.details["peer"], address.to_string());
        assert_eq!(report.details["status"], 204);
        server.await.unwrap();
    }

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
}
