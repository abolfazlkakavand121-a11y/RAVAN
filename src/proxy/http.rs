use crate::config::ProxyConfig;
use anyhow::{anyhow, bail, Context, Result};
use std::time::Duration;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpStream},
    time::timeout,
};
use url::Url;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const READ_CHUNK_BYTES: usize = 2048;

enum RequestKind {
    Connect {
        host: String,
        port: u16,
    },
    Forward {
        host: String,
        port: u16,
        rewritten_head: Vec<u8>,
    },
}

pub async fn handle_client(mut client: TcpStream, config: ProxyConfig) -> Result<()> {
    let (raw_head, buffered_body) =
        match read_request_head(&mut client, config.handshake_timeout_secs).await {
            Ok(parts) => parts,
            Err(error) => {
                let _ = write_error(&mut client, 400, "Bad Request").await;
                return Err(error);
            }
        };
    let request = match parse_request_head(&raw_head) {
        Ok(request) => request,
        Err(error) => {
            write_error(&mut client, 400, "Bad Request").await?;
            return Err(error);
        }
    };
    let (host, port) = match &request {
        RequestKind::Connect { host, port } | RequestKind::Forward { host, port, .. } => {
            (host.clone(), *port)
        }
    };
    let mut upstream = match connect_upstream(&host, port, config.connect_timeout_secs).await {
        Ok(stream) => stream,
        Err(error) => {
            write_error(&mut client, 502, "Bad Gateway").await?;
            return Err(error);
        }
    };
    match request {
        RequestKind::Connect { .. } => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        }
        RequestKind::Forward { rewritten_head, .. } => {
            upstream
                .write_all(&rewritten_head)
                .await
                .context("forward HTTP request headers")?;
        }
    }
    if !buffered_body.is_empty() {
        upstream
            .write_all(&buffered_body)
            .await
            .context("forward bytes buffered after HTTP headers")?;
    }
    copy_bidirectional(&mut client, &mut upstream)
        .await
        .context("relay HTTP proxy TCP stream")?;
    Ok(())
}

async fn read_request_head(
    client: &mut TcpStream,
    timeout_secs: u64,
) -> Result<(Vec<u8>, Vec<u8>)> {
    timeout(Duration::from_secs(timeout_secs), async {
        let mut received = Vec::new();
        loop {
            let mut chunk = [0_u8; READ_CHUNK_BYTES];
            let count = client
                .read(&mut chunk)
                .await
                .context("read HTTP proxy request")?;
            if count == 0 {
                bail!("client closed before completing HTTP request headers");
            }
            received.extend_from_slice(&chunk[..count]);
            if let Some(end) = find_header_end(&received) {
                if end > MAX_HEADER_BYTES {
                    bail!("HTTP request headers exceed {MAX_HEADER_BYTES} bytes");
                }
                let remainder = received.split_off(end);
                return Ok((received, remainder));
            }
            if received.len() > MAX_HEADER_BYTES {
                bail!("HTTP request headers exceed {MAX_HEADER_BYTES} bytes");
            }
        }
    })
    .await
    .context("HTTP proxy request-header timeout")?
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn valid_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_|~".contains(&byte)
}

fn parse_request_head(raw: &[u8]) -> Result<RequestKind> {
    anyhow::ensure!(
        raw.ends_with(b"\r\n\r\n"),
        "incomplete HTTP request headers"
    );
    anyhow::ensure!(
        raw.len() <= MAX_HEADER_BYTES,
        "HTTP request headers are too large"
    );
    let text = std::str::from_utf8(&raw[..raw.len() - 4])
        .context("HTTP headers must be valid UTF-8/ASCII")?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().context("missing HTTP request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("missing HTTP method")?;
    let target = parts.next().context("missing HTTP request target")?;
    let version = parts.next().context("missing HTTP version")?;
    anyhow::ensure!(parts.next().is_none(), "malformed HTTP request line");
    anyhow::ensure!(
        matches!(version, "HTTP/1.0" | "HTTP/1.1"),
        "unsupported HTTP version"
    );
    anyhow::ensure!(
        !method.is_empty() && method.bytes().all(valid_token_byte),
        "invalid HTTP method"
    );

    let mut headers = Vec::<(String, String)>::new();
    let mut host_header: Option<String> = None;
    for line in lines {
        let (name, value) = line.split_once(':').context("malformed HTTP header")?;
        let name = name.trim();
        let value = value.trim();
        anyhow::ensure!(
            !name.is_empty() && name.bytes().all(valid_token_byte),
            "invalid HTTP header name"
        );
        anyhow::ensure!(
            !value.chars().any(|c| c.is_control() && c != '\t'),
            "invalid control character in HTTP header"
        );
        if name.eq_ignore_ascii_case("host") {
            anyhow::ensure!(host_header.is_none(), "duplicate Host header");
            host_header = Some(value.to_owned());
        }
        headers.push((name.to_owned(), value.to_owned()));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_authority(target, "https")?;
        return Ok(RequestKind::Connect { host, port });
    }

    let (host, port, path, host_value) = if target == "*" || target.starts_with('/') {
        let authority = host_header.context("origin-form HTTP request is missing Host")?;
        let (host, port) = parse_authority(&authority, "http")?;
        (
            host.clone(),
            port,
            target.to_owned(),
            format_host_header(&host, port, 80),
        )
    } else {
        let url = Url::parse(target).context("HTTP proxy requires an absolute http:// URL")?;
        anyhow::ensure!(url.scheme() == "http", "HTTPS requests must use CONNECT");
        anyhow::ensure!(
            url.username().is_empty() && url.password().is_none(),
            "userinfo in proxy URLs is not allowed"
        );
        let host = url.host_str().context("HTTP URL is missing a host")?;
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = url
            .port_or_known_default()
            .context("HTTP URL has no port")?;
        let mut path = url.path().to_owned();
        if path.is_empty() {
            path.push('/');
        }
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        let host_value = format_host_header(&host, port, 80);
        (host, port, path, host_value)
    };

    let mut rewritten = format!("{method} {path} {version}\r\n");
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-authenticate")
            || name.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        rewritten.push_str(&name);
        rewritten.push_str(": ");
        rewritten.push_str(&value);
        rewritten.push_str("\r\n");
    }
    rewritten.push_str("Host: ");
    rewritten.push_str(&host_value);
    rewritten.push_str("\r\nConnection: close\r\n\r\n");
    Ok(RequestKind::Forward {
        host,
        port,
        rewritten_head: rewritten.into_bytes(),
    })
}

fn parse_authority(authority: &str, scheme: &str) -> Result<(String, u16)> {
    anyhow::ensure!(!authority.is_empty(), "empty HTTP authority");
    let url =
        Url::parse(&format!("{scheme}://{authority}/")).context("invalid HTTP host authority")?;
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "userinfo in HTTP authority is not allowed"
    );
    let host = url.host_str().context("HTTP authority is missing a host")?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url
        .port_or_known_default()
        .context("HTTP authority has no usable port")?;
    Ok((host, port))
}

fn format_host_header(host: &str, port: u16, default_port: u16) -> String {
    let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    }
}

async fn connect_upstream(host: &str, port: u16, timeout_secs: u64) -> Result<TcpStream> {
    timeout(Duration::from_secs(timeout_secs), async {
        let addresses = lookup_host((host, port))
            .await
            .with_context(|| format!("resolve HTTP destination {host}:{port}"))?;
        let mut last_error = None;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        match last_error {
            Some(error) => Err(anyhow!(error)).context("connect to HTTP destination"),
            None => bail!("DNS returned no addresses for HTTP destination {host}"),
        }
    })
    .await
    .context("HTTP proxy outbound connection timed out")?
}

async fn write_error(client: &mut TcpStream, code: u16, reason: &str) -> Result<()> {
    let body = format!("{code} {reason}\n");
    let response = format!("HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    client.write_all(response.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        task::JoinHandle,
    };

    async fn spawn_proxy(config: ProxyConfig) -> (std::net::SocketAddr, JoinHandle<Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (client, _) = listener.accept().await?;
            handle_client(client, config).await
        });
        (address, task)
    }

    async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
        let mut data = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            if stream.read_exact(&mut byte).await.is_err() {
                break;
            }
            data.push(byte[0]);
            if data.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        data
    }

    #[test]
    fn rewrites_absolute_http_url_and_drops_proxy_credentials() {
        let raw = b"GET http://example.com:8080/a?q=1 HTTP/1.1\r\nHost: ignored.example\r\nProxy-Authorization: Basic secret\r\nX-Test: yes\r\n\r\n";
        match parse_request_head(raw).unwrap() {
            RequestKind::Forward {
                host,
                port,
                rewritten_head,
            } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 8080);
                let text = String::from_utf8(rewritten_head).unwrap();
                assert!(text.starts_with("GET /a?q=1 HTTP/1.1\r\n"));
                assert!(text.contains("Host: example.com:8080\r\n"));
                assert!(text.contains("X-Test: yes\r\n"));
                assert!(!text.to_ascii_lowercase().contains("proxy-authorization"));
            }
            RequestKind::Connect { .. } => panic!("expected forwarding"),
        }
    }

    #[test]
    fn parses_https_connect_request() {
        match parse_request_head(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        )
        .unwrap()
        {
            RequestKind::Connect { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            RequestKind::Forward { .. } => panic!("expected CONNECT"),
        }
    }

    #[tokio::test]
    async fn forwards_http_request_and_response() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = upstream_listener.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (mut upstream, _) = upstream_listener.accept().await.unwrap();
            let request = String::from_utf8(read_headers(&mut upstream).await).unwrap();
            assert!(request.starts_with("GET /test HTTP/1.1\r\n"));
            assert!(request.contains("Host: 127.0.0.1:"));
            assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
            upstream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            upstream.shutdown().await.unwrap();
        });
        let (proxy_address, proxy_task) = spawn_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        let request = format!("GET http://127.0.0.1:{port}/test HTTP/1.1\r\nHost: ignored.invalid\r\nProxy-Authorization: Basic test\r\n\r\n");
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(response.ends_with(b"ok"));
        upstream_task.await.unwrap();
        proxy_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connect_tunnel_forwards_early_client_bytes() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = upstream_listener.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (mut upstream, _) = upstream_listener.accept().await.unwrap();
            let mut input = [0_u8; 4];
            upstream.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"ping");
            upstream.write_all(b"pong").await.unwrap();
            upstream.shutdown().await.unwrap();
        });
        let (proxy_address, proxy_task) = spawn_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        let request =
            format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\nping");
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"));
        assert!(response.ends_with(b"pong"));
        upstream_task.await.unwrap();
        proxy_task.await.unwrap().unwrap();
    }
}
