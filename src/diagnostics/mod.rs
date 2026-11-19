pub mod dns;
pub mod http;
pub mod tcp;
pub mod tls;

use anyhow::{Context, Result};
use url::Url;

pub(crate) fn parse_host_port(target: &str) -> Result<(String, u16)> {
    let parsed = Url::parse(&format!("tcp://{target}"))
        .context("target must be host:port; bracket IPv6 literals")?;
    anyhow::ensure!(parsed.username().is_empty() && parsed.password().is_none(), "credentials are not allowed in a diagnostic target");
    anyhow::ensure!((parsed.path().is_empty() || parsed.path() == "/") && parsed.query().is_none() && parsed.fragment().is_none(), "target must contain only host and port");
    let host = normalized_host(&parsed).context("target has no hostname")?;
    let port = parsed.port().context("target must include a port")?;
    Ok((host, port))
}

pub(crate) fn normalized_host(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let host = host.strip_prefix('[').and_then(|value| value.strip_suffix(']')).unwrap_or(host);
    Some(host.to_owned())
}

pub(crate) fn safe_target(url: &Url) -> String {
    let host = normalized_host(url).unwrap_or_else(|| "<invalid-host>".to_owned());
    let display_host = if host.contains(':') { format!("[{host}]") } else { host };
    match url.port() {
        Some(port) => format!("{}://{}:{}{}", url.scheme(), display_host, port, url.path()),
        None => format!("{}://{}{}", url.scheme(), display_host, url.path()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_bracketed_ipv6_targets() {
        assert_eq!(parse_host_port("example.com:443").unwrap(), ("example.com".to_owned(), 443));
        assert_eq!(parse_host_port("[::1]:443").unwrap(), ("::1".to_owned(), 443));
    }

    #[test]
    fn rejects_targets_with_credentials_or_without_port() {
        assert!(parse_host_port("user:pass@example.com:443").is_err());
        assert!(parse_host_port("example.com").is_err());
    }

    #[test]
    fn sanitized_url_omits_query_and_credentials() {
        let url = Url::parse("https://user:pass@example.com/path?token=secret").unwrap();
        assert_eq!(safe_target(&url), "https://example.com/path");
    }

    #[test]
    fn ipv6_host_is_normalized_without_brackets_for_socket_apis() {
        let url = Url::parse("https://[::1]:8443/").unwrap();
        assert_eq!(normalized_host(&url).unwrap(), "::1");
        assert_eq!(safe_target(&url), "https://[::1]:8443/");
    }
}
