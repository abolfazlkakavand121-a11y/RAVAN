use crate::config::ProxyConfig;
use anyhow::{bail, Context, Result};
use std::{io::ErrorKind, net::SocketAddr, time::Duration};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpStream},
    time::timeout,
};

const SOCKS_VERSION: u8 = 5;

pub async fn handle_client(mut client: TcpStream, config: ProxyConfig) -> Result<()> {
    let handshake_timeout = Duration::from_secs(config.handshake_timeout_secs);
    let request = match timeout(handshake_timeout, negotiate(&mut client)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => return Err(error),
        Err(_) => bail!("SOCKS5 handshake timed out"),
    };

    let mut destination =
        match connect_destination(&request.0, request.1, config.connect_timeout_secs).await {
            Ok(stream) => stream,
            Err(reply_code) => {
                send_reply(&mut client, reply_code, None).await?;
                bail!("SOCKS5 destination connection failed (reply {reply_code})");
            }
        };

    let bound_address = destination
        .local_addr()
        .context("read destination socket's local address")?;
    send_reply(&mut client, 0x00, Some(bound_address)).await?;

    copy_bidirectional(&mut client, &mut destination)
        .await
        .context("forward TCP stream")?;
    Ok(())
}

async fn negotiate(client: &mut TcpStream) -> Result<(String, u16)> {
    let mut greeting = [0_u8; 2];
    client
        .read_exact(&mut greeting)
        .await
        .context("read SOCKS5 greeting")?;
    if greeting[0] != SOCKS_VERSION {
        bail!("unsupported SOCKS version");
    }

    let mut methods = vec![0_u8; greeting[1] as usize];
    client
        .read_exact(&mut methods)
        .await
        .context("read SOCKS5 methods")?;
    if !methods.contains(&0x00) {
        client.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        bail!("client does not offer no-authentication method");
    }
    client.write_all(&[SOCKS_VERSION, 0x00]).await?;

    let mut request = [0_u8; 4];
    client
        .read_exact(&mut request)
        .await
        .context("read SOCKS5 request")?;
    if request[0] != SOCKS_VERSION || request[2] != 0 {
        send_reply(client, 0x01, None).await?;
        bail!("malformed SOCKS5 request");
    }
    if request[1] != 0x01 {
        send_reply(client, 0x07, None).await?;
        bail!("only SOCKS5 CONNECT is supported");
    }

    let host = match request[3] {
        0x01 => {
            let mut bytes = [0_u8; 4];
            client.read_exact(&mut bytes).await?;
            std::net::Ipv4Addr::from(bytes).to_string()
        }
        0x03 => {
            let mut length = [0_u8; 1];
            client.read_exact(&mut length).await?;
            if length[0] == 0 {
                send_reply(client, 0x08, None).await?;
                bail!("empty SOCKS5 domain name");
            }

            let mut bytes = vec![0_u8; length[0] as usize];
            client.read_exact(&mut bytes).await?;
            let name = match String::from_utf8(bytes) {
                Ok(name) => name,
                Err(error) => {
                    send_reply(client, 0x08, None).await?;
                    bail!("SOCKS5 domain name is not valid UTF-8: {error}");
                }
            };
            if name.trim().is_empty()
                || name
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            {
                send_reply(client, 0x08, None).await?;
                bail!("invalid SOCKS5 domain name");
            }
            name
        }
        0x04 => {
            let mut bytes = [0_u8; 16];
            client.read_exact(&mut bytes).await?;
            std::net::Ipv6Addr::from(bytes).to_string()
        }
        _ => {
            send_reply(client, 0x08, None).await?;
            bail!("unsupported SOCKS5 address type");
        }
    };

    let mut port = [0_u8; 2];
    client.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        send_reply(client, 0x08, None).await?;
        bail!("destination port 0 is invalid");
    }

    Ok((host, port))
}

async fn connect_destination(
    host: &str,
    port: u16,
    timeout_secs: u64,
) -> std::result::Result<TcpStream, u8> {
    timeout(Duration::from_secs(timeout_secs), async {
        let addresses: Vec<SocketAddr> = match lookup_host((host, port)).await {
            Ok(addresses) => addresses.collect(),
            Err(_) => return Err(0x04),
        };
        if addresses.is_empty() {
            return Err(0x04);
        }

        let mut last_reply = 0x05;
        for address in addresses {
            match TcpStream::connect(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => last_reply = 0x05,
                Err(_) => last_reply = 0x01,
            }
        }
        Err(last_reply)
    })
    .await
    .unwrap_or(Err(0x01))
}

async fn send_reply(
    client: &mut TcpStream,
    code: u8,
    bound_address: Option<SocketAddr>,
) -> Result<()> {
    let mut reply = vec![SOCKS_VERSION, code, 0x00];
    match bound_address {
        Some(SocketAddr::V4(address)) => {
            reply.push(0x01);
            reply.extend_from_slice(&address.ip().octets());
            reply.extend_from_slice(&address.port().to_be_bytes());
        }
        Some(SocketAddr::V6(address)) => {
            reply.push(0x04);
            reply.extend_from_slice(&address.ip().octets());
            reply.extend_from_slice(&address.port().to_be_bytes());
        }
        None => {
            reply.push(0x01);
            reply.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
    }
    client.write_all(&reply).await?;
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

    async fn spawn_single_client_proxy(
        config: ProxyConfig,
    ) -> (SocketAddr, JoinHandle<Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (client, _) = listener.accept().await?;
            handle_client(client, config).await
        });
        (address, task)
    }

    async fn negotiate_client(client: &mut TcpStream) {
        client.write_all(&[SOCKS_VERSION, 1, 0]).await.unwrap();
        let mut selection = [0_u8; 2];
        client.read_exact(&mut selection).await.unwrap();
        assert_eq!(selection, [SOCKS_VERSION, 0x00]);
    }

    async fn read_ipv4_reply(client: &mut TcpStream) -> [u8; 10] {
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        reply
    }

    #[tokio::test]
    async fn parses_domain_connect_request_without_external_network_access() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(address).await.unwrap();
            let mut request = vec![SOCKS_VERSION, 1, 0, SOCKS_VERSION, 0x01, 0, 0x03, 11];
            request.extend_from_slice(b"example.com");
            request.extend_from_slice(&443_u16.to_be_bytes());
            client.write_all(&request).await.unwrap();

            let mut selection = [0_u8; 2];
            client.read_exact(&mut selection).await.unwrap();
            selection
        });

        let (mut server, _) = listener.accept().await.unwrap();
        let parsed = negotiate(&mut server).await.unwrap();

        assert_eq!(parsed, ("example.com".to_owned(), 443));
        assert_eq!(client_task.await.unwrap(), [SOCKS_VERSION, 0x00]);
    }

    #[tokio::test]
    async fn connects_to_ipv4_and_relays_data_in_both_directions() {
        let destination_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination_listener.local_addr().unwrap();
        let destination_task = tokio::spawn(async move {
            let (mut destination, _) = destination_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            destination.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            destination.write_all(b"pong").await.unwrap();
            destination.shutdown().await.unwrap();
        });

        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        negotiate_client(&mut client).await;

        let mut request = vec![SOCKS_VERSION, 0x01, 0x00, 0x01];
        request.extend_from_slice(&[127, 0, 0, 1]);
        request.extend_from_slice(&destination_address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();

        let reply = read_ipv4_reply(&mut client).await;
        assert_eq!(reply[0], SOCKS_VERSION);
        assert_eq!(reply[1], 0x00);
        assert_eq!(reply[3], 0x01);
        assert_ne!(&reply[8..10], &[0, 0]);

        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        client.shutdown().await.unwrap();

        destination_task.await.unwrap();
        proxy_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_clients_without_no_authentication_support() {
        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        client.write_all(&[SOCKS_VERSION, 1, 0x02]).await.unwrap();

        let mut selection = [0_u8; 2];
        client.read_exact(&mut selection).await.unwrap();
        assert_eq!(selection, [SOCKS_VERSION, 0xFF]);
        assert!(proxy_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_unsupported_commands_with_protocol_reply() {
        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        negotiate_client(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, 0x02, 0x00, 0x01])
            .await
            .unwrap();

        let reply = read_ipv4_reply(&mut client).await;
        assert_eq!(reply[1], 0x07);
        assert!(proxy_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_malformed_reserved_field() {
        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        negotiate_client(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, 0x01, 0x01, 0x01])
            .await
            .unwrap();

        let reply = read_ipv4_reply(&mut client).await;
        assert_eq!(reply[1], 0x01);
        assert!(proxy_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_unknown_address_type() {
        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        negotiate_client(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, 0x01, 0x00, 0x09])
            .await
            .unwrap();

        let reply = read_ipv4_reply(&mut client).await;
        assert_eq!(reply[1], 0x08);
        assert!(proxy_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_empty_domain_name() {
        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        negotiate_client(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, 0x01, 0x00, 0x03, 0x00])
            .await
            .unwrap();

        let reply = read_ipv4_reply(&mut client).await;
        assert_eq!(reply[1], 0x08);
        assert!(proxy_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_non_utf8_domain_name() {
        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        negotiate_client(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, 0x01, 0x00, 0x03, 0x01, 0xFF])
            .await
            .unwrap();

        let reply = read_ipv4_reply(&mut client).await;
        assert_eq!(reply[1], 0x08);
        assert!(proxy_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn rejects_destination_port_zero() {
        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        negotiate_client(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();

        let reply = read_ipv4_reply(&mut client).await;
        assert_eq!(reply[1], 0x08);
        assert!(proxy_task.await.unwrap().is_err());
    }

    async fn read_reply(client: &mut TcpStream) -> (u8, u8) {
        let mut header = [0_u8; 4];
        client.read_exact(&mut header).await.unwrap();
        let tail_len = match header[3] {
            0x01 => 6,
            0x04 => 18,
            0x03 => {
                let mut length = [0_u8; 1];
                client.read_exact(&mut length).await.unwrap();
                let mut tail = vec![0_u8; length[0] as usize + 2];
                client.read_exact(&mut tail).await.unwrap();
                return (header[1], header[3]);
            }
            _ => panic!("unexpected SOCKS5 address type in reply: {}", header[3]),
        };
        let mut tail = vec![0_u8; tail_len];
        client.read_exact(&mut tail).await.unwrap();
        (header[1], header[3])
    }

    #[tokio::test]
    async fn connects_to_localhost_domain_and_relays_data() {
        let destination_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination_listener.local_addr().unwrap();
        let destination_task = tokio::spawn(async move {
            let (mut destination, _) = destination_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            destination.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            destination.write_all(b"pong").await.unwrap();
            destination.shutdown().await.unwrap();
        });

        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        negotiate_client(&mut client).await;

        let mut request = vec![SOCKS_VERSION, 0x01, 0x00, 0x03, 9];
        request.extend_from_slice(b"localhost");
        request.extend_from_slice(&destination_address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();

        assert_eq!(read_reply(&mut client).await.0, 0x00);
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        client.shutdown().await.unwrap();

        destination_task.await.unwrap();
        proxy_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connects_to_ipv6_and_relays_data_in_both_directions() {
        let destination_listener = TcpListener::bind("[::1]:0").await.unwrap();
        let destination_address = destination_listener.local_addr().unwrap();
        let destination_task = tokio::spawn(async move {
            let (mut destination, _) = destination_listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            destination.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            destination.write_all(b"pong").await.unwrap();
            destination.shutdown().await.unwrap();
        });

        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        negotiate_client(&mut client).await;

        let mut request = vec![SOCKS_VERSION, 0x01, 0x00, 0x04];
        let destination_ip = match destination_address.ip() {
            std::net::IpAddr::V6(ip) => ip,
            _ => panic!("IPv6 listener returned a non-IPv6 address"),
        };
        request.extend_from_slice(&destination_ip.octets());
        request.extend_from_slice(&destination_address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();

        let (reply_code, address_type) = read_reply(&mut client).await;
        assert_eq!(reply_code, 0x00);
        assert_eq!(address_type, 0x04);

        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        client.shutdown().await.unwrap();

        destination_task.await.unwrap();
        proxy_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn returns_failure_reply_when_destination_refuses_connection() {
        let destination_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination_listener.local_addr().unwrap();
        drop(destination_listener);

        let (proxy_address, proxy_task) = spawn_single_client_proxy(ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        negotiate_client(&mut client).await;

        let mut request = vec![SOCKS_VERSION, 0x01, 0x00, 0x01];
        let destination_ip = match destination_address.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => panic!("IPv4 listener returned a non-IPv4 address"),
        };
        request.extend_from_slice(&destination_ip.octets());
        request.extend_from_slice(&destination_address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();

        let reply = read_ipv4_reply(&mut client).await;
        assert_ne!(reply[1], 0x00);
        assert!(proxy_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn closes_clients_that_do_not_complete_handshake_in_time() {
        let mut config = ProxyConfig::default();
        config.handshake_timeout_secs = 1;
        let (proxy_address, proxy_task) = spawn_single_client_proxy(config).await;
        let _client = TcpStream::connect(proxy_address).await.unwrap();

        let result = timeout(Duration::from_secs(2), proxy_task)
            .await
            .expect("handshake timeout should close the session")
            .unwrap();
        assert!(result.is_err());
    }
}
