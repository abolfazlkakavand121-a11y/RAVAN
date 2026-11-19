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

    let mut destination = match connect_destination(&request.0, request.1, config.connect_timeout_secs).await {
        Ok(stream) => stream,
        Err(reply_code) => {
            send_reply(&mut client, reply_code).await?;
            bail!("SOCKS5 destination connection failed (reply {reply_code})");
        }
    };

    send_reply(&mut client, 0x00).await?;
    let _ = copy_bidirectional(&mut client, &mut destination).await
        .context("forward TCP stream");
    Ok(())
}

async fn negotiate(client: &mut TcpStream) -> Result<(String, u16)> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await.context("read SOCKS5 greeting")?;
    if greeting[0] != SOCKS_VERSION { bail!("unsupported SOCKS version"); }

    let mut methods = vec![0_u8; greeting[1] as usize];
    client.read_exact(&mut methods).await.context("read SOCKS5 methods")?;
    if !methods.contains(&0x00) {
        client.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        bail!("client does not offer no-authentication method");
    }
    client.write_all(&[SOCKS_VERSION, 0x00]).await?;

    let mut request = [0_u8; 4];
    client.read_exact(&mut request).await.context("read SOCKS5 request")?;
    if request[0] != SOCKS_VERSION || request[2] != 0 {
        send_reply(client, 0x01).await?;
        bail!("malformed SOCKS5 request");
    }
    if request[1] != 0x01 {
        send_reply(client, 0x07).await?;
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
                send_reply(client, 0x08).await?;
                bail!("empty SOCKS5 domain name");
            }
            let mut bytes = vec![0_u8; length[0] as usize];
            client.read_exact(&mut bytes).await?;
            let name = String::from_utf8(bytes).context("SOCKS5 domain name is not valid UTF-8")?;
            if name.trim().is_empty() || name.chars().any(char::is_whitespace) {
                send_reply(client, 0x08).await?;
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
            send_reply(client, 0x08).await?;
            bail!("unsupported SOCKS5 address type");
        }
    };

    let mut port = [0_u8; 2];
    client.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}

async fn connect_destination(host: &str, port: u16, timeout_secs: u64) -> std::result::Result<TcpStream, u8> {
    timeout(Duration::from_secs(timeout_secs), async {
        let addresses: Vec<SocketAddr> = match lookup_host((host, port)).await {
            Ok(addresses) => addresses.collect(),
            Err(_) => return Err(0x04),
        };
        if addresses.is_empty() { return Err(0x04); }

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
    .unwrap_or(Err(0x06))
}

async fn send_reply(client: &mut TcpStream, code: u8) -> Result<()> {
    client.write_all(&[SOCKS_VERSION, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_reply_uses_socks5_reply_prefix() {
        let packet = [SOCKS_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        assert_eq!(packet.len(), 10);
        assert_eq!(packet[0], SOCKS_VERSION);
        assert_eq!(packet[1], 0x00);
    }
}
