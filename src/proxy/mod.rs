mod socks5;

use crate::config::ProxyConfig;
use anyhow::{Context, Result};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};

pub async fn run(address: SocketAddr, config: ProxyConfig) -> Result<()> {
    anyhow::ensure!(
        address.ip().is_loopback(),
        "RAVAN refuses to listen on a non-loopback address"
    );
    anyhow::ensure!(
        address.port() != 0,
        "port 0 is not supported for the CLI listener"
    );
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("bind SOCKS5 listener at {address}"))?;
    let actual = listener.local_addr()?;
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();

    println!("RAVAN SOCKS5 listening on {actual}");
    println!("TCP CONNECT only; no authentication on loopback; press Ctrl+C to stop.");

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("wait for Ctrl+C")?;
                println!("Stopping RAVAN SOCKS5...");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept SOCKS5 client")?;
                let permit: Option<OwnedSemaphorePermit> = semaphore.clone().try_acquire_owned().ok();
                if let Some(permit) = permit {
                    let cfg = config.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = socks5::handle_client(stream, cfg).await {
                            tracing::debug!("SOCKS5 client session ended: {error:#}");
                        }
                    });
                } else {
                    tracing::warn!("SOCKS5 connection limit reached; rejecting client {peer}");
                    drop(stream);
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
