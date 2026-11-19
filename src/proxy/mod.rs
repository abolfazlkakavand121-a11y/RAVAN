mod http;
mod socks5;

use crate::config::{Config, ProxyConfig};
use anyhow::{Context, Result};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};

const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(2);

pub async fn run(address: SocketAddr, config: ProxyConfig) -> Result<()> {
    Config {
        proxy: config.clone(),
    }
    .validate()?;
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
    let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());

    println!("RAVAN SOCKS5 listening on {actual}");
    println!("TCP CONNECT only; no authentication on loopback; press Ctrl+C to stop.");

    loop {
        tokio::select! {
            signal = &mut ctrl_c => {
                signal.context("wait for Ctrl+C")?;
                println!(
                    "Stopping RAVAN SOCKS5; allowing active connections up to {} second(s) to finish...",
                    SHUTDOWN_GRACE_PERIOD.as_secs()
                );
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept SOCKS5 client")?;
                if let Some(permit) = acquire_connection_slot(&semaphore) {
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

    // Close the listening socket before draining active sessions.
    drop(listener);
    shutdown_tasks(&mut tasks, SHUTDOWN_GRACE_PERIOD).await;
    Ok(())
}

/// Run the loopback-only HTTP proxy listener.
pub async fn run_http(address: SocketAddr, config: ProxyConfig) -> Result<()> {
    Config {
        proxy: config.clone(),
    }
    .validate()?;
    anyhow::ensure!(
        address.ip().is_loopback(),
        "RAVAN refuses to listen on a non-loopback HTTP proxy address"
    );
    anyhow::ensure!(
        address.port() != 0,
        "port 0 is not supported for the HTTP proxy CLI listener"
    );
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("bind HTTP proxy listener at {address}"))?;
    let actual = listener.local_addr()?;
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks = JoinSet::new();
    let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());
    println!("RAVAN HTTP proxy listening on {actual}");
    println!("HTTP forwarding and HTTPS CONNECT; loopback only; press Ctrl+C to stop.");
    loop {
        tokio::select! {
            signal = &mut ctrl_c => {
                signal.context("wait for Ctrl+C")?;
                println!("Stopping RAVAN HTTP proxy; allowing active connections up to {} second(s) to finish...", SHUTDOWN_GRACE_PERIOD.as_secs());
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept HTTP proxy client")?;
                if let Some(permit) = acquire_connection_slot(&semaphore) {
                    let cfg = config.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = http::handle_client(stream, cfg).await {
                            tracing::debug!("HTTP proxy client session ended: {error:#}");
                        }
                    });
                } else {
                    tracing::warn!("HTTP proxy connection limit reached; rejecting client {peer}");
                    drop(stream);
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    drop(listener);
    shutdown_tasks(&mut tasks, SHUTDOWN_GRACE_PERIOD).await;
    Ok(())
}

fn acquire_connection_slot(semaphore: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    semaphore.clone().try_acquire_owned().ok()
}

async fn shutdown_tasks(tasks: &mut JoinSet<()>, grace_period: Duration) {
    let drained = timeout(grace_period, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_ok();

    if !drained {
        tracing::warn!(
            "graceful shutdown deadline reached; aborting {} remaining SOCKS5 session(s)",
            tasks.len()
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;
    use tokio::time::sleep;

    #[test]
    fn semaphore_enforces_connection_limit_and_releases_slots() {
        let semaphore = Arc::new(Semaphore::new(2));
        let first = acquire_connection_slot(&semaphore).expect("first slot");
        let second = acquire_connection_slot(&semaphore).expect("second slot");
        assert!(acquire_connection_slot(&semaphore).is_none());

        drop(first);
        assert!(acquire_connection_slot(&semaphore).is_some());
        drop(second);
    }

    #[tokio::test]
    async fn shutdown_waits_for_sessions_that_finish_within_grace_period() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async {
            sleep(Duration::from_millis(5)).await;
        });

        shutdown_tasks(&mut tasks, Duration::from_millis(100)).await;
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn shutdown_aborts_sessions_after_grace_period() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async {
            pending::<()>().await;
        });

        shutdown_tasks(&mut tasks, Duration::from_millis(10)).await;
        assert!(tasks.is_empty());
    }
}
