mod cli;
mod config;
mod diagnostics;
mod proxy;
mod report;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands, ConfigCommands, DiagnosticCommands};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    // Select the compiled TLS provider for rustls 0.23.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor => {
            let path = config::config_path()?;
            let cfg = config::Config::load()?;
            println!("RAVAN {} — local diagnostics", env!("CARGO_PKG_VERSION"));
            println!(
                "Platform: {} / {}",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            println!("Configuration: {}", path.display());
            println!(
                "Configuration status: {}",
                if path.exists() {
                    "loaded from file and validated"
                } else {
                    "file not found; using safe defaults"
                }
            );
            println!("SOCKS5 listen address: {}", cfg.proxy.listen_addr);
            println!(
                "SOCKS5 handshake timeout: {} seconds",
                cfg.proxy.handshake_timeout_secs
            );
            println!(
                "Outbound connect timeout: {} seconds",
                cfg.proxy.connect_timeout_secs
            );
            println!(
                "Maximum concurrent connections: {}",
                cfg.proxy.max_connections
            );
            println!("Network tests: not run; use an explicit diagnostic command.");
        }
        Commands::Proxy(args) => {
            let cfg = config::Config::load().context("load RAVAN configuration")?;
            let address = match args.listen {
                Some(value) => value,
                None => cfg
                    .proxy
                    .listen_addr
                    .parse()
                    .context("invalid proxy.listen_addr in config")?,
            };
            proxy::run(address, cfg.proxy).await?;
        }
        Commands::Analyze {
            url,
            json,
            ip_family,
        } => {
            let parsed = url::Url::parse(&url).context("invalid analysis URL")?;
            let result = if ip_family == "both" {
                diagnostics::analyzer::run(parsed).await
            } else {
                diagnostics::analyzer::run_with_family(parsed, &ip_family).await
            };
            report::emit_analysis(&result, json);
            if !result.success {
                anyhow::bail!("protocol analysis did not complete successfully");
            }
        }
        Commands::Diag(args) => match args.command {
            DiagnosticCommands::Dns { host, json } => {
                let result = diagnostics::dns::run(&host).await;
                report::emit(&result, json);
                if !result.success {
                    anyhow::bail!("DNS diagnostic failed");
                }
            }
            DiagnosticCommands::Tcp { target, json } => {
                let result = diagnostics::tcp::run(&target).await;
                report::emit(&result, json);
                if !result.success {
                    anyhow::bail!("TCP diagnostic failed");
                }
            }
            DiagnosticCommands::Tls { target, json } => {
                let result = diagnostics::tls::run(&target).await;
                report::emit(&result, json);
                if !result.success {
                    anyhow::bail!("TLS diagnostic failed");
                }
            }
            DiagnosticCommands::Http { url, json } => {
                let parsed = url::Url::parse(&url).context("invalid URL")?;
                let result = diagnostics::http::run(parsed).await;
                report::emit(&result, json);
                if !result.success {
                    anyhow::bail!("HTTP diagnostic failed");
                }
            }
        },
        Commands::Config(args) => match args.command {
            ConfigCommands::Init => config::initialize()?,
            ConfigCommands::Show => config::show()?,
        },
    }
    Ok(())
}
