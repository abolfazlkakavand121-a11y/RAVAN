use clap::{Args, Parser, Subcommand};
use std::net::SocketAddr;

#[derive(Debug, Parser)]
#[command(
    name = "ravan",
    version,
    about = "Local network diagnostics and SOCKS5 proxy"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Check local runtime and configuration without making internet requests.
    Doctor,
    /// Run the local SOCKS5 TCP proxy in the foreground.
    Proxy(ProxyArgs),
    /// Run a staged DNS, TCP, TLS, and HTTP protocol analysis.
    Analyze {
        url: String,
        #[arg(long)]
        json: bool,
        /// Select address family: both, ipv4, or ipv6.
        #[arg(long, value_parser = ["both", "ipv4", "ipv6"], default_value = "both")]
        ip_family: String,
    },
    /// Run an explicit network diagnostic.
    Diag(DiagArgs),
    /// Manage the local RAVAN configuration.
    Config(ConfigArgs),
}

#[derive(Debug, Args)]
pub struct ProxyArgs {
    /// Loopback listener address. Defaults to config or 127.0.0.1:2080.
    #[arg(long)]
    pub listen: Option<SocketAddr>,
}

#[derive(Debug, Args)]
pub struct DiagArgs {
    #[command(subcommand)]
    pub command: DiagnosticCommands,
}

#[derive(Debug, Subcommand)]
pub enum DiagnosticCommands {
    /// Resolve a hostname using the device's system resolver.
    Dns {
        host: String,
        /// Print a machine-readable JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Test a TCP connection; target must be host:port (bracket IPv6 literals).
    Tcp {
        target: String,
        #[arg(long)]
        json: bool,
    },
    /// Test TLS with normal certificate-chain and hostname verification.
    Tls {
        target: String,
        #[arg(long)]
        json: bool,
    },
    /// Send an HTTP HEAD request to an http:// or https:// URL.
    Http {
        url: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    /// Create a default configuration without overwriting an existing file.
    Init,
    /// Show effective local settings.
    Show,
}
