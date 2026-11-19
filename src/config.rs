use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub proxy: ProxyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub http_listen_addr: String,
    pub handshake_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub max_connections: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:2080".to_owned(),
            http_listen_addr: "127.0.0.1:1820".to_owned(),
            handshake_timeout_secs: 5,
            connect_timeout_secs: 10,
            max_connections: 128,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let input = fs::read_to_string(&path)
            .with_context(|| format!("read configuration at {}", path.display()))?;
        let config: Self = toml::from_str(&input)
            .with_context(|| format!("parse configuration at {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let address: std::net::SocketAddr = self
            .proxy
            .listen_addr
            .parse()
            .context("proxy.listen_addr must be a valid socket address")?;
        anyhow::ensure!(
            address.ip().is_loopback(),
            "proxy.listen_addr must be a loopback address"
        );
        anyhow::ensure!(
            address.port() != 0,
            "proxy.listen_addr must use a non-zero port"
        );
        let http_address: std::net::SocketAddr = self.proxy.http_listen_addr.parse().context("proxy.http_listen_addr must be a valid socket address")?;
        anyhow::ensure!(http_address.ip().is_loopback(), "proxy.http_listen_addr must be a loopback address");
        anyhow::ensure!(http_address.port() != 0, "proxy.http_listen_addr must use a non-zero port");
        anyhow::ensure!(
            (1..=30).contains(&self.proxy.handshake_timeout_secs),
            "handshake_timeout_secs must be between 1 and 30"
        );
        anyhow::ensure!(
            (1..=60).contains(&self.proxy.connect_timeout_secs),
            "connect_timeout_secs must be between 1 and 60"
        );
        anyhow::ensure!(
            (1..=1024).contains(&self.proxy.max_connections),
            "max_connections must be between 1 and 1024"
        );
        Ok(())
    }
}

pub fn config_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path).join("ravan").join("config.toml"));
    }
    let home = env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("ravan")
        .join("config.toml"))
}

pub fn initialize() -> Result<()> {
    let config = Config::default();
    config.validate()?;
    let path = config_path()?;
    let parent = path.parent().context("configuration path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let content = toml::to_string_pretty(&config)?;
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            println!(
                "Configuration already exists; left unchanged: {}",
                path.display()
            );
            return Ok(());
        }
        Err(error) => return Err(error).with_context(|| format!("create {}", path.display())),
    };
    file.write_all(content.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    println!("Created configuration: {}", path.display());
    Ok(())
}

pub fn show() -> Result<()> {
    let config = Config::load()?;
    println!("{}", toml::to_string_pretty(&config)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_loopback_and_bounded() {
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.proxy.listen_addr, "127.0.0.1:2080");
        assert_eq!(config.proxy.http_listen_addr, "127.0.0.1:1820");
    }

    #[test]
    fn public_listener_is_rejected() {
        let mut config = Config::default();
        config.proxy.listen_addr = "0.0.0.0:2080".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn public_http_listener_is_rejected() {
        let mut config = Config::default();
        config.proxy.http_listen_addr = "0.0.0.0:1820".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_port_is_rejected() {
        let mut config = Config::default();
        config.proxy.listen_addr = "127.0.0.1:0".to_owned();
        assert!(config.validate().is_err());
    }
}
