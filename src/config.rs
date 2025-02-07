use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    /// Debug model
    pub debug: bool,

    /// Server bind address
    pub bind: SocketAddr,

    /// Forward timeout (seconds)
    pub timeout: u64,

    /// Forward connect timeout (seconds)
    pub connect_timeout: u64,

    /// Forward TCP keepalive (seconds)
    pub tcp_keepalive: Option<u64>,

    /// TLS certificate file path
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file path (EC/PKCS8/RSA)
    pub tls_key: Option<PathBuf>,

    /// Authentication Key
    pub api_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            debug: false,
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080),
            timeout: 60,
            connect_timeout: 10,
            tcp_keepalive: Some(90),
            tls_cert: Default::default(),
            tls_key: Default::default(),
            api_key: Default::default(),
        }
    }
}

pub fn generate_template(path: PathBuf) -> crate::Result<()> {
    let yaml_config = serde_yaml::to_string(&Config::default())?;
    std::fs::write(path, yaml_config).map_err(Into::into)
}
