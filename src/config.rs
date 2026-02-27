use std::path::PathBuf;

use anyhow::Context;

/// Daemon startup configuration (name, port, paths, identity).
#[derive(Clone, Debug)]
pub struct OuijaConfig {
    pub name: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    /// Nostr public key used as the daemon's universal identity.
    pub npub: String,
}

impl OuijaConfig {
    /// Return the platform-default config directory.
    pub fn default_config_dir() -> PathBuf {
        dirs_config_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    /// Return the platform-default data directory.
    pub fn default_data_dir() -> PathBuf {
        dirs_data_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    /// Build a config from CLI args, creating directories as needed.
    pub fn new(
        name: String,
        port: u16,
        data_dir: Option<String>,
        npub: String,
    ) -> anyhow::Result<Self> {
        // When --data is given, co-locate config there (e.g. tests).
        // Otherwise use XDG dirs.
        let (data_dir, config_dir) = match data_dir {
            Some(ref d) => {
                let p = PathBuf::from(d);
                (p.clone(), p)
            }
            None => (dirs_data_dir()?, dirs_config_dir()?),
        };
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("creating data dir: {}", data_dir.display()))?;
        std::fs::create_dir_all(&config_dir)
            .with_context(|| format!("creating config dir: {}", config_dir.display()))?;
        Ok(Self {
            name,
            port,
            data_dir,
            config_dir,
            npub,
        })
    }
}

fn xdg_dir(env_var: &str, fallback_suffix: &str) -> anyhow::Result<PathBuf> {
    let base = std::env::var(env_var)
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(fallback_suffix)
        });
    Ok(base.join("ouija"))
}

fn dirs_data_dir() -> anyhow::Result<PathBuf> {
    xdg_dir("XDG_DATA_HOME", ".local/share")
}

fn dirs_config_dir() -> anyhow::Result<PathBuf> {
    xdg_dir("XDG_CONFIG_HOME", ".config")
}
