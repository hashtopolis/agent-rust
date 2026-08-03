use std::path::PathBuf;

use clap::Parser;

use crate::config::{DEFAULT_SETTINGS_FILE, DEFAULT_STATE_FILE, Overrides};

#[derive(Debug, Parser)]
#[command(name = "htp-agent", version, about = "Hashtopolis agent (Rust)")]
pub struct Cli {
    /// User settings file (TOML). Read only; never written by the agent.
    #[arg(long, env = "HTP_CONFIG", default_value = DEFAULT_SETTINGS_FILE)]
    pub config: PathBuf,

    /// Agent state file (JSON) holding the token and uuid.
    #[arg(long, env = "HTP_STATE", default_value = DEFAULT_STATE_FILE)]
    pub state: PathBuf,

    /// Server API URL, e.g. https://example.com/api/server.php.
    #[arg(long, env = "HTP_URL")]
    pub url: Option<String>,

    /// Voucher used to register when no token exists yet.
    #[arg(long, env = "HTP_VOUCHER")]
    pub voucher: Option<String>,

    /// Client certificate presented to the server.
    #[arg(long)]
    pub cert: Option<PathBuf>,

    /// Register as CPU-only and skip accelerator inventory.
    #[arg(long)]
    pub cpu_only: bool,

    /// Never ask the server for a newer agent build.
    #[arg(long)]
    pub disable_update: bool,

    #[arg(long)]
    pub files_path: Option<PathBuf>,
    #[arg(long)]
    pub crackers_path: Option<PathBuf>,
    #[arg(long)]
    pub hashlists_path: Option<PathBuf>,
    #[arg(long)]
    pub preprocessors_path: Option<PathBuf>,
    #[arg(long)]
    pub zaps_path: Option<PathBuf>,

    /// Deregister this agent from the server, then exit.
    #[arg(long)]
    pub de_register: bool,

    /// Enable debug logging.
    #[arg(long, short)]
    pub debug: bool,
}

impl Cli {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }

    pub fn overrides(&self) -> Overrides {
        Overrides {
            url: self.url.clone(),
            voucher: self.voucher.clone(),
            cert: self.cert.clone(),
            cpu_only: self.cpu_only,
            disable_update: self.disable_update,
            files_path: self.files_path.clone(),
            crackers_path: self.crackers_path.clone(),
            hashlists_path: self.hashlists_path.clone(),
            preprocessors_path: self.preprocessors_path.clone(),
            zaps_path: self.zaps_path.clone(),
        }
    }
}
