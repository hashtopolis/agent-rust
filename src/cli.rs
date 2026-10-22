use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::Parser;

use crate::config::{
    ByteSize, DEFAULT_SETTINGS_FILE, DEFAULT_STATE_FILE, LogFileConfig, Overrides,
};

// No `Debug`: `--proxy` may carry credentials.
#[derive(Parser)]
#[command(name = "htp-agent", version, about = "Hashtopolis agent (Rust)")]
pub struct Cli {
    /// User settings file (JSON). Read only; never written by the agent.
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

    /// Client certificate for mutual TLS: one PEM file with the certificate
    /// and its unencrypted private key.
    #[arg(long, alias = "cert")]
    pub client_cert: Option<PathBuf>,

    /// Proxy for all HTTP traffic, e.g. http://proxy:3128. Put proxy
    /// credentials in the config file or HTP_PROXY: a flag value shows in the
    /// process list.
    #[arg(long, env = "HTP_PROXY", hide_env_values = true)]
    pub proxy: Option<String>,

    /// HTTP basic auth user for the server. The password is read only from
    /// the HTP_AUTH_PASSWORD environment variable, never from a flag, so it
    /// stays out of the process list.
    #[arg(long, env = "HTP_AUTH_USER")]
    pub auth_user: Option<String>,

    /// Register as CPU-only and skip accelerator inventory.
    #[arg(long)]
    pub cpu_only: bool,

    /// Never ask the server for a newer agent build.
    #[arg(long)]
    pub disable_update: bool,

    /// Local hashcat binary or install directory. Used only on macOS, as a
    /// fallback when the cracker archive contains no `hashcat.osx`.
    #[arg(long, env = "HTP_HASHCAT_PATH")]
    pub hashcat_path: Option<PathBuf>,

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

    /// Enable trace logging, including full request/response bodies.
    #[arg(long)]
    pub trace: bool,

    /// Also write the log to this file, rotated and gzip-compressed by size.
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Rotate the log file before it grows past this size, e.g. 500KB, 10MB
    /// (the default) or 1GB.
    #[arg(long)]
    pub log_max_size: Option<ByteSize>,

    /// How many rotated log files to keep (default 5).
    #[arg(long)]
    pub log_max_files: Option<NonZeroUsize>,
}

impl Cli {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }

    /// The log file as the flags alone describe it, for reporting why the
    /// config file could not be loaded.
    pub fn log_file_from_flags(&self) -> Option<LogFileConfig> {
        let mut log = LogFileConfig::new(self.log_file.clone()?);

        if let Some(max_size) = self.log_max_size {
            log.max_size = max_size;
        }

        if let Some(max_files) = self.log_max_files {
            log.max_files = max_files;
        }

        Some(log)
    }

    pub fn overrides(&self) -> Overrides {
        Overrides {
            url: self.url.clone(),
            voucher: self.voucher.clone(),
            client_cert: self.client_cert.clone(),
            proxy: self.proxy.clone(),
            auth_user: self.auth_user.clone(),
            auth_password: std::env::var("HTP_AUTH_PASSWORD")
                .ok()
                .filter(|password| !password.is_empty()),
            cpu_only: self.cpu_only,
            disable_update: self.disable_update,
            files_path: self.files_path.clone(),
            crackers_path: self.crackers_path.clone(),
            hashlists_path: self.hashlists_path.clone(),
            preprocessors_path: self.preprocessors_path.clone(),
            zaps_path: self.zaps_path.clone(),
            hashcat_path: self.hashcat_path.clone(),
            log_file: self.log_file.clone(),
            log_max_size: self.log_max_size,
            log_max_files: self.log_max_files,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_file_flags_alone_describe_a_log_file() {
        let cli = Cli::try_parse_from([
            "htp-agent",
            "--log-file",
            "agent.log",
            "--log-max-files",
            "2",
        ])
        .unwrap();

        let log = cli.log_file_from_flags().unwrap();

        assert_eq!(log.file, PathBuf::from("agent.log"));
        assert_eq!(log.max_files.get(), 2);
        assert_eq!(log.max_size.bytes(), 10_485_760);
    }

    #[test]
    fn without_a_log_file_flag_there_is_no_log_file() {
        let cli = Cli::try_parse_from(["htp-agent", "--log-max-size", "1MB"]).unwrap();

        assert_eq!(cli.log_file_from_flags(), None);
    }
}
