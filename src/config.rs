//! Configuration split over two files with different owners: `config.json` is
//! user-owned and read once at startup, while `state.json` is agent-owned and
//! rewritten when the token or uuid change.

use std::fmt;
use std::fs;
use std::io;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_SETTINGS_FILE: &str = "config.json";
pub const DEFAULT_STATE_FILE: &str = "state.json";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write {}: {source}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create directory {}: {source}", path.display())]
    CreateDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid JSON in {}: {source}", path.display())]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("no server url configured: set server.url in {} or pass --url", path.display())]
    MissingUrl { path: PathBuf },
    #[error(
        "no token and no voucher to register with: set server.voucher in {} or pass --voucher",
        path.display()
    )]
    MissingVoucher { path: PathBuf },
    #[error(
        "--log-max-size and --log-max-files need a log file: set log.file in {} or pass --log-file",
        path.display()
    )]
    LogOptionsWithoutFile { path: PathBuf },
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub url: Option<String>,
    pub voucher: Option<String>,
    /// Client certificate and key (one PEM file) for servers that require
    /// mutual TLS. Not a CA bundle. `cert` is the earlier name of this key.
    #[serde(alias = "cert")]
    pub client_cert: Option<PathBuf>,
    pub proxy: Option<String>,
    pub basic_auth: Option<BasicAuthConfig>,
}

/// Both halves are optional here because the password may come from the
/// environment instead of the file; `http::HttpSettings` insists on both.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BasicAuthConfig {
    pub user: Option<String>,
    pub password: Option<String>,
}

// The proxy url may carry credentials, so these two only say whether a
// secret is set.
impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("url", &self.url)
            .field("voucher", &self.voucher)
            .field("client_cert", &self.client_cert)
            .field("proxy", &redacted(&self.proxy))
            .field("basic_auth", &self.basic_auth)
            .finish()
    }
}

impl fmt::Debug for BasicAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicAuthConfig")
            .field("user", &self.user)
            .field("password", &redacted(&self.password))
            .finish()
    }
}

fn redacted(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<redacted>")
}

#[cfg(test)]
impl BasicAuthConfig {
    pub(crate) fn new(user: &str, password: &str) -> Self {
        Self {
            user: Some(user.to_string()),
            password: Some(password.to_string()),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentInfo {
    pub name: Option<String>,
    pub devices: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Paths {
    pub files: PathBuf,
    pub crackers: PathBuf,
    pub hashlists: PathBuf,
    pub preprocessors: PathBuf,
    pub zaps: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            files: PathBuf::from("files"),
            crackers: PathBuf::from("crackers"),
            hashlists: PathBuf::from("hashlists"),
            preprocessors: PathBuf::from("preprocessors"),
            zaps: PathBuf::from("zaps"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Behavior {
    pub cpu_only: bool,
    pub disable_update: bool,
    pub allow_piping: bool,
    pub piping_threshold: u8,
    pub outfile_history: bool,
    pub rsync: bool,
    pub rsync_path: Option<PathBuf>,
    pub multicast_device: String,
    pub file_deletion_disable: bool,
    pub file_deletion_interval: u64,
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            cpu_only: false,
            disable_update: false,
            allow_piping: false,
            piping_threshold: 95,
            outfile_history: false,
            rsync: false,
            rsync_path: None,
            multicast_device: "eth0".to_string(),
            file_deletion_disable: false,
            file_deletion_interval: 600,
        }
    }
}

impl Behavior {
    pub fn file_deletion_interval(&self) -> Duration {
        Duration::from_secs(self.file_deletion_interval)
    }
}

/// Local cracker overrides. Currently a single fallback used only on macOS,
/// where the official hashcat archive ships no `hashcat.osx`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CrackerConfig {
    /// A local hashcat binary or install directory. On macOS, when the cracker
    /// archive contains no `hashcat.osx`, the agent falls back to this.
    pub hashcat_path: Option<PathBuf>,
}

/// Writing the log to a file as well as the console. Once the file would grow
/// past `max_size` it is rotated, keeping `max_files` old ones.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogFileConfig {
    pub file: PathBuf,
    #[serde(default = "LogFileConfig::default_max_size")]
    pub max_size: ByteSize,
    #[serde(default = "LogFileConfig::default_max_files")]
    pub max_files: NonZeroUsize,
}

impl LogFileConfig {
    /// `file` with the default size and count limits.
    pub fn new(file: PathBuf) -> Self {
        Self {
            file,
            max_size: Self::default_max_size(),
            max_files: Self::default_max_files(),
        }
    }

    fn default_max_size() -> ByteSize {
        ByteSize(NonZeroU64::new(10 << 20).expect("non-zero"))
    }

    fn default_max_files() -> NonZeroUsize {
        NonZeroUsize::new(5).expect("non-zero")
    }
}

/// A size in bytes, written as a plain byte count or with a binary unit:
/// `500KB`, `10MB`, `1GB`. Never zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ByteSizeRepr", into = "String")]
pub struct ByteSize(NonZeroU64);

impl ByteSize {
    const UNITS: [(&str, u64); 3] = [("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)];

    pub fn bytes(self) -> u64 {
        self.0.get()
    }
}

impl FromStr for ByteSize {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid =
            || format!("invalid size {text:?}: expected e.g. 10MB, 500KB, 1GB or a byte count");

        let trimmed = text.trim();
        let digits = trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len());
        let (number, unit) = trimmed.split_at(digits);
        let unit = unit.trim().to_ascii_uppercase();

        let multiplier = match unit.as_str() {
            "" | "B" => 1,
            unit => Self::UNITS
                .iter()
                .find(|(name, _)| *name == unit)
                .map(|(_, multiplier)| *multiplier)
                .ok_or_else(invalid)?,
        };

        number
            .parse::<u64>()
            .ok()
            .and_then(|number| number.checked_mul(multiplier))
            .and_then(NonZeroU64::new)
            .map(Self)
            .ok_or_else(invalid)
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.bytes();

        match Self::UNITS
            .iter()
            .find(|(_, size)| bytes.is_multiple_of(*size))
        {
            Some((unit, size)) => write!(f, "{}{unit}", bytes / size),
            None => write!(f, "{bytes}"),
        }
    }
}

/// The config file may give a size as text (`"10MB"`) or as a byte count.
#[derive(Deserialize)]
#[serde(untagged)]
enum ByteSizeRepr {
    Bytes(u64),
    Text(String),
}

impl TryFrom<ByteSizeRepr> for ByteSize {
    type Error = String;

    fn try_from(repr: ByteSizeRepr) -> Result<Self, Self::Error> {
        match repr {
            ByteSizeRepr::Bytes(bytes) => NonZeroU64::new(bytes)
                .map(Self)
                .ok_or_else(|| "size must be greater than zero".to_string()),
            ByteSizeRepr::Text(text) => text.parse(),
        }
    }
}

impl From<ByteSize> for String {
    fn from(size: ByteSize) -> Self {
        size.to_string()
    }
}

/// User-owned; never written by the agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub server: Server,
    pub agent: AgentInfo,
    pub paths: Paths,
    pub behavior: Behavior,
    pub cracker: CrackerConfig,
    pub log: Option<LogFileConfig>,
}

/// Agent-owned; what the agent must remember across restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct State {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
}

/// Never written back; applied once at load so a flag wins over the file.
/// No `Debug`: it carries the basic auth password and possibly proxy
/// credentials.
#[derive(Clone, Default)]
pub struct Overrides {
    pub url: Option<String>,
    pub voucher: Option<String>,
    pub client_cert: Option<PathBuf>,
    pub proxy: Option<String>,
    pub auth_user: Option<String>,
    pub auth_password: Option<String>,
    pub cpu_only: bool,
    pub disable_update: bool,
    pub files_path: Option<PathBuf>,
    pub crackers_path: Option<PathBuf>,
    pub hashlists_path: Option<PathBuf>,
    pub preprocessors_path: Option<PathBuf>,
    pub zaps_path: Option<PathBuf>,
    pub hashcat_path: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub log_max_size: Option<ByteSize>,
    pub log_max_files: Option<NonZeroUsize>,
}

impl Overrides {
    fn apply(self, settings: &mut Settings, settings_path: &Path) -> Result<(), ConfigError> {
        if self.hashcat_path.is_some() {
            settings.cracker.hashcat_path = self.hashcat_path;
        }

        for (target, override_value) in [
            (&mut settings.server.url, self.url),
            (&mut settings.server.voucher, self.voucher),
            (&mut settings.server.proxy, self.proxy),
        ] {
            if override_value.is_some() {
                *target = override_value;
            }
        }

        if self.auth_user.is_some() || self.auth_password.is_some() {
            let auth = settings
                .server
                .basic_auth
                .get_or_insert_with(BasicAuthConfig::default);

            for (target, override_value) in [
                (&mut auth.user, self.auth_user),
                (&mut auth.password, self.auth_password),
            ] {
                if override_value.is_some() {
                    *target = override_value;
                }
            }
        }

        if self.client_cert.is_some() {
            settings.server.client_cert = self.client_cert;
        }

        if self.cpu_only {
            settings.behavior.cpu_only = true;
        }

        if self.disable_update {
            settings.behavior.disable_update = true;
        }

        for (target, override_value) in [
            (&mut settings.paths.files, self.files_path),
            (&mut settings.paths.crackers, self.crackers_path),
            (&mut settings.paths.hashlists, self.hashlists_path),
            (&mut settings.paths.preprocessors, self.preprocessors_path),
            (&mut settings.paths.zaps, self.zaps_path),
        ] {
            if let Some(path) = override_value {
                *target = path;
            }
        }

        if let Some(file) = self.log_file {
            match &mut settings.log {
                Some(log) => log.file = file,
                None => settings.log = Some(LogFileConfig::new(file)),
            }
        }

        if self.log_max_size.is_some() || self.log_max_files.is_some() {
            let log = settings
                .log
                .as_mut()
                .ok_or_else(|| ConfigError::LogOptionsWithoutFile {
                    path: settings_path.to_path_buf(),
                })?;

            if let Some(max_size) = self.log_max_size {
                log.max_size = max_size;
            }

            if let Some(max_files) = self.log_max_files {
                log.max_files = max_files;
            }
        }

        Ok(())
    }
}

/// The only writer of `state.json`.
#[derive(Debug, Clone)]
pub struct Config {
    settings_path: PathBuf,
    state_path: PathBuf,
    settings: Settings,
    state: State,
}

impl Config {
    /// A missing settings file yields defaults; a missing state file means this
    /// agent has not registered yet.
    pub fn load(
        settings_path: impl Into<PathBuf>,
        state_path: impl Into<PathBuf>,
        overrides: Overrides,
    ) -> Result<Self, ConfigError> {
        let settings_path = settings_path.into();
        let state_path = state_path.into();

        let mut settings = read_settings(&settings_path)?;
        overrides.apply(&mut settings, &settings_path)?;

        let state = read_state(&state_path)?;

        Ok(Self {
            settings_path,
            state_path,
            settings,
            state,
        })
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn settings_path(&self) -> &Path {
        &self.settings_path
    }

    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub fn token(&self) -> Option<&str> {
        self.state.token.as_deref()
    }

    pub fn set_token(&mut self, token: impl Into<String>) -> Result<(), ConfigError> {
        self.state.token = Some(token.into());
        self.save_state()
    }

    /// Generates and persists a uuid on first use.
    pub fn uuid_or_create(&mut self) -> Result<&str, ConfigError> {
        if self.state.uuid.is_none() {
            self.state.uuid = Some(Uuid::new_v4().to_string());
            self.save_state()?;
        }

        Ok(self
            .state
            .uuid
            .as_deref()
            .expect("uuid was just set if it was missing"))
    }

    pub fn require_url(&self) -> Result<&str, ConfigError> {
        self.settings
            .server
            .url
            .as_deref()
            .filter(|url| !url.is_empty())
            .ok_or_else(|| ConfigError::MissingUrl {
                path: self.settings_path.clone(),
            })
    }

    pub fn require_voucher(&self) -> Result<&str, ConfigError> {
        self.settings
            .server
            .voucher
            .as_deref()
            .filter(|voucher| !voucher.is_empty())
            .ok_or_else(|| ConfigError::MissingVoucher {
                path: self.settings_path.clone(),
            })
    }

    pub fn remove_state_file(&self) -> Result<(), ConfigError> {
        match fs::remove_file(&self.state_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(ConfigError::Write {
                path: self.state_path.clone(),
                source,
            }),
        }
    }

    /// Writes via a temp file and rename so a crash midway cannot leave a
    /// truncated token behind.
    fn save_state(&self) -> Result<(), ConfigError> {
        let json =
            serde_json::to_string_pretty(&self.state).map_err(|source| ConfigError::Json {
                path: self.state_path.clone(),
                source,
            })?;

        let temp_path = temp_path_for(&self.state_path);
        fs::write(&temp_path, json).map_err(|source| ConfigError::Write {
            path: temp_path.clone(),
            source,
        })?;

        fs::rename(&temp_path, &self.state_path).map_err(|source| ConfigError::Write {
            path: self.state_path.clone(),
            source,
        })
    }
}

fn read_settings(path: &Path) -> Result<Settings, ConfigError> {
    let Some(contents) = read_optional(path)? else {
        return Ok(Settings::default());
    };
    serde_json::from_str(&contents).map_err(|source| ConfigError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn read_state(path: &Path) -> Result<State, ConfigError> {
    let Some(contents) = read_optional(path)? else {
        return Ok(State::default());
    };
    serde_json::from_str(&contents).map_err(|source| ConfigError::Json {
        path: path.to_path_buf(),
        source,
    })
}

fn read_optional(path: &Path) -> Result<Option<String>, ConfigError> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ConfigError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        settings_path: PathBuf,
        state_path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let settings_path = dir.path().join(DEFAULT_SETTINGS_FILE);
            let state_path = dir.path().join(DEFAULT_STATE_FILE);

            Self {
                _dir: dir,
                settings_path,
                state_path,
            }
        }

        fn write_settings(&self, contents: &str) {
            fs::write(&self.settings_path, contents).unwrap();
        }

        fn read_state(&self) -> String {
            fs::read_to_string(&self.state_path).unwrap()
        }

        fn load(&self, overrides: Overrides) -> Result<Config, ConfigError> {
            Config::load(&self.settings_path, &self.state_path, overrides)
        }
    }

    #[test]
    fn missing_files_yield_defaults() {
        let fixture = Fixture::new();

        let config = fixture.load(Overrides::default()).unwrap();

        assert_eq!(config.settings(), &Settings::default());
        assert_eq!(config.token(), None);
        assert!(!fixture.state_path.exists());
    }

    #[test]
    fn settings_round_trip_through_json() {
        let settings = Settings {
            server: Server {
                url: Some("https://example.com/api/server.php".to_string()),
                voucher: Some("89GD78tf".to_string()),
                client_cert: Some(PathBuf::from("/etc/htp/client.pem")),
                proxy: Some("http://proxy:3128".to_string()),
                basic_auth: Some(BasicAuthConfig::new("agent", "secret")),
            },
            agent: AgentInfo {
                name: Some("cruncher".to_string()),
                devices: Some(vec!["ATI HD7970".to_string()]),
            },
            paths: Paths {
                files: PathBuf::from("/data/files"),
                ..Paths::default()
            },
            behavior: Behavior {
                allow_piping: true,
                piping_threshold: 80,
                ..Behavior::default()
            },
            cracker: CrackerConfig {
                hashcat_path: Some(PathBuf::from("/opt/homebrew/bin/hashcat")),
            },
            log: Some(LogFileConfig {
                file: PathBuf::from("/var/log/htp-agent.log"),
                max_size: "500KB".parse().unwrap(),
                max_files: NonZeroUsize::new(3).unwrap(),
            }),
        };

        let encoded = serde_json::to_string_pretty(&settings).unwrap();
        let decoded: Settings = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, settings);
    }

    #[test]
    fn partial_settings_file_keeps_defaults_for_the_rest() {
        let fixture = Fixture::new();
        fixture.write_settings(r#"{ "server": { "url": "https://example.com/api/server.php" } }"#);

        let config = fixture.load(Overrides::default()).unwrap();

        assert_eq!(
            config.require_url().unwrap(),
            "https://example.com/api/server.php"
        );
        assert_eq!(config.settings().paths, Paths::default());
        assert_eq!(config.settings().behavior.piping_threshold, 95);
        assert_eq!(
            config.settings().behavior.file_deletion_interval(),
            Duration::from_secs(600)
        );
    }

    #[test]
    fn unknown_settings_key_is_rejected() {
        let fixture = Fixture::new();
        fixture.write_settings(r#"{ "server": { "urls": "typo" } }"#);

        let error = fixture.load(Overrides::default()).unwrap_err();

        assert!(
            matches!(error, ConfigError::Json { .. }),
            "expected a JSON error, got {error:?}"
        );
    }

    #[test]
    fn overrides_win_over_the_file() {
        let fixture = Fixture::new();
        fixture.write_settings(
            r#"{
                "server": { "url": "https://from-file.example/api/server.php" },
                "behavior": { "cpu_only": false }
            }"#,
        );

        let config = fixture
            .load(Overrides {
                url: Some("https://from-cli.example/api/server.php".to_string()),
                cpu_only: true,
                files_path: Some(PathBuf::from("/scratch/files")),
                ..Overrides::default()
            })
            .unwrap();

        assert_eq!(
            config.require_url().unwrap(),
            "https://from-cli.example/api/server.php"
        );
        assert!(config.settings().behavior.cpu_only);
        assert_eq!(
            config.settings().paths.files,
            PathBuf::from("/scratch/files")
        );
    }

    #[test]
    fn set_token_persists_and_is_read_back() {
        let fixture = Fixture::new();
        let mut config = fixture.load(Overrides::default()).unwrap();

        config.set_token("GHhgdf(/&").unwrap();

        assert!(fixture.read_state().contains("GHhgdf(/&"));
        let reloaded = fixture.load(Overrides::default()).unwrap();
        assert_eq!(reloaded.token(), Some("GHhgdf(/&"));
    }

    #[test]
    fn uuid_is_generated_once_and_survives_a_restart() {
        let fixture = Fixture::new();
        let mut config = fixture.load(Overrides::default()).unwrap();

        let first = config.uuid_or_create().unwrap().to_string();
        let second = config.uuid_or_create().unwrap().to_string();
        assert_eq!(first, second);

        let mut reloaded = fixture.load(Overrides::default()).unwrap();
        assert_eq!(reloaded.uuid_or_create().unwrap(), first);
    }

    #[test]
    fn state_file_keeps_both_values_when_written_twice() {
        let fixture = Fixture::new();
        let mut config = fixture.load(Overrides::default()).unwrap();

        let uuid = config.uuid_or_create().unwrap().to_string();
        config.set_token("GHhgdf(/&").unwrap();

        let reloaded = fixture.load(Overrides::default()).unwrap();
        assert_eq!(reloaded.token(), Some("GHhgdf(/&"));
        assert_eq!(reloaded.state.uuid.as_deref(), Some(uuid.as_str()));
    }

    #[test]
    fn save_state_leaves_no_temporary_file_behind() {
        let fixture = Fixture::new();
        let mut config = fixture.load(Overrides::default()).unwrap();

        config.set_token("GHhgdf(/&").unwrap();

        assert!(!temp_path_for(&fixture.state_path).exists());
    }

    #[test]
    fn require_url_and_voucher_name_the_file_and_the_flag() {
        let fixture = Fixture::new();
        let config = fixture.load(Overrides::default()).unwrap();

        let url_error = config.require_url().unwrap_err().to_string();
        assert!(url_error.contains("server.url"), "{url_error}");
        assert!(url_error.contains("--url"), "{url_error}");
        assert!(url_error.contains(DEFAULT_SETTINGS_FILE), "{url_error}");

        let voucher_error = config.require_voucher().unwrap_err().to_string();
        assert!(voucher_error.contains("server.voucher"), "{voucher_error}");
        assert!(voucher_error.contains("--voucher"), "{voucher_error}");
    }

    #[test]
    fn empty_url_counts_as_missing() {
        let fixture = Fixture::new();
        fixture.write_settings(r#"{ "server": { "url": "" } }"#);

        let config = fixture.load(Overrides::default()).unwrap();

        assert!(matches!(
            config.require_url(),
            Err(ConfigError::MissingUrl { .. })
        ));
    }

    #[test]
    fn remove_state_file_is_idempotent() {
        let fixture = Fixture::new();
        let mut config = fixture.load(Overrides::default()).unwrap();
        config.set_token("GHhgdf(/&").unwrap();

        config.remove_state_file().unwrap();
        config.remove_state_file().unwrap();

        assert!(!fixture.state_path.exists());
    }

    #[test]
    fn connection_settings_are_read_from_the_server_section() {
        let fixture = Fixture::new();
        fixture.write_settings(
            r#"{
                "server": {
                    "client_cert": "/etc/htp/client.pem",
                    "proxy": "http://proxy:3128",
                    "basic_auth": { "user": "agent", "password": "secret" }
                }
            }"#,
        );

        let config = fixture.load(Overrides::default()).unwrap();

        let server = &config.settings().server;
        assert_eq!(
            server.client_cert.as_deref(),
            Some(Path::new("/etc/htp/client.pem"))
        );
        assert_eq!(server.proxy.as_deref(), Some("http://proxy:3128"));
        assert_eq!(
            server.basic_auth,
            Some(BasicAuthConfig::new("agent", "secret"))
        );
    }

    #[test]
    fn the_old_flat_connection_keys_are_rejected() {
        for old_key in [
            r#"{ "server": { "auth_user": "agent" } }"#,
            r#"{ "server": { "basic_auth": { "username": "agent" } } }"#,
        ] {
            let fixture = Fixture::new();
            fixture.write_settings(old_key);

            let error = fixture.load(Overrides::default()).unwrap_err();

            assert!(
                matches!(error, ConfigError::Json { .. }),
                "{old_key}: expected a JSON error, got {error:?}"
            );
        }
    }

    #[test]
    fn the_old_cert_key_still_names_the_client_certificate() {
        let fixture = Fixture::new();
        fixture.write_settings(r#"{ "server": { "cert": "/etc/htp/client.pem" } }"#);

        let config = fixture.load(Overrides::default()).unwrap();

        assert_eq!(
            config.settings().server.client_cert.as_deref(),
            Some(Path::new("/etc/htp/client.pem"))
        );
    }

    #[test]
    fn connection_overrides_win_over_the_file() {
        let fixture = Fixture::new();
        fixture.write_settings(
            r#"{
                "server": {
                    "client_cert": "/from/file.pem",
                    "proxy": "http://file-proxy:3128",
                    "basic_auth": { "user": "file-user", "password": "file-password" }
                }
            }"#,
        );

        let config = fixture
            .load(Overrides {
                client_cert: Some(PathBuf::from("/from/cli.pem")),
                proxy: Some("http://cli-proxy:3128".to_string()),
                auth_user: Some("cli-user".to_string()),
                auth_password: Some("env-password".to_string()),
                ..Overrides::default()
            })
            .unwrap();

        let server = &config.settings().server;
        assert_eq!(
            server.client_cert.as_deref(),
            Some(Path::new("/from/cli.pem"))
        );
        assert_eq!(server.proxy.as_deref(), Some("http://cli-proxy:3128"));
        assert_eq!(
            server.basic_auth,
            Some(BasicAuthConfig::new("cli-user", "env-password"))
        );
    }

    #[test]
    fn the_password_can_come_from_the_environment_alone() {
        let fixture = Fixture::new();
        fixture.write_settings(r#"{ "server": { "basic_auth": { "user": "agent" } } }"#);

        let config = fixture
            .load(Overrides {
                auth_password: Some("env-password".to_string()),
                ..Overrides::default()
            })
            .unwrap();

        assert_eq!(
            config.settings().server.basic_auth,
            Some(BasicAuthConfig::new("agent", "env-password"))
        );
    }

    #[test]
    fn no_auth_anywhere_leaves_basic_auth_unset() {
        let fixture = Fixture::new();

        let config = fixture.load(Overrides::default()).unwrap();

        assert_eq!(config.settings().server.basic_auth, None);
    }

    #[test]
    fn debug_output_hides_secrets() {
        let fixture = Fixture::new();
        fixture.write_settings(r#"{ "server": { "basic_auth": { "user": "agent" } } }"#);

        let config = fixture
            .load(Overrides {
                proxy: Some("http://puser:hunter2@proxy:3128".to_string()),
                auth_password: Some("secret".to_string()),
                ..Overrides::default()
            })
            .unwrap();

        let debug = format!("{config:?}");

        assert!(debug.contains("agent"), "{debug}");
        assert!(!debug.contains("secret"), "{debug}");
        assert!(!debug.contains("hunter2"), "{debug}");
    }

    #[test]
    fn byte_sizes_take_a_binary_unit_or_a_plain_byte_count() {
        for (text, bytes) in [
            ("4096", 4096),
            ("500KB", 512_000),
            ("10MB", 10_485_760),
            ("1GB", 1_073_741_824),
            ("10 mb", 10_485_760),
            ("2b", 2),
        ] {
            assert_eq!(text.parse::<ByteSize>().unwrap().bytes(), bytes, "{text}");
        }
    }

    #[test]
    fn byte_sizes_reject_zero_unknown_units_and_garbage() {
        for text in ["", "0", "0MB", "MB", "10XB", "-1", "1.5MB", "99999999999GB"] {
            assert!(
                text.parse::<ByteSize>().is_err(),
                "{text} should be rejected"
            );
        }
    }

    #[test]
    fn a_log_file_without_limits_rotates_at_10mb_and_keeps_5_files() {
        let fixture = Fixture::new();
        fixture.write_settings(r#"{ "log": { "file": "agent.log" } }"#);

        let config = fixture.load(Overrides::default()).unwrap();

        let log = config.settings().log.as_ref().unwrap();
        assert_eq!(log.file, PathBuf::from("agent.log"));
        assert_eq!(log.max_size.bytes(), 10_485_760);
        assert_eq!(log.max_files.get(), 5);
    }

    #[test]
    fn the_log_size_is_read_as_text_or_as_a_byte_count() {
        for (max_size, bytes) in [(r#""500KB""#, 512_000), ("2048", 2048)] {
            let fixture = Fixture::new();
            fixture.write_settings(&format!(
                r#"{{ "log": {{ "file": "agent.log", "max_size": {max_size}, "max_files": 3 }} }}"#
            ));

            let config = fixture.load(Overrides::default()).unwrap();

            let log = config.settings().log.as_ref().unwrap();
            assert_eq!(log.max_size.bytes(), bytes, "{max_size}");
            assert_eq!(log.max_files.get(), 3);
        }
    }

    #[test]
    fn invalid_log_limits_in_the_file_are_rejected() {
        for log in [
            r#"{ "file": "agent.log", "max_files": 0 }"#,
            r#"{ "file": "agent.log", "max_size": "10XB" }"#,
            r#"{ "file": "agent.log", "max_size": 0 }"#,
            r#"{ "max_size": "10MB" }"#,
        ] {
            let fixture = Fixture::new();
            fixture.write_settings(&format!(r#"{{ "log": {log} }}"#));

            let error = fixture.load(Overrides::default()).unwrap_err();

            assert!(
                matches!(error, ConfigError::Json { .. }),
                "{log}: expected a JSON error, got {error:?}"
            );
        }
    }

    #[test]
    fn log_overrides_win_over_the_file() {
        let fixture = Fixture::new();
        fixture.write_settings(
            r#"{ "log": { "file": "from-file.log", "max_size": "1MB", "max_files": 2 } }"#,
        );

        let config = fixture
            .load(Overrides {
                log_file: Some(PathBuf::from("from-cli.log")),
                log_max_size: Some("20MB".parse().unwrap()),
                log_max_files: Some(NonZeroUsize::new(9).unwrap()),
                ..Overrides::default()
            })
            .unwrap();

        let log = config.settings().log.as_ref().unwrap();
        assert_eq!(log.file, PathBuf::from("from-cli.log"));
        assert_eq!(log.max_size.bytes(), 20_971_520);
        assert_eq!(log.max_files.get(), 9);
    }

    #[test]
    fn a_log_file_flag_alone_turns_on_file_logging_with_the_defaults() {
        let fixture = Fixture::new();

        let config = fixture
            .load(Overrides {
                log_file: Some(PathBuf::from("agent.log")),
                ..Overrides::default()
            })
            .unwrap();

        let log = config.settings().log.as_ref().unwrap();
        assert_eq!(log.file, PathBuf::from("agent.log"));
        assert_eq!(log.max_size.bytes(), 10_485_760);
        assert_eq!(log.max_files.get(), 5);
    }

    #[test]
    fn log_file_flags_without_a_log_file_are_rejected() {
        for overrides in [
            Overrides {
                log_max_files: Some(NonZeroUsize::new(3).unwrap()),
                ..Overrides::default()
            },
            Overrides {
                log_max_size: Some("1MB".parse().unwrap()),
                ..Overrides::default()
            },
        ] {
            let fixture = Fixture::new();

            let error = fixture.load(overrides).unwrap_err();

            let message = error.to_string();
            assert!(
                matches!(error, ConfigError::LogOptionsWithoutFile { .. }),
                "{error:?}"
            );
            assert!(message.contains("log.file"), "{message}");
            assert!(message.contains("pass --log-file"), "{message}");
            assert!(message.contains(DEFAULT_SETTINGS_FILE), "{message}");
        }
    }
}
