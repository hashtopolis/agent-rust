//! Configuration split over two files with different owners: `config.json` is
//! user-owned and only ever read (so it is safe to reload every loop iteration),
//! while `state.json` is agent-owned and rewritten when the token or uuid change.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    pub url: Option<String>,
    pub voucher: Option<String>,
    pub cert: Option<PathBuf>,
    pub auth_user: Option<String>,
    pub auth_password: Option<String>,
    pub proxy: Option<String>,
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

/// User-owned; never written by the agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub server: Server,
    pub agent: AgentInfo,
    pub paths: Paths,
    pub behavior: Behavior,
    pub cracker: CrackerConfig,
}

/// The lifecycle boundary required to activate a settings change. The
/// supervisor uses this classification to choose between an in-place settings
/// update and replacement of the complete runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadImpact {
    Live,
    RebuildTask,
    Reconnect,
}

/// A fully parsed settings snapshot which has not been made active yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigCandidate {
    settings: Settings,
    impact: ReloadImpact,
}

impl ConfigCandidate {
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn impact(&self) -> ReloadImpact {
        self.impact
    }
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

/// Never written back; re-applied after every reload so a flag keeps winning.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub url: Option<String>,
    pub voucher: Option<String>,
    pub cert: Option<PathBuf>,
    pub cpu_only: bool,
    pub disable_update: bool,
    pub files_path: Option<PathBuf>,
    pub crackers_path: Option<PathBuf>,
    pub hashlists_path: Option<PathBuf>,
    pub preprocessors_path: Option<PathBuf>,
    pub zaps_path: Option<PathBuf>,
    pub hashcat_path: Option<PathBuf>,
}

impl Overrides {
    fn apply(&self, settings: &mut Settings) {
        if let Some(hashcat_path) = &self.hashcat_path {
            settings.cracker.hashcat_path = Some(hashcat_path.clone());
        }

        if let Some(url) = &self.url {
            settings.server.url = Some(url.clone());
        }

        if let Some(voucher) = &self.voucher {
            settings.server.voucher = Some(voucher.clone());
        }

        if let Some(cert) = &self.cert {
            settings.server.cert = Some(cert.clone());
        }

        if self.cpu_only {
            settings.behavior.cpu_only = true;
        }

        if self.disable_update {
            settings.behavior.disable_update = true;
        }

        for (target, override_value) in [
            (&mut settings.paths.files, &self.files_path),
            (&mut settings.paths.crackers, &self.crackers_path),
            (&mut settings.paths.hashlists, &self.hashlists_path),
            (&mut settings.paths.preprocessors, &self.preprocessors_path),
            (&mut settings.paths.zaps, &self.zaps_path),
        ] {
            if let Some(path) = override_value {
                *target = path.clone();
            }
        }
    }
}

/// The only writer of `state.json`.
#[derive(Debug, Clone)]
pub struct Config {
    settings_path: PathBuf,
    state_path: PathBuf,
    overrides: Overrides,
    settings: Settings,
    state: State,
    persist_state: bool,
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
        overrides.apply(&mut settings);

        let state = read_state(&state_path)?;

        Ok(Self {
            settings_path,
            state_path,
            overrides,
            settings,
            state,
            persist_state: true,
        })
    }

    /// Read and validate a prospective settings generation without changing the
    /// active one. State is deliberately excluded: tokens and UUIDs remain owned
    /// by this process rather than being hot-reloaded from disk.
    pub fn load_candidate(&self) -> Result<Option<ConfigCandidate>, ConfigError> {
        let mut settings = read_settings(&self.settings_path)?;
        self.overrides.apply(&mut settings);

        if settings == self.settings {
            return Ok(None);
        }

        let impact = reload_impact(&self.settings, &settings);

        Ok(Some(ConfigCandidate { settings, impact }))
    }

    /// Publish a candidate after the supervisor has prepared and authenticated
    /// a complete replacement runtime for it.
    pub fn commit_candidate(&mut self, candidate: ConfigCandidate) {
        self.settings = candidate.settings;
    }

    /// Clone this config with a candidate made active. Used to prepare a runtime
    /// off to the side while the current generation remains untouched.
    pub fn with_candidate(&self, candidate: &ConfigCandidate) -> Self {
        let mut config = self.clone();
        config.settings = candidate.settings.clone();
        config.persist_state = false;
        config
    }

    /// Compatibility helper for callers which do not need transactional
    /// activation. The supervisor uses [`Config::load_candidate`] and
    /// [`Config::commit_candidate`] directly.
    pub fn reload_settings(&mut self) -> Result<(), ConfigError> {
        if let Some(candidate) = self.load_candidate()? {
            self.commit_candidate(candidate);
        }

        Ok(())
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
        self.save_state_if_enabled()
    }

    /// Discard an endpoint-specific token while preparing a connection to a
    /// different server. Candidate state remains in memory until activation.
    pub(crate) fn clear_token(&mut self) {
        self.state.token = None;
    }

    /// Commit state accumulated while preparing a candidate, then make future
    /// state changes from that generation persistent.
    pub(crate) fn persist_prepared_state(&mut self) -> Result<(), ConfigError> {
        self.save_state()?;
        self.persist_state = true;
        Ok(())
    }

    /// Generates and persists a uuid on first use.
    pub fn uuid_or_create(&mut self) -> Result<&str, ConfigError> {
        if self.state.uuid.is_none() {
            self.state.uuid = Some(Uuid::new_v4().to_string());
            self.save_state_if_enabled()?;
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
    fn save_state_if_enabled(&self) -> Result<(), ConfigError> {
        if self.persist_state {
            self.save_state()?;
        }

        Ok(())
    }

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

fn reload_impact(current: &Settings, candidate: &Settings) -> ReloadImpact {
    let Settings {
        server: current_server,
        agent: current_agent,
        paths: current_paths,
        behavior: current_behavior,
        cracker: current_cracker,
    } = current;
    let Settings {
        server: candidate_server,
        agent: candidate_agent,
        paths: candidate_paths,
        behavior: candidate_behavior,
        cracker: candidate_cracker,
    } = candidate;

    if current_server != candidate_server || current_agent != candidate_agent {
        return ReloadImpact::Reconnect;
    }

    if current_paths != candidate_paths || current_cracker != candidate_cracker {
        return ReloadImpact::RebuildTask;
    }

    let Behavior {
        cpu_only: current_cpu_only,
        disable_update: current_disable_update,
        allow_piping: current_allow_piping,
        piping_threshold: current_piping_threshold,
        outfile_history: current_outfile_history,
        rsync: current_rsync,
        rsync_path: current_rsync_path,
        multicast_device: current_multicast_device,
        file_deletion_disable: current_file_deletion_disable,
        file_deletion_interval: current_file_deletion_interval,
    } = current_behavior;
    let Behavior {
        cpu_only: candidate_cpu_only,
        disable_update: candidate_disable_update,
        allow_piping: candidate_allow_piping,
        piping_threshold: candidate_piping_threshold,
        outfile_history: candidate_outfile_history,
        rsync: candidate_rsync,
        rsync_path: candidate_rsync_path,
        multicast_device: candidate_multicast_device,
        file_deletion_disable: candidate_file_deletion_disable,
        file_deletion_interval: candidate_file_deletion_interval,
    } = candidate_behavior;

    if current_cpu_only != candidate_cpu_only {
        ReloadImpact::Reconnect
    } else if current_allow_piping != candidate_allow_piping
        || current_piping_threshold != candidate_piping_threshold
        || current_outfile_history != candidate_outfile_history
        || current_rsync != candidate_rsync
        || current_rsync_path != candidate_rsync_path
        || current_multicast_device != candidate_multicast_device
    {
        ReloadImpact::RebuildTask
    } else if current_disable_update != candidate_disable_update
        || current_file_deletion_disable != candidate_file_deletion_disable
        || current_file_deletion_interval != candidate_file_deletion_interval
    {
        ReloadImpact::Live
    } else {
        unreachable!("reload impact requested for identical settings")
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
                cert: Some(PathBuf::from("/etc/htp/client.pem")),
                auth_user: Some("agent".to_string()),
                auth_password: Some("secret".to_string()),
                proxy: Some("http://proxy:3128".to_string()),
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
    fn overrides_are_reapplied_after_reload() {
        let fixture = Fixture::new();
        fixture.write_settings(
            r#"{ "server": { "url": "https://from-file.example/api/server.php" } }"#,
        );
        let mut config = fixture
            .load(Overrides {
                url: Some("https://from-cli.example/api/server.php".to_string()),
                ..Overrides::default()
            })
            .unwrap();

        fixture.write_settings(
            r#"{
                "server": { "url": "https://edited.example/api/server.php" },
                "behavior": { "piping_threshold": 42 }
            }"#,
        );
        config.reload_settings().unwrap();

        assert_eq!(config.settings().behavior.piping_threshold, 42);
        assert_eq!(
            config.require_url().unwrap(),
            "https://from-cli.example/api/server.php",
            "the CLI override must keep winning after a reload"
        );
    }

    #[test]
    fn candidate_is_transactional_and_classifies_live_changes() {
        let fixture = Fixture::new();
        let mut config = fixture.load(Overrides::default()).unwrap();

        fixture.write_settings(r#"{ "behavior": { "disable_update": true } }"#);

        let candidate = config.load_candidate().unwrap().unwrap();

        assert_eq!(candidate.impact(), ReloadImpact::Live);
        assert!(!config.settings().behavior.disable_update);

        config.commit_candidate(candidate);
        assert!(config.settings().behavior.disable_update);
        assert!(config.load_candidate().unwrap().is_none());
    }

    #[test]
    fn deletion_schedule_changes_are_explicitly_live() {
        let fixture = Fixture::new();
        let config = fixture.load(Overrides::default()).unwrap();

        fixture.write_settings(
            r#"{
                "behavior": {
                    "file_deletion_disable": true,
                    "file_deletion_interval": 42
                }
            }"#,
        );

        let candidate = config.load_candidate().unwrap().unwrap();

        assert_eq!(candidate.impact(), ReloadImpact::Live);
    }

    #[test]
    fn candidate_classifies_task_runtime_changes() {
        let fixture = Fixture::new();
        let config = fixture.load(Overrides::default()).unwrap();

        fixture.write_settings(r#"{ "paths": { "files": "/new/files" } }"#);

        let candidate = config.load_candidate().unwrap().unwrap();

        assert_eq!(candidate.impact(), ReloadImpact::RebuildTask);
        assert_eq!(config.settings().paths.files, PathBuf::from("files"));
        assert_eq!(
            candidate.settings().paths.files,
            PathBuf::from("/new/files")
        );
    }

    #[test]
    fn candidate_classifies_connection_changes() {
        let fixture = Fixture::new();
        fixture.write_settings(r#"{ "server": { "url": "https://old.example/api/server.php" } }"#);
        let config = fixture.load(Overrides::default()).unwrap();

        fixture.write_settings(r#"{ "server": { "url": "https://new.example/api/server.php" } }"#);

        let candidate = config.load_candidate().unwrap().unwrap();
        let prepared = config.with_candidate(&candidate);

        assert_eq!(candidate.impact(), ReloadImpact::Reconnect);
        assert_eq!(
            config.require_url().unwrap(),
            "https://old.example/api/server.php"
        );
        assert_eq!(
            prepared.require_url().unwrap(),
            "https://new.example/api/server.php"
        );
    }

    #[test]
    fn reload_does_not_touch_the_token() {
        let fixture = Fixture::new();
        let mut config = fixture.load(Overrides::default()).unwrap();
        config.set_token("GHhgdf(/&").unwrap();

        fixture.write_settings(r#"{ "server": { "url": "https://example.com/api/server.php" } }"#);
        config.reload_settings().unwrap();

        assert_eq!(config.token(), Some("GHhgdf(/&"));
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
    fn prepared_state_is_not_visible_until_committed() {
        let fixture = Fixture::new();
        let mut config = fixture.load(Overrides::default()).unwrap();
        config.set_token("old-token").unwrap();
        fixture.write_settings(
            r#"{
                "server": {
                    "url": "https://new.example/api/server.php",
                    "voucher": "voucher"
                }
            }"#,
        );

        let candidate = config.load_candidate().unwrap().unwrap();
        let mut prepared = config.with_candidate(&candidate);
        prepared.clear_token();
        prepared.set_token("new-token").unwrap();

        assert!(fixture.read_state().contains("old-token"));
        prepared.persist_prepared_state().unwrap();
        assert!(fixture.read_state().contains("new-token"));
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
}
