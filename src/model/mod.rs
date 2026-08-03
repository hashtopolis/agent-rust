//! The domain types the agent works with, plus the wire layer they are
//! decoded from: [`raw`] holds the on-the-wire shapes and [`convert`] the
//! translation between the two.

mod convert;
pub(crate) mod raw;
pub use convert::ProtocolError;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    Windows,
    Darwin,
}

impl Os {
    pub const fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            Os::Linux
        }
        #[cfg(target_os = "windows")]
        {
            Os::Windows
        }
        #[cfg(target_os = "macos")]
        {
            Os::Darwin
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            compile_error!(
                "unsupported target: Hashtopolis defines OS codes only for linux, windows and macos"
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchmarkType {
    Speed,
    Run,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub id: u64,
    pub skip: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterResponse {
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResponse {
    pub timeout: i64,
    pub multicast_enabled: bool,
    pub server_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckClientVersionResponse {
    UpToDate,
    NewVersion { url: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadUtilityResponse {
    // NB: on the wire this URL arrives in the `executable` field (not `url`)
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadCrackerResponse {
    pub url: String,
    pub name: String,
    pub binary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadPreprocessorResponse {
    pub url: String,
    pub name: String,
    pub binary: String,
    pub keyspace_command: Option<String>,
    pub skip_command: Option<String>,
    pub limit_command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrainConfig {
    pub host: String,
    pub port: i64,
    pub pass: String,
    pub features: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preprocessor {
    pub id: u64,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAssignment {
    pub task_id: u64,
    pub cracker_id: u64,
    pub attack_command: String,
    pub cmd_parameters: String,
    pub hashlist_id: u64,
    pub benchmark: i64,
    pub status_timer: i64,
    pub files: Vec<String>,
    pub bench_type: BenchmarkType,
    pub hashlist_alias: String,
    pub keyspace: u64,
    pub enforce_pipe: bool,
    pub slow_hash: bool,
    pub preprocessor: Option<Preprocessor>,
    pub brain: Option<BrainConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetTaskResponse {
    HealthCheck,
    NoTask { reason: Option<String> },
    Task(Box<TaskAssignment>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetChunkResponse {
    Chunk(Chunk),
    KeyspaceRequired,
    BenchmarkRequired,
    FullyDispatched,
    CrackerUpdate,
    HealthCheck,
}

#[derive(Debug, Clone, Default)]
pub struct ProgressReport {
    pub chunk_id: u64,
    pub keyspace_progress: u64,
    pub relative_progress: u64,
    pub speed: u64,
    pub state: u32,
    pub cracks: Vec<Vec<String>>,
    pub debug_output: Option<Vec<String>>,
    pub gpu_temp: Option<Vec<i64>>,
    pub gpu_util: Option<Vec<i64>>,
    pub cpu_util: Option<Vec<f64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendProgressResponse {
    Continue {
        cracked: u64,
        skipped: u64,
        zaps: Vec<String>,
    },
    Stop {
        cracked: u64,
        skipped: u64,
    },
    /// The server refused the update with an `ERROR` envelope (chunk aborted,
    /// manually interrupted, agent inactive, ...). An expected control-flow
    /// outcome for `sendProgress`, not a failure to reach the server.
    Rejected {
        reason: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFileResponse {
    pub filename: String,
    pub extension: String,
    pub url: String,
    pub filesize: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFileStatusResponse {
    pub filenames: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHashlistResponse {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFoundResponse {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHealthCheckResponse {
    pub attack: String,
    pub cracker_binary_id: u64,
    pub hashes: Vec<String>,
    pub check_id: u64,
    pub hashlist_alias: String,
}
