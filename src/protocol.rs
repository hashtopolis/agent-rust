use serde::{Deserialize, Serialize};

use crate::model::{BenchmarkType, Os, TaskId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseStatus {
    #[serde(rename = "SUCCESS")]
    Success,
    #[serde(rename = "ERROR")]
    Error,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseEnvelope {
    #[serde(default)]
    pub action: Option<String>,
    pub response: ResponseStatus,
    #[serde(default)]
    pub message: Option<String>,
}

impl ResponseEnvelope {
    pub fn is_success(&self) -> bool {
        self.response == ResponseStatus::Success
    }
}

// Shared by every action whose only payload is the SUCCESS/ERROR status itself.
// sendKeyspace and sendBenchmark also fold in here: their one field is a constant
// "OK" that merely restates SUCCESS, so it carries no information worth a distinct type.
#[derive(Debug, Clone, Deserialize)]
pub struct AckResponse {
    #[serde(flatten)]
    pub envelope: ResponseEnvelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkStatus {
    #[serde(rename = "keyspace_required")]
    KeyspaceRequired,
    #[serde(rename = "benchmark")]
    BenchmarkRequired,
    #[serde(rename = "fully_dispatched")]
    FullyDispatched,
    #[serde(rename = "cracker_update")]
    CrackerUpdate,
    #[serde(rename = "health_check")]
    HealthCheck,
    #[serde(rename = "OK")]
    Ok,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UpdateVersion {
    #[serde(rename = "OK")]
    UpToDate,
    #[serde(rename = "NEW")]
    NewVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryType {
    #[serde(rename = "7zr")]
    Extractor,
    #[serde(rename = "cracker")]
    Cracker,
    #[serde(rename = "prince")]
    Prince,
    #[serde(rename = "uftpd")]
    Uftpd,
    #[serde(rename = "preprocessor")]
    Preprocessor,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action")]
pub enum Request {
    #[serde(rename = "register")]
    Register {
        voucher: String,
        name: String,
        #[serde(rename = "cpu-only", skip_serializing_if = "Option::is_none")]
        cpu_only: Option<bool>,
    },

    #[serde(rename = "login")]
    Login {
        token: String,
        #[serde(rename = "clientSignature")]
        client_signature: String,
    },

    #[serde(rename = "updateInformation")]
    UpdateInformation {
        token: String,
        uid: String,
        os: Os,
        devices: Vec<String>,
    },

    #[serde(rename = "checkClientVersion")]
    CheckClientVersion {
        token: String,
        version: String,
        #[serde(rename = "type")]
        agent_type: String,
    },

    #[serde(rename = "downloadBinary")]
    DownloadBinary {
        token: String,
        #[serde(rename = "type")]
        binary_type: BinaryType,
        #[serde(rename = "binaryVersionId", skip_serializing_if = "Option::is_none")]
        binary_version_id: Option<u64>,
        #[serde(rename = "preprocessorId", skip_serializing_if = "Option::is_none")]
        preprocessor_id: Option<u64>,
    },

    #[serde(rename = "testConnection")]
    TestConnection,

    #[serde(rename = "getTask")]
    GetTask { token: String },

    #[serde(rename = "getChunk")]
    GetChunk {
        token: String,
        #[serde(rename = "taskId")]
        task_id: u64,
    },

    #[serde(rename = "sendKeyspace")]
    SendKeyspace {
        token: String,
        #[serde(rename = "taskId")]
        task_id: u64,
        keyspace: u64,
    },

    #[serde(rename = "sendBenchmark")]
    SendBenchmark {
        token: String,
        #[serde(rename = "taskId")]
        task_id: u64,
        #[serde(rename = "type")]
        bench_type: BenchmarkType,
        result: String,
    },

    #[serde(rename = "sendProgress")]
    SendProgress {
        token: String,
        #[serde(rename = "chunkId")]
        chunk_id: u64,
        #[serde(rename = "keyspaceProgress")]
        keyspace_progress: u64,
        #[serde(rename = "relativeProgress")]
        relative_progress: u64,
        speed: u64,
        state: u32,
        cracks: Vec<String>,

        #[serde(rename = "debugOutput", skip_serializing_if = "Option::is_none")]
        debug_output: Option<Vec<String>>,
        #[serde(rename = "gpuTemp", skip_serializing_if = "Option::is_none")]
        gpu_temp: Option<Vec<i64>>,
        #[serde(rename = "gpuUtil", skip_serializing_if = "Option::is_none")]
        gpu_util: Option<Vec<i64>>,
        #[serde(rename = "cpuUtil", skip_serializing_if = "Option::is_none")]
        cpu_util: Option<Vec<f64>>,
    },

    #[serde(rename = "clientError")]
    ClientError {
        token: String,
        #[serde(rename = "taskId")]
        task_id: u64,
        #[serde(rename = "chunkId")]
        chunk_id: Option<u64>,
        message: String,
    },

    #[serde(rename = "getHashlist")]
    GetHashlist {
        token: String,
        #[serde(rename = "hashlistId")]
        hashlist_id: u64,
    },

    #[serde(rename = "getFound")]
    GetFound {
        token: String,
        #[serde(rename = "hashlistId")]
        hashlist_id: u64,
    },

    #[serde(rename = "getFile")]
    GetFile {
        token: String,
        #[serde(rename = "taskId")]
        task_id: u64,
        file: String,
    },

    #[serde(rename = "getFileStatus")]
    GetFileStatus { token: String },

    #[serde(rename = "getHealthCheck")]
    GetHealthCheck { token: String },

    #[serde(rename = "sendHealthCheck")]
    SendHealthCheck {
        token: String,
        #[serde(rename = "checkId")]
        check_id: u64,
        #[serde(rename = "numCracked")]
        num_cracked: u64,
        start: i64,
        end: i64,
        #[serde(rename = "numGpus")]
        num_gpus: u32,
        errors: Vec<String>,
    },

    #[serde(rename = "deregister")]
    Deregister { token: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    MissingField(&'static str),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::MissingField(name) => {
                write!(f, "missing expected field '{name}' in server response")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

trait Require<T> {
    fn require(self, field: &'static str) -> Result<T, ProtocolError>;
}

impl<T> Require<T> for Option<T> {
    fn require(self, field: &'static str) -> Result<T, ProtocolError> {
        self.ok_or(ProtocolError::MissingField(field))
    }
}

pub mod raw {
    use serde::Deserialize;

    use super::{ChunkStatus, UpdateVersion};
    use crate::model::BenchmarkType;

    #[derive(Debug, Clone, Deserialize)]
    pub struct GetTaskResponse {
        #[serde(rename = "taskId", default)]
        pub task_id: Option<i64>,
        #[serde(default)]
        pub reason: Option<String>,
        #[serde(rename = "crackerId", default)]
        pub cracker_id: Option<u64>,
        #[serde(rename = "attackcmd", default)]
        pub attack_command: Option<String>,
        #[serde(rename = "cmdpars", default)]
        pub cmd_parameters: Option<String>,
        #[serde(rename = "hashlistId", default)]
        pub hashlist_id: Option<u64>,
        #[serde(rename = "bench", default)]
        pub benchmark: Option<i64>,
        #[serde(rename = "statustimer", default)]
        pub status_timer: Option<i64>,
        #[serde(default)]
        pub files: Vec<String>,
        #[serde(rename = "benchType", default)]
        pub bench_type: Option<BenchmarkType>,
        #[serde(rename = "hashlistAlias", default)]
        pub hashlist_alias: Option<String>,
        #[serde(default)]
        pub keyspace: Option<u64>,
        #[serde(rename = "usePreprocessor", default)]
        pub use_preprocessor: bool,
        #[serde(rename = "preprocessor", default)]
        pub preprocessor: Option<u64>,
        #[serde(rename = "preprocessorCommand", default)]
        pub preprocessor_command: Option<String>,
        #[serde(rename = "enforcePipe", default)]
        pub enforce_pipe: bool,
        #[serde(rename = "slowHash", default)]
        pub slow_hash: bool,
        #[serde(rename = "useBrain", default)]
        pub use_brain: bool,
        #[serde(rename = "brainHost", default)]
        pub brain_host: Option<String>,
        #[serde(rename = "brainPort", default)]
        pub brain_port: Option<i64>,
        #[serde(rename = "brainPass", default)]
        pub brain_pass: Option<String>,
        #[serde(rename = "brainFeatures", default)]
        pub brain_features: Option<i64>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct GetChunkResponse {
        pub status: ChunkStatus,
        #[serde(rename = "chunkId", default)]
        pub chunk_id: Option<u64>,
        #[serde(default)]
        pub skip: Option<u64>,
        #[serde(default)]
        pub length: Option<u64>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct DownloadBinaryResponse {
        #[serde(default)]
        pub executable: Option<String>,
        #[serde(default)]
        pub url: Option<String>,
        #[serde(default)]
        pub name: Option<String>,
        #[serde(rename = "keyspaceCommand", default)]
        pub keyspace_command: Option<String>,
        #[serde(rename = "skipCommand", default)]
        pub skip_command: Option<String>,
        #[serde(rename = "limitCommand", default)]
        pub limit_command: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct CheckClientVersionResponse {
        #[serde(default)]
        pub version: Option<UpdateVersion>,
        #[serde(default)]
        pub url: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct GetFileResponse {
        #[serde(default)]
        pub filename: Option<String>,
        #[serde(default)]
        pub extension: Option<String>,
        #[serde(default)]
        pub url: Option<String>,
        #[serde(default)]
        pub filesize: Option<u64>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct GetFileStatusResponse {
        #[serde(default)]
        pub filenames: Vec<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct GetHashlistResponse {
        #[serde(default)]
        pub url: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct GetFoundResponse {
        #[serde(default)]
        pub url: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct GetHealthCheckResponse {
        #[serde(default)]
        pub attack: Option<String>,
        #[serde(rename = "crackerBinaryId", default)]
        pub cracker_binary_id: Option<u64>,
        #[serde(default)]
        pub hashes: Vec<String>,
        #[serde(rename = "checkId", default)]
        pub check_id: Option<u64>,
        #[serde(rename = "hashlistAlias", default)]
        pub hashlist_alias: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct RegisterResponse {
        #[serde(default)]
        pub token: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct LoginResponse {
        #[serde(default)]
        pub timeout: Option<i64>,
        #[serde(rename = "multicastEnabled", default)]
        pub multicast_enabled: Option<bool>,
        #[serde(rename = "server-version", default)]
        pub server_version: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct SendProgressResponse {
        #[serde(default)]
        pub cracked: u64,
        #[serde(default)]
        pub skipped: u64,
        #[serde(default)]
        pub agent: Option<String>,
        #[serde(default)]
        pub zaps: Vec<String>,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterResponse {
    pub token: String,
}

impl TryFrom<raw::RegisterResponse> for RegisterResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::RegisterResponse) -> Result<Self, Self::Error> {
        Ok(RegisterResponse {
            token: raw.token.require("token")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResponse {
    pub timeout: i64,
    pub multicast_enabled: bool,
    pub server_version: String,
}

impl TryFrom<raw::LoginResponse> for LoginResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::LoginResponse) -> Result<Self, Self::Error> {
        Ok(LoginResponse {
            timeout: raw.timeout.require("timeout")?,
            multicast_enabled: raw.multicast_enabled.require("multicastEnabled")?,
            server_version: raw.server_version.require("server-version")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckClientVersionResponse {
    UpToDate,
    NewVersion { url: String },
}

impl TryFrom<raw::CheckClientVersionResponse> for CheckClientVersionResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::CheckClientVersionResponse) -> Result<Self, Self::Error> {
        match raw.version.require("version")? {
            UpdateVersion::UpToDate => Ok(CheckClientVersionResponse::UpToDate),
            UpdateVersion::NewVersion => Ok(CheckClientVersionResponse::NewVersion {
                url: raw.url.require("url")?,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadBinaryResponse {
    // NB: on the wire this URL arrives in the `executable` field (not `url`);
    // we expose it as `url` here to mirror the other variants
    Utility {
        url: String,
    },
    Archive {
        url: String,
        name: String,
        binary: String,
    },
    Preprocessor {
        url: String,
        name: String,
        binary: String,
        keyspace_command: String,
        skip_command: String,
        limit_command: String,
    },
}

impl TryFrom<raw::DownloadBinaryResponse> for DownloadBinaryResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::DownloadBinaryResponse) -> Result<Self, Self::Error> {
        if raw.keyspace_command.is_some()
            || raw.skip_command.is_some()
            || raw.limit_command.is_some()
        {
            return Ok(DownloadBinaryResponse::Preprocessor {
                url: raw.url.require("url")?,
                name: raw.name.require("name")?,
                binary: raw.executable.require("executable")?,
                keyspace_command: raw.keyspace_command.require("keyspaceCommand")?,
                skip_command: raw.skip_command.require("skipCommand")?,
                limit_command: raw.limit_command.require("limitCommand")?,
            });
        }

        if let Some(url) = raw.url {
            return Ok(DownloadBinaryResponse::Archive {
                url,
                name: raw.name.require("name")?,
                binary: raw.executable.require("executable")?,
            });
        }

        Ok(DownloadBinaryResponse::Utility {
            url: raw.executable.require("executable")?,
        })
    }
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

impl TryFrom<raw::GetTaskResponse> for GetTaskResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetTaskResponse) -> Result<Self, Self::Error> {
        let task_id = match TaskId::from_raw(raw.task_id) {
            TaskId::HealthCheck => return Ok(GetTaskResponse::HealthCheck),
            TaskId::None => return Ok(GetTaskResponse::NoTask { reason: raw.reason }),
            TaskId::Id(id) => id,
        };

        let preprocessor = if raw.use_preprocessor {
            Some(Preprocessor {
                id: raw.preprocessor.unwrap_or_default(),
                command: raw.preprocessor_command.unwrap_or_default(),
            })
        } else {
            None
        };

        let brain = if raw.use_brain {
            Some(BrainConfig {
                host: raw.brain_host.require("brainHost")?,
                port: raw.brain_port.require("brainPort")?,
                pass: raw.brain_pass.require("brainPass")?,
                features: raw.brain_features.require("brainFeatures")?,
            })
        } else {
            None
        };

        Ok(GetTaskResponse::Task(Box::new(TaskAssignment {
            task_id,
            cracker_id: raw.cracker_id.require("crackerId")?,
            attack_command: raw.attack_command.require("attackcmd")?,
            cmd_parameters: raw.cmd_parameters.require("cmdpars")?,
            hashlist_id: raw.hashlist_id.require("hashlistId")?,
            benchmark: raw.benchmark.require("bench")?,
            status_timer: raw.status_timer.require("statustimer")?,
            files: raw.files,
            bench_type: raw.bench_type.require("benchType")?,
            hashlist_alias: raw.hashlist_alias.require("hashlistAlias")?,
            keyspace: raw.keyspace.require("keyspace")?,
            enforce_pipe: raw.enforce_pipe,
            slow_hash: raw.slow_hash,
            preprocessor,
            brain,
        })))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetChunkResponse {
    Chunk { id: u64, skip: u64, length: u64 },
    KeyspaceRequired,
    BenchmarkRequired,
    FullyDispatched,
    CrackerUpdate,
    HealthCheck,
}

impl TryFrom<raw::GetChunkResponse> for GetChunkResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetChunkResponse) -> Result<Self, Self::Error> {
        Ok(match raw.status {
            ChunkStatus::Ok => GetChunkResponse::Chunk {
                id: raw.chunk_id.require("chunkId")?,
                skip: raw.skip.require("skip")?,
                length: raw.length.require("length")?,
            },
            ChunkStatus::KeyspaceRequired => GetChunkResponse::KeyspaceRequired,
            ChunkStatus::BenchmarkRequired => GetChunkResponse::BenchmarkRequired,
            ChunkStatus::FullyDispatched => GetChunkResponse::FullyDispatched,
            ChunkStatus::CrackerUpdate => GetChunkResponse::CrackerUpdate,
            ChunkStatus::HealthCheck => GetChunkResponse::HealthCheck,
        })
    }
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
}

impl From<raw::SendProgressResponse> for SendProgressResponse {
    fn from(raw: raw::SendProgressResponse) -> Self {
        if raw.agent.as_deref() == Some("stop") {
            SendProgressResponse::Stop {
                cracked: raw.cracked,
                skipped: raw.skipped,
            }
        } else {
            SendProgressResponse::Continue {
                cracked: raw.cracked,
                skipped: raw.skipped,
                zaps: raw.zaps,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFileResponse {
    pub filename: String,
    pub extension: String,
    pub url: String,
    pub filesize: u64,
}

impl TryFrom<raw::GetFileResponse> for GetFileResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetFileResponse) -> Result<Self, Self::Error> {
        Ok(GetFileResponse {
            filename: raw.filename.require("filename")?,
            extension: raw.extension.require("extension")?,
            url: raw.url.require("url")?,
            filesize: raw.filesize.require("filesize")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFileStatusResponse {
    pub filenames: Vec<String>,
}

impl From<raw::GetFileStatusResponse> for GetFileStatusResponse {
    fn from(raw: raw::GetFileStatusResponse) -> Self {
        GetFileStatusResponse {
            filenames: raw.filenames,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHashlistResponse {
    pub url: String,
}

impl TryFrom<raw::GetHashlistResponse> for GetHashlistResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetHashlistResponse) -> Result<Self, Self::Error> {
        Ok(GetHashlistResponse {
            url: raw.url.require("url")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFoundResponse {
    pub url: String,
}

impl TryFrom<raw::GetFoundResponse> for GetFoundResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetFoundResponse) -> Result<Self, Self::Error> {
        Ok(GetFoundResponse {
            url: raw.url.require("url")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetHealthCheckResponse {
    pub attack: String,
    pub cracker_binary_id: u64,
    pub hashes: Vec<String>,
    pub check_id: u64,
    pub hashlist_alias: String,
}

impl TryFrom<raw::GetHealthCheckResponse> for GetHealthCheckResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetHealthCheckResponse) -> Result<Self, Self::Error> {
        Ok(GetHealthCheckResponse {
            attack: raw.attack.require("attack")?,
            cracker_binary_id: raw.cracker_binary_id.require("crackerBinaryId")?,
            hashes: raw.hashes,
            check_id: raw.check_id.require("checkId")?,
            hashlist_alias: raw.hashlist_alias.require("hashlistAlias")?,
        })
    }
}
