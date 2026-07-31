use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{self, BrainConfig, Chunk, Preprocessor, TaskAssignment};

/// Classifies `taskId` field in a `getTask` reply:
/// - absent means no task,
/// - `-1` means a health check
/// - any non-negative value is a real id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskId {
    None,
    HealthCheck,
    Id(u64), // TODO: maybe use NonZeroU64?
}

impl TaskId {
    const HEALTH_CHECK: i64 = -1;

    pub(crate) fn from_raw(raw: Option<i64>) -> Self {
        match raw {
            None => TaskId::None,
            Some(Self::HEALTH_CHECK) => TaskId::HealthCheck,
            Some(id) if id >= 0 => TaskId::Id(id as u64),
            Some(_) => TaskId::None,
        }
    }
}

/// Wire mirror of [`model::Os`]: serialized as the numeric code the server expects.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(into = "u8")]
pub(crate) enum Os {
    Linux = 0,
    Windows = 1,
    Darwin = 2,
}

impl From<model::Os> for Os {
    fn from(os: model::Os) -> Self {
        match os {
            model::Os::Linux => Os::Linux,
            model::Os::Windows => Os::Windows,
            model::Os::Darwin => Os::Darwin,
        }
    }
}

impl From<Os> for u8 {
    fn from(os: Os) -> u8 {
        os as u8
    }
}

/// Wire mirror of [`model::BenchmarkType`]: serialized as its lowercase name.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum BenchmarkType {
    #[serde(rename = "speed")]
    Speed,
    #[serde(rename = "run")]
    Run,
}

impl From<model::BenchmarkType> for BenchmarkType {
    fn from(bench: model::BenchmarkType) -> Self {
        match bench {
            model::BenchmarkType::Speed => BenchmarkType::Speed,
            model::BenchmarkType::Run => BenchmarkType::Run,
        }
    }
}

impl From<BenchmarkType> for model::BenchmarkType {
    fn from(bench: BenchmarkType) -> Self {
        match bench {
            BenchmarkType::Speed => model::BenchmarkType::Speed,
            BenchmarkType::Run => model::BenchmarkType::Run,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) enum BinaryType {
    #[serde(rename = "7zr")]
    Extractor,
    #[serde(rename = "cracker")]
    Cracker,
    #[serde(rename = "uftpd")]
    Uftpd,
    #[serde(rename = "preprocessor")]
    Preprocessor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum ChunkStatus {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum UpdateVersion {
    #[serde(rename = "OK")]
    UpToDate,
    #[serde(rename = "NEW")]
    NewVersion,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action")]
pub(crate) enum Request {
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
        cracks: Vec<Vec<String>>,

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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("missing expected field '{0}' in server response")]
    MissingField(&'static str),
}

trait Require<T> {
    fn require(self, field: &'static str) -> Result<T, ProtocolError>;
}

impl<T> Require<T> for Option<T> {
    fn require(self, field: &'static str) -> Result<T, ProtocolError> {
        self.ok_or(ProtocolError::MissingField(field))
    }
}

pub(crate) mod raw {
    use serde::Deserialize;

    use super::{BenchmarkType, ChunkStatus, UpdateVersion};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    pub(crate) enum Status {
        #[serde(rename = "SUCCESS")]
        Success,
        #[serde(rename = "ERROR")]
        Error,
        #[serde(other)]
        Other,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub(crate) struct GetTaskResponse {
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
    pub(crate) struct GetChunkResponse {
        pub status: ChunkStatus,
        #[serde(rename = "chunkId", default)]
        pub chunk_id: Option<u64>,
        #[serde(default)]
        pub skip: Option<u64>,
        #[serde(default)]
        pub length: Option<u64>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub(crate) struct DownloadBinaryResponse {
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
    pub(crate) struct CheckClientVersionResponse {
        #[serde(default)]
        pub version: Option<UpdateVersion>,
        #[serde(default)]
        pub url: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub(crate) struct GetFileResponse {
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
    pub(crate) struct GetFileStatusResponse {
        #[serde(default)]
        pub filenames: Vec<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub(crate) struct GetHashlistResponse {
        #[serde(default)]
        pub url: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub(crate) struct GetFoundResponse {
        #[serde(default)]
        pub url: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub(crate) struct GetHealthCheckResponse {
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
    pub(crate) struct RegisterResponse {
        #[serde(default)]
        pub token: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub(crate) struct LoginResponse {
        #[serde(default)]
        pub timeout: Option<i64>,
        #[serde(rename = "multicastEnabled", default)]
        pub multicast_enabled: Option<bool>,
        #[serde(rename = "server-version", default)]
        pub server_version: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub(crate) struct SendProgressResponse {
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

impl TryFrom<raw::RegisterResponse> for model::RegisterResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::RegisterResponse) -> Result<Self, Self::Error> {
        Ok(model::RegisterResponse {
            token: raw.token.require("token")?,
        })
    }
}

impl TryFrom<raw::LoginResponse> for model::LoginResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::LoginResponse) -> Result<Self, Self::Error> {
        Ok(model::LoginResponse {
            timeout: raw.timeout.require("timeout")?,
            multicast_enabled: raw.multicast_enabled.require("multicastEnabled")?,
            server_version: raw.server_version.require("server-version")?,
        })
    }
}

impl TryFrom<raw::CheckClientVersionResponse> for model::CheckClientVersionResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::CheckClientVersionResponse) -> Result<Self, Self::Error> {
        match raw.version.require("version")? {
            UpdateVersion::UpToDate => Ok(model::CheckClientVersionResponse::UpToDate),
            UpdateVersion::NewVersion => Ok(model::CheckClientVersionResponse::NewVersion {
                url: raw.url.require("url")?,
            }),
        }
    }
}

impl TryFrom<raw::DownloadBinaryResponse> for model::DownloadUtilityResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::DownloadBinaryResponse) -> Result<Self, Self::Error> {
        Ok(model::DownloadUtilityResponse {
            url: raw.executable.require("executable")?,
        })
    }
}

impl TryFrom<raw::DownloadBinaryResponse> for model::DownloadCrackerResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::DownloadBinaryResponse) -> Result<Self, Self::Error> {
        Ok(model::DownloadCrackerResponse {
            url: raw.url.require("url")?,
            name: raw.name.require("name")?,
            binary: raw.executable.require("executable")?,
        })
    }
}

impl TryFrom<raw::DownloadBinaryResponse> for model::DownloadPreprocessorResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::DownloadBinaryResponse) -> Result<Self, Self::Error> {
        Ok(model::DownloadPreprocessorResponse {
            url: raw.url.require("url")?,
            name: raw.name.require("name")?,
            binary: raw.executable.require("executable")?,
            keyspace_command: raw.keyspace_command,
            skip_command: raw.skip_command,
            limit_command: raw.limit_command,
        })
    }
}

impl TryFrom<raw::GetTaskResponse> for model::GetTaskResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetTaskResponse) -> Result<Self, Self::Error> {
        let task_id = match TaskId::from_raw(raw.task_id) {
            TaskId::HealthCheck => return Ok(model::GetTaskResponse::HealthCheck),
            TaskId::None => return Ok(model::GetTaskResponse::NoTask { reason: raw.reason }),
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

        Ok(model::GetTaskResponse::Task(Box::new(TaskAssignment {
            task_id,
            cracker_id: raw.cracker_id.require("crackerId")?,
            attack_command: raw.attack_command.require("attackcmd")?,
            cmd_parameters: raw.cmd_parameters.require("cmdpars")?,
            hashlist_id: raw.hashlist_id.require("hashlistId")?,
            benchmark: raw.benchmark.require("bench")?,
            status_timer: raw.status_timer.require("statustimer")?,
            files: raw.files,
            bench_type: raw
                .bench_type
                .map(model::BenchmarkType::from)
                .require("benchType")?,
            hashlist_alias: raw.hashlist_alias.require("hashlistAlias")?,
            keyspace: raw.keyspace.require("keyspace")?,
            enforce_pipe: raw.enforce_pipe,
            slow_hash: raw.slow_hash,
            preprocessor,
            brain,
        })))
    }
}

impl TryFrom<raw::GetChunkResponse> for model::GetChunkResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetChunkResponse) -> Result<Self, Self::Error> {
        Ok(match raw.status {
            ChunkStatus::Ok => model::GetChunkResponse::Chunk(Chunk {
                id: raw.chunk_id.require("chunkId")?,
                skip: raw.skip.require("skip")?,
                length: raw.length.require("length")?,
            }),
            ChunkStatus::KeyspaceRequired => model::GetChunkResponse::KeyspaceRequired,
            ChunkStatus::BenchmarkRequired => model::GetChunkResponse::BenchmarkRequired,
            ChunkStatus::FullyDispatched => model::GetChunkResponse::FullyDispatched,
            ChunkStatus::CrackerUpdate => model::GetChunkResponse::CrackerUpdate,
            ChunkStatus::HealthCheck => model::GetChunkResponse::HealthCheck,
        })
    }
}

impl From<raw::SendProgressResponse> for model::SendProgressResponse {
    fn from(raw: raw::SendProgressResponse) -> Self {
        if raw.agent.as_deref() == Some("stop") {
            model::SendProgressResponse::Stop {
                cracked: raw.cracked,
                skipped: raw.skipped,
            }
        } else {
            model::SendProgressResponse::Continue {
                cracked: raw.cracked,
                skipped: raw.skipped,
                zaps: raw.zaps,
            }
        }
    }
}

impl TryFrom<raw::GetFileResponse> for model::GetFileResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetFileResponse) -> Result<Self, Self::Error> {
        Ok(model::GetFileResponse {
            filename: raw.filename.require("filename")?,
            extension: raw.extension.require("extension")?,
            url: raw.url.require("url")?,
            filesize: raw.filesize.require("filesize")?,
        })
    }
}

impl From<raw::GetFileStatusResponse> for model::GetFileStatusResponse {
    fn from(raw: raw::GetFileStatusResponse) -> Self {
        model::GetFileStatusResponse {
            filenames: raw.filenames,
        }
    }
}

impl TryFrom<raw::GetHashlistResponse> for model::GetHashlistResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetHashlistResponse) -> Result<Self, Self::Error> {
        Ok(model::GetHashlistResponse {
            url: raw.url.require("url")?,
        })
    }
}

impl TryFrom<raw::GetFoundResponse> for model::GetFoundResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetFoundResponse) -> Result<Self, Self::Error> {
        Ok(model::GetFoundResponse {
            url: raw.url.require("url")?,
        })
    }
}

impl TryFrom<raw::GetHealthCheckResponse> for model::GetHealthCheckResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetHealthCheckResponse) -> Result<Self, Self::Error> {
        Ok(model::GetHealthCheckResponse {
            attack: raw.attack.require("attack")?,
            cracker_binary_id: raw.cracker_binary_id.require("crackerBinaryId")?,
            hashes: raw.hashes,
            check_id: raw.check_id.require("checkId")?,
            hashlist_alias: raw.hashlist_alias.require("hashlistAlias")?,
        })
    }
}

#[cfg(test)]
mod task_id_tests {
    use super::TaskId;

    #[test]
    fn classifies_the_overloaded_field() {
        assert_eq!(TaskId::from_raw(None), TaskId::None);
        assert_eq!(TaskId::from_raw(Some(-1)), TaskId::HealthCheck);
        assert_eq!(TaskId::from_raw(Some(0)), TaskId::Id(0));
        assert_eq!(TaskId::from_raw(Some(42)), TaskId::Id(42));
        assert_eq!(TaskId::from_raw(Some(-99)), TaskId::None);
    }
}

#[cfg(test)]
mod wire_tests {
    use super::{BenchmarkType, BinaryType, Os};
    use crate::model;
    use serde_json::json;

    #[test]
    fn os_serializes_as_numeric_code() {
        assert_eq!(
            serde_json::to_value(Os::from(model::Os::Linux)).unwrap(),
            json!(0)
        );
        assert_eq!(
            serde_json::to_value(Os::from(model::Os::Windows)).unwrap(),
            json!(1)
        );
        assert_eq!(
            serde_json::to_value(Os::from(model::Os::Darwin)).unwrap(),
            json!(2)
        );
    }

    #[test]
    fn benchmark_type_round_trips_through_wire() {
        for (bench, wire) in [
            (model::BenchmarkType::Speed, "speed"),
            (model::BenchmarkType::Run, "run"),
        ] {
            assert_eq!(
                serde_json::to_value(BenchmarkType::from(bench)).unwrap(),
                json!(wire)
            );
            let decoded: BenchmarkType = serde_json::from_value(json!(wire)).unwrap();
            assert_eq!(model::BenchmarkType::from(decoded), bench);
        }
    }

    #[test]
    fn binary_type_wire_values() {
        for (binary, wire) in [
            (BinaryType::Extractor, "7zr"),
            (BinaryType::Cracker, "cracker"),
            (BinaryType::Uftpd, "uftpd"),
            (BinaryType::Preprocessor, "preprocessor"),
        ] {
            assert_eq!(serde_json::to_value(binary).unwrap(), json!(wire));
        }
    }
}

#[cfg(test)]
mod request_tests {
    use super::{BinaryType, Request};
    use crate::model::{BenchmarkType, Os};
    use serde_json::json;

    #[test]
    fn register_full() {
        let req = Request::Register {
            voucher: "89GD78tf".to_string(),
            name: "client name".to_string(),
            cpu_only: Some(true),
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "action": "register",
                "voucher": "89GD78tf",
                "name": "client name",
                "cpu-only": true
            })
        );
    }

    #[test]
    fn register_omits_cpu_only_when_none() {
        let req = Request::Register {
            voucher: "89GD78tf".to_string(),
            name: "client name".to_string(),
            cpu_only: None,
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"action": "register", "voucher": "89GD78tf", "name": "client name"})
        );
    }

    #[test]
    fn login() {
        let req = Request::Login {
            token: "GHhgdf(/&".to_string(),
            client_signature: "generic-python".to_string(),
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"action": "login", "token": "GHhgdf(/&", "clientSignature": "generic-python"})
        );
    }

    #[test]
    fn test_connection_carries_only_the_action() {
        assert_eq!(
            serde_json::to_value(Request::TestConnection).unwrap(),
            json!({"action": "testConnection"})
        );
    }

    #[test]
    fn update_information_serializes_os_as_numeric_code() {
        let req = Request::UpdateInformation {
            token: "GHhgdf(/&".to_string(),
            uid: "230-34-345-345".to_string(),
            os: Os::Linux.into(),
            devices: vec!["ATI HD7970".to_string(), "ATI HD7970".to_string()],
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "action": "updateInformation",
                "token": "GHhgdf(/&",
                "uid": "230-34-345-345",
                "os": 0,
                "devices": ["ATI HD7970", "ATI HD7970"]
            })
        );
    }

    #[test]
    fn check_client_version() {
        let req = Request::CheckClientVersion {
            token: "GHhgdf(/&".to_string(),
            version: "0.43.5".to_string(),
            agent_type: "csharp".to_string(),
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "action": "checkClientVersion",
                "token": "GHhgdf(/&",
                "version": "0.43.5",
                "type": "csharp"
            })
        );
    }

    #[test]
    fn download_binary_cracker_includes_version_id() {
        let req = Request::DownloadBinary {
            token: "GHhgdf(/&".to_string(),
            binary_type: BinaryType::Cracker,
            binary_version_id: Some(45),
            preprocessor_id: None,
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "action": "downloadBinary",
                "token": "GHhgdf(/&",
                "type": "cracker",
                "binaryVersionId": 45
            })
        );
    }

    #[test]
    fn download_binary_util_omits_optional_ids() {
        let req = Request::DownloadBinary {
            token: "GHhgdf(/&".to_string(),
            binary_type: BinaryType::Extractor,
            binary_version_id: None,
            preprocessor_id: None,
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"action": "downloadBinary", "token": "GHhgdf(/&", "type": "7zr"})
        );
    }

    #[test]
    fn get_task() {
        let req = Request::GetTask {
            token: "GHhgdf(/&".to_string(),
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"action": "getTask", "token": "GHhgdf(/&"})
        );
    }

    #[test]
    fn get_chunk() {
        let req = Request::GetChunk {
            token: "GHhgdf(/&".to_string(),
            task_id: 5,
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"action": "getChunk", "token": "GHhgdf(/&", "taskId": 5})
        );
    }

    #[test]
    fn send_keyspace() {
        let req = Request::SendKeyspace {
            token: "GHhgdf(/&".to_string(),
            task_id: 35,
            keyspace: 568000,
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "action": "sendKeyspace",
                "token": "GHhgdf(/&",
                "taskId": 35,
                "keyspace": 568000
            })
        );
    }

    #[test]
    fn send_benchmark() {
        let req = Request::SendBenchmark {
            token: "GHhgdf(/&".to_string(),
            task_id: 35,
            bench_type: BenchmarkType::Speed.into(),
            result: "674:674.74".to_string(),
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "action": "sendBenchmark",
                "token": "GHhgdf(/&",
                "taskId": 35,
                "type": "speed",
                "result": "674:674.74"
            })
        );
    }

    #[test]
    fn send_progress_omits_optional_telemetry() {
        let req = Request::SendProgress {
            token: "GHhgdf(/&".to_string(),
            chunk_id: 35,
            keyspace_progress: 568000,
            relative_progress: 4545,
            speed: 570000,
            state: 3,
            cracks: vec![
                vec![
                    "7fde65673fd28736423f23423786f".to_string(),
                    "thisisplain".to_string(),
                    "746869736973706c61696e".to_string(),
                    "787523889".to_string(),
                ],
                vec![
                    "7fde65673f28987f7423f2342378f".to_string(),
                    "otherplain".to_string(),
                    "6f74686572706c61696e".to_string(),
                    "78652".to_string(),
                ],
            ],
            debug_output: None,
            gpu_temp: None,
            gpu_util: None,
            cpu_util: None,
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "action": "sendProgress",
                "token": "GHhgdf(/&",
                "chunkId": 35,
                "keyspaceProgress": 568000,
                "relativeProgress": 4545,
                "speed": 570000,
                "state": 3,
                "cracks": [
                    ["7fde65673fd28736423f23423786f", "thisisplain", "746869736973706c61696e", "787523889"],
                    ["7fde65673f28987f7423f2342378f", "otherplain", "6f74686572706c61696e", "78652"]
                ]
            })
        );
    }

    #[test]
    fn send_progress_includes_telemetry_when_present() {
        let req = Request::SendProgress {
            token: "GHhgdf(/&".to_string(),
            chunk_id: 35,
            keyspace_progress: 568000,
            relative_progress: 4545,
            speed: 570000,
            state: 3,
            cracks: vec![],
            debug_output: Some(vec!["oops".to_string()]),
            gpu_temp: Some(vec![67]),
            gpu_util: Some(vec![99]),
            cpu_util: Some(vec![12.5]),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["debugOutput"], json!(["oops"]));
        assert_eq!(v["gpuTemp"], json!([67]));
        assert_eq!(v["gpuUtil"], json!([99]));
        assert_eq!(v["cpuUtil"], json!([12.5]));
    }

    #[test]
    fn client_error_keeps_null_chunk_id() {
        let req = Request::ClientError {
            token: "GHhgdf(/&".to_string(),
            task_id: 45,
            chunk_id: None,
            message: "This is a sample error message!".to_string(),
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "action": "clientError",
                "token": "GHhgdf(/&",
                "taskId": 45,
                "chunkId": null,
                "message": "This is a sample error message!"
            })
        );
    }

    #[test]
    fn client_error_with_chunk_id() {
        let req = Request::ClientError {
            token: "GHhgdf(/&".to_string(),
            task_id: 45,
            chunk_id: Some(1),
            message: "This is a sample error message!".to_string(),
        };

        assert_eq!(serde_json::to_value(&req).unwrap()["chunkId"], json!(1));
    }

    #[test]
    fn get_hashlist() {
        let req = Request::GetHashlist {
            token: "GHhgdf(/&".to_string(),
            hashlist_id: 23,
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"action": "getHashlist", "token": "GHhgdf(/&", "hashlistId": 23})
        );
    }

    #[test]
    fn get_found() {
        let req = Request::GetFound {
            token: "GHhgdf(/&".to_string(),
            hashlist_id: 7,
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"action": "getFound", "token": "GHhgdf(/&", "hashlistId": 7})
        );
    }

    #[test]
    fn get_file() {
        let req = Request::GetFile {
            token: "GHhgdf(/&".to_string(),
            task_id: 56,
            file: "rockyou.txt".to_string(),
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "action": "getFile",
                "token": "GHhgdf(/&",
                "taskId": 56,
                "file": "rockyou.txt"
            })
        );
    }

    #[test]
    fn get_file_status() {
        let req = Request::GetFileStatus {
            token: "GHhgdf(/&".to_string(),
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"action": "getFileStatus", "token": "GHhgdf(/&"})
        );
    }

    #[test]
    fn get_health_check() {
        let req = Request::GetHealthCheck {
            token: "GHhgdf(/&".to_string(),
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"action": "getHealthCheck", "token": "GHhgdf(/&"})
        );
    }

    #[test]
    fn send_health_check() {
        let req = Request::SendHealthCheck {
            token: "GHhgdf(/&".to_string(),
            check_id: 7,
            num_cracked: 23,
            start: 1536306884,
            end: 1536306902,
            num_gpus: 1,
            errors: vec![
                "nvmlDeviceGetTemperatureThreshold(): Not Supported".to_string(),
                "nvmlDeviceGetTemperatureThreshold(): Not Supported".to_string(),
            ],
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "action": "sendHealthCheck",
                "token": "GHhgdf(/&",
                "checkId": 7,
                "numCracked": 23,
                "start": 1536306884,
                "end": 1536306902,
                "numGpus": 1,
                "errors": [
                    "nvmlDeviceGetTemperatureThreshold(): Not Supported",
                    "nvmlDeviceGetTemperatureThreshold(): Not Supported"
                ]
            })
        );
    }

    #[test]
    fn deregister() {
        let req = Request::Deregister {
            token: "GHhgdf(/&".to_string(),
        };

        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"action": "deregister", "token": "GHhgdf(/&"})
        );
    }
}

#[cfg(test)]
mod response_tests {
    use super::raw;
    use crate::model::{
        BenchmarkType, BrainConfig, CheckClientVersionResponse, Chunk, DownloadCrackerResponse,
        DownloadPreprocessorResponse, DownloadUtilityResponse, GetChunkResponse, GetFileResponse,
        GetFileStatusResponse, GetFoundResponse, GetHashlistResponse, GetHealthCheckResponse,
        GetTaskResponse, LoginResponse, Preprocessor, RegisterResponse, SendProgressResponse,
    };
    use serde::de::DeserializeOwned;
    use serde_json::json;

    fn decode<Raw, Real>(value: serde_json::Value) -> Real
    where
        Raw: DeserializeOwned,
        Real: TryFrom<Raw>,
        <Real as TryFrom<Raw>>::Error: std::fmt::Debug,
    {
        let raw: Raw = serde_json::from_value(value).expect("raw wire decode failed");
        Real::try_from(raw).expect("raw -> real conversion failed")
    }

    #[test]
    fn register_returns_token() {
        let res: RegisterResponse = decode::<raw::RegisterResponse, _>(json!({
            "action": "register",
            "response": "SUCCESS",
            "token": "GHhgdf(/&"
        }));

        assert_eq!(res.token, "GHhgdf(/&");
    }

    #[test]
    fn register_without_token_is_rejected() {
        let raw: raw::RegisterResponse =
            serde_json::from_value(json!({"action": "register", "response": "SUCCESS"})).unwrap();

        assert!(RegisterResponse::try_from(raw).is_err());
    }

    #[test]
    fn login_fields() {
        let res: LoginResponse = decode::<raw::LoginResponse, _>(json!({
            "action": "login",
            "response": "SUCCESS",
            "server-version": "0.14.0 (abc)",
            "multicastEnabled": true,
            "timeout": 30
        }));

        assert_eq!(res.server_version, "0.14.0 (abc)");
        assert!(res.multicast_enabled);
        assert_eq!(res.timeout, 30);
    }

    #[test]
    fn login_without_all_fields_is_rejected() {
        let raw: raw::LoginResponse =
            serde_json::from_value(json!({"action": "login", "response": "SUCCESS"})).unwrap();

        assert!(LoginResponse::try_from(raw).is_err());
    }

    #[test]
    fn check_client_version_up_to_date() {
        let res: CheckClientVersionResponse = decode::<raw::CheckClientVersionResponse, _>(json!({
            "action": "checkClientVersion",
            "response": "SUCCESS",
            "version": "OK"
        }));

        assert_eq!(res, CheckClientVersionResponse::UpToDate);
    }

    #[test]
    fn check_client_version_new() {
        let res: CheckClientVersionResponse = decode::<raw::CheckClientVersionResponse, _>(json!({
            "action": "checkClientVersion",
            "response": "SUCCESS",
            "version": "NEW",
            "url": "https://example.com/getclient.php"
        }));

        assert_eq!(
            res,
            CheckClientVersionResponse::NewVersion {
                url: "https://example.com/getclient.php".to_string()
            }
        );
    }

    #[test]
    fn check_client_version_new_without_url_is_rejected() {
        let raw: raw::CheckClientVersionResponse = serde_json::from_value(json!({
            "action": "checkClientVersion",
            "response": "SUCCESS",
            "version": "NEW"
        }))
        .unwrap();

        assert!(CheckClientVersionResponse::try_from(raw).is_err());
    }

    #[test]
    fn download_binary_utility() {
        let res: DownloadUtilityResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
            "action": "downloadBinary",
            "response": "SUCCESS",
            "executable": "https://example.com/getapp.php"
        }));

        assert_eq!(
            res,
            DownloadUtilityResponse {
                url: "https://example.com/getapp.php".to_string()
            }
        );
    }

    #[test]
    fn download_binary_cracker() {
        let res: DownloadCrackerResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
            "action": "downloadBinary",
            "response": "SUCCESS",
            "url": "https://hashcat.net/files/hashcat-3.01.7z",
            "name": "Hashcat",
            "executable": "hashcat64.bin"
        }));

        assert_eq!(
            res,
            DownloadCrackerResponse {
                url: "https://hashcat.net/files/hashcat-3.01.7z".to_string(),
                name: "Hashcat".to_string(),
                binary: "hashcat64.bin".to_string()
            }
        );
    }

    #[test]
    fn download_binary_preprocessor_carries_commands() {
        let res: DownloadPreprocessorResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
            "action": "downloadBinary",
            "response": "SUCCESS",
            "url": "https://github.com/hashcat/princeprocessor/releases/download/v0.22/princeprocessor-0.22.7z",
            "name": "Prince",
            "executable": "pp.bin",
            "keyspaceCommand": "--keyspace",
            "skipCommand": "--skip",
            "limitCommand": "--limit"
        }));

        assert_eq!(
            res,
            DownloadPreprocessorResponse {
                url: "https://github.com/hashcat/princeprocessor/releases/download/v0.22/princeprocessor-0.22.7z".to_string(),
                name: "Prince".to_string(),
                binary: "pp.bin".to_string(),
                keyspace_command: Some("--keyspace".to_string()),
                skip_command: Some("--skip".to_string()),
                limit_command: Some("--limit".to_string())
            }
        );
    }

    #[test]
    fn download_binary_preprocessor_allows_absent_commands() {
        // A preprocessor without a keyspace/skip/limit flag reports them as null;
        // the agent falls back to head/tail, so the fields are optional.
        let res: DownloadPreprocessorResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
            "action": "downloadBinary",
            "response": "SUCCESS",
            "url": "https://example.com/pp.7z",
            "name": "Prince",
            "executable": "pp.bin",
            "keyspaceCommand": null,
            "skipCommand": null,
            "limitCommand": null
        }));

        assert_eq!(res.keyspace_command, None);
        assert_eq!(res.skip_command, None);
        assert_eq!(res.limit_command, None);
    }

    #[test]
    fn download_binary_utility_without_executable_is_rejected() {
        let raw: raw::DownloadBinaryResponse =
            serde_json::from_value(json!({"action": "downloadBinary", "response": "SUCCESS"}))
                .unwrap();

        assert!(DownloadUtilityResponse::try_from(raw).is_err());
    }

    #[test]
    fn download_binary_cracker_without_name_is_rejected() {
        let raw: raw::DownloadBinaryResponse = serde_json::from_value(json!({
            "action": "downloadBinary",
            "response": "SUCCESS",
            "url": "https://hashcat.net/files/hashcat-3.01.7z",
            "executable": "hashcat64.bin"
        }))
        .unwrap();

        assert!(DownloadCrackerResponse::try_from(raw).is_err());
    }

    #[test]
    fn download_binary_preprocessor_without_url_is_rejected() {
        let raw: raw::DownloadBinaryResponse = serde_json::from_value(json!({
            "action": "downloadBinary",
            "response": "SUCCESS",
            "name": "Prince",
            "executable": "pp.bin"
        }))
        .unwrap();

        assert!(DownloadPreprocessorResponse::try_from(raw).is_err());
    }

    #[test]
    fn get_task_no_task_available() {
        let res: GetTaskResponse = decode::<raw::GetTaskResponse, _>(json!({
            "action": "getTask",
            "response": "SUCCESS",
            "taskId": null,
            "reason": "No task available!"
        }));

        assert_eq!(
            res,
            GetTaskResponse::NoTask {
                reason: Some("No task available!".to_string())
            }
        );
    }

    #[test]
    fn get_task_health_check() {
        let res: GetTaskResponse = decode::<raw::GetTaskResponse, _>(json!({
            "action": "getTask",
            "response": "SUCCESS",
            "taskId": -1
        }));

        assert_eq!(res, GetTaskResponse::HealthCheck);
    }

    #[test]
    fn get_task_full_assignment_without_conditional_groups() {
        let res: GetTaskResponse = decode::<raw::GetTaskResponse, _>(json!({
            "action": "getTask",
            "response": "SUCCESS",
            "taskId": 25,
            "crackerId": 45,
            "attackcmd": "#HL# -a 3 ?a?a?a?a --hash-type=0",
            "cmdpars": " --hash-type=0 ",
            "hashlistId": 13,
            "bench": 30,
            "statustimer": 5,
            "files": ["rockyou.txt", "wordlist.txt"],
            "benchType": "speed",
            "hashlistAlias": "#HL#",
            "keyspace": 0,
            "usePreprocessor": false,
            "preprocessor": null,
            "preprocessorCommand": null,
            "enforcePipe": false,
            "slowHash": false,
            "useBrain": false
        }));

        let GetTaskResponse::Task(task) = res else {
            panic!("expected a task assignment, got {res:?}");
        };
        assert_eq!(task.task_id, 25);
        assert_eq!(task.cracker_id, 45);
        assert_eq!(task.attack_command, "#HL# -a 3 ?a?a?a?a --hash-type=0");
        assert_eq!(task.bench_type, BenchmarkType::Speed);
        assert_eq!(task.keyspace, 0);
        assert_eq!(
            task.files,
            vec!["rockyou.txt".to_string(), "wordlist.txt".to_string()]
        );
        assert!(!task.slow_hash);
        assert!(task.preprocessor.is_none());
        assert!(task.brain.is_none());
    }

    #[test]
    fn get_task_with_brain_and_preprocessor() {
        let res: GetTaskResponse = decode::<raw::GetTaskResponse, _>(json!({
            "action": "getTask",
            "response": "SUCCESS",
            "taskId": 25,
            "crackerId": 45,
            "attackcmd": "#HL# -a 3 ?a?a?a?a --hash-type=0",
            "cmdpars": " --hash-type=0 ",
            "hashlistId": 13,
            "bench": 30,
            "statustimer": 5,
            "files": ["rockyou.txt", "wordlist.txt"],
            "benchType": "speed",
            "hashlistAlias": "#HL#",
            "keyspace": 0,
            "enforcePipe": false,
            "slowHash": false,
            "usePreprocessor": true,
            "preprocessor": 2,
            "preprocessorCommand": "wordlist.txt",
            "useBrain": true,
            "brainHost": "10.20.30.40",
            "brainPort": 1234,
            "brainPass": "password",
            "brainFeatures": 3
        }));

        let GetTaskResponse::Task(task) = res else {
            panic!("expected a task assignment, got {res:?}");
        };
        assert_eq!(
            task.preprocessor,
            Some(Preprocessor {
                id: 2,
                command: "wordlist.txt".to_string()
            })
        );
        assert_eq!(
            task.brain,
            Some(BrainConfig {
                host: "10.20.30.40".to_string(),
                port: 1234,
                pass: "password".to_string(),
                features: 3
            })
        );
    }

    #[test]
    fn get_task_brain_flag_without_fields_is_rejected() {
        let raw: raw::GetTaskResponse = serde_json::from_value(json!({
            "action": "getTask",
            "response": "SUCCESS",
            "taskId": 1,
            "crackerId": 3,
            "attackcmd": "#HL#",
            "cmdpars": "",
            "hashlistId": 7,
            "bench": 30,
            "statustimer": 5,
            "files": [],
            "benchType": "run",
            "hashlistAlias": "#HL#",
            "keyspace": 100,
            "enforcePipe": false,
            "slowHash": false,
            "usePreprocessor": false,
            "useBrain": true
        }))
        .unwrap();

        assert!(GetTaskResponse::try_from(raw).is_err());
    }

    #[test]
    fn get_chunk_ok_variant() {
        let res: GetChunkResponse = decode::<raw::GetChunkResponse, _>(json!({
            "action": "getChunk",
            "response": "SUCCESS",
            "status": "OK",
            "chunkId": 13,
            "skip": 45000,
            "length": 10000
        }));

        assert_eq!(
            res,
            GetChunkResponse::Chunk(Chunk {
                id: 13,
                skip: 45000,
                length: 10000
            })
        );
    }

    #[test]
    fn get_chunk_ok_without_chunk_fields_is_rejected() {
        let raw: raw::GetChunkResponse = serde_json::from_value(json!({
            "action": "getChunk",
            "response": "SUCCESS",
            "status": "OK"
        }))
        .unwrap();

        assert!(GetChunkResponse::try_from(raw).is_err());
    }

    #[test]
    fn get_chunk_status_only_variants() {
        for (status, expected) in [
            ("keyspace_required", GetChunkResponse::KeyspaceRequired),
            ("benchmark", GetChunkResponse::BenchmarkRequired),
            ("fully_dispatched", GetChunkResponse::FullyDispatched),
            ("cracker_update", GetChunkResponse::CrackerUpdate),
            ("health_check", GetChunkResponse::HealthCheck),
        ] {
            let res: GetChunkResponse = decode::<raw::GetChunkResponse, _>(json!({
                "action": "getChunk",
                "response": "SUCCESS",
                "status": status
            }));
            assert_eq!(res, expected, "status {status}");
        }
    }

    #[test]
    fn send_progress_stop_branch() {
        let raw: raw::SendProgressResponse = serde_json::from_value(json!({
            "action": "sendProgress",
            "response": "SUCCESS",
            "cracked": 2,
            "skipped": 1,
            "agent": "stop"
        }))
        .unwrap();

        assert_eq!(
            SendProgressResponse::from(raw),
            SendProgressResponse::Stop {
                cracked: 2,
                skipped: 1
            }
        );
    }

    #[test]
    fn send_progress_continue_branch_carries_zaps() {
        let raw: raw::SendProgressResponse = serde_json::from_value(json!({
            "action": "sendProgress",
            "response": "SUCCESS",
            "cracked": 2,
            "skipped": 0,
            "zaps": ["87634876fe7f7df5e76f56a757", "7863487563874ffefe67575745"]
        }))
        .unwrap();

        assert_eq!(
            SendProgressResponse::from(raw),
            SendProgressResponse::Continue {
                cracked: 2,
                skipped: 0,
                zaps: vec![
                    "87634876fe7f7df5e76f56a757".to_string(),
                    "7863487563874ffefe67575745".to_string()
                ]
            }
        );
    }

    #[test]
    fn send_progress_defaults_to_continue_when_fields_absent() {
        let raw: raw::SendProgressResponse = serde_json::from_value(json!({
            "action": "sendProgress",
            "response": "SUCCESS"
        }))
        .unwrap();

        assert_eq!(
            SendProgressResponse::from(raw),
            SendProgressResponse::Continue {
                cracked: 0,
                skipped: 0,
                zaps: vec![]
            }
        );
    }

    #[test]
    fn get_file() {
        let res: GetFileResponse = decode::<raw::GetFileResponse, _>(json!({
            "action": "getFile",
            "response": "SUCCESS",
            "filename": "rockyou.txt",
            "extension": ".txt",
            "url": "get.php?file=5&token=GHhgdf(/&",
            "filesize": 267729
        }));

        assert_eq!(res.filename, "rockyou.txt");
        assert_eq!(res.extension, ".txt");
        assert_eq!(res.url, "get.php?file=5&token=GHhgdf(/&");
        assert_eq!(res.filesize, 267729);
    }

    #[test]
    fn get_file_without_all_fields_is_rejected() {
        let raw: raw::GetFileResponse = serde_json::from_value(json!({
            "action": "getFile",
            "response": "SUCCESS",
            "filename": "rockyou.txt"
        }))
        .unwrap();

        assert!(GetFileResponse::try_from(raw).is_err());
    }

    #[test]
    fn get_file_status() {
        let res: GetFileStatusResponse = raw::GetFileStatusResponse {
            filenames: vec!["a.txt".to_string(), "b.7z".to_string()],
        }
        .into();

        assert_eq!(res.filenames, vec!["a.txt".to_string(), "b.7z".to_string()]);
    }

    #[test]
    fn get_file_status_empty() {
        let raw: raw::GetFileStatusResponse = serde_json::from_value(json!({
            "action": "getFileStatus",
            "response": "SUCCESS"
        }))
        .unwrap();
        let res = GetFileStatusResponse::from(raw);
        assert!(res.filenames.is_empty());
    }

    #[test]
    fn get_hashlist() {
        let res: GetHashlistResponse = decode::<raw::GetHashlistResponse, _>(json!({
            "action": "getHashlist",
            "response": "SUCCESS",
            "url": "get.php?hashlist=5&token=GHhgdf(/&"
        }));

        assert_eq!(res.url, "get.php?hashlist=5&token=GHhgdf(/&");
    }

    #[test]
    fn get_found() {
        let res: GetFoundResponse = decode::<raw::GetFoundResponse, _>(json!({
            "action": "getFound",
            "response": "SUCCESS",
            "url": "getFound.php?hashlist=7"
        }));

        assert_eq!(res.url, "getFound.php?hashlist=7");
    }

    #[test]
    fn get_health_check() {
        let res: GetHealthCheckResponse = decode::<raw::GetHealthCheckResponse, _>(json!({
            "action": "getHealthCheck",
            "response": "SUCCESS",
            "attack": "#HL# -a 3 -1 ?l?u?d ?1?1?1?1?1",
            "crackerBinaryId": 1,
            "hashes": ["9f650d4ef70eead895e7a03ce0f83e88", "24a7bdfd14bca7f9d14154c0800a833d"],
            "checkId": 7,
            "hashlistAlias": "#HL#"
        }));

        assert_eq!(res.attack, "#HL# -a 3 -1 ?l?u?d ?1?1?1?1?1");
        assert_eq!(res.cracker_binary_id, 1);
        assert_eq!(
            res.hashes,
            vec![
                "9f650d4ef70eead895e7a03ce0f83e88".to_string(),
                "24a7bdfd14bca7f9d14154c0800a833d".to_string()
            ]
        );
        assert_eq!(res.check_id, 7);
        assert_eq!(res.hashlist_alias, "#HL#");
    }

    #[test]
    fn get_health_check_without_all_fields_is_rejected() {
        let raw: raw::GetHealthCheckResponse = serde_json::from_value(json!({
            "action": "getHealthCheck",
            "response": "SUCCESS",
            "attack": " --hash-type=0 #HL# -a 3 ?a?a?a"
        }))
        .unwrap();

        assert!(GetHealthCheckResponse::try_from(raw).is_err());
    }
}
