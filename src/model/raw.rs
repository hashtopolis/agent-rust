//! Wire representations: exactly what goes out in a request and comes back in
//! a response, before any interpretation. Translation to and from the domain
//! types in [`super`] lives in [`super::convert`].

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum BenchmarkType {
    #[serde(rename = "speed")]
    Speed,
    #[serde(rename = "run")]
    Run,
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
        // Numeric OS code; see `From<model::Os> for u8` in `super::convert`.
        os: u8,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "response")]
pub(crate) enum Reply<P> {
    #[serde(rename = "SUCCESS")]
    Success(P),
    #[serde(rename = "ERROR")]
    Error {
        #[serde(default)]
        message: Option<String>,
    },
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
