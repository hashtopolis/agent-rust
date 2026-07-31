//! Translation between the wire types in [`super::raw`] and the domain types
//! in [`super`]. Every field the server may omit is checked here, so the domain
//! types carry no `Option`s that exist for wire reasons alone.

use thiserror::Error;

use super::raw::{self, ChunkStatus, UpdateVersion};
use super::{BrainConfig, Chunk, Preprocessor, TaskAssignment};
use crate::model;

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

impl From<model::Os> for u8 {
    fn from(os: model::Os) -> u8 {
        match os {
            model::Os::Linux => 0,
            model::Os::Windows => 1,
            model::Os::Darwin => 2,
        }
    }
}

impl From<model::BenchmarkType> for raw::BenchmarkType {
    fn from(bench: model::BenchmarkType) -> Self {
        match bench {
            model::BenchmarkType::Speed => raw::BenchmarkType::Speed,
            model::BenchmarkType::Run => raw::BenchmarkType::Run,
        }
    }
}

impl From<raw::BenchmarkType> for model::BenchmarkType {
    fn from(bench: raw::BenchmarkType) -> Self {
        match bench {
            raw::BenchmarkType::Speed => model::BenchmarkType::Speed,
            raw::BenchmarkType::Run => model::BenchmarkType::Run,
        }
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
