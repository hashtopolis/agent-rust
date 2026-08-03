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
            token: raw.token.ok_or(ProtocolError::MissingField("token"))?,
        })
    }
}

impl TryFrom<raw::LoginResponse> for model::LoginResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::LoginResponse) -> Result<Self, Self::Error> {
        Ok(model::LoginResponse {
            timeout: raw.timeout.ok_or(ProtocolError::MissingField("timeout"))?,
            multicast_enabled: raw
                .multicast_enabled
                .ok_or(ProtocolError::MissingField("multicastEnabled"))?,
            server_version: raw
                .server_version
                .ok_or(ProtocolError::MissingField("server-version"))?,
        })
    }
}

impl TryFrom<raw::CheckClientVersionResponse> for model::CheckClientVersionResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::CheckClientVersionResponse) -> Result<Self, Self::Error> {
        match raw.version.ok_or(ProtocolError::MissingField("version"))? {
            UpdateVersion::UpToDate => Ok(model::CheckClientVersionResponse::UpToDate),
            UpdateVersion::NewVersion => Ok(model::CheckClientVersionResponse::NewVersion {
                url: raw.url.ok_or(ProtocolError::MissingField("url"))?,
            }),
        }
    }
}

impl TryFrom<raw::DownloadBinaryResponse> for model::DownloadUtilityResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::DownloadBinaryResponse) -> Result<Self, Self::Error> {
        Ok(model::DownloadUtilityResponse {
            url: raw
                .executable
                .ok_or(ProtocolError::MissingField("executable"))?,
        })
    }
}

impl TryFrom<raw::DownloadBinaryResponse> for model::DownloadCrackerResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::DownloadBinaryResponse) -> Result<Self, Self::Error> {
        Ok(model::DownloadCrackerResponse {
            url: raw.url.ok_or(ProtocolError::MissingField("url"))?,
            name: raw.name.ok_or(ProtocolError::MissingField("name"))?,
            binary: raw
                .executable
                .ok_or(ProtocolError::MissingField("executable"))?,
        })
    }
}

impl TryFrom<raw::DownloadBinaryResponse> for model::DownloadPreprocessorResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::DownloadBinaryResponse) -> Result<Self, Self::Error> {
        Ok(model::DownloadPreprocessorResponse {
            url: raw.url.ok_or(ProtocolError::MissingField("url"))?,
            name: raw.name.ok_or(ProtocolError::MissingField("name"))?,
            binary: raw
                .executable
                .ok_or(ProtocolError::MissingField("executable"))?,
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
                host: raw
                    .brain_host
                    .ok_or(ProtocolError::MissingField("brainHost"))?,
                port: raw
                    .brain_port
                    .ok_or(ProtocolError::MissingField("brainPort"))?,
                pass: raw
                    .brain_pass
                    .ok_or(ProtocolError::MissingField("brainPass"))?,
                features: raw
                    .brain_features
                    .ok_or(ProtocolError::MissingField("brainFeatures"))?,
            })
        } else {
            None
        };

        Ok(model::GetTaskResponse::Task(Box::new(TaskAssignment {
            task_id,
            cracker_id: raw
                .cracker_id
                .ok_or(ProtocolError::MissingField("crackerId"))?,
            attack_command: raw
                .attack_command
                .ok_or(ProtocolError::MissingField("attackcmd"))?,
            cmd_parameters: raw
                .cmd_parameters
                .ok_or(ProtocolError::MissingField("cmdpars"))?,
            hashlist_id: raw
                .hashlist_id
                .ok_or(ProtocolError::MissingField("hashlistId"))?,
            benchmark: raw.benchmark.ok_or(ProtocolError::MissingField("bench"))?,
            status_timer: raw
                .status_timer
                .ok_or(ProtocolError::MissingField("statustimer"))?,
            files: raw.files,
            bench_type: raw
                .bench_type
                .map(model::BenchmarkType::from)
                .ok_or(ProtocolError::MissingField("benchType"))?,
            hashlist_alias: raw
                .hashlist_alias
                .ok_or(ProtocolError::MissingField("hashlistAlias"))?,
            keyspace: raw
                .keyspace
                .ok_or(ProtocolError::MissingField("keyspace"))?,
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
                id: raw.chunk_id.ok_or(ProtocolError::MissingField("chunkId"))?,
                skip: raw.skip.ok_or(ProtocolError::MissingField("skip"))?,
                length: raw.length.ok_or(ProtocolError::MissingField("length"))?,
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
            filename: raw
                .filename
                .ok_or(ProtocolError::MissingField("filename"))?,
            extension: raw
                .extension
                .ok_or(ProtocolError::MissingField("extension"))?,
            url: raw.url.ok_or(ProtocolError::MissingField("url"))?,
            filesize: raw
                .filesize
                .ok_or(ProtocolError::MissingField("filesize"))?,
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
            url: raw.url.ok_or(ProtocolError::MissingField("url"))?,
        })
    }
}

impl TryFrom<raw::GetFoundResponse> for model::GetFoundResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetFoundResponse) -> Result<Self, Self::Error> {
        Ok(model::GetFoundResponse {
            url: raw.url.ok_or(ProtocolError::MissingField("url"))?,
        })
    }
}

impl TryFrom<raw::GetHealthCheckResponse> for model::GetHealthCheckResponse {
    type Error = ProtocolError;

    fn try_from(raw: raw::GetHealthCheckResponse) -> Result<Self, Self::Error> {
        Ok(model::GetHealthCheckResponse {
            attack: raw.attack.ok_or(ProtocolError::MissingField("attack"))?,
            cracker_binary_id: raw
                .cracker_binary_id
                .ok_or(ProtocolError::MissingField("crackerBinaryId"))?,
            hashes: raw.hashes,
            check_id: raw.check_id.ok_or(ProtocolError::MissingField("checkId"))?,
            hashlist_alias: raw
                .hashlist_alias
                .ok_or(ProtocolError::MissingField("hashlistAlias"))?,
        })
    }
}
