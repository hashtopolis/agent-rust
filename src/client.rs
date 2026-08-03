use serde::de::{DeserializeOwned, IgnoredAny};
use thiserror::Error;

use crate::model::raw::{self, BinaryType, Request};
use crate::model::{
    BenchmarkType, CheckClientVersionResponse, DownloadCrackerResponse,
    DownloadPreprocessorResponse, DownloadUtilityResponse, GetChunkResponse, GetFileResponse,
    GetFileStatusResponse, GetFoundResponse, GetHashlistResponse, GetHealthCheckResponse,
    GetTaskResponse, LoginResponse, Os, ProgressReport, ProtocolError, RegisterResponse,
    SendProgressResponse,
};
use crate::transport::{Transport, TransportError};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("server error on '{action}'{}", message.as_deref().map(|m| format!(": {m}")).unwrap_or_default())]
    Server {
        action: &'static str,
        message: Option<String>,
    },
    #[error("codec error: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

/// A bad token is a plain `ERROR` reply, so this message text is the only way to
/// tell it apart.
const INVALID_TOKEN_MESSAGE: &str = "Invalid token!";

impl ClientError {
    pub fn is_invalid_token(&self) -> bool {
        matches!(
            self,
            ClientError::Server {
                message: Some(message),
                ..
            } if message == INVALID_TOKEN_MESSAGE
        )
    }
}

#[derive(Debug, Clone)]
pub struct Client<T: Transport> {
    transport: T,
    token: String,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            token: String::new(),
        }
    }

    pub fn with_token(transport: T, token: impl Into<String>) -> Self {
        Self {
            transport,
            token: token.into(),
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub async fn test_connection(&self) -> Result<(), ClientError> {
        self.call_ack("testConnection", Request::TestConnection)
            .await
    }

    pub async fn register(
        &self,
        voucher: impl Into<String>,
        name: impl Into<String>,
        cpu_only: Option<bool>,
    ) -> Result<RegisterResponse, ClientError> {
        let raw: raw::RegisterResponse = self
            .call(
                "register",
                Request::Register {
                    voucher: voucher.into(),
                    name: name.into(),
                    cpu_only,
                },
            )
            .await?;
        Ok(RegisterResponse::try_from(raw)?)
    }

    pub async fn login(
        &self,
        client_signature: impl Into<String>,
    ) -> Result<LoginResponse, ClientError> {
        let raw: raw::LoginResponse = self
            .call(
                "login",
                Request::Login {
                    token: self.token_owned(),
                    client_signature: client_signature.into(),
                },
            )
            .await?;
        Ok(LoginResponse::try_from(raw)?)
    }

    pub async fn update_information(
        &self,
        uid: impl Into<String>,
        devices: &[impl AsRef<str>],
    ) -> Result<(), ClientError> {
        self.call_ack(
            "updateInformation",
            Request::UpdateInformation {
                token: self.token_owned(),
                uid: uid.into(),
                os: Os::detect().into(),
                devices: to_string_vec(devices),
            },
        )
        .await
    }

    pub async fn check_client_version(
        &self,
        version: impl Into<String>,
        agent_type: impl Into<String>,
    ) -> Result<CheckClientVersionResponse, ClientError> {
        let raw: raw::CheckClientVersionResponse = self
            .call(
                "checkClientVersion",
                Request::CheckClientVersion {
                    token: self.token_owned(),
                    version: version.into(),
                    agent_type: agent_type.into(),
                },
            )
            .await?;
        Ok(CheckClientVersionResponse::try_from(raw)?)
    }

    pub async fn download_extractor(&self) -> Result<DownloadUtilityResponse, ClientError> {
        self.download_utility(BinaryType::Extractor).await
    }

    pub async fn download_uftpd(&self) -> Result<DownloadUtilityResponse, ClientError> {
        self.download_utility(BinaryType::Uftpd).await
    }

    pub async fn download_cracker(
        &self,
        binary_version_id: u64,
    ) -> Result<DownloadCrackerResponse, ClientError> {
        let raw: raw::DownloadBinaryResponse = self
            .call(
                "downloadBinary",
                Request::DownloadBinary {
                    token: self.token_owned(),
                    binary_type: BinaryType::Cracker,
                    binary_version_id: Some(binary_version_id),
                    preprocessor_id: None,
                },
            )
            .await?;
        Ok(DownloadCrackerResponse::try_from(raw)?)
    }

    pub async fn download_preprocessor(
        &self,
        preprocessor_id: u64,
    ) -> Result<DownloadPreprocessorResponse, ClientError> {
        let raw: raw::DownloadBinaryResponse = self
            .call(
                "downloadBinary",
                Request::DownloadBinary {
                    token: self.token_owned(),
                    binary_type: BinaryType::Preprocessor,
                    binary_version_id: None,
                    preprocessor_id: Some(preprocessor_id),
                },
            )
            .await?;
        Ok(DownloadPreprocessorResponse::try_from(raw)?)
    }

    async fn download_utility(
        &self,
        binary_type: BinaryType,
    ) -> Result<DownloadUtilityResponse, ClientError> {
        let raw: raw::DownloadBinaryResponse = self
            .call(
                "downloadBinary",
                Request::DownloadBinary {
                    token: self.token_owned(),
                    binary_type,
                    binary_version_id: None,
                    preprocessor_id: None,
                },
            )
            .await?;
        Ok(DownloadUtilityResponse::try_from(raw)?)
    }

    pub async fn get_task(&self) -> Result<GetTaskResponse, ClientError> {
        let raw: raw::GetTaskResponse = self
            .call(
                "getTask",
                Request::GetTask {
                    token: self.token_owned(),
                },
            )
            .await?;
        Ok(GetTaskResponse::try_from(raw)?)
    }

    pub async fn get_chunk(&self, task_id: u64) -> Result<GetChunkResponse, ClientError> {
        let raw: raw::GetChunkResponse = self
            .call(
                "getChunk",
                Request::GetChunk {
                    token: self.token_owned(),
                    task_id,
                },
            )
            .await?;
        Ok(GetChunkResponse::try_from(raw)?)
    }

    pub async fn send_keyspace(&self, task_id: u64, keyspace: u64) -> Result<(), ClientError> {
        self.call_ack(
            "sendKeyspace",
            Request::SendKeyspace {
                token: self.token_owned(),
                task_id,
                keyspace,
            },
        )
        .await
    }

    pub async fn send_benchmark(
        &self,
        task_id: u64,
        bench_type: BenchmarkType,
        result: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.call_ack(
            "sendBenchmark",
            Request::SendBenchmark {
                token: self.token_owned(),
                task_id,
                bench_type: bench_type.into(),
                result: result.into(),
            },
        )
        .await
    }

    pub async fn send_progress(
        &self,
        report: ProgressReport,
    ) -> Result<SendProgressResponse, ClientError> {
        let raw: raw::SendProgressResponse = self
            .call(
                "sendProgress",
                Request::SendProgress {
                    token: self.token_owned(),
                    chunk_id: report.chunk_id,
                    keyspace_progress: report.keyspace_progress,
                    relative_progress: report.relative_progress,
                    speed: report.speed,
                    state: report.state,
                    cracks: report.cracks,
                    debug_output: report.debug_output,
                    gpu_temp: report.gpu_temp,
                    gpu_util: report.gpu_util,
                    cpu_util: report.cpu_util,
                },
            )
            .await?;
        Ok(SendProgressResponse::from(raw))
    }

    pub async fn client_error(
        &self,
        task_id: u64,
        chunk_id: Option<u64>,
        message: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.call_ack(
            "clientError",
            Request::ClientError {
                token: self.token_owned(),
                task_id,
                chunk_id,
                message: message.into(),
            },
        )
        .await
    }

    pub async fn get_hashlist(&self, hashlist_id: u64) -> Result<GetHashlistResponse, ClientError> {
        let raw: raw::GetHashlistResponse = self
            .call(
                "getHashlist",
                Request::GetHashlist {
                    token: self.token_owned(),
                    hashlist_id,
                },
            )
            .await?;
        Ok(GetHashlistResponse::try_from(raw)?)
    }

    pub async fn get_found(&self, hashlist_id: u64) -> Result<GetFoundResponse, ClientError> {
        let raw: raw::GetFoundResponse = self
            .call(
                "getFound",
                Request::GetFound {
                    token: self.token_owned(),
                    hashlist_id,
                },
            )
            .await?;
        Ok(GetFoundResponse::try_from(raw)?)
    }

    pub async fn get_file(
        &self,
        task_id: u64,
        file: impl Into<String>,
    ) -> Result<GetFileResponse, ClientError> {
        let raw: raw::GetFileResponse = self
            .call(
                "getFile",
                Request::GetFile {
                    token: self.token_owned(),
                    task_id,
                    file: file.into(),
                },
            )
            .await?;
        Ok(GetFileResponse::try_from(raw)?)
    }

    pub async fn get_file_status(&self) -> Result<GetFileStatusResponse, ClientError> {
        let raw: raw::GetFileStatusResponse = self
            .call(
                "getFileStatus",
                Request::GetFileStatus {
                    token: self.token_owned(),
                },
            )
            .await?;
        Ok(GetFileStatusResponse::from(raw))
    }

    pub async fn get_health_check(&self) -> Result<GetHealthCheckResponse, ClientError> {
        let raw: raw::GetHealthCheckResponse = self
            .call(
                "getHealthCheck",
                Request::GetHealthCheck {
                    token: self.token_owned(),
                },
            )
            .await?;
        Ok(GetHealthCheckResponse::try_from(raw)?)
    }

    pub async fn send_health_check(
        &self,
        check_id: u64,
        num_cracked: u64,
        start: i64,
        end: i64,
        num_gpus: u32,
        errors: &[impl AsRef<str>],
    ) -> Result<(), ClientError> {
        self.call_ack(
            "sendHealthCheck",
            Request::SendHealthCheck {
                token: self.token_owned(),
                check_id,
                num_cracked,
                start,
                end,
                num_gpus,
                errors: to_string_vec(errors),
            },
        )
        .await
    }

    pub async fn deregister(&self) -> Result<(), ClientError> {
        self.call_ack(
            "deregister",
            Request::Deregister {
                token: self.token_owned(),
            },
        )
        .await
    }

    fn token_owned(&self) -> String {
        self.token.clone()
    }

    async fn call<R: DeserializeOwned>(
        &self,
        action: &'static str,
        request: Request,
    ) -> Result<R, ClientError> {
        let body = serde_json::to_value(&request)?;
        let value = self.transport.post_json(&body).await?;
        match serde_json::from_value::<raw::Reply<R>>(value)? {
            raw::Reply::Success(payload) => Ok(payload),
            raw::Reply::Error { message } => Err(ClientError::Server { action, message }),
            raw::Reply::Other => Err(ClientError::Server {
                action,
                message: None,
            }),
        }
    }

    /// Runs an action whose reply carries nothing beyond the status, so there is
    /// no payload to decode once [`Client::call`] has accepted it.
    async fn call_ack(&self, action: &'static str, request: Request) -> Result<(), ClientError> {
        self.call::<IgnoredAny>(action, request).await?;
        Ok(())
    }
}

fn to_string_vec(items: &[impl AsRef<str>]) -> Vec<String> {
    items.iter().map(|s| s.as_ref().to_owned()).collect()
}
