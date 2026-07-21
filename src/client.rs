use std::fmt;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::model::{
    AckResponse, BenchmarkType, BinaryType, CheckClientVersionResponse, DownloadBinaryResponse,
    GetChunkResponse, GetFileResponse, GetFileStatusResponse, GetFoundResponse,
    GetHashlistResponse, GetHealthCheckResponse, GetTaskResponse, LoginResponse, Os,
    ProgressReport, RegisterResponse, SendProgressResponse,
};
use crate::protocol::{ProtocolError, Request, raw};
use crate::transport::{Transport, TransportError};

#[derive(Debug)]
pub enum ClientError {
    Transport(TransportError),
    Server {
        action: &'static str,
        message: Option<String>,
    },
    Codec(serde_json::Error),
    Protocol(ProtocolError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Transport(e) => write!(f, "transport error: {e}"),
            ClientError::Server { action, message } => match message {
                Some(m) => write!(f, "server error on '{action}': {m}"),
                None => write!(f, "server error on '{action}'"),
            },
            ClientError::Codec(e) => write!(f, "codec error: {e}"),
            ClientError::Protocol(e) => write!(f, "protocol error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Transport(e) => Some(e),
            ClientError::Codec(e) => Some(e),
            ClientError::Protocol(e) => Some(e),
            ClientError::Server { .. } => None,
        }
    }
}

impl From<TransportError> for ClientError {
    fn from(e: TransportError) -> Self {
        ClientError::Transport(e)
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(e: serde_json::Error) -> Self {
        ClientError::Codec(e)
    }
}

impl From<ProtocolError> for ClientError {
    fn from(e: ProtocolError) -> Self {
        ClientError::Protocol(e)
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

    pub fn set_token(&mut self, token: impl Into<String>) {
        self.token = token.into();
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub async fn test_connection(&self) -> Result<AckResponse, ClientError> {
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
        os: Os,
        devices: Vec<String>,
    ) -> Result<AckResponse, ClientError> {
        self.call_ack(
            "updateInformation",
            Request::UpdateInformation {
                token: self.token_owned(),
                uid: uid.into(),
                os: os.into(),
                devices,
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

    pub async fn download_binary(
        &self,
        binary_type: BinaryType,
        binary_version_id: Option<u64>,
        preprocessor_id: Option<u64>,
    ) -> Result<DownloadBinaryResponse, ClientError> {
        let raw: raw::DownloadBinaryResponse = self
            .call(
                "downloadBinary",
                Request::DownloadBinary {
                    token: self.token_owned(),
                    binary_type: binary_type.into(),
                    binary_version_id,
                    preprocessor_id,
                },
            )
            .await?;
        Ok(DownloadBinaryResponse::try_from(raw)?)
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

    pub async fn send_keyspace(
        &self,
        task_id: u64,
        keyspace: u64,
    ) -> Result<AckResponse, ClientError> {
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
    ) -> Result<AckResponse, ClientError> {
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
    ) -> Result<AckResponse, ClientError> {
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
        errors: Vec<String>,
    ) -> Result<AckResponse, ClientError> {
        self.call_ack_expecting(
            "sendHealthCheck",
            Request::SendHealthCheck {
                token: self.token_owned(),
                check_id,
                num_cracked,
                start,
                end,
                num_gpus,
                errors,
            },
            raw::Status::Ok,
        )
        .await
    }

    pub async fn deregister(&self) -> Result<AckResponse, ClientError> {
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
        self.call_expecting(action, request, raw::Status::Success)
            .await
    }

    /// Like [`Client::call`] but gated on a caller-supplied success token.
    /// Every action answers with "SUCCESS" except `sendHealthCheck`, which the
    /// server answers with "OK" (see `APISendHealthCheck` server-side).
    async fn call_expecting<R: DeserializeOwned>(
        &self,
        action: &'static str,
        request: Request,
        expected_status: raw::Status,
    ) -> Result<R, ClientError> {
        let body = serde_json::to_value(&request)?;
        let value = self.transport.post_json(&body).await?;
        check_status(&value, action, expected_status)?;
        Ok(serde_json::from_value(value)?)
    }

    async fn call_ack(
        &self,
        action: &'static str,
        request: Request,
    ) -> Result<AckResponse, ClientError> {
        self.call_ack_expecting(action, request, raw::Status::Success)
            .await
    }

    async fn call_ack_expecting(
        &self,
        action: &'static str,
        request: Request,
        expected_status: raw::Status,
    ) -> Result<AckResponse, ClientError> {
        let raw: raw::AckResponse = self
            .call_expecting(action, request, expected_status)
            .await?;
        Ok(raw.into())
    }
}

fn check_status(
    value: &Value,
    action: &'static str,
    expected_status: raw::Status,
) -> Result<(), ClientError> {
    let status = value
        .get("response")
        .and_then(|response| serde_json::from_value::<raw::Status>(response.clone()).ok());
    match status {
        Some(status) if status == expected_status => Ok(()),
        _ => Err(ClientError::Server {
            action,
            message: value
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }),
    }
}
