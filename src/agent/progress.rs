//! Progress reporting from a running chunk back to the server.

use crate::client::Client;
use crate::cracker::{ProgressCommand, ProgressSink, ProgressUpdateError};
use crate::model::{ProgressReport, SendProgressResponse};
use crate::transport::Transport;

pub(super) struct ClientSink<'a, T: Transport> {
    pub(super) client: &'a Client<T>,
    pub(super) task_id: u64,
    pub(super) chunk_id: u64,
}

impl<T: Transport> ProgressSink for ClientSink<'_, T> {
    async fn send_progress(
        &self,
        report: ProgressReport,
    ) -> Result<ProgressCommand, ProgressUpdateError> {
        let response = self.client.send_progress(report).await;

        match response {
            Ok(SendProgressResponse::Continue { zaps, .. }) => {
                Ok(ProgressCommand::Continue { zaps })
            }
            Ok(SendProgressResponse::Stop { .. }) => Ok(ProgressCommand::Stop),
            // The server refused the update (chunk aborted, manually interrupted,
            // agent marked inactive, token rejected): stop and let the loop
            // re-sync with a fresh task.
            Ok(SendProgressResponse::Rejected { reason }) => {
                tracing::warn!(?reason, "server rejected progress; stopping chunk");
                Ok(ProgressCommand::Stop)
            }
            // No usable answer (unreachable server, timeout, unparsable reply):
            // keep cracking and retry on the next update, retaining unsent state
            Err(error) => {
                tracing::warn!(%error, "failed to deliver progress; will retry");
                Err(ProgressUpdateError(error.to_string()))
            }
        }
    }

    async fn report_error(&self, message: String) {
        let response = self
            .client
            .client_error(self.task_id, Some(self.chunk_id), message)
            .await;

        if let Err(error) = response {
            tracing::error!(%error, "failed to report cracker error")
        }
    }
}
