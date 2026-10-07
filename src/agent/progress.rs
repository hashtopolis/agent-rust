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
        is_keepalive: bool,
    ) -> Result<ProgressCommand, ProgressUpdateError> {
        let new_cracks = report.cracks.len();
        let keyspace_progress = report.keyspace_progress;
        let state = report.state;

        match self.client.send_progress(report).await {
            Ok(SendProgressResponse::Continue {
                zaps,
                cracked,
                skipped,
            }) => {
                if is_keepalive {
                    tracing::debug!(
                        chunk_id = self.chunk_id,
                        keyspace_progress,
                        state,
                        new_cracks,
                        cracked,
                        skipped,
                        zaps = zaps.len(),
                        "keepalive accepted"
                    );
                } else {
                    tracing::info!(
                        chunk_id = self.chunk_id,
                        keyspace_progress,
                        state,
                        new_cracks,
                        cracked,
                        skipped,
                        zaps = zaps.len(),
                        "progress accepted"
                    );
                }

                Ok(ProgressCommand::Continue { zaps })
            }
            Ok(SendProgressResponse::Stop { cracked, skipped }) => {
                tracing::info!(
                    chunk_id = self.chunk_id,
                    cracked,
                    skipped,
                    "server signalled chunk stop"
                );

                Ok(ProgressCommand::Stop)
            }
            // The server refused the update (chunk aborted, manually interrupted,
            // agent marked inactive, token rejected): stop and let the loop
            // re-sync with a fresh task.
            Ok(SendProgressResponse::Rejected { reason }) => {
                tracing::warn!(
                    reason = reason.as_deref().unwrap_or("none"),
                    "server rejected progress; stopping chunk"
                );
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

    async fn report_error(&self, message: impl Into<String>) {
        let message = message.into();

        tracing::warn!(
            chunk_id = self.chunk_id,
            message = %message,
            "reporting cracker error to server"
        );

        let response = self
            .client
            .client_error(self.task_id, Some(self.chunk_id), message)
            .await;

        if let Err(error) = response {
            tracing::error!(%error, "failed to report cracker error")
        }
    }
}
