//! Progress reporting from a running chunk back to the server.

use crate::client::Client;
use crate::cracker::{ProgressCommand, ProgressSink};
use crate::model::{ProgressReport, SendProgressResponse};
use crate::transport::Transport;

pub(super) struct ClientSink<'a, T: Transport> {
    pub(super) client: &'a Client<T>,
}

impl<T: Transport> ProgressSink for ClientSink<'_, T> {
    async fn send_progress(&self, report: ProgressReport) -> ProgressCommand {
        match self.client.send_progress(report).await {
            Ok(SendProgressResponse::Continue { zaps, .. }) => ProgressCommand::Continue { zaps },
            Ok(SendProgressResponse::Stop { .. }) => ProgressCommand::Stop,
            Err(error) => {
                tracing::error!(%error, "failed to send progress");
                ProgressCommand::Failed
            }
        }
    }
}
