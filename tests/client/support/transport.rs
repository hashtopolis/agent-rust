use std::sync::Mutex;

use htp_agent::transport::{Transport, TransportError};
use serde_json::Value;

pub struct MockTransport {
    reply: Value,
    last_request_body: Mutex<Option<Value>>,
}

impl MockTransport {
    pub fn new(reply: Value) -> Self {
        Self {
            reply,
            last_request_body: Mutex::new(None),
        }
    }

    pub fn last_request_body(&self) -> Value {
        self.last_request_body
            .lock()
            .unwrap()
            .clone()
            .expect("no request sent")
    }
}

impl Transport for MockTransport {
    async fn post_json(&self, body: &Value) -> Result<Value, TransportError> {
        *self.last_request_body.lock().unwrap() = Some(body.clone());
        Ok(self.reply.clone())
    }
}

pub struct FailingTransport;

impl Transport for FailingTransport {
    async fn post_json(&self, _body: &Value) -> Result<Value, TransportError> {
        Err(TransportError::Status(500))
    }
}
