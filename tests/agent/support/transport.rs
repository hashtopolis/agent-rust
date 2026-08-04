use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use htp_agent::transport::{Transport, TransportError};
use serde_json::{Value, json};

/// Answers each request with the next queued reply and records every request.
/// Clones share the same queue and log, so a handle survives being moved into a
/// `Client`.
#[derive(Clone)]
pub struct ScriptedTransport {
    replies: Arc<Mutex<VecDeque<Value>>>,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl ScriptedTransport {
    pub fn new(replies: impl IntoIterator<Item = Value>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(VecDeque::from_iter(replies))),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn requests(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }

    pub fn actions(&self) -> Vec<String> {
        self.requests()
            .iter()
            .filter_map(|body| body["action"].as_str().map(str::to_owned))
            .collect()
    }

    pub fn request_for(&self, action: &str) -> Value {
        let matches: Vec<Value> = self
            .requests()
            .into_iter()
            .filter(|body| body["action"] == action)
            .collect();

        assert_eq!(
            matches.len(),
            1,
            "expected exactly one {action} request, got {}",
            matches.len()
        );

        matches.into_iter().next().unwrap()
    }
}

impl Transport for ScriptedTransport {
    async fn post_json(&self, body: &Value) -> Result<Value, TransportError> {
        // Record request for later inspection
        self.requests.lock().unwrap().push(body.clone());

        // Return reply in recorded order
        match self.replies.lock().unwrap().pop_front() {
            Some(reply) => Ok(reply),
            None => panic!("no scripted reply left for request: {body}"),
        }
    }
}

/// A minimal `getTask` reply for a real task, with no preprocessor and no brain.
pub fn task_reply(task_id: i64, cracker_id: u64, hashlist_id: u64) -> Value {
    json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": task_id,
        "crackerId": cracker_id,
        "attackcmd": "#HL# -a 3 ?a?a?a?a",
        "cmdpars": "",
        "hashlistId": hashlist_id,
        "bench": 30,
        "statustimer": 5,
        "files": [],
        "benchType": "speed",
        "hashlistAlias": "#HL#",
        "keyspace": 0,
        "enforcePipe": false,
        "slowHash": false,
        "usePreprocessor": false,
        "useBrain": false
    })
}

/// A `getTask` reply for a task that uses a preprocessor, so the loop calls
/// `ensure_preprocessor`.
pub fn task_reply_with_preprocessor(task_id: i64, cracker_id: u64, hashlist_id: u64) -> Value {
    let mut reply = task_reply(task_id, cracker_id, hashlist_id);

    reply["usePreprocessor"] = json!(true);
    reply["preprocessor"] = json!(1);
    reply["preprocessorCommand"] = json!("");

    reply
}

/// A `getTask` reply for a task that uses hashcat brain, so the loop calls
/// `ensure_found`.
pub fn task_reply_with_brain(task_id: i64, cracker_id: u64, hashlist_id: u64) -> Value {
    let mut reply = task_reply(task_id, cracker_id, hashlist_id);

    reply["useBrain"] = json!(true);
    reply["brainHost"] = json!("127.0.0.1");
    reply["brainPort"] = json!(6379);
    reply["brainPass"] = json!("secret");
    reply["brainFeatures"] = json!(3);

    reply
}

/// A `sendProgress` reply that lets the chunk keep running (no stop flag).
pub fn progress_continue() -> Value {
    json!({
        "action": "sendProgress",
        "response": "SUCCESS",
        "cracked": 0,
        "skipped": 0
    })
}

/// A `getHealthCheck` reply the loop can run end to end.
pub fn health_check_reply(check_id: u64, cracker_binary_id: u64) -> Value {
    json!({
        "action": "getHealthCheck",
        "response": "SUCCESS",
        "attack": "#HL# -a 3 ?d?d?d",
        "crackerBinaryId": cracker_binary_id,
        "hashes": ["hash:plain"],
        "checkId": check_id,
        "hashlistAlias": "#HL#"
    })
}

pub fn success(action: &str) -> Value {
    json!({ "action": action, "response": "SUCCESS" })
}
