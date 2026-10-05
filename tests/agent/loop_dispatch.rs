use std::time::Duration;

use htp_agent::agent::{Agent, AgentError, LoopState, Step};
use htp_agent::client::Client;
use serde_json::{Value, json};

use crate::support::env::{Env, test_session};
use crate::support::provisioner::{FakeCracker, FakeProvisioner, Stage};
use crate::support::transport::{
    ScriptedTransport, health_check_reply, progress_continue, success, task_reply,
    task_reply_with_brain, task_reply_with_preprocessor,
};

/// One loop iteration's worth of moving parts. `env` is kept alive because
/// every tick reloads settings from its files.
struct AgentRig {
    agent: Agent<ScriptedTransport, FakeProvisioner>,
    transport: ScriptedTransport,
    provisioner: FakeProvisioner,
    state: LoopState,
    _env: Env,
}

impl AgentRig {
    fn rig(replies: impl IntoIterator<Item = Value>) -> Self {
        Self::with_provisioner(replies, FakeProvisioner::new())
    }

    fn with_provisioner(
        replies: impl IntoIterator<Item = Value>,
        provisioner: FakeProvisioner,
    ) -> Self {
        let env = Env::new();
        let transport = ScriptedTransport::new(replies);

        let client = Client::with_token(transport.clone(), "token");
        let agent = Agent::new(client, env.config(), provisioner.clone(), test_session());

        Self {
            agent,
            transport,
            provisioner,
            state: LoopState::new(),
            _env: env,
        }
    }

    async fn tick(&mut self) -> Result<Step, AgentError> {
        self.agent.tick(&mut self.state).await
    }
}

fn chunk_reply(length: u64) -> Value {
    json!({
        "action": "getChunk",
        "response": "SUCCESS",
        "status": "OK",
        "chunkId": 7,
        "skip": 0,
        "length": length
    })
}

fn chunk_status(status: &str) -> Value {
    json!({"action": "getChunk", "response": "SUCCESS", "status": status})
}

#[tokio::test]
async fn no_task_sleeps_and_marks_task_change() {
    let mut rig =
        AgentRig::rig([json!({"action": "getTask", "response": "SUCCESS", "taskId": null})]);

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
    assert!(rig.state.current_task().is_none());
}

#[tokio::test]
async fn keyspace_required_measures_and_sends_keyspace() {
    let mut rig = AgentRig::with_provisioner(
        [
            task_reply(25, 45, 13),
            chunk_status("keyspace_required"),
            json!({"action": "sendKeyspace", "response": "SUCCESS"}),
        ],
        FakeProvisioner::new().with_cracker(FakeCracker {
            keyspace: 568_000,
            ..FakeCracker::default()
        }),
    );

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Continue);
    let sent = rig.transport.request_for("sendKeyspace");
    assert_eq!(sent["taskId"], 25);
    assert_eq!(sent["keyspace"], 568_000);
    // The task is kept so the next tick can fetch a real chunk.
    assert_eq!(rig.state.current_task().map(|task| task.task_id), Some(25));
}

#[tokio::test]
async fn benchmark_required_sends_benchmark() {
    let mut rig = AgentRig::rig([
        task_reply(25, 45, 13),
        chunk_status("benchmark"),
        json!({"action": "sendBenchmark", "response": "SUCCESS"}),
    ]);

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Continue);
    let sent = rig.transport.request_for("sendBenchmark");
    assert_eq!(sent["taskId"], 25);
    assert_eq!(sent["result"], "674:674.74");
    // The task is kept so the next tick can fetch a real chunk.
    assert_eq!(rig.state.current_task().map(|task| task.task_id), Some(25));
}

#[tokio::test]
async fn benchmark_without_result_sleeps_and_resets() {
    let mut rig = AgentRig::with_provisioner(
        [
            task_reply(25, 45, 13),
            chunk_status("benchmark"),
            success("clientError"),
        ],
        FakeProvisioner::new().with_cracker(FakeCracker {
            benchmark: None,
            ..FakeCracker::default()
        }),
    );

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Sleep(Duration::from_secs(10)));
    assert!(rig.state.current_task().is_none());
    assert!(
        !rig.transport
            .actions()
            .contains(&"sendBenchmark".to_string())
    );
}

#[tokio::test]
async fn chunk_runs_and_a_stop_reply_resets_the_task() {
    let mut rig = AgentRig::rig([
        task_reply(25, 45, 13),
        chunk_reply(10_000),
        json!({
            "action": "sendProgress",
            "response": "SUCCESS",
            "cracked": 0,
            "skipped": 0,
            "agent": "stop"
        }),
    ]);

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Continue);
    assert!(
        rig.state.current_task().is_none(),
        "a stop must reset the task"
    );
    assert!(
        rig.transport
            .actions()
            .contains(&"sendProgress".to_string())
    );
}

#[tokio::test]
async fn zero_length_chunk_sleeps_and_resets() {
    let mut rig = AgentRig::rig([task_reply(25, 45, 13), chunk_reply(0)]);

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
    assert!(rig.state.current_task().is_none());
}

#[tokio::test]
async fn fully_dispatched_sleeps_and_resets() {
    let mut rig = AgentRig::rig([task_reply(25, 45, 13), chunk_status("fully_dispatched")]);

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
    assert!(rig.state.current_task().is_none());
}

#[tokio::test]
async fn cracker_update_resets_and_sleeps() {
    let mut rig = AgentRig::rig([task_reply(25, 45, 13), chunk_status("cracker_update")]);

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
    assert!(rig.state.current_task().is_none());
}

#[tokio::test]
async fn unready_cracker_resets_and_sleeps() {
    let mut rig = AgentRig::with_provisioner(
        [task_reply(25, 45, 13)],
        FakeProvisioner::new().failing_at(Stage::Cracker),
    );

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
    assert!(rig.state.current_task().is_none());
    // The loop must not have asked for a chunk once provisioning failed.
    assert!(!rig.transport.actions().contains(&"getChunk".to_string()));
}

#[tokio::test]
async fn invalid_token_in_the_loop_is_fatal() {
    let mut rig = AgentRig::rig([
        json!({"action": "getTask", "response": "ERROR", "message": "Invalid token!"}),
    ]);

    let error = rig.tick().await.unwrap_err();

    assert!(matches!(error, AgentError::TokenRejected), "got {error:?}");
}

#[tokio::test]
async fn getchunk_server_error_backs_off_and_drops_the_task() {
    let mut rig = AgentRig::rig([
        task_reply(25, 45, 13),
        json!({"action": "getChunk", "response": "ERROR", "message": "You are not assigned to this task!"}),
    ]);

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
    assert!(rig.state.current_task().is_none());
}

#[tokio::test]
async fn a_run_chunk_tick_checks_version_during_prep_and_after_the_chunk() {
    let mut rig = AgentRig::rig([
        task_reply(25, 45, 13),
        chunk_reply(10_000),
        progress_continue(),
    ]);

    rig.tick().await.unwrap();

    assert_eq!(
        rig.provisioner.calls(),
        [
            Stage::DeletionCheck,
            Stage::Cracker,
            Stage::Files,
            Stage::Hashlist,
            // task-change
            Stage::CheckVersion,
            // chunk-complete
            Stage::CheckVersion,
        ]
    );
}

#[tokio::test]
async fn a_tick_that_never_runs_a_chunk_checks_version_once() {
    let mut rig = AgentRig::rig([task_reply(25, 45, 13), chunk_reply(0)]);

    rig.tick().await.unwrap();

    // A zero-length chunk returns before run_chunk, so only the prep-time check
    // fires.
    assert_eq!(
        rig.provisioner.calls(),
        [
            Stage::DeletionCheck,
            Stage::Cracker,
            Stage::Files,
            Stage::Hashlist,
            Stage::CheckVersion,
        ]
    );
}

#[tokio::test]
async fn a_downstream_failure_resets_and_never_asks_for_a_chunk() {
    let mut rig = AgentRig::with_provisioner(
        [task_reply(25, 45, 13)],
        FakeProvisioner::new().failing_at(Stage::Hashlist),
    );

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
    assert!(rig.state.current_task().is_none());
    assert!(!rig.transport.actions().contains(&"getChunk".to_string()));
    // Stops right at the failing stage; the version check after it never runs.
    assert_eq!(
        rig.provisioner.calls(),
        [
            Stage::DeletionCheck,
            Stage::Cracker,
            Stage::Files,
            Stage::Hashlist,
        ]
    );
}

#[tokio::test]
async fn a_plain_task_skips_preprocessor_and_found() {
    let mut rig = AgentRig::rig([task_reply(25, 45, 13), chunk_reply(0)]);

    rig.tick().await.unwrap();

    let calls = rig.provisioner.calls();
    assert!(calls.contains(&Stage::Cracker));
    assert!(calls.contains(&Stage::Hashlist));
    assert!(!calls.contains(&Stage::Preprocessor));
    assert!(!calls.contains(&Stage::Found));
}

#[tokio::test]
async fn a_preprocessor_task_provisions_the_preprocessor() {
    let mut rig = AgentRig::rig([task_reply_with_preprocessor(25, 45, 13), chunk_reply(0)]);

    rig.tick().await.unwrap();

    let calls = rig.provisioner.calls();
    assert!(calls.contains(&Stage::Preprocessor));
    assert!(!calls.contains(&Stage::Found));
}

#[tokio::test]
async fn a_brain_task_loads_found_hashes() {
    let mut rig = AgentRig::rig([task_reply_with_brain(25, 45, 13), chunk_reply(0)]);

    rig.tick().await.unwrap();

    let calls = rig.provisioner.calls();
    assert!(calls.contains(&Stage::Found));
    assert!(!calls.contains(&Stage::Preprocessor));
}

#[tokio::test]
async fn a_running_chunk_that_continues_keeps_the_task() {
    let mut rig = AgentRig::rig([
        task_reply(25, 45, 13),
        chunk_reply(10_000),
        progress_continue(),
    ]);

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Continue);
    // A continue (unlike a stop) leaves the task in place for the next chunk.
    assert_eq!(rig.state.current_task().map(|task| task.task_id), Some(25));
    assert!(
        rig.transport
            .actions()
            .contains(&"sendProgress".to_string())
    );
}

#[tokio::test]
async fn setup_is_prepared_once_and_reused_across_ticks() {
    let mut rig = AgentRig::rig([
        task_reply(25, 45, 13),
        chunk_reply(10_000),
        progress_continue(),
        chunk_reply(10_000),
        progress_continue(),
    ]);

    // A continue keeps the task, so the second tick runs the same task without
    // asking for it again.
    rig.tick().await.unwrap();
    rig.tick().await.unwrap();

    let count = |stage: Stage| {
        rig.provisioner
            .calls()
            .iter()
            .filter(|&&s| s == stage)
            .count()
    };

    // The files and hashlist (and the rest of task setup) are provisioned once;
    // the cracker is re-ensured every tick. Ensuring files once per task keeps a
    // completed task from issuing a trailing getFile after its assignment is gone.
    assert_eq!(count(Stage::Files), 1);
    assert_eq!(count(Stage::Hashlist), 1);
    assert_eq!(count(Stage::Cracker), 2);
}

#[tokio::test]
async fn a_get_task_health_check_runs_and_reports_results() {
    let mut rig = AgentRig::rig([
        json!({"action": "getTask", "response": "SUCCESS", "taskId": -1}),
        health_check_reply(88, 45),
        success("sendHealthCheck"),
    ]);

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Continue);
    // The health check provisions its own cracker and reports the crack count.
    assert!(rig.provisioner.calls().contains(&Stage::Cracker));
    let sent = rig.transport.request_for("sendHealthCheck");
    assert_eq!(sent["checkId"], 88);
    assert_eq!(sent["numCracked"], 1);
}

#[tokio::test]
async fn a_get_chunk_health_check_runs_and_resets_the_task() {
    let mut rig = AgentRig::rig([
        task_reply(25, 45, 13),
        chunk_status("health_check"),
        health_check_reply(88, 45),
        success("sendHealthCheck"),
    ]);

    let step = rig.tick().await.unwrap();

    assert_eq!(step, Step::Continue);
    // A health check reached through getChunk clears the task afterwards.
    assert!(rig.state.current_task().is_none());
    assert!(
        rig.transport
            .actions()
            .contains(&"sendHealthCheck".to_string())
    );
}
