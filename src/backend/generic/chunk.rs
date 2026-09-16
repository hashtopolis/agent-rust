//! The generic cracker chunk run loop.
//!
//! It mirrors the *shape* of the hashcat loop (spawn, an mpsc channel, a
//! `tokio::select!` with a warmup keepalive, batched flushes, a finalize pass)
//! but is simpler in every dimension: both status and cracks arrive on the
//! child's stdout, there is no outfile to tail, no zap directory, and no
//! preprocessor pipe.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use crate::cracker::{ChunkOutcome, CrackerError, ProgressCommand, ProgressSink};
use crate::model::{Chunk, Crack, ProgressReport};
use crate::process;

use super::status::GenericStatus;

const CHANNEL_CAPACITY: usize = 256;
const MAX_CRACKS_PER_UPDATE: usize = 1000;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

pub(super) struct GenericInvocation {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub zap_file: PathBuf,
}

pub(super) async fn run<S: ProgressSink>(
    invocation: GenericInvocation,
    chunk: Chunk,
    sink: &S,
) -> Result<ChunkOutcome, CrackerError> {
    let mut child = process::spawn_grouped(&invocation.program, &invocation.args, &invocation.cwd)
        .map_err(|error| CrackerError::Process(error.to_string()))?;

    let pid = child.id();

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CrackerError::Process("generic cracker stdout not captured".into()))?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| CrackerError::Process("generic cracker stderr not captured".into()))?;

    let (tx, mut rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);

    // Status and cracks share stdout; stderr is diagnostic only. Both readers
    // hold a sender, so the channel closes once both pipes reach EOF (the child
    // has exited and its output is fully drained).
    process::spawn_line_reader(stdout, tx.clone(), parse_stdout);
    process::spawn_line_reader(stderr, tx.clone(), parse_stderr);

    // Drop our own handle so the channel can close when the readers finish.
    drop(tx);

    let waiter = tokio::spawn(async move {
        let _ = child.wait().await;
    });

    // Heartbeats before the first real status keep the server from timing the
    // chunk out while a slow child warms up.
    let mut keepalive = tokio::time::interval_at(
        tokio::time::Instant::now() + KEEPALIVE_INTERVAL,
        KEEPALIVE_INTERVAL,
    );
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut state = ChunkRun::new(chunk);

    loop {
        tokio::select! {
            event = rx.recv() => {
                let Some(event) = event else { break; };

                if let Flow::Stop = state.handle(event, sink, &invocation.zap_file).await {
                    process::kill_group(pid);
                    state.stopped = true;
                    break;
                }
            }

            _ = keepalive.tick(), if !state.first_status => {
                let _ = sink.send_progress(state.keepalive_report()).await;
            }
        }
    }

    state.finalize(sink, &invocation.zap_file).await;

    let _ = waiter.await;

    Ok(ChunkOutcome {
        stopped: state.stopped,
    })
}

/// One item multiplexed onto the run's single channel. Status and cracks both
/// come from stdout; stderr is logged, never reported to the server (matching
/// the reference, which prints stderr and never aborts on it).
#[derive(Debug)]
enum Event {
    Status(GenericStatus),
    Crack(String),
    Debug(String),
    Stderr(String),
}

enum Flow {
    Continue,
    Stop,
}

#[derive(Clone)]
struct Progress {
    relative_progress: u64,
    speed: u64,
    state: u32,
}

struct ChunkRun {
    chunk: Chunk,
    pending: Vec<String>,
    last_progress: Option<Progress>,
    first_status: bool,
    stopped: bool,
}

impl ChunkRun {
    fn new(chunk: Chunk) -> Self {
        Self {
            chunk,
            pending: Vec::new(),
            last_progress: None,
            first_status: false,
            stopped: false,
        }
    }

    async fn handle<S: ProgressSink>(&mut self, event: Event, sink: &S, zap_file: &Path) -> Flow {
        match event {
            Event::Status(status) => self.handle_status(status, sink, zap_file).await,

            Event::Crack(line) => {
                self.pending.push(line);
                Flow::Continue
            }

            Event::Debug(line) => {
                tracing::warn!(%line, "generic cracker stdout");
                Flow::Continue
            }

            Event::Stderr(line) => {
                tracing::warn!(%line, "generic cracker stderr");
                Flow::Continue
            }
        }
    }

    async fn handle_status<S: ProgressSink>(
        &mut self,
        status: GenericStatus,
        sink: &S,
        zap_file: &Path,
    ) -> Flow {
        self.first_status = true;

        let progress = Progress {
            relative_progress: status.progress(),
            speed: status.speed(),
            state: if status.progress() == GenericStatus::COMPLETE {
                4
            } else {
                2
            },
        };

        self.last_progress = Some(progress.clone());

        self.flush(sink, zap_file, &progress).await
    }

    /// Send the current progress, draining pending cracks in batches of at most
    /// [`MAX_CRACKS_PER_UPDATE`]. One report always goes out even with no cracks.
    /// A delivery failure keeps the unsent cracks for the next status; a server
    /// `Stop` ends the run.
    async fn flush<S: ProgressSink>(
        &mut self,
        sink: &S,
        zap_file: &Path,
        progress: &Progress,
    ) -> Flow {
        let mut first_batch = true;

        while first_batch || !self.pending.is_empty() {
            first_batch = false;

            let take = self.pending.len().min(MAX_CRACKS_PER_UPDATE);

            // Each crack is a raw stdout line, sent as a JSON string; the server
            // splits it with the hashlist's field separator.
            let cracks = self.pending[..take]
                .iter()
                .map(|line| Crack::Raw(line.clone()))
                .collect();

            // The generic cursor does not move: keyspaceProgress is pinned to the
            // chunk's start offset, and relativeProgress carries the real figure.
            let report = ProgressReport {
                chunk_id: self.chunk.id,
                keyspace_progress: self.chunk.skip,
                relative_progress: progress.relative_progress,
                speed: progress.speed,
                state: progress.state,
                cracks,
                ..Default::default()
            };

            match sink.send_progress(report).await {
                Ok(ProgressCommand::Continue { zaps }) => {
                    self.pending.drain(..take);
                    write_zap_file(zap_file, &zaps).await;
                }
                Ok(ProgressCommand::Stop) => {
                    tracing::info!("server sent stop command after progress update");
                    return Flow::Stop;
                }
                Err(error) => {
                    tracing::warn!(%error, "progress not delivered; keeping cracks for retry");
                    break;
                }
            }
        }

        Flow::Continue
    }

    /// After the process has exited, push any cracks that arrived past the last
    /// status so the final ones are not dropped.
    async fn finalize<S: ProgressSink>(&mut self, sink: &S, zap_file: &Path) {
        if self.stopped || self.pending.is_empty() {
            return;
        }

        let Some(progress) = self.last_progress.clone() else {
            return;
        };

        let _ = self.flush(sink, zap_file, &progress).await;
    }

    /// A heartbeat sent before the first real status, pinned to the chunk's start
    /// offset so the server does not read it as progress from zero.
    fn keepalive_report(&self) -> ProgressReport {
        ProgressReport {
            chunk_id: self.chunk.id,
            keyspace_progress: self.chunk.skip,
            state: 2,
            ..Default::default()
        }
    }
}

fn parse_stdout(line: String) -> Option<Event> {
    let status = GenericStatus::parse(&line);

    if status.is_valid() {
        Some(Event::Status(status))
    } else if line.contains(':') {
        // A non-status line with a colon is a cracked hash, stored stripped.
        Some(Event::Crack(line.trim().to_owned()))
    } else {
        Some(Event::Debug(line))
    }
}

fn parse_stderr(line: String) -> Option<Event> {
    let line = line.trim();

    if line.is_empty() {
        return None;
    }

    Some(Event::Stderr(line.to_owned()))
}

/// Overwrite `<files-path>/zap` with the server's zaps, newline-joined, for
/// parity with the reference. Nothing reads it back; a write failure is logged,
/// never fatal.
async fn write_zap_file(zap_file: &Path, zaps: &[String]) {
    if zaps.is_empty() {
        return;
    }

    let body = zaps.join("\n");

    if let Err(error) = tokio::fs::write(zap_file, body).await {
        tracing::warn!(%error, path = %zap_file.display(), "failed to write generic zap file");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Mutex;

    use crate::cracker::{ProgressCommand, ProgressUpdateError};

    use super::*;

    /// A scripted [`ProgressSink`]: it records every report and replies
    /// `Continue` with no zaps, unless configured to reply `Stop` on the Nth send.
    struct FakeSink {
        reports: Mutex<Vec<ProgressReport>>,
        stop_on: Option<usize>,
    }

    impl FakeSink {
        fn new() -> Self {
            Self {
                reports: Mutex::new(Vec::new()),
                stop_on: None,
            }
        }

        fn stopping_on(nth: usize) -> Self {
            Self {
                reports: Mutex::new(Vec::new()),
                stop_on: Some(nth),
            }
        }

        fn reports(&self) -> Vec<ProgressReport> {
            self.reports.lock().unwrap().clone()
        }
    }

    impl ProgressSink for FakeSink {
        async fn send_progress(
            &self,
            report: ProgressReport,
        ) -> Result<ProgressCommand, ProgressUpdateError> {
            let count = {
                let mut reports = self.reports.lock().unwrap();
                reports.push(report);
                reports.len()
            };

            if self.stop_on == Some(count) {
                Ok(ProgressCommand::Stop)
            } else {
                Ok(ProgressCommand::Continue { zaps: Vec::new() })
            }
        }

        async fn report_error(&self, _message: impl Into<String>) {}
    }

    const CHUNK: Chunk = Chunk {
        id: 1,
        skip: 10,
        length: 20,
    };

    /// Build an invocation whose child is a shell emitting the given stdout
    /// script verbatim, then exiting.
    fn emitting(script: &str) -> (tempfile::TempDir, GenericInvocation) {
        let dir = tempfile::tempdir().unwrap();

        let invocation = GenericInvocation {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_owned(), script.to_owned()],
            cwd: dir.path().to_path_buf(),
            zap_file: dir.path().join("zap"),
        };

        (dir, invocation)
    }

    #[tokio::test]
    async fn interleaved_status_and_cracks_map_to_reports() {
        let (_dir, invocation) = emitting(
            "echo 'h1:p1'; echo 'STATUS 5000 1000'; echo 'h2:p2'; echo 'STATUS 10000 2000'",
        );
        let sink = FakeSink::new();

        let outcome = run(invocation, CHUNK, &sink).await.unwrap();

        assert!(!outcome.stopped);

        let reports = sink.reports();
        assert_eq!(reports.len(), 2, "one report per status line");

        // Every report pins keyspaceProgress to the chunk's start offset.
        assert!(reports.iter().all(|r| r.keyspace_progress == CHUNK.skip));

        // First status: mid-chunk, state 2, carrying the first crack unsplit.
        assert_eq!(reports[0].relative_progress, 5000);
        assert_eq!(reports[0].state, 2);
        assert_eq!(reports[0].cracks, vec![Crack::Raw("h1:p1".to_owned())]);

        // Final status: complete, state 4, carrying the second crack.
        assert_eq!(reports[1].relative_progress, 10000);
        assert_eq!(reports[1].state, 4);
        assert_eq!(reports[1].cracks, vec![Crack::Raw("h2:p2".to_owned())]);
    }

    #[tokio::test]
    async fn cracks_batch_at_the_limit() {
        // 1500 cracks buffered before a single status flushes them in batches of
        // at most 1000.
        let (_dir, invocation) =
            emitting("for i in $(seq 1 1500); do echo 'h:p'; done; echo 'STATUS 5000 1000'");
        let sink = FakeSink::new();

        run(invocation, CHUNK, &sink).await.unwrap();

        let reports = sink.reports();
        assert_eq!(reports.len(), 2, "1500 cracks split into two batches");
        assert_eq!(reports[0].cracks.len(), MAX_CRACKS_PER_UPDATE);
        assert_eq!(reports[1].cracks.len(), 500);
    }

    #[tokio::test]
    async fn cracks_after_the_last_status_flush_in_finalize() {
        // A crack printed after the final status must not be dropped: the finalize
        // pass flushes it using the last status's progress figures.
        let (_dir, invocation) = emitting("echo 'STATUS 5000 1000'; echo 'late:crack'");
        let sink = FakeSink::new();

        run(invocation, CHUNK, &sink).await.unwrap();

        let reports = sink.reports();
        assert_eq!(reports.len(), 2);

        // The status flush carried no cracks; the trailing crack lands in finalize.
        assert!(reports[0].cracks.is_empty());
        assert_eq!(reports[1].cracks, vec![Crack::Raw("late:crack".to_owned())]);
        assert_eq!(reports[1].relative_progress, 5000);
    }

    #[tokio::test]
    async fn a_server_stop_tears_down_the_run() {
        // The child emits a status then sleeps; the server replies Stop to the
        // first update, which must kill the child and end the run promptly.
        let (_dir, invocation) = emitting("echo 'STATUS 5000 1000'; sleep 30");
        let sink = FakeSink::stopping_on(1);

        let outcome = run(invocation, CHUNK, &sink).await.unwrap();

        assert!(outcome.stopped, "a server stop sets the stopped outcome");
        assert_eq!(sink.reports().len(), 1);
    }
}
