use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, watch};
use tokio::time::MissedTickBehavior;

use crate::cracker::{ChunkOutcome, CrackerError, ProgressCommand, ProgressSink};
use crate::model::{Chunk, ProgressReport};
use crate::process::{self, ProcessSpec};

use super::HashcatInvocation;
use super::status::{self, HashcatStatus};

const CHANNEL_CAPACITY: usize = 256;
const MAX_CRACKS_PER_UPDATE: usize = 1000;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Drive one chunk to completion: spawn the process, read back status/cracks/
/// errors, and report them until the channel closes (process exited) or the
/// server orders a stop.
pub(super) async fn run<S: ProgressSink>(
    invocation: HashcatInvocation,
    chunk: Chunk,
    sink: &S,
) -> Result<ChunkOutcome, CrackerError> {
    prepare_outfile(&invocation.outfile).await?;
    prepare_zaps_dir(&invocation.zaps_dir).await?;

    let (mut hashcat, mut preprocessor) =
        spawn_processes(&invocation).map_err(|error| CrackerError::Process(error.to_string()))?;

    // Both hashcat and the preprocessor lead their own groups; a stop must take
    // down both.
    let hashcat_pid = hashcat.id();
    let preprocessor_pid = preprocessor.as_ref().and_then(|child| child.id());

    let stdout = hashcat
        .stdout
        .take()
        .ok_or_else(|| CrackerError::Process("hashcat stdout not captured".into()))?;

    let stderr = hashcat
        .stderr
        .take()
        .ok_or_else(|| CrackerError::Process("hashcat stderr not captured".into()))?;

    // The preprocessor's stderr is logged, not reported as a crack-run error;
    // hashcat's own stderr is what the server acts on.
    if let Some(preprocessor_stderr) = preprocessor.as_mut().and_then(|child| child.stderr.take()) {
        process::spawn_stderr_logger(preprocessor_stderr);
    }

    let (tx, mut rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
    let (finish_tx, finish_rx) = watch::channel(false);

    process::spawn_line_reader(stdout, tx.clone(), parse_stdout);
    process::spawn_line_reader(stderr, tx.clone(), parse_stderr);
    process::spawn_file_tail(
        invocation.outfile.clone(),
        tx.clone(),
        finish_rx,
        parse_crack,
    );

    // The loop learns the process has exited when the last sender drops its handle and
    // the channel closes. We need to drop our handle too so we dont stall progress here.
    drop(tx);

    // Wait for both groups to finish in a separate task (not blocking).
    let waiter = tokio::spawn(async move {
        let _ = hashcat.wait().await;

        if let Some(mut preprocessor) = preprocessor {
            let _ = preprocessor.wait().await;
        }

        let _ = finish_tx.send(true);
    });

    // While process is running, schedule keep alive heartbeats so server does
    // not shut us down as inactive.
    let mut keepalive = tokio::time::interval_at(
        tokio::time::Instant::now() + KEEPALIVE_INTERVAL,
        KEEPALIVE_INTERVAL,
    );
    keepalive.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut state = ChunkRun::new(chunk, invocation.preprocessor.is_some());

    loop {
        tokio::select! {
            event = rx.recv() => {
                let Some(event) = event else { break; };

                if let Flow::Stop = state.handle(event, sink, &invocation).await {
                    process::kill_group(hashcat_pid);
                    process::kill_group(preprocessor_pid);
                    state.stopped = true;
                    break;
                }
            }

            _ = keepalive.tick(), if !state.first_status => {
                let _ = sink.send_progress(state.keepalive_report()).await;
            }
        }
    }

    state.finalize(sink, &invocation).await;

    let _ = waiter.await;

    Ok(ChunkOutcome {
        stopped: state.stopped,
    })
}

/// Spawn the run: a plain hashcat process, or a `preprocessor | hashcat`
/// pipeline when the invocation carries a preprocessor. Returns hashcat, whose
/// output the loop reads, plus the preprocessor to reap.
fn spawn_processes(
    invocation: &HashcatInvocation,
) -> std::io::Result<(tokio::process::Child, Option<tokio::process::Child>)> {
    match &invocation.preprocessor {
        None => {
            let child =
                process::spawn_grouped(&invocation.program, &invocation.args, &invocation.cwd)?;

            Ok((child, None))
        }
        Some(preprocessor) => {
            let pipeline = process::spawn_pipeline(
                ProcessSpec {
                    program: &preprocessor.program,
                    args: &preprocessor.args,
                },
                ProcessSpec {
                    program: &invocation.program,
                    args: &invocation.args,
                },
                &invocation.cwd,
                preprocessor.window,
            )?;

            Ok((pipeline.consumer, Some(pipeline.producer)))
        }
    }
}

/// One item multiplexed onto the run's single channel. Status and debug come
/// from stdout, errors from stderr, and cracks are tailed from the outfile.
#[derive(Debug)]
enum Event {
    Status(HashcatStatus),
    Debug(String),
    Stderr(String),
    Crack(String),
}

/// Whether the run loop should keep going or tear the process down.
enum Flow {
    Continue,
    Stop,
}

/// The progress figures carried by the most recent status, reused to flush any
/// cracks that trickle in after that status (including the final ones).
#[derive(Clone)]
struct Progress {
    keyspace_progress: u64,
    relative_progress: u64,
    speed: u64,
    state: u32,
    gpu_temp: Option<Vec<i64>>,
    gpu_util: Option<Vec<i64>>,
}

/// Mutable state carried across the run loop's iterations.
struct ChunkRun {
    chunk: Chunk,
    piped: bool,
    pending: Vec<String>,
    last_progress: Option<Progress>,
    first_status: bool,
    stopped: bool,
}

impl ChunkRun {
    fn new(chunk: Chunk, piped: bool) -> Self {
        Self {
            chunk,
            piped,
            pending: Vec::new(),
            last_progress: None,
            first_status: false,
            stopped: false,
        }
    }

    async fn handle<S: ProgressSink>(
        &mut self,
        event: Event,
        sink: &S,
        invocation: &HashcatInvocation,
    ) -> Flow {
        match event {
            Event::Status(status) => self.handle_status(status, sink, invocation).await,

            Event::Crack(line) => {
                self.pending.push(line);
                Flow::Continue
            }

            Event::Stderr(message) => {
                sink.report_error(message).await;
                Flow::Continue
            }

            Event::Debug(line) => {
                tracing::trace!(%line, "hashcat stdout");
                Flow::Continue
            }
        }
    }

    async fn handle_status<S: ProgressSink>(
        &mut self,
        status: HashcatStatus,
        sink: &S,
        invocation: &HashcatInvocation,
    ) -> Flow {
        self.first_status = true;

        let progress = self.progress_from(&status);
        self.last_progress = Some(progress.clone());

        self.flush(sink, invocation, &progress).await
    }

    /// A chunk's progress does not start at zero, so we offset by where this
    /// chunk begins in the whole keyspace and scale the remainder to basis
    /// points (0..=10000).
    fn progress_from(&self, status: &HashcatStatus) -> Progress {
        let total = status.progress_total();
        let span = self.chunk.skip + self.chunk.length;

        let chunk_start = total
            .checked_div(span)
            .map(|per_unit| per_unit * self.chunk.skip)
            .unwrap_or(0);

        let relative_progress = if total > chunk_start {
            ((status.progress().saturating_sub(chunk_start) as u128) * 10_000
                / (total - chunk_start) as u128) as u64
        } else {
            0
        };

        let temps = status.temps();
        let utils = status.utils();

        // When hashcat cannot report a restore point, the chunk's own start offset
        // stands in, or the server would read it as no progress from the beginning.
        let keyspace_progress = if self.restore_point_unavailable(status) {
            self.chunk.skip
        } else {
            status.curku()
        };

        Progress {
            keyspace_progress,
            relative_progress,
            speed: status.speed(),
            state: status.state(),
            gpu_temp: (!temps.is_empty()).then(|| temps.to_vec()),
            gpu_util: (!utils.is_empty()).then(|| utils.to_vec()),
        }
    }

    /// hashcat cannot produce a restore point (`curku`) when it reads candidates
    /// from a pipe rather than seeking a wordlist, so it reports `0`. A piped run
    /// reporting `0` is that case, not genuinely zero progress.
    fn restore_point_unavailable(&self, status: &HashcatStatus) -> bool {
        self.piped && status.curku() == 0
    }

    /// Send the current progress, draining pending cracks in batches of at most
    /// [`MAX_CRACKS_PER_UPDATE`]. One report always goes out even with no cracks.
    /// A delivery failure keeps the unsent cracks for the next status; a server
    /// `Stop` ends the run.
    async fn flush<S: ProgressSink>(
        &mut self,
        sink: &S,
        invocation: &HashcatInvocation,
        progress: &Progress,
    ) -> Flow {
        let mut first_batch = true;

        while first_batch || !self.pending.is_empty() {
            first_batch = false;

            let take = self.pending.len().min(MAX_CRACKS_PER_UPDATE);

            let cracks = self.pending[..take]
                .iter()
                .map(|line| line.split('\t').map(str::to_owned).collect())
                .collect();

            let report = ProgressReport {
                chunk_id: self.chunk.id,
                keyspace_progress: progress.keyspace_progress,
                relative_progress: progress.relative_progress,
                speed: progress.speed,
                state: progress.state,
                cracks,
                gpu_temp: progress.gpu_temp.clone(),
                gpu_util: progress.gpu_util.clone(),
                ..Default::default()
            };

            match sink.send_progress(report).await {
                Ok(ProgressCommand::Continue { zaps }) => {
                    self.pending.drain(..take);
                    write_zaps(&invocation.zaps_dir, &zaps).await;
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
    async fn finalize<S: ProgressSink>(&mut self, sink: &S, invocation: &HashcatInvocation) {
        if self.stopped || self.pending.is_empty() {
            return;
        }

        let Some(progress) = self.last_progress.clone() else {
            return;
        };

        let _ = self.flush(sink, invocation, &progress).await;
    }

    /// A heartbeat sent before the first real status so the server does not time
    /// the chunk out while hashcat is still warming up.
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
    let status = HashcatStatus::parse(&line);

    if status.is_valid() {
        Some(Event::Status(status))
    } else {
        Some(Event::Debug(line))
    }
}

fn parse_stderr(line: String) -> Option<Event> {
    let message = status::strip_ansi(&line);
    let message = message.trim();

    // Ctrl+C is forwarded to the child, which echoes it on stderr; not an error.
    if message.is_empty() || message == "^C" {
        return None;
    }

    Some(Event::Stderr(message.to_owned()))
}

fn parse_crack(line: String) -> Option<Event> {
    (!line.is_empty()).then_some(Event::Crack(line))
}

async fn prepare_outfile(outfile: &Path) -> Result<(), CrackerError> {
    match tokio::fs::remove_file(outfile).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CrackerError::Process(format!(
            "could not clear old outfile {}: {error}",
            outfile.display()
        ))),
    }
}

async fn prepare_zaps_dir(zap_dir: &Path) -> Result<(), CrackerError> {
    tokio::fs::create_dir_all(zap_dir).await.map_err(|error| {
        CrackerError::Process(format!(
            "could not create zap dir {}: {error}",
            zap_dir.display()
        ))
    })
}

/// Append server-supplied zaps (hashes cracked elsewhere) to a fresh file in the
/// zap dir, in the `hash\tFF` shape hashcat's `--outfile-check-dir` expects.
/// Best-effort: a write failure is logged, not fatal to the run.
async fn write_zaps(zap_dir: &Path, zaps: &[String]) {
    if zaps.is_empty() {
        return;
    }

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let path = zap_dir.join(stamp.to_string());

    let body = {
        let mut body = String::new();

        for zap in zaps {
            body.push_str(zap);
            body.push_str("\tFF\n");
        }

        body
    };

    if let Err(error) = tokio::fs::write(&path, body).await {
        tracing::warn!(%error, path = %path.display(), "failed to write zaps");
    }
}
