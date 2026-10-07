//! Generic child-process helpers shared by the cracker backends: spawning a
//! process as its own group leader so the whole group can be signalled at once,
//! plus the line-oriented readers that feed a backend's event channel.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::log;

/// The full output of a process run to completion.
pub struct Captured {
    pub stdout: String,
    pub stderr: String,
    pub status: ExitStatus,
}

/// Spawn `program` with `args` in `cwd` as the leader of a fresh process group,
/// stdout/stderr piped and stdin closed. Leading its own group is what lets
/// [`kill_group`] take down the process together with any children it spawns
pub fn spawn_grouped(program: &Path, args: &[impl AsRef<str>], cwd: &Path) -> io::Result<Child> {
    tracing::debug!(command = %log::Invocation { program, args }, "spawning process");

    let mut command = Command::new(program);

    command
        .args(args.iter().map(|arg| arg.as_ref()))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    #[cfg(unix)]
    command.process_group(0);

    command.spawn()
}

/// A program and its argument list, borrowed together so a pipeline stage is one
/// value. Grouping them keeps the two stages of [`spawn_pipeline`] from being
/// transposed at the call site.
pub struct ProcessSpec<'a, A: AsRef<str>> {
    pub program: &'a Path,
    pub args: &'a [A],
}

/// The two children of a `producer | consumer` pipeline. The caller reads the
/// consumer's stdout/stderr and must tear down both process groups.
pub struct Pipeline {
    pub producer: Child,
    pub consumer: Child,
}

/// Spawn `producer | consumer`, both as their own process groups in `cwd`, with
/// the producer's stdout feeding the consumer's stdin.
///
/// With `window` set to `(skip, length)` the stream is filtered in-process: the
/// first `skip` lines are dropped and the next `length` forwarded, emulating
/// `| head -n (skip+length) | tail -n length` for preprocessors that lack native
/// skip/limit flags. Without a window the producer's stdout is handed directly to
/// the consumer as a kernel pipe, with no per-line overhead.
pub fn spawn_pipeline<P, C>(
    producer: ProcessSpec<'_, P>,
    consumer: ProcessSpec<'_, C>,
    cwd: &Path,
    window: Option<(u64, u64)>,
) -> io::Result<Pipeline>
where
    P: AsRef<str>,
    C: AsRef<str>,
{
    let mut producer = spawn_grouped(producer.program, producer.args, cwd)?;

    let producer_stdout = producer
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("producer stdout not captured"))?;

    tracing::debug!(
        command = %log::Invocation { program: consumer.program, args: consumer.args },
        "spawning process"
    );

    let mut consumer_command = Command::new(consumer.program);
    consumer_command
        .args(consumer.args.iter().map(|arg| arg.as_ref()))
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    #[cfg(unix)]
    consumer_command.process_group(0);

    match window {
        None => {
            consumer_command.stdin(child_stdout_to_stdio(producer_stdout)?);
            let consumer = consumer_command.spawn()?;

            Ok(Pipeline { producer, consumer })
        }
        Some((skip, length)) => {
            consumer_command.stdin(Stdio::piped());
            let mut consumer = consumer_command.spawn()?;

            let stdin = consumer
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("consumer stdin not captured"))?;

            spawn_line_window(producer_stdout, stdin, skip, length);

            Ok(Pipeline { producer, consumer })
        }
    }
}

/// Hand a producer's stdout to a consumer's stdin as a direct kernel pipe, by
/// taking ownership of the underlying fd/handle. This is what keeps the
/// no-window path free of a userspace copy.
fn child_stdout_to_stdio(stdout: tokio::process::ChildStdout) -> io::Result<Stdio> {
    #[cfg(unix)]
    {
        Ok(Stdio::from(stdout.into_owned_fd()?))
    }

    #[cfg(windows)]
    {
        Ok(Stdio::from(stdout.into_owned_handle()?))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = stdout;
        Err(io::Error::other(
            "pipelining is unsupported on this platform",
        ))
    }
}

/// Read lines from `source`, drop the first `skip`, forward the next `length` to
/// `sink`, then drop `sink` so the consumer sees EOF. Best-effort: a write error
/// (consumer gone) just ends the task.
///
/// This replaces the `| head -n (skip+length) | tail -n length` the Python agent
/// splices into the pipe for preprocessors without native skip/limit flags
fn spawn_line_window(
    source: impl AsyncRead + Unpin + Send + 'static,
    mut sink: tokio::process::ChildStdin,
    skip: u64,
    length: u64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut lines = BufReader::new(source).lines();
        let mut seen: u64 = 0;
        let mut forwarded: u64 = 0;

        while forwarded < length {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    seen += 1;

                    if seen <= skip {
                        continue;
                    }

                    if sink.write_all(line.as_bytes()).await.is_err()
                        || sink.write_all(b"\n").await.is_err()
                    {
                        return;
                    }

                    forwarded += 1;
                }
                _ => break,
            }
        }

        let _ = sink.shutdown().await;
    })
}

/// Run a process to completion and return its captured output. For the one-shot
/// cracker calls (keyspace, benchmark, health check) that read everything at the
/// end rather than streaming. Both streams are drained concurrently with the
/// wait so a process that fills a pipe buffer cannot deadlock.
pub async fn run_capture(
    program: &Path,
    args: &[impl AsRef<str>],
    cwd: &Path,
) -> io::Result<Captured> {
    let mut child = spawn_grouped(program, args, cwd)?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout not captured"))?;

    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr not captured"))?;

    let out = tokio::spawn(async move {
        let mut buf = String::new();
        stdout.read_to_string(&mut buf).await.map(|_| buf)
    });

    let err = tokio::spawn(async move {
        let mut buf = String::new();
        stderr.read_to_string(&mut buf).await.map(|_| buf)
    });

    let status = child.wait().await?;

    let stdout = out.await.map_err(io::Error::other)??;
    let stderr = err.await.map_err(io::Error::other)??;

    Ok(Captured {
        stdout,
        stderr,
        status,
    })
}

/// Send a termination signal to the whole process group led by `pid`. A no-op if
/// the process is already gone (`pid` is `None`).
pub fn kill_group(pid: Option<u32>) {
    let Some(pid) = pid else {
        return;
    };

    #[cfg(unix)]
    unsafe {
        // A negative target addresses the entire group; the group id equals the
        // leader's pid, because the child was spawned with process_group(0).
        libc::kill(-(pid as i32), libc::SIGTERM);
    }

    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/T", "/PID", &pid.to_string()])
            .spawn();
    }
}

/// Read `reader` line by line, map each line to an optional event, and forward
/// the mapped events on `tx`. Returns on EOF or once the receiver is gone,
/// dropping its `tx` clone so the shared channel can eventually close.
pub fn spawn_line_reader<R, T, F>(reader: R, tx: mpsc::Sender<T>, map: F) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    T: Send + 'static,
    F: Fn(String) -> Option<T> + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(event) = map(line)
                && tx.send(event).await.is_err()
            {
                break;
            }
        }
    })
}

/// Read `reader` line by line and log each non-empty line at `warn`. Used for a
/// pipeline producer's stderr, which is diagnostic rather than something the
/// server acts on.
pub fn spawn_stderr_logger(reader: impl AsyncRead + Unpin + Send + 'static) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim();

            if !line.is_empty() {
                tracing::warn!(%line, "preprocessor stderr");
            }
        }
    })
}

const TAIL_POLL: Duration = Duration::from_millis(50);

/// Tail `path`, forwarding each newly appended line as a mapped event. The file
/// need not exist yet (hashcat creates the outfile lazily on the first crack).
///
/// The task keeps polling until `finish` flips to `true`, then drains whatever
/// remains and returns. Partial lines (a write seen before its trailing newline)
/// are buffered and stitched to the next read, so a crack is never emitted
/// half-written.
pub fn spawn_file_tail<T, F>(
    path: PathBuf,
    tx: mpsc::Sender<T>,
    mut finish: watch::Receiver<bool>,
    map: F,
) -> JoinHandle<()>
where
    T: Send + 'static,
    F: Fn(String) -> Option<T> + Send + 'static,
{
    tokio::spawn(async move {
        let Some(file) = open_when_created(&path, &finish).await else {
            return;
        };

        let mut reader = BufReader::new(file);
        let mut carry = String::new();

        loop {
            let mut chunk = String::new();

            match reader.read_line(&mut chunk).await {
                Ok(0) => {
                    if *finish.borrow() {
                        break;
                    }

                    tokio::select! {
                        _ = tokio::time::sleep(TAIL_POLL) => {}
                        _ = finish.changed() => {}
                    }
                }
                Ok(_) => {
                    let complete = chunk.ends_with('\n');
                    carry.push_str(&chunk);

                    if !complete {
                        continue;
                    }

                    let line = std::mem::take(&mut carry);
                    let line = line.trim_end_matches(['\r', '\n']).to_owned();

                    if let Some(event) = map(line)
                        && tx.send(event).await.is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}

/// Poll until `path` can be opened, returning the handle. Returns `None` if the
/// run finishes (`finish` flips to `true`) before the file is ever created:
/// hashcat writes the outfile only once it has a crack, so a run that finds
/// nothing never produces one, and there is nothing left to wait for.
async fn open_when_created(path: &Path, finish: &watch::Receiver<bool>) -> Option<tokio::fs::File> {
    loop {
        match tokio::fs::File::open(path).await {
            Ok(file) => return Some(file),
            Err(_) => {
                if *finish.borrow() {
                    return None;
                }

                tokio::time::sleep(TAIL_POLL).await;
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// `seq 1 100 | cat` with a `(skip=3, length=4)` window should surface lines
    /// 4..=7 on the consumer's stdout, matching `head -n 7 | tail -n 4`.
    #[tokio::test]
    async fn line_window_drops_skip_and_forwards_length() {
        let mut pipeline = spawn_pipeline(
            ProcessSpec {
                program: Path::new("seq"),
                args: &["1", "100"],
            },
            ProcessSpec {
                program: Path::new("cat"),
                args: &[] as &[&str],
            },
            Path::new("."),
            Some((3, 4)),
        )
        .unwrap();

        let mut output = String::new();
        pipeline
            .consumer
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .await
            .unwrap();

        let _ = pipeline.consumer.wait().await;
        let _ = pipeline.producer.wait().await;

        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines, ["4", "5", "6", "7"]);
    }

    /// Without a window the whole producer stream reaches the consumer.
    #[tokio::test]
    async fn no_window_passes_the_full_stream() {
        let mut pipeline = spawn_pipeline(
            ProcessSpec {
                program: Path::new("seq"),
                args: &["1", "5"],
            },
            ProcessSpec {
                program: Path::new("cat"),
                args: &[] as &[&str],
            },
            Path::new("."),
            None,
        )
        .unwrap();

        let mut output = String::new();
        pipeline
            .consumer
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .await
            .unwrap();

        let _ = pipeline.consumer.wait().await;
        let _ = pipeline.producer.wait().await;

        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines, ["1", "2", "3", "4", "5"]);
    }
}
