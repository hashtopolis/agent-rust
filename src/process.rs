//! Generic child-process helpers shared by the cracker backends: spawning a
//! process as its own group leader so the whole group can be signalled at once,
//! plus the line-oriented readers that feed a backend's event channel.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

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
