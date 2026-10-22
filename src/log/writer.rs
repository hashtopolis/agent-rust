//! The thread that writes log lines to the file, so rotation never stalls the
//! agent's own threads.

use std::io::{self, Write};
use std::sync::mpsc::{self, SyncSender};
use std::thread;

use super::file::RotatingFile;
use super::warn;

/// How many log lines may queue up for the writer thread before logging waits.
const QUEUE_LINES: usize = 1024;

enum Message {
    Line(Vec<u8>),
    Flush(SyncSender<()>),
}

/// Hands each log line to the writer thread.
#[derive(Clone)]
pub(super) struct BackgroundWriter(SyncSender<Message>);

impl Write for BackgroundWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .send(Message::Line(buf.to_vec()))
            .map_err(|_| io::Error::other("the log writer thread has stopped"))?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Keeps the log file complete: dropping it, or calling [`LogGuard::flush`],
/// waits until every line logged so far is in the file.
pub struct LogGuard(Option<SyncSender<Message>>);

impl LogGuard {
    pub(super) fn console_only() -> Self {
        Self(None)
    }

    /// Block until every line logged so far is in the file. Logging carries on
    /// afterwards.
    pub fn flush(&self) {
        let Some(sender) = &self.0 else {
            return;
        };

        let (done, written) = mpsc::sync_channel(1);

        if sender.send(Message::Flush(done)).is_ok() {
            let _ = written.recv();
        }
    }
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Start the writer thread that owns `file`. It lives as long as the process:
/// the subscriber keeps a sender for good.
pub(super) fn spawn(mut file: RotatingFile) -> io::Result<(BackgroundWriter, LogGuard)> {
    let (sender, receiver) = mpsc::sync_channel(QUEUE_LINES);

    thread::Builder::new()
        .name("log-writer".to_string())
        .spawn(move || {
            let mut failing = false;

            for message in receiver {
                match message {
                    Message::Line(line) => match file.write_all(&line) {
                        Ok(()) => failing = false,
                        Err(error) => {
                            if !failing {
                                warn(format_args!("cannot write to the log file: {error}"));
                            }

                            failing = true;
                        }
                    },
                    Message::Flush(done) => {
                        let _ = done.send(());
                    }
                }
            }
        })?;

    Ok((BackgroundWriter(sender.clone()), LogGuard(Some(sender))))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use tempfile::TempDir;

    #[test]
    fn flush_waits_until_every_queued_line_is_in_the_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent.log");
        let (writer, guard) = spawn(RotatingFile::open(&path, 1 << 20, 5).unwrap()).unwrap();

        for n in 0..500 {
            writeln!(writer.clone(), "line {n}").unwrap();
        }

        guard.flush();

        let expected: String = (0..500).map(|n| format!("line {n}\n")).collect();
        assert_eq!(fs::read_to_string(&path).unwrap(), expected);
    }

    #[test]
    fn logging_carries_on_after_a_flush() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent.log");
        let (mut writer, guard) = spawn(RotatingFile::open(&path, 1 << 20, 5).unwrap()).unwrap();

        writer.write_all(b"before\n").unwrap();
        guard.flush();
        writer.write_all(b"after\n").unwrap();
        guard.flush();

        assert_eq!(fs::read_to_string(&path).unwrap(), "before\nafter\n");
    }

    #[test]
    fn dropping_the_guard_flushes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent.log");
        let (mut writer, guard) = spawn(RotatingFile::open(&path, 1 << 20, 5).unwrap()).unwrap();

        writer.write_all(b"last words\n").unwrap();
        drop(guard);

        assert_eq!(fs::read_to_string(&path).unwrap(), "last words\n");
    }
}
