//! The thread that writes the log file: the agent's own threads only queue
//! their lines.

use std::fmt;
use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;

use super::file::RotatingFile;
use super::warn_on_stderr;

/// How many log lines may queue up for the writer thread before logging waits.
const QUEUE_LINES: usize = 1024;

enum Message {
    Line(Vec<u8>),
    Flush(SyncSender<()>),
}

/// The fmt layer writes an event with a single `write` call, so one call
/// carries one whole line.
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

/// Prints text to the console and writes it to the log file as it is,
/// whatever the log level.
pub struct RawPrinter(Option<BackgroundWriter>);

impl RawPrinter {
    pub(super) fn console_only() -> Self {
        Self(None)
    }

    pub(super) fn with_file(file: BackgroundWriter) -> Self {
        Self(Some(file))
    }

    pub fn print(&self, text: impl fmt::Display) {
        let text = text.to_string();
        print!("{text}");

        if let Some(file) = &self.0 {
            let _ = file.clone().write_all(text.as_bytes());
        }
    }
}

/// Dropping it waits until every line logged so far is in the file and the
/// last rotation is compressed.
pub struct LogGuard(Option<SyncSender<Message>>);

impl LogGuard {
    pub(super) fn console_only() -> Self {
        Self(None)
    }

    /// Block until every line logged so far is in the file and the last
    /// rotation is compressed.
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

/// The thread lives as long as the process: the subscriber keeps a sender for
/// good.
pub(super) fn spawn(file: RotatingFile) -> io::Result<(BackgroundWriter, LogGuard)> {
    let (sender, receiver) = mpsc::sync_channel(QUEUE_LINES);

    thread::Builder::new()
        .name("log-writer".to_string())
        .spawn(move || write_lines(file, receiver))?;

    Ok((BackgroundWriter(sender.clone()), LogGuard(Some(sender))))
}

fn write_lines(mut file: RotatingFile, receiver: Receiver<Message>) {
    let mut failing = false;
    for message in receiver {
        match message {
            Message::Line(line) => match file.write_line(&line) {
                Ok(()) => failing = false,
                Err(error) => {
                    if !failing {
                        warn_on_stderr(format_args!("cannot write to the log file: {error}"));
                    }

                    failing = true;
                }
            },
            Message::Flush(done) => {
                file.wait_for_compression();
                let _ = done.send(());
            }
        }
    }
}

#[cfg(test)]
pub(super) struct TestLog {
    pub(super) path: std::path::PathBuf,
    pub(super) writer: BackgroundWriter,
    pub(super) guard: LogGuard,
    _dir: tempfile::TempDir,
}

#[cfg(test)]
impl TestLog {
    pub(super) fn new() -> Self {
        Self::rotating_at(1 << 20)
    }

    pub(super) fn rotating_at(max_size: u64) -> Self {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("agent.log");
        let (writer, guard) = spawn(RotatingFile::open(&path, max_size, 5).unwrap()).unwrap();

        Self {
            path,
            writer,
            guard,
            _dir: dir,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    #[test]
    fn flush_waits_until_every_queued_line_is_in_the_file() {
        let log = TestLog::new();

        for n in 0..500 {
            let line = format!("line {n}\n");
            log.writer.clone().write_all(line.as_bytes()).unwrap();
        }

        log.guard.flush();

        let expected: String = (0..500).map(|n| format!("line {n}\n")).collect();
        assert_eq!(fs::read_to_string(&log.path).unwrap(), expected);
    }

    #[test]
    fn logging_carries_on_after_a_flush() {
        let mut log = TestLog::new();

        log.writer.write_all(b"before\n").unwrap();
        log.guard.flush();
        log.writer.write_all(b"after\n").unwrap();
        log.guard.flush();

        assert_eq!(fs::read_to_string(&log.path).unwrap(), "before\nafter\n");
    }

    #[test]
    fn printed_text_lands_in_the_file_between_the_lines_around_it() {
        let mut log = TestLog::new();
        let printer = RawPrinter::with_file(log.writer.clone());

        log.writer.write_all(b"before\n").unwrap();
        printer.print("two\nlines\n");
        log.writer.write_all(b"after\n").unwrap();
        log.guard.flush();

        assert_eq!(
            fs::read_to_string(&log.path).unwrap(),
            "before\ntwo\nlines\nafter\n"
        );
    }

    #[test]
    fn printed_text_is_never_split_by_a_rotation() {
        let mut log = TestLog::rotating_at(10);
        let printer = RawPrinter::with_file(log.writer.clone());

        log.writer.write_all(b"12345\n").unwrap();
        printer.print("two\nlines\n");
        log.guard.flush();

        assert_eq!(fs::read_to_string(&log.path).unwrap(), "two\nlines\n");
    }

    #[test]
    fn flush_waits_for_the_last_rotation_to_be_compressed() {
        let mut log = TestLog::rotating_at(10);

        log.writer.write_all(b"12345\n").unwrap();
        log.writer.write_all(b"abcdef\n").unwrap();
        log.guard.flush();

        assert!(log.path.with_added_extension("1.gz").exists());
        assert!(!log.path.with_added_extension("1").exists());
    }

    #[test]
    fn dropping_the_guard_flushes() {
        let mut log = TestLog::new();

        log.writer.write_all(b"last words\n").unwrap();
        drop(log.guard);

        assert_eq!(fs::read_to_string(&log.path).unwrap(), "last words\n");
    }
}
