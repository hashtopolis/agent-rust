//! The log file: rotated by size, gzip-compressed, and written from a
//! background thread so rotation never stalls the agent's own threads.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use flate2::Compression;
use flate2::write::GzEncoder;

/// How long a failed rotation waits before it is tried again.
const ROTATION_RETRY: Duration = Duration::from_secs(10);

/// A log file that is rotated before a write would take it past `max_size`.
/// The live file moves to `.1`, older rotations shift up one, and at most
/// `max_files` of them are kept. `.1` is compressed to `.1.gz` on a thread of
/// its own, so writing carries on meanwhile.
///
/// A rotation that fails (on Windows, typically because another program holds
/// one of the files open) is reported on stderr and retried after
/// [`ROTATION_RETRY`]; meanwhile lines keep going to the live file.
pub(crate) struct RotatingFile {
    path: PathBuf,
    max_size: u64,
    max_files: usize,
    /// `None` between closing the file for a rotation and reopening it.
    file: Option<File>,
    size: u64,
    /// Set while rotation is failing: when to try again.
    retry_at: Option<Instant>,
    rotation_retry: Duration,
    compressing: Option<JoinHandle<()>>,
}

impl RotatingFile {
    pub(crate) fn open(path: &Path, max_size: u64, max_files: usize) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut log = Self {
            path: path.to_path_buf(),
            max_size,
            max_files,
            file: None,
            size: 0,
            retry_at: None,
            rotation_retry: ROTATION_RETRY,
            compressing: None,
        };

        // A compression cut short by a crash or restart leaves its temporary
        // file behind; the plain rotation it was made from is still there.
        remove_if_exists(&log.compression_temp())?;

        if let Err(error) = log.remove_extra_rotations() {
            warn(format_args!(
                "cannot remove old rotations of log file {}: {error}",
                log.path.display()
            ));
        }

        log.live_file()?;

        Ok(log)
    }

    fn live_file(&mut self) -> io::Result<&mut File> {
        if self.file.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;

            self.size = file.metadata()?.len();
            self.file = Some(file);
        }

        Ok(self.file.as_mut().expect("opened above"))
    }

    fn rotation_due(&self, len: u64) -> bool {
        self.size > 0
            && self.size + len > self.max_size
            && self.retry_at.is_none_or(|at| Instant::now() >= at)
    }

    fn rotate(&mut self) {
        // Windows cannot rename a file that is still open.
        self.file = None;

        // Deleted from outside: there is nothing to rotate, and the next write
        // starts a new file.
        if !self.path.exists() {
            self.retry_at = None;

            return;
        }

        // `.1` must not move while it is still being compressed.
        self.finish_compression();

        if let Err(error) = self.shift() {
            if self.retry_at.is_none() {
                warn(format_args!(
                    "cannot rotate log file {}: {error}; still writing to it",
                    self.path.display()
                ));
            }

            self.retry_at = Some(Instant::now() + self.rotation_retry);

            return;
        }

        self.retry_at = None;
        self.start_compression();
    }

    /// Move the live file to `.1`, shifting older rotations up one. Only the
    /// rotations below the first free slot move, so a retry after a failed
    /// rename never pushes another old file out.
    fn shift(&self) -> io::Result<()> {
        let free = (1..=self.max_files).find(|&n| !self.occupied(n));

        let top = match free {
            Some(n) => n,
            None => {
                self.remove(self.max_files)?;
                self.max_files
            }
        };

        for n in (1..top).rev() {
            self.move_rotation(n, n + 1)?;
        }

        fs::rename(&self.path, self.rotated(1, false))
    }

    fn start_compression(&mut self) {
        let plain = self.rotated(1, false);
        let temp = self.compression_temp();
        let compressed = self.rotated(1, true);

        let spawned = {
            let (plain, temp, compressed) = (plain.clone(), temp.clone(), compressed.clone());

            thread::Builder::new()
                .name("log-compress".to_string())
                .spawn(move || compress_rotation(&plain, &temp, &compressed))
        };

        match spawned {
            Ok(handle) => self.compressing = Some(handle),
            Err(_) => compress_rotation(&plain, &temp, &compressed),
        }
    }

    fn finish_compression(&mut self) {
        if let Some(compressing) = self.compressing.take() {
            let _ = compressing.join();
        }
    }

    /// Remove rotations numbered above `max_files`, left over from a higher
    /// limit.
    fn remove_extra_rotations(&self) -> io::Result<()> {
        let directory = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };

        let Some(name) = self.path.file_name().and_then(|name| name.to_str()) else {
            return Ok(());
        };

        let prefix = format!("{name}.");

        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let file_name = entry.file_name();

            let Some(suffix) = file_name.to_str().and_then(|n| n.strip_prefix(&prefix)) else {
                continue;
            };

            let number = suffix.strip_suffix(".gz").unwrap_or(suffix);

            if number.parse::<usize>().is_ok_and(|n| n > self.max_files) {
                fs::remove_file(entry.path())?;
            }
        }

        Ok(())
    }

    /// A rotation may be plain (its compression failed) or compressed.
    fn occupied(&self, n: usize) -> bool {
        self.rotated(n, false).exists() || self.rotated(n, true).exists()
    }

    fn remove(&self, n: usize) -> io::Result<()> {
        remove_if_exists(&self.rotated(n, false))?;
        remove_if_exists(&self.rotated(n, true))
    }

    fn move_rotation(&self, from: usize, to: usize) -> io::Result<()> {
        let compressed = self.rotated(from, true);

        if compressed.exists() {
            // A plain copy next to it is one whose deletion failed after it
            // was compressed; the compressed one is complete.
            remove_if_exists(&self.rotated(from, false))?;

            return fs::rename(compressed, self.rotated(to, true));
        }

        fs::rename(self.rotated(from, false), self.rotated(to, false))
    }

    fn rotated(&self, n: usize, compressed: bool) -> PathBuf {
        let extension = if compressed { ".gz" } else { "" };

        with_suffix(&self.path, &format!(".{n}{extension}"))
    }

    fn compression_temp(&self) -> PathBuf {
        with_suffix(&self.path, ".1.gz.tmp")
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len() as u64;

        if self.rotation_due(len) {
            self.rotate();
        }

        self.live_file()?.write_all(buf)?;
        self.size += len;

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.file {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

/// Compress a rotation, keeping it uncompressed if that fails.
fn compress_rotation(plain: &Path, temp: &Path, compressed: &Path) {
    if let Err(error) = compress(plain, temp, compressed) {
        warn(format_args!(
            "cannot compress rotated log file {}: {error}; keeping it uncompressed",
            plain.display()
        ));
    }
}

/// Compress `plain` into `compressed` through `temp`, so an interrupted run
/// never leaves a truncated `.gz` behind.
fn compress(plain: &Path, temp: &Path, compressed: &Path) -> io::Result<()> {
    let written = (|| {
        let mut encoder = GzEncoder::new(File::create(temp)?, Compression::fast());
        io::copy(&mut File::open(plain)?, &mut encoder)?;
        encoder.finish()?;

        fs::rename(temp, compressed)
    })();

    if written.is_err() {
        let _ = fs::remove_file(temp);
    }

    written?;
    fs::remove_file(plain)
}

/// Report a problem with the log file on stderr. A failing stderr is ignored:
/// `eprintln!` would panic and take the writer thread down with it.
fn warn(message: fmt::Arguments) {
    let _ = writeln!(io::stderr(), "warning: {message}");
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);

    PathBuf::from(name)
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

/// How many log lines may queue up for the writer thread before logging waits.
const QUEUE_LINES: usize = 1024;

enum Message {
    Line(Vec<u8>),
    Flush(SyncSender<()>),
}

/// Hands each log line to the writer thread.
#[derive(Clone)]
pub(crate) struct BackgroundWriter(SyncSender<Message>);

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
    pub(crate) fn console_only() -> Self {
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
pub(crate) fn spawn(mut file: RotatingFile) -> io::Result<(BackgroundWriter, LogGuard)> {
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

    use std::io::Read;
    use std::time::Duration;

    use flate2::read::GzDecoder;
    use tempfile::TempDir;

    struct Fixture {
        dir: TempDir,
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("agent.log");

            Self { dir, path }
        }

        fn open(&self, max_size: u64, max_files: usize) -> RotatingFile {
            RotatingFile::open(&self.path, max_size, max_files).unwrap()
        }

        fn rotated(&self, suffix: &str) -> PathBuf {
            self.dir.path().join(format!("agent.log.{suffix}"))
        }

        fn live(&self) -> String {
            fs::read_to_string(&self.path).unwrap()
        }

        fn plain(&self, n: usize) -> String {
            fs::read_to_string(self.rotated(&n.to_string())).unwrap()
        }

        fn compressed(&self, n: usize) -> String {
            let mut text = String::new();
            GzDecoder::new(File::open(self.rotated(&format!("{n}.gz"))).unwrap())
                .read_to_string(&mut text)
                .unwrap();

            text
        }

        fn write_gz(&self, n: usize, text: &str) {
            let mut encoder = GzEncoder::new(
                File::create(self.rotated(&format!("{n}.gz"))).unwrap(),
                Compression::default(),
            );
            encoder.write_all(text.as_bytes()).unwrap();
            encoder.finish().unwrap();
        }

        fn files(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();

            names
        }
    }

    /// Wait for the background compression of the latest rotation.
    fn settle(log: &mut RotatingFile) {
        if let Some(compressing) = log.compressing.take() {
            compressing.join().unwrap();
        }
    }

    #[test]
    fn rotates_before_a_line_would_cross_the_limit_and_never_splits_one() {
        let fixture = Fixture::new();
        let mut log = fixture.open(10, 5);

        log.write_all(b"12345\n").unwrap();
        log.write_all(b"abcdef\n").unwrap();
        settle(&mut log);

        assert_eq!(fixture.live(), "abcdef\n");
        assert_eq!(fixture.compressed(1), "12345\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1.gz"]);
    }

    #[test]
    fn a_line_longer_than_the_limit_still_lands_in_a_file_of_its_own() {
        let fixture = Fixture::new();
        let mut log = fixture.open(4, 5);

        log.write_all(b"too long\n").unwrap();
        log.write_all(b"x\n").unwrap();
        settle(&mut log);

        assert_eq!(fixture.compressed(1), "too long\n");
        assert_eq!(fixture.live(), "x\n");
    }

    #[test]
    fn appends_to_an_existing_file_and_counts_its_size() {
        let fixture = Fixture::new();
        fs::write(&fixture.path, "earlier\n").unwrap();
        let mut log = fixture.open(20, 5);

        log.write_all(b"0123456789\n").unwrap();

        assert_eq!(fixture.live(), "earlier\n0123456789\n");

        log.write_all(b"abc\n").unwrap();
        settle(&mut log);

        assert_eq!(fixture.compressed(1), "earlier\n0123456789\n");
        assert_eq!(fixture.live(), "abc\n");
    }

    #[test]
    fn keeps_only_max_files_rotations_newest_first() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);

        for line in ["a\n", "b\n", "c\n", "d\n"] {
            log.write_all(line.as_bytes()).unwrap();
        }

        settle(&mut log);

        assert_eq!(fixture.live(), "d\n");
        assert_eq!(fixture.compressed(1), "c\n");
        assert_eq!(fixture.compressed(2), "b\n");
        assert_eq!(
            fixture.files(),
            ["agent.log", "agent.log.1.gz", "agent.log.2.gz"]
        );
    }

    #[test]
    fn creates_a_missing_log_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("logs").join("agent.log");

        RotatingFile::open(&path, 10, 5)
            .unwrap()
            .write_all(b"x\n")
            .unwrap();

        assert_eq!(fs::read_to_string(path).unwrap(), "x\n");
    }

    #[test]
    fn a_stray_compression_temp_file_is_removed_on_open() {
        let fixture = Fixture::new();
        fs::write(fixture.rotated("1.gz.tmp"), "half a gzip").unwrap();

        fixture.open(10, 5);

        assert_eq!(fixture.files(), ["agent.log"]);
    }

    #[test]
    fn a_rotation_left_uncompressed_shifts_along_with_the_rest() {
        let fixture = Fixture::new();
        fs::write(&fixture.path, "c\n").unwrap();
        fs::write(fixture.rotated("1"), "b\n").unwrap();
        fixture.write_gz(2, "a\n");
        let mut log = fixture.open(2, 3);

        log.write_all(b"d\n").unwrap();
        settle(&mut log);

        assert_eq!(fixture.live(), "d\n");
        assert_eq!(fixture.compressed(1), "c\n");
        assert_eq!(fixture.plain(2), "b\n");
        assert_eq!(fixture.compressed(3), "a\n");
    }

    #[test]
    fn a_rotation_deleted_from_outside_leaves_a_gap_that_is_filled_first() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 3);

        for line in ["a\n", "b\n", "c\n", "d\n"] {
            log.write_all(line.as_bytes()).unwrap();
        }

        settle(&mut log);
        fs::remove_file(fixture.rotated("2.gz")).unwrap();
        log.write_all(b"e\n").unwrap();
        settle(&mut log);

        // Only `.1` moves up into the gap; `.3` stays where it was.
        assert_eq!(fixture.live(), "e\n");
        assert_eq!(fixture.compressed(1), "d\n");
        assert_eq!(fixture.compressed(2), "c\n");
        assert_eq!(fixture.compressed(3), "a\n");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_rotation_keeps_writing_to_the_live_file_and_loses_nothing() {
        use std::os::unix::fs::PermissionsExt;

        // Root ignores directory permissions, so the rename would not fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);
        log.rotation_retry = Duration::ZERO;

        for line in ["a\n", "b\n", "c\n"] {
            log.write_all(line.as_bytes()).unwrap();
        }

        settle(&mut log);

        let set_mode = |mode| {
            fs::set_permissions(fixture.dir.path(), fs::Permissions::from_mode(mode)).unwrap()
        };

        set_mode(0o555);
        log.write_all(b"d\n").unwrap();
        log.write_all(b"e\n").unwrap();
        set_mode(0o755);

        assert_eq!(fixture.live(), "c\nd\ne\n");
        assert_eq!(fixture.compressed(1), "b\n");
        assert_eq!(fixture.compressed(2), "a\n");

        log.write_all(b"f\n").unwrap();
        settle(&mut log);

        assert_eq!(fixture.live(), "f\n");
        assert_eq!(fixture.compressed(1), "c\nd\ne\n");
        assert_eq!(fixture.compressed(2), "b\n");
    }

    #[test]
    fn rotations_beyond_max_files_are_removed_on_open() {
        let fixture = Fixture::new();
        fixture.write_gz(1, "c\n");
        fixture.write_gz(2, "b\n");
        fixture.write_gz(4, "a\n");
        fs::write(fixture.rotated("3"), "plain\n").unwrap();
        fs::write(fixture.rotated("old"), "not a rotation\n").unwrap();

        fixture.open(10, 1);

        assert_eq!(
            fixture.files(),
            ["agent.log", "agent.log.1.gz", "agent.log.old"]
        );
    }

    #[test]
    fn a_rotation_kept_both_plain_and_compressed_moves_on_compressed_only() {
        let fixture = Fixture::new();
        fs::write(&fixture.path, "c\n").unwrap();
        fs::write(fixture.rotated("1"), "b\n").unwrap();
        fixture.write_gz(1, "b\n");
        let mut log = fixture.open(2, 3);

        log.write_all(b"d\n").unwrap();
        settle(&mut log);

        assert_eq!(fixture.compressed(2), "b\n");
        assert_eq!(
            fixture.files(),
            ["agent.log", "agent.log.1.gz", "agent.log.2.gz"]
        );
    }

    #[test]
    fn a_live_file_deleted_from_outside_is_recreated_without_a_rotation() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 3);

        for line in ["a\n", "b\n"] {
            log.write_all(line.as_bytes()).unwrap();
        }

        settle(&mut log);
        fs::remove_file(&fixture.path).unwrap();
        log.write_all(b"c\n").unwrap();
        settle(&mut log);

        assert_eq!(fixture.live(), "c\n");
        assert_eq!(fixture.compressed(1), "a\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1.gz"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_rotation_is_not_retried_on_every_line() {
        use std::os::unix::fs::PermissionsExt;

        // Root ignores directory permissions, so the rename would not fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);
        log.write_all(b"a\n").unwrap();

        let set_mode = |mode| {
            fs::set_permissions(fixture.dir.path(), fs::Permissions::from_mode(mode)).unwrap()
        };

        set_mode(0o555);
        log.write_all(b"b\n").unwrap();
        set_mode(0o755);
        log.write_all(b"c\n").unwrap();
        settle(&mut log);

        // The rename would work again, but the retry interval has not passed.
        assert_eq!(fixture.live(), "a\nb\nc\n");
        assert_eq!(fixture.files(), ["agent.log"]);
    }

    #[test]
    fn flush_waits_until_every_queued_line_is_in_the_file() {
        let fixture = Fixture::new();
        let (writer, guard) = spawn(fixture.open(1 << 20, 5)).unwrap();

        for n in 0..500 {
            writeln!(writer.clone(), "line {n}").unwrap();
        }

        guard.flush();

        let expected: String = (0..500).map(|n| format!("line {n}\n")).collect();
        assert_eq!(fixture.live(), expected);
    }

    #[test]
    fn logging_carries_on_after_a_flush() {
        let fixture = Fixture::new();
        let (mut writer, guard) = spawn(fixture.open(1 << 20, 5)).unwrap();

        writer.write_all(b"before\n").unwrap();
        guard.flush();
        writer.write_all(b"after\n").unwrap();
        guard.flush();

        assert_eq!(fixture.live(), "before\nafter\n");
    }

    #[test]
    fn dropping_the_guard_flushes() {
        let fixture = Fixture::new();
        let (mut writer, guard) = spawn(fixture.open(1 << 20, 5)).unwrap();

        writer.write_all(b"last words\n").unwrap();
        drop(guard);

        assert_eq!(fixture.live(), "last words\n");
    }
}
