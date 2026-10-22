//! The log file, rotated by size.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::warn;

/// How long a failed rotation waits before it is tried again.
const ROTATION_RETRY: Duration = Duration::from_secs(10);

/// A log file that is rotated before a write would take it past `max_size`.
/// The live file moves to `.1`, older rotations shift up one, and at most
/// `max_files` of them are kept.
///
/// A rotation that fails (on Windows, typically because another program holds
/// one of the files open) is reported on stderr and retried after
/// [`ROTATION_RETRY`]; meanwhile lines keep going to the live file.
pub(super) struct RotatingFile {
    path: PathBuf,
    max_size: u64,
    max_files: usize,
    /// `None` between closing the file for a rotation and reopening it.
    file: Option<File>,
    size: u64,
    /// Set while rotation is failing: when to try again.
    retry_at: Option<Instant>,
    rotation_retry: Duration,
}

impl RotatingFile {
    pub(super) fn open(path: &Path, max_size: u64, max_files: usize) -> io::Result<Self> {
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
        };

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
    }

    /// Move the live file to `.1`, shifting older rotations up one. Only the
    /// rotations below the first free slot move, so a retry after a failed
    /// rename never pushes another old file out.
    fn shift(&self) -> io::Result<()> {
        let free = (1..=self.max_files).find(|&n| !self.rotated(n).exists());

        let top = match free {
            Some(n) => n,
            None => {
                remove_if_exists(&self.rotated(self.max_files))?;
                self.max_files
            }
        };

        for n in (1..top).rev() {
            fs::rename(self.rotated(n), self.rotated(n + 1))?;
        }

        fs::rename(&self.path, self.rotated(1))
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

            let Some(number) = file_name.to_str().and_then(|n| n.strip_prefix(&prefix)) else {
                continue;
            };

            if number.parse::<usize>().is_ok_and(|n| n > self.max_files) {
                fs::remove_file(entry.path())?;
            }
        }

        Ok(())
    }

    fn rotated(&self, n: usize) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(format!(".{n}"));

        PathBuf::from(name)
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

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        fn files(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();

            names
        }
    }

    #[test]
    fn rotates_before_a_line_would_cross_the_limit_and_never_splits_one() {
        let fixture = Fixture::new();
        let mut log = fixture.open(10, 5);

        log.write_all(b"12345\n").unwrap();
        log.write_all(b"abcdef\n").unwrap();

        assert_eq!(fixture.live(), "abcdef\n");
        assert_eq!(fixture.plain(1), "12345\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1"]);
    }

    #[test]
    fn a_line_longer_than_the_limit_still_lands_in_a_file_of_its_own() {
        let fixture = Fixture::new();
        let mut log = fixture.open(4, 5);

        log.write_all(b"too long\n").unwrap();
        log.write_all(b"x\n").unwrap();

        assert_eq!(fixture.plain(1), "too long\n");
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

        assert_eq!(fixture.plain(1), "earlier\n0123456789\n");
        assert_eq!(fixture.live(), "abc\n");
    }

    #[test]
    fn keeps_only_max_files_rotations_newest_first() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);

        for line in ["a\n", "b\n", "c\n", "d\n"] {
            log.write_all(line.as_bytes()).unwrap();
        }

        assert_eq!(fixture.live(), "d\n");
        assert_eq!(fixture.plain(1), "c\n");
        assert_eq!(fixture.plain(2), "b\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1", "agent.log.2"]);
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
    fn a_rotation_deleted_from_outside_leaves_a_gap_that_is_filled_first() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 3);

        for line in ["a\n", "b\n", "c\n", "d\n"] {
            log.write_all(line.as_bytes()).unwrap();
        }

        fs::remove_file(fixture.rotated("2")).unwrap();
        log.write_all(b"e\n").unwrap();

        // Only `.1` moves up into the gap; `.3` stays where it was.
        assert_eq!(fixture.live(), "e\n");
        assert_eq!(fixture.plain(1), "d\n");
        assert_eq!(fixture.plain(2), "c\n");
        assert_eq!(fixture.plain(3), "a\n");
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

        let set_mode = |mode| {
            fs::set_permissions(fixture.dir.path(), fs::Permissions::from_mode(mode)).unwrap()
        };

        set_mode(0o555);
        log.write_all(b"d\n").unwrap();
        log.write_all(b"e\n").unwrap();
        set_mode(0o755);

        assert_eq!(fixture.live(), "c\nd\ne\n");
        assert_eq!(fixture.plain(1), "b\n");
        assert_eq!(fixture.plain(2), "a\n");

        log.write_all(b"f\n").unwrap();

        assert_eq!(fixture.live(), "f\n");
        assert_eq!(fixture.plain(1), "c\nd\ne\n");
        assert_eq!(fixture.plain(2), "b\n");
    }

    #[test]
    fn rotations_beyond_max_files_are_removed_on_open() {
        let fixture = Fixture::new();
        fs::write(fixture.rotated("1"), "c\n").unwrap();
        fs::write(fixture.rotated("2"), "b\n").unwrap();
        fs::write(fixture.rotated("4"), "a\n").unwrap();
        fs::write(fixture.rotated("old"), "not a rotation\n").unwrap();

        fixture.open(10, 1);

        assert_eq!(
            fixture.files(),
            ["agent.log", "agent.log.1", "agent.log.old"]
        );
    }

    #[test]
    fn a_live_file_deleted_from_outside_is_recreated_without_a_rotation() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 3);

        for line in ["a\n", "b\n"] {
            log.write_all(line.as_bytes()).unwrap();
        }

        fs::remove_file(&fixture.path).unwrap();
        log.write_all(b"c\n").unwrap();

        assert_eq!(fixture.live(), "c\n");
        assert_eq!(fixture.plain(1), "a\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1"]);
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

        // The rename would work again, but the retry interval has not passed.
        assert_eq!(fixture.live(), "a\nb\nc\n");
        assert_eq!(fixture.files(), ["agent.log"]);
    }
}
