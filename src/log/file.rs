//! The log file, rotated by size.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::warn_on_stderr;

const ROTATION_RETRY_DELAY: Duration = Duration::from_secs(10);

/// Rotates before a line would take the file past `max_size`: the live file
/// becomes `.1`, older rotations shift up one and `max_files` of them are
/// kept. A failed rotation loses nothing: lines keep going to the live file
/// until a retry succeeds.
pub(super) struct RotatingFile {
    path: PathBuf,
    max_size: u64,
    max_files: usize,
    /// `None` between closing the file for a rotation and reopening it.
    live: Option<LiveFile>,
    /// Permissions of the old live file, so the new one gets the same.
    permissions: Option<fs::Permissions>,
    /// When to retry a failed rotation.
    retry_at: Option<Instant>,
}

impl RotatingFile {
    pub(super) fn open(path: &Path, max_size: u64, max_files: usize) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let log = Self {
            path: path.to_path_buf(),
            max_size,
            max_files,
            live: Some(LiveFile::open(path, None)?),
            permissions: None,
            retry_at: None,
        };

        if let Err(error) = log.remove_excess_rotations() {
            warn_on_stderr(format_args!(
                "cannot remove old rotations of log file {}: {error}",
                log.path.display()
            ));
        }

        Ok(log)
    }

    pub(super) fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        if !self.has_room_for(line) {
            self.rotate();
        }

        self.live_file()?.append(line)
    }

    /// An empty file takes any line, even one longer than `max_size`.
    fn has_room_for(&self, line: &[u8]) -> bool {
        let Some(live) = &self.live else {
            return true;
        };

        live.size == 0 || live.size + line.len() as u64 <= self.max_size
    }

    fn live_file(&mut self) -> io::Result<&mut LiveFile> {
        let live = match self.live.take() {
            Some(live) => live,
            None => LiveFile::open(&self.path, self.permissions.as_ref())?,
        };

        Ok(self.live.insert(live))
    }

    fn rotate(&mut self) {
        if self.retry_at.is_some_and(|at| Instant::now() < at) {
            return;
        }

        // Windows cannot rename a file that is still open.
        if let Some(live) = self.live.take() {
            self.permissions = live.permissions();
        }

        // Someone deleted the file, so there is nothing to rotate.
        if !self.path.exists() {
            self.retry_at = None;

            return;
        }

        match self.shift_rotations() {
            Ok(()) => self.retry_at = None,
            Err(error) => {
                if self.retry_at.is_none() {
                    warn_on_stderr(format_args!(
                        "cannot rotate log file {}: {error}; still writing to it",
                        self.path.display()
                    ));
                }

                self.retry_at = Some(Instant::now() + ROTATION_RETRY_DELAY);
            }
        }
    }

    /// Only the rotations below the first free slot move, so a retry after a
    /// failed rename never pushes another old file out.
    fn shift_rotations(&self) -> io::Result<()> {
        let free = (1..=self.max_files).find(|&n| !self.rotation_path(n).exists());

        let top = match free {
            Some(n) => n,
            None => {
                remove_if_exists(&self.rotation_path(self.max_files))?;
                self.max_files
            }
        };

        for n in (1..top).rev() {
            fs::rename(self.rotation_path(n), self.rotation_path(n + 1))?;
        }

        fs::rename(&self.path, self.rotation_path(1))
    }

    /// Rotations numbered above `max_files` are left over from a higher limit.
    fn remove_excess_rotations(&self) -> io::Result<()> {
        let directory = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };

        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let number = self.rotation_number(&path);

            if number.is_some_and(|n| n > self.max_files) {
                fs::remove_file(path)?;
            }
        }

        Ok(())
    }

    fn rotation_path(&self, n: usize) -> PathBuf {
        self.path.with_added_extension(n.to_string())
    }

    /// The inverse of [`Self::rotation_path`].
    fn rotation_number(&self, path: &Path) -> Option<usize> {
        if path.file_stem() != self.path.file_name() {
            return None;
        }

        path.extension()?.to_str()?.parse().ok()
    }
}

struct LiveFile {
    file: File,
    size: u64,
}

impl LiveFile {
    fn open(path: &Path, permissions: Option<&fs::Permissions>) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        if let Some(permissions) = permissions {
            file.set_permissions(permissions.clone())?;
        }

        let size = file.metadata()?.len();

        Ok(Self { file, size })
    }

    fn permissions(&self) -> Option<fs::Permissions> {
        let metadata = self.file.metadata().ok()?;

        Some(metadata.permissions())
    }

    fn append(&mut self, line: &[u8]) -> io::Result<()> {
        self.file.write_all(line)?;
        self.size += line.len() as u64;

        Ok(())
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

        fn rotation_path(&self, suffix: &str) -> PathBuf {
            self.dir.path().join(format!("agent.log.{suffix}"))
        }

        fn live(&self) -> String {
            fs::read_to_string(&self.path).unwrap()
        }

        fn rotation(&self, n: usize) -> String {
            fs::read_to_string(self.rotation_path(&n.to_string())).unwrap()
        }

        fn files(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();

            names
        }

        #[cfg(unix)]
        fn forbid_renames(&self) {
            self.set_mode(0o555);
        }

        #[cfg(unix)]
        fn allow_renames(&self) {
            self.set_mode(0o755);
        }

        #[cfg(unix)]
        fn set_mode(&self, mode: u32) {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(self.dir.path(), fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    fn skip_retry_delay(log: &mut RotatingFile) {
        log.retry_at = Some(Instant::now());
    }

    /// Root ignores directory permissions, so its renames would not fail.
    #[cfg(unix)]
    fn is_root() -> bool {
        let uid = unsafe { libc::geteuid() };

        uid == 0
    }

    #[test]
    fn rotates_before_a_line_would_cross_the_limit_and_never_splits_one() {
        let fixture = Fixture::new();
        let mut log = fixture.open(10, 5);

        log.write_line(b"12345\n").unwrap();
        log.write_line(b"abcdef\n").unwrap();

        assert_eq!(fixture.live(), "abcdef\n");
        assert_eq!(fixture.rotation(1), "12345\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1"]);
    }

    #[test]
    fn a_line_longer_than_the_limit_still_lands_in_a_file_of_its_own() {
        let fixture = Fixture::new();
        let mut log = fixture.open(4, 5);

        log.write_line(b"too long\n").unwrap();
        log.write_line(b"x\n").unwrap();

        assert_eq!(fixture.rotation(1), "too long\n");
        assert_eq!(fixture.live(), "x\n");
    }

    #[test]
    fn appends_to_an_existing_file_and_counts_its_size() {
        let fixture = Fixture::new();
        fs::write(&fixture.path, "earlier\n").unwrap();
        let mut log = fixture.open(20, 5);

        log.write_line(b"0123456789\n").unwrap();

        assert_eq!(fixture.live(), "earlier\n0123456789\n");

        log.write_line(b"abc\n").unwrap();

        assert_eq!(fixture.rotation(1), "earlier\n0123456789\n");
        assert_eq!(fixture.live(), "abc\n");
    }

    #[test]
    fn keeps_only_max_files_rotations_newest_first() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);

        for line in ["a\n", "b\n", "c\n", "d\n"] {
            log.write_line(line.as_bytes()).unwrap();
        }

        assert_eq!(fixture.live(), "d\n");
        assert_eq!(fixture.rotation(1), "c\n");
        assert_eq!(fixture.rotation(2), "b\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1", "agent.log.2"]);
    }

    #[test]
    fn creates_a_missing_log_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("logs").join("agent.log");

        RotatingFile::open(&path, 10, 5)
            .unwrap()
            .write_line(b"x\n")
            .unwrap();

        assert_eq!(fs::read_to_string(path).unwrap(), "x\n");
    }

    #[test]
    fn a_rotation_deleted_from_outside_leaves_a_gap_that_is_filled_first() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 3);

        for line in ["a\n", "b\n", "c\n", "d\n"] {
            log.write_line(line.as_bytes()).unwrap();
        }

        fs::remove_file(fixture.rotation_path("2")).unwrap();
        log.write_line(b"e\n").unwrap();

        assert_eq!(fixture.live(), "e\n");
        assert_eq!(fixture.rotation(1), "d\n");
        assert_eq!(fixture.rotation(2), "c\n");
        assert_eq!(fixture.rotation(3), "a\n");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_rotation_keeps_writing_to_the_live_file_and_loses_nothing() {
        if is_root() {
            return;
        }

        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);

        for line in ["a\n", "b\n", "c\n"] {
            log.write_line(line.as_bytes()).unwrap();
        }

        fixture.forbid_renames();
        log.write_line(b"d\n").unwrap();
        skip_retry_delay(&mut log);
        log.write_line(b"e\n").unwrap();
        fixture.allow_renames();

        assert_eq!(fixture.live(), "c\nd\ne\n");
        assert_eq!(fixture.rotation(1), "b\n");
        assert_eq!(fixture.rotation(2), "a\n");

        skip_retry_delay(&mut log);
        log.write_line(b"f\n").unwrap();

        assert_eq!(fixture.live(), "f\n");
        assert_eq!(fixture.rotation(1), "c\nd\ne\n");
        assert_eq!(fixture.rotation(2), "b\n");
    }

    #[test]
    fn rotations_beyond_max_files_are_removed_on_open() {
        let fixture = Fixture::new();
        fs::write(fixture.rotation_path("1"), "c\n").unwrap();
        fs::write(fixture.rotation_path("2"), "b\n").unwrap();
        fs::write(fixture.rotation_path("4"), "a\n").unwrap();
        fs::write(fixture.rotation_path("old"), "not a rotation\n").unwrap();

        fixture.open(10, 1);

        assert_eq!(
            fixture.files(),
            ["agent.log", "agent.log.1", "agent.log.old"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_new_live_file_keeps_the_permissions_of_the_one_before() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);
        log.write_line(b"a\n").unwrap();
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();

        log.write_line(b"b\n").unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(fixture.live(), "b\n");
        assert_eq!(mode(&fixture.path), 0o600);
        assert_eq!(mode(&fixture.rotation_path("1")), 0o600);
    }

    #[cfg(windows)]
    #[test]
    fn a_rotation_held_open_by_another_program_keeps_logging_and_recovers() {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;

        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);

        for line in ["a\n", "b\n", "c\n"] {
            log.write_line(line.as_bytes()).unwrap();
        }

        // Another program has `.1` open, so it cannot be renamed.
        let held = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(fixture.rotation_path("1"))
            .unwrap();

        log.write_line(b"d\n").unwrap();
        skip_retry_delay(&mut log);
        log.write_line(b"e\n").unwrap();

        // `.2` was already removed when renaming `.1` failed.
        assert_eq!(fixture.live(), "c\nd\ne\n");
        assert_eq!(fixture.rotation(1), "b\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1"]);

        drop(held);
        skip_retry_delay(&mut log);
        log.write_line(b"f\n").unwrap();

        assert_eq!(fixture.live(), "f\n");
        assert_eq!(fixture.rotation(1), "c\nd\ne\n");
        assert_eq!(fixture.rotation(2), "b\n");
    }

    #[test]
    fn a_live_file_deleted_from_outside_is_recreated_without_a_rotation() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 3);

        for line in ["a\n", "b\n"] {
            log.write_line(line.as_bytes()).unwrap();
        }

        fs::remove_file(&fixture.path).unwrap();
        log.write_line(b"c\n").unwrap();

        assert_eq!(fixture.live(), "c\n");
        assert_eq!(fixture.rotation(1), "a\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_rotation_is_not_retried_on_every_line() {
        if is_root() {
            return;
        }

        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);
        log.write_line(b"a\n").unwrap();

        fixture.forbid_renames();
        log.write_line(b"b\n").unwrap();
        fixture.allow_renames();
        log.write_line(b"c\n").unwrap();

        // The rename would work again, but the retry delay has not passed.
        assert_eq!(fixture.live(), "a\nb\nc\n");
        assert_eq!(fixture.files(), ["agent.log"]);
    }
}
