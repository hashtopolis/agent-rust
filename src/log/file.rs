//! The log file: rotated by size and gzip-compressed.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use flate2::Compression;
use flate2::write::GzEncoder;

use super::warn_on_stderr;

const ROTATION_RETRY_DELAY: Duration = Duration::from_secs(10);

/// Rotates before a line would take the file past `max_size`: the live file
/// becomes `.1`, older rotations shift up one and `max_files` of them are
/// kept. A failed rotation loses nothing: lines keep going to the live file
/// until a retry succeeds.
///
/// `.1` is compressed to `.1.gz` on a thread of its own, so writing carries on
/// meanwhile.
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
    compressing: Option<JoinHandle<()>>,
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
            compressing: None,
        };

        if let Err(error) = log.remove_leftovers() {
            warn_on_stderr(format_args!(
                "cannot remove old files of log file {}: {error}",
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

        // `.1` must not move while it is still being compressed.
        self.wait_for_compression();

        match self.shift_rotations() {
            Ok(()) => {
                self.retry_at = None;
                self.start_compression();
            }
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
        let free = (1..=self.max_files).find(|&n| !self.occupied(n));

        let top = match free {
            Some(n) => n,
            None => {
                self.remove_rotation(self.max_files)?;
                self.max_files
            }
        };

        for n in (1..top).rev() {
            self.move_rotation(n, n + 1)?;
        }

        fs::rename(&self.path, self.rotation_path(1))
    }

    fn start_compression(&mut self) {
        let plain = self.rotation_path(1);
        let temp = self.compression_temp();
        let compressed = self.compressed_path(1);

        let spawned = thread::Builder::new()
            .name("log-compress".to_string())
            .spawn(move || compress_rotation(&plain, &temp, &compressed));

        match spawned {
            Ok(handle) => self.compressing = Some(handle),
            Err(error) => warn_on_stderr(format_args!(
                "cannot start compressing a rotation of log file {}: {error}",
                self.path.display()
            )),
        }
    }

    pub(super) fn wait_for_compression(&mut self) {
        if let Some(compressing) = self.compressing.take() {
            let _ = compressing.join();
        }
    }

    /// Removes rotations above `max_files`, in case the limit was lowered, and
    /// the temporary file of an interrupted compression.
    fn remove_leftovers(&self) -> io::Result<()> {
        remove_if_exists(&self.compression_temp())?;

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

    /// A rotation may be plain (its compression failed) or compressed.
    fn occupied(&self, n: usize) -> bool {
        self.rotation_path(n).exists() || self.compressed_path(n).exists()
    }

    fn remove_rotation(&self, n: usize) -> io::Result<()> {
        remove_if_exists(&self.rotation_path(n))?;
        remove_if_exists(&self.compressed_path(n))
    }

    fn move_rotation(&self, from: usize, to: usize) -> io::Result<()> {
        let compressed = self.compressed_path(from);

        if compressed.exists() {
            // If the plain file is still there, deleting it failed after
            // compression. The `.gz` is complete, so the plain one can go.
            remove_if_exists(&self.rotation_path(from))?;

            return fs::rename(compressed, self.compressed_path(to));
        }

        fs::rename(self.rotation_path(from), self.rotation_path(to))
    }

    fn rotation_path(&self, n: usize) -> PathBuf {
        self.path.with_added_extension(n.to_string())
    }

    fn compressed_path(&self, n: usize) -> PathBuf {
        self.path.with_added_extension(format!("{n}.gz"))
    }

    fn compression_temp(&self) -> PathBuf {
        self.path.with_added_extension("1.gz.tmp")
    }

    /// The inverse of [`Self::rotation_path`] and [`Self::compressed_path`].
    fn rotation_number(&self, path: &Path) -> Option<usize> {
        let plain = match path.extension() {
            Some(extension) if extension == "gz" => Path::new(path.file_stem()?),
            _ => path,
        };

        if plain.file_stem() != self.path.file_name() {
            return None;
        }

        plain.extension()?.to_str()?.parse().ok()
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

fn compress_rotation(plain: &Path, temp: &Path, compressed: &Path) {
    if let Err(error) = compress(plain, temp, compressed) {
        let _ = fs::remove_file(temp);

        warn_on_stderr(format_args!(
            "cannot finish compressing rotated log file {}: {error}",
            plain.display()
        ));
    }
}

/// Writes to `temp` first, so an interrupted run never leaves a truncated
/// `.gz` behind.
fn compress(plain: &Path, temp: &Path, compressed: &Path) -> io::Result<()> {
    let mut source = File::open(plain)?;
    let archive = File::create(temp)?;

    // The archive gets the log's permissions before any content is written.
    archive.set_permissions(source.metadata()?.permissions())?;

    let mut encoder = GzEncoder::new(archive, Compression::fast());
    io::copy(&mut source, &mut encoder)?;
    encoder.finish()?;

    fs::rename(temp, compressed)?;
    fs::remove_file(plain)
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

    use std::io::Read;

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

        fn rotation_path(&self, suffix: &str) -> PathBuf {
            self.dir.path().join(format!("agent.log.{suffix}"))
        }

        fn live(&self) -> String {
            fs::read_to_string(&self.path).unwrap()
        }

        fn plain(&self, n: usize) -> String {
            fs::read_to_string(self.rotation_path(&n.to_string())).unwrap()
        }

        fn compressed(&self, n: usize) -> String {
            let mut text = String::new();
            GzDecoder::new(File::open(self.rotation_path(&format!("{n}.gz"))).unwrap())
                .read_to_string(&mut text)
                .unwrap();

            text
        }

        fn write_gz(&self, n: usize, text: &str) {
            let mut encoder = GzEncoder::new(
                File::create(self.rotation_path(&format!("{n}.gz"))).unwrap(),
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
        log.wait_for_compression();

        assert_eq!(fixture.live(), "abcdef\n");
        assert_eq!(fixture.compressed(1), "12345\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1.gz"]);
    }

    #[test]
    fn a_line_longer_than_the_limit_still_lands_in_a_file_of_its_own() {
        let fixture = Fixture::new();
        let mut log = fixture.open(4, 5);

        log.write_line(b"too long\n").unwrap();
        log.write_line(b"x\n").unwrap();
        log.wait_for_compression();

        assert_eq!(fixture.compressed(1), "too long\n");
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
        log.wait_for_compression();

        assert_eq!(fixture.compressed(1), "earlier\n0123456789\n");
        assert_eq!(fixture.live(), "abc\n");
    }

    #[test]
    fn keeps_only_max_files_rotations_newest_first() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);

        for line in ["a\n", "b\n", "c\n", "d\n"] {
            log.write_line(line.as_bytes()).unwrap();
        }

        log.wait_for_compression();

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
            .write_line(b"x\n")
            .unwrap();

        assert_eq!(fs::read_to_string(path).unwrap(), "x\n");
    }

    #[test]
    fn a_stray_compression_temp_file_is_removed_on_open() {
        let fixture = Fixture::new();
        fs::write(fixture.rotation_path("1.gz.tmp"), "half a gzip").unwrap();

        fixture.open(10, 5);

        assert_eq!(fixture.files(), ["agent.log"]);
    }

    #[test]
    fn a_rotation_left_uncompressed_shifts_along_with_the_rest() {
        let fixture = Fixture::new();
        fs::write(&fixture.path, "c\n").unwrap();
        fs::write(fixture.rotation_path("1"), "b\n").unwrap();
        fixture.write_gz(2, "a\n");
        let mut log = fixture.open(2, 3);

        log.write_line(b"d\n").unwrap();
        log.wait_for_compression();

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
            log.write_line(line.as_bytes()).unwrap();
        }

        log.wait_for_compression();
        fs::remove_file(fixture.rotation_path("2.gz")).unwrap();
        log.write_line(b"e\n").unwrap();
        log.wait_for_compression();

        assert_eq!(fixture.live(), "e\n");
        assert_eq!(fixture.compressed(1), "d\n");
        assert_eq!(fixture.compressed(2), "c\n");
        assert_eq!(fixture.compressed(3), "a\n");
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

        log.wait_for_compression();

        fixture.forbid_renames();
        log.write_line(b"d\n").unwrap();
        skip_retry_delay(&mut log);
        log.write_line(b"e\n").unwrap();
        fixture.allow_renames();

        assert_eq!(fixture.live(), "c\nd\ne\n");
        assert_eq!(fixture.compressed(1), "b\n");
        assert_eq!(fixture.compressed(2), "a\n");

        skip_retry_delay(&mut log);
        log.write_line(b"f\n").unwrap();
        log.wait_for_compression();

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
        fs::write(fixture.rotation_path("3"), "plain\n").unwrap();
        fs::write(fixture.rotation_path("old"), "not a rotation\n").unwrap();

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
        fs::write(fixture.rotation_path("1"), "b\n").unwrap();
        fixture.write_gz(1, "b\n");
        let mut log = fixture.open(2, 3);

        log.write_line(b"d\n").unwrap();
        log.wait_for_compression();

        assert_eq!(fixture.compressed(2), "b\n");
        assert_eq!(
            fixture.files(),
            ["agent.log", "agent.log.1.gz", "agent.log.2.gz"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_new_live_file_and_the_archive_keep_the_permissions_of_the_old_file() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        let mut log = fixture.open(2, 2);
        log.write_line(b"a\n").unwrap();
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600)).unwrap();

        log.write_line(b"b\n").unwrap();
        log.wait_for_compression();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(fixture.live(), "b\n");
        assert_eq!(mode(&fixture.path), 0o600);
        assert_eq!(mode(&fixture.rotation_path("1.gz")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn rotations_of_a_log_with_a_non_utf8_name_are_removed_on_open() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join(OsStr::from_bytes(b"agent\xff.log"));
        let excess = path.with_added_extension("7.gz");

        // macOS only takes file names that are valid UTF-8.
        if fs::write(&excess, "old").is_err() {
            return;
        }

        RotatingFile::open(&path, 10, 1).unwrap();

        assert!(!excess.exists());
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

        log.wait_for_compression();

        // Another program has `.1.gz` open, so it cannot be renamed.
        let held = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(fixture.rotation_path("1.gz"))
            .unwrap();

        log.write_line(b"d\n").unwrap();
        skip_retry_delay(&mut log);
        log.write_line(b"e\n").unwrap();

        // `.2.gz` was already removed when renaming `.1.gz` failed.
        assert_eq!(fixture.live(), "c\nd\ne\n");
        assert_eq!(fixture.compressed(1), "b\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1.gz"]);

        drop(held);
        skip_retry_delay(&mut log);
        log.write_line(b"f\n").unwrap();
        log.wait_for_compression();

        assert_eq!(fixture.live(), "f\n");
        assert_eq!(fixture.compressed(1), "c\nd\ne\n");
        assert_eq!(fixture.compressed(2), "b\n");
    }

    #[test]
    fn a_live_file_deleted_from_outside_is_recreated_without_a_rotation() {
        let fixture = Fixture::new();
        let mut log = fixture.open(2, 3);

        for line in ["a\n", "b\n"] {
            log.write_line(line.as_bytes()).unwrap();
        }

        log.wait_for_compression();
        fs::remove_file(&fixture.path).unwrap();
        log.write_line(b"c\n").unwrap();
        log.wait_for_compression();

        assert_eq!(fixture.live(), "c\n");
        assert_eq!(fixture.compressed(1), "a\n");
        assert_eq!(fixture.files(), ["agent.log", "agent.log.1.gz"]);
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
        log.wait_for_compression();

        // The rename would work again, but the retry delay has not passed.
        assert_eq!(fixture.live(), "a\nb\nc\n");
        assert_eq!(fixture.files(), ["agent.log"]);
    }
}
