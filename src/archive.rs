//! 7z extraction for the assets the server ships as archives, via the pure-Rust
//! [`sevenz_rust2`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("failed to extract {}: {source}", archive.display())]
    Extract {
        archive: PathBuf,
        #[source]
        source: sevenz_rust2::Error,
    },
    #[error("filesystem error at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Extract so the archive's contents land directly in `dest_dir`, overwriting
/// what is already there. Used for task files, where the archive holds the
/// wordlist at its root.
pub fn extract_into(archive: &Path, dest_dir: &Path) -> Result<(), ArchiveError> {
    fs::create_dir_all(dest_dir).map_err(io_at(dest_dir))?;

    decompress(archive, dest_dir)
}

/// Extract into `dest`, collapsing a single wrapping top-level folder. Crackers
/// are packed either as bare files or wrapped in one directory; this leaves
/// `dest` holding the binary directly in both cases.
pub fn extract_flattened(archive: &Path, dest: &Path) -> Result<(), ArchiveError> {
    let staging = staging_sibling(dest);

    remove_dir_all_if_exists(&staging)?;
    fs::create_dir_all(&staging).map_err(io_at(&staging))?;

    decompress(archive, &staging)?;

    remove_dir_all_if_exists(dest)?;

    let source = single_wrapping_dir(&staging)?.unwrap_or_else(|| staging.clone());
    with_retry(|| fs::rename(&source, dest)).map_err(io_at(dest))?;

    // A wrapping folder leaves the staging dir behind; a bare-file archive moved
    // staging itself and this is a no-op.
    remove_dir_all_if_exists(&staging)?;

    Ok(())
}

fn decompress(archive: &Path, dest_dir: &Path) -> Result<(), ArchiveError> {
    sevenz_rust2::decompress_file(archive, dest_dir).map_err(|source| ArchiveError::Extract {
        archive: archive.to_path_buf(),
        source,
    })
}

/// The single entry inside `dir` when it is exactly one directory, else `None`.
fn single_wrapping_dir(dir: &Path) -> Result<Option<PathBuf>, ArchiveError> {
    let mut entries = fs::read_dir(dir)
        .map_err(io_at(dir))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_at(dir))?;

    if entries.len() != 1 {
        return Ok(None);
    }

    let entry = entries.remove(0);
    let is_dir = entry.file_type().map_err(io_at(&entry.path()))?.is_dir();

    Ok(is_dir.then(|| entry.path()))
}

fn staging_sibling(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(".extract");

    dest.with_file_name(name)
}

fn remove_dir_all_if_exists(path: &Path) -> Result<(), ArchiveError> {
    with_retry(|| match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    })
    .map_err(io_at(path))
}

fn io_at(path: &Path) -> impl FnOnce(io::Error) -> ArchiveError {
    let path = path.to_path_buf();

    move |source| ArchiveError::Io { path, source }
}

/// Retry an fs operation that Windows can transiently refuse. Freshly written
/// or just-deleted directory entries stay locked while antivirus and the search
/// indexer finish scanning them, so `rename` and `remove_dir_all` come back with
/// ERROR_ACCESS_DENIED (5) or ERROR_SHARING_VIOLATION (32) until the handle is
/// released. A short backoff gives the scan time to let go; on other platforms
/// those codes never arise, so the operation runs exactly once.
fn with_retry<T>(op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry_while(is_transient, op)
}

/// The retry loop with the transient-error test injected, so it can be
/// exercised on platforms where [`is_transient`] is a hard `false`.
fn retry_while<T>(
    is_transient: impl Fn(&io::Error) -> bool,
    mut op: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    const MAX_ATTEMPTS: u32 = 10;
    const BASE_DELAY: Duration = Duration::from_millis(20);

    let mut attempt = 1;

    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(error) if attempt < MAX_ATTEMPTS && is_transient(&error) => {
                thread::sleep(BASE_DELAY * attempt);
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(windows)]
fn is_transient(error: &io::Error) -> bool {
    // ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION
    matches!(error.raw_os_error(), Some(5) | Some(32))
}

#[cfg(not(windows))]
fn is_transient(_error: &io::Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// Pack the *contents* of `src_dir` into a fresh `.7z`. `compress_to_path`
    /// stores a directory's children at the archive root, so whatever tree we
    /// build under `src_dir` is exactly what lands at the archive root.
    fn pack(archive: &Path, src_dir: &Path) {
        sevenz_rust2::compress_to_path(src_dir, archive).unwrap();
    }

    #[test]
    fn extract_into_places_contents_at_the_root() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        write(&src.join("wordlist.txt"), "hunter2\n");

        let archive = tmp.path().join("a.7z");
        pack(&archive, &src);
        let dest = tmp.path().join("files");

        extract_into(&archive, &dest).unwrap();

        assert_eq!(
            fs::read_to_string(dest.join("wordlist.txt")).unwrap(),
            "hunter2\n"
        );
    }

    #[test]
    fn flattened_collapses_a_single_wrapping_folder() {
        let tmp = TempDir::new().unwrap();
        // A sole child folder becomes the single top-level entry in the archive.
        let src = tmp.path().join("src");
        write(&src.join("hashcat-6.2.6").join("hashcat.bin"), "binary");
        write(
            &src.join("hashcat-6.2.6").join("rules").join("best64.rule"),
            "rules",
        );

        let archive = tmp.path().join("a.7z");
        pack(&archive, &src);
        let dest = tmp.path().join("crackers").join("1");

        extract_flattened(&archive, &dest).unwrap();

        assert_eq!(
            fs::read_to_string(dest.join("hashcat.bin")).unwrap(),
            "binary"
        );
        assert_eq!(
            fs::read_to_string(dest.join("rules").join("best64.rule")).unwrap(),
            "rules"
        );
        assert!(!dest.join("hashcat-6.2.6").exists());
    }

    #[test]
    fn flattened_keeps_bare_files_that_have_no_wrapping_folder() {
        let tmp = TempDir::new().unwrap();
        // Two entries at the root: not a single wrapping folder.
        let src = tmp.path().join("src");
        write(&src.join("hashcat.bin"), "binary");
        write(&src.join("extra.txt"), "extra");

        let archive = tmp.path().join("a.7z");
        pack(&archive, &src);
        let dest = tmp.path().join("crackers").join("2");

        extract_flattened(&archive, &dest).unwrap();

        assert_eq!(
            fs::read_to_string(dest.join("hashcat.bin")).unwrap(),
            "binary"
        );
        assert_eq!(fs::read_to_string(dest.join("extra.txt")).unwrap(), "extra");
    }

    #[test]
    fn retry_while_recovers_after_transient_failures() {
        let mut attempts = 0;

        let result = retry_while(
            |_| true,
            || {
                attempts += 1;

                if attempts < 3 {
                    Err(io::Error::from_raw_os_error(5))
                } else {
                    Ok(attempts)
                }
            },
        );

        assert_eq!(result.unwrap(), 3);
        assert_eq!(attempts, 3);
    }

    #[test]
    fn retry_while_returns_non_transient_errors_at_once() {
        let mut attempts = 0;

        let result = retry_while(
            |_| false,
            || {
                attempts += 1;
                Err::<(), _>(io::Error::from_raw_os_error(5))
            },
        );

        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn retry_while_gives_up_after_the_attempt_cap() {
        let mut attempts = 0;

        let result = retry_while(
            |_| true,
            || {
                attempts += 1;
                Err::<(), _>(io::Error::from_raw_os_error(5))
            },
        );

        assert!(result.is_err());
        assert_eq!(attempts, 10);
    }

    #[test]
    fn flattened_overwrites_a_previous_extraction() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        write(&src.join("wrap").join("hashcat.bin"), "new");

        let archive = tmp.path().join("a.7z");
        pack(&archive, &src);
        let dest = tmp.path().join("crackers").join("3");
        write(&dest.join("stale.bin"), "old");

        extract_flattened(&archive, &dest).unwrap();

        assert_eq!(fs::read_to_string(dest.join("hashcat.bin")).unwrap(), "new");
        assert!(!dest.join("stale.bin").exists());
    }
}
