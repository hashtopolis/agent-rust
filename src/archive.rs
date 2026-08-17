//! 7z extraction for the assets the server ships as archives, via the pure-Rust
//! [`sevenz_rust2`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

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
    fs::rename(&source, dest).map_err(io_at(dest))?;

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
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ArchiveError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn io_at(path: &Path) -> impl FnOnce(io::Error) -> ArchiveError {
    let path = path.to_path_buf();

    move |source| ArchiveError::Io { path, source }
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
