//! Path helpers shared across the cracker backends.

use std::path::PathBuf;

/// Make `path` absolute without touching the filesystem, falling back to the
/// original on the (platform-specific) error paths.
pub(crate) fn absolute(path: PathBuf) -> PathBuf {
    std::path::absolute(&path).unwrap_or(path)
}
