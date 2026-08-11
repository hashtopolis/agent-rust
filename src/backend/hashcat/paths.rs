use std::path::{Path, PathBuf};

use super::HashcatCracker;

impl HashcatCracker {
    pub(super) fn program(&self) -> &Path {
        &self.binary_path
    }

    pub(super) fn cwd(&self) -> &Path {
        self.binary_path.parent().unwrap_or(Path::new("."))
    }

    pub(super) fn hashlist_file(&self, hashlist_id: u64) -> PathBuf {
        absolute(self.paths.hashlists.join(hashlist_id.to_string()))
    }

    pub(super) fn hashlist_outfile(&self, hashlist_id: u64) -> PathBuf {
        absolute(self.paths.hashlists.join(format!("{hashlist_id}.out")))
    }

    pub(super) fn hashlists_path(&self, name: &str) -> PathBuf {
        absolute(self.paths.hashlists.join(name))
    }

    pub(super) fn zaps_dir(&self, hashlist_id: u64) -> PathBuf {
        absolute(self.paths.zaps.join(format!("hashlist_{hashlist_id}")))
    }
}

/// Make `path` absolute without touching the filesystem, falling back to the
/// original on the (platform-specific) error paths.
pub(super) fn absolute(path: PathBuf) -> PathBuf {
    std::path::absolute(&path).unwrap_or(path)
}
