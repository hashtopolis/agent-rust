use std::path::{Path, PathBuf};

use crate::backend::paths::absolute;

use super::GenericCracker;

impl GenericCracker {
    pub(super) fn program(&self) -> &Path {
        &self.binary_path
    }

    /// All three generic invocations run from the files directory (contrast
    /// hashcat, which runs from the cracker directory), matching the reference
    /// agent's `cwd = files-path`.
    pub(super) fn cwd(&self) -> &Path {
        &self.paths.files
    }

    pub(super) fn hashlist_file(&self, hashlist_id: u64) -> PathBuf {
        absolute(self.paths.hashlists.join(hashlist_id.to_string()))
    }

    /// The reference writes server-returned zaps to `<files-path>/zap`.
    pub(super) fn zap_file(&self) -> PathBuf {
        absolute(self.paths.files.join("zap"))
    }
}
