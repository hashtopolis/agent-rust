//! `--cache-path`: where hashcat keeps the per-wordlist seek databases that make
//! the `-s` of every chunk cheap, and its compiled kernels. Unset, hashcat keeps
//! them in the cracker directory, cold again after every cracker update.

use std::path::{Path, PathBuf};

use crate::backend::paths::absolute;

use super::HashcatCracker;
use super::argv::path_arg;
use super::version::HashcatVersion;

/// The first build that knows the option: it appears in `src/usage.c` at
/// `v7.1.2-627-g6570a49f2`. Every release after 7.1.2 has it.
const CACHE_PATH_SINCE: HashcatVersion = HashcatVersion::new(7, 1, 2, 627);

/// The configured cache directory, made absolute, if this hashcat version can be
/// given one. hashcat stops on an option it does not know, so an older binary
/// is never handed it. Made absolute because hashcat runs in the cracker
/// directory, where a relative path would land.
pub(super) fn supported_cache_dir(
    configured: Option<&Path>,
    version: HashcatVersion,
) -> Option<PathBuf> {
    let configured = configured?;

    if version < CACHE_PATH_SINCE {
        tracing::warn!(
            cache_path = %configured.display(),
            "ignoring cache path: this hashcat version does not support --cache-path"
        );

        return None;
    }

    Some(absolute(configured.to_path_buf()))
}

/// The `--cache-path` argument for `dir`, or nothing when the directory is not
/// there right now (an unmounted share, say). hashcat aborts on a missing cache
/// directory, and a cache is only a speed-up, never worth failing a run over,
/// so it then falls back to its own location.
fn cache_arg(dir: Option<&Path>) -> Option<String> {
    let dir = dir?;

    if !dir.is_dir() {
        tracing::warn!(
            cache_path = %dir.display(),
            "cache path is not a directory; hashcat will use its own cache location"
        );

        return None;
    }

    Some(format!("--cache-path={}", path_arg(dir)))
}

impl HashcatCracker {
    /// The `--cache-path` argument for every hashcat run, if any applies.
    pub(super) fn cache_arg(&self) -> Option<String> {
        cache_arg(self.cache_dir.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absolute on every platform: `/mnt/...` has no drive letter on Windows,
    /// so `absolute` would prefix the current drive.
    fn absolute_dir() -> PathBuf {
        std::env::temp_dir().join("hccache")
    }

    fn version(raw: &str) -> HashcatVersion {
        HashcatVersion::parse(raw).unwrap()
    }

    #[test]
    fn nothing_configured_means_no_cache_dir() {
        assert_eq!(supported_cache_dir(None, version("8.0.0")), None);
    }

    #[test]
    fn versions_before_the_option_get_no_cache_dir() {
        let dir = absolute_dir();

        for raw in [
            "6.2.6",
            "7.1.1",
            "7.1.2",
            "7.1.2-1-gdeadbee",
            "7.1.2-626-gc84986904",
        ] {
            assert_eq!(supported_cache_dir(Some(&dir), version(raw)), None, "{raw}");
        }
    }

    #[test]
    fn versions_with_the_option_keep_the_cache_dir() {
        let dir = absolute_dir();

        for raw in [
            "7.1.2-627-g6570a49f2",
            "7.1.2-629-g3b4a9ea09+",
            "7.1.2-1200-gabcdef1",
            "7.1.3",
            "7.2.0",
            "10.0.0",
        ] {
            assert_eq!(
                supported_cache_dir(Some(&dir), version(raw)),
                Some(dir.clone()),
                "{raw}"
            );
        }
    }

    #[test]
    fn a_relative_cache_dir_is_made_absolute() {
        let dir = supported_cache_dir(Some(Path::new("cache")), version("7.2.0")).unwrap();

        assert!(dir.is_absolute(), "{}", dir.display());
        assert!(dir.ends_with("cache"));
    }

    #[test]
    fn an_existing_directory_becomes_the_argument() {
        let tmp = tempfile::tempdir().unwrap();

        assert_eq!(
            cache_arg(Some(tmp.path())),
            Some(format!("--cache-path={}", path_arg(tmp.path())))
        );
    }

    #[test]
    fn a_missing_directory_or_none_yields_no_argument() {
        let tmp = tempfile::tempdir().unwrap();

        assert_eq!(cache_arg(Some(&tmp.path().join("gone"))), None);
        assert_eq!(cache_arg(None), None);
    }

    #[test]
    fn a_path_with_spaces_is_passed_as_is() {
        // argv carries the value verbatim; there is no shell to quote for.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("hashcat cache");
        std::fs::create_dir(&dir).unwrap();

        assert_eq!(
            cache_arg(Some(&dir)),
            Some(format!("--cache-path={}", path_arg(&dir)))
        );
    }
}
