//! The hashcat version a cracker binary reports, read once when the cracker is
//! built. Several behaviours (the `PROGRESS` convention, `--cache-path`) changed
//! part way through the builds after a release, so the git build number counts.

use std::path::Path;
use std::process::Output;

use tokio::process::Command;

use crate::cracker::CrackerError;

/// `major.minor.patch` plus the git build number past that release, 0 for the
/// release itself. Field order makes the derived ordering the version ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct HashcatVersion {
    major: u64,
    minor: u64,
    patch: u64,
    build: u64,
}

impl HashcatVersion {
    pub(super) const fn new(major: u64, minor: u64, patch: u64, build: u64) -> Self {
        Self {
            major,
            minor,
            patch,
            build,
        }
    }

    /// Run `binary --version` and parse what it prints.
    pub(super) async fn probe(binary: &Path) -> Result<Self, CrackerError> {
        let cwd = binary.parent().unwrap_or(Path::new("."));

        // A one-line probe needs neither a process group nor the spawn log of
        // `process::run_capture`, so it bypasses the shared helper.
        let Output {
            stdout,
            stderr,
            status,
        } = Command::new(binary)
            .arg("--version")
            .current_dir(cwd)
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|error| CrackerError::Process(error.to_string()))?;

        if !status.success() {
            return Err(CrackerError::Process(format!(
                "hashcat --version failed ({}): {}",
                status,
                String::from_utf8_lossy(&stderr).trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&stdout);
        let raw = stdout.trim();

        let version = Self::parse(raw).ok_or_else(|| {
            CrackerError::Other(format!(
                "hashcat --version returned an invalid version: {raw:?}"
            ))
        })?;

        tracing::debug!(version = raw, "hashcat version");

        Ok(version)
    }

    /// Accept release and git-describe versions, e.g. `v7.1.2-546-gc885beef`.
    pub(super) fn parse(version: &str) -> Option<Self> {
        let version = version.trim().trim_start_matches('v');
        let mut fields = version.split(['.', '-']);

        let major = fields.next()?.parse::<u64>().ok()?;
        let minor = fields.next()?.parse::<u64>().ok()?;
        let patch = fields.next()?.parse::<u64>().ok()?;
        let build = fields
            .next()
            .map(str::parse::<u64>)
            .transpose()
            .ok()?
            .unwrap_or(0);

        Some(Self::new(major, minor, patch, build))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_and_builds_parse() {
        assert_eq!(
            HashcatVersion::parse("v7.1.2"),
            Some(HashcatVersion::new(7, 1, 2, 0))
        );
        assert_eq!(
            HashcatVersion::parse(" 7.1.2-627-g6570a49f2+\n"),
            Some(HashcatVersion::new(7, 1, 2, 627))
        );
    }

    #[test]
    fn a_build_orders_after_its_release_and_before_the_next() {
        let release = HashcatVersion::new(7, 1, 2, 0);
        let build = HashcatVersion::new(7, 1, 2, 627);
        let next = HashcatVersion::new(7, 1, 3, 0);

        assert!(release < build);
        assert!(build < next);
        assert!(HashcatVersion::new(7, 1, 2, 1200) < next);
    }

    #[test]
    fn invalid_versions_are_rejected() {
        for version in ["", "hashcat", "v7.1", "v7.x.2", "v7.1.2-invalid"] {
            assert_eq!(HashcatVersion::parse(version), None, "{version}");
        }
    }

    #[cfg(unix)]
    fn fake_hashcat(dir: &Path, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("hashcat");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

        path
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn probe_reads_the_version_from_the_binary() {
        let tmp = tempfile::TempDir::new().unwrap();

        let path = fake_hashcat(tmp.path(), "#!/bin/sh\necho 'v7.1.2-546-gc885beef'\n");
        let version = HashcatVersion::probe(&path).await.unwrap();

        assert_eq!(version, HashcatVersion::new(7, 1, 2, 546));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn probe_rejects_a_failing_or_unparsable_binary() {
        let tmp = tempfile::TempDir::new().unwrap();

        let path = fake_hashcat(tmp.path(), "#!/bin/sh\necho 'broken' >&2\nexit 1\n");
        let error = HashcatVersion::probe(&path).await.unwrap_err();

        assert!(
            matches!(&error, CrackerError::Process(message) if message.contains("broken")),
            "{error:?}"
        );

        let path = fake_hashcat(tmp.path(), "#!/bin/sh\necho 'hashcat'\n");
        let error = HashcatVersion::probe(&path).await.unwrap_err();

        assert!(matches!(error, CrackerError::Other(_)), "{error:?}");

        let error = HashcatVersion::probe(&tmp.path().join("missing"))
            .await
            .unwrap_err();

        assert!(matches!(error, CrackerError::Process(_)), "{error:?}");
    }
}
