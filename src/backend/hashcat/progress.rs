//! Scales hashcat `PROGRESS` into 0..=10000 basis points for the server.
//!
//! Before 7.1.2-546, `PROGRESS` includes skipped candidates. From that build
//! onward it is relative to the chunk's start. `CURKU` remains absolute.

use std::path::Path;
use std::process::Output;

use tokio::process::Command;

use crate::cracker::CrackerError;
use crate::model::Chunk;

use super::status::HashcatStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProgressMode {
    Absolute,
    Relative,
}

impl ProgressMode {
    /// Read the binary's version to select its progress convention.
    pub(super) async fn detect(binary: &Path) -> Result<Self, CrackerError> {
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
        let version = stdout.trim();

        let mode = ProgressMode::from_version(version).ok_or_else(|| {
            CrackerError::Other(format!(
                "hashcat --version returned an invalid version: {version:?}"
            ))
        })?;

        tracing::debug!(version, ?mode, "hashcat progress convention");

        Ok(mode)
    }

    /// Accept release and git-describe versions, e.g. `v7.1.2-546-gc885beef`.
    fn from_version(version: &str) -> Option<Self> {
        let version = version.trim().trim_start_matches('v');

        let (major, minor, patch, revision) = {
            let mut fields = version.split(['.', '-']);

            let major = fields.next()?.parse::<u64>().ok()?;
            let minor = fields.next()?.parse::<u64>().ok()?;
            let patch = fields.next()?.parse::<u64>().ok()?;
            let revision = fields
                .next()
                .map(str::parse::<u64>)
                .transpose()
                .ok()?
                .unwrap_or(0);

            (major, minor, patch, revision)
        };

        if (major, minor, patch, revision) >= (7, 1, 2, 546) {
            Some(Self::Relative)
        } else {
            Some(Self::Absolute)
        }
    }

    /// Piped runs have no hashcat `--skip`, so neither version needs an offset.
    pub(super) fn basis_points(self, status: &HashcatStatus, chunk: &Chunk, piped: bool) -> u64 {
        let relative = piped || self == Self::Relative;

        let basis_points = if relative {
            relative_from_relative(status)
        } else {
            relative_from_absolute(status, chunk)
        };

        tracing::trace!(
            chunk = chunk.id,
            piped,
            relative,
            curku = status.curku(),
            progress = status.progress(),
            total = status.progress_total(),
            relative_progress = basis_points,
            "chunk progress scaled"
        );

        basis_points
    }
}

/// Absolute convention: `current` runs from the chunk's start up to `total`, so
/// offset by that start and scale the rest.
fn relative_from_absolute(status: &HashcatStatus, chunk: &Chunk) -> u64 {
    let total = status.progress_total();
    let chunk_start = absolute_chunk_start(total, chunk);

    if total > chunk_start {
        ((status.progress().min(total).saturating_sub(chunk_start) as u128) * 10_000
            / (total - chunk_start) as u128) as u64
    } else {
        0
    }
}

/// Relative convention: `current` already spans `0..total`, a plain fraction.
fn relative_from_relative(status: &HashcatStatus) -> u64 {
    let total = status.progress_total();

    if total == 0 {
        return 0;
    }

    (((status.progress().min(total) as u128) * 10_000) / total as u128) as u64
}

/// The chunk's start in `PROGRESS` units: `total / (skip + length) * skip`.
fn absolute_chunk_start(total: u64, chunk: &Chunk) -> u64 {
    let span = chunk.skip + chunk.length;

    total
        .checked_div(span)
        .map(|per_unit| per_unit * chunk.skip)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LENGTH: u64 = 3000;
    const TOTAL: u64 = 60000;

    fn chunk(skip: u64) -> Chunk {
        Chunk {
            id: skip / LENGTH,
            skip,
            length: LENGTH,
        }
    }

    fn status(current: u64, total: u64) -> HashcatStatus {
        HashcatStatus::parse(&format!(
            "STATUS\t3\tCURKU\t9000\tPROGRESS\t{current}\t{total}"
        ))
    }

    #[test]
    fn version_cutoff_includes_git_build_number() {
        for version in [
            "v6.2.6",
            "7.1.1-999-gabcdef",
            "v7.1.2",
            "v7.1.2-545-gc885beef",
        ] {
            assert_eq!(
                ProgressMode::from_version(version),
                Some(ProgressMode::Absolute),
                "{version}"
            );
        }

        for version in [
            "v7.1.2-546-gc885beef",
            "7.1.2-547-gabcdef",
            " v7.1.3\n",
            "v7.2.0",
            "v8.0.0",
        ] {
            assert_eq!(
                ProgressMode::from_version(version),
                Some(ProgressMode::Relative),
                "{version}"
            );
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
    async fn detect_reads_the_version_from_the_binary() {
        let tmp = tempfile::TempDir::new().unwrap();

        let path = fake_hashcat(tmp.path(), "#!/bin/sh\necho 'v7.1.2-546-gc885beef'\n");
        let mode = ProgressMode::detect(&path).await.unwrap();

        assert_eq!(mode, ProgressMode::Relative);

        let path = fake_hashcat(tmp.path(), "#!/bin/sh\necho 'v6.2.6'\n");
        let mode = ProgressMode::detect(&path).await.unwrap();

        assert_eq!(mode, ProgressMode::Absolute);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn detect_rejects_a_failing_or_unparsable_binary() {
        let tmp = tempfile::TempDir::new().unwrap();

        let path = fake_hashcat(tmp.path(), "#!/bin/sh\necho 'broken' >&2\nexit 1\n");
        let error = ProgressMode::detect(&path).await.unwrap_err();

        assert!(
            matches!(&error, CrackerError::Process(message) if message.contains("broken")),
            "{error:?}"
        );

        let path = fake_hashcat(tmp.path(), "#!/bin/sh\necho 'hashcat'\n");
        let error = ProgressMode::detect(&path).await.unwrap_err();

        assert!(matches!(error, CrackerError::Other(_)), "{error:?}");

        let error = ProgressMode::detect(&tmp.path().join("missing"))
            .await
            .unwrap_err();

        assert!(matches!(error, CrackerError::Process(_)), "{error:?}");
    }

    #[test]
    fn invalid_versions_are_rejected() {
        for version in ["", "hashcat", "v7.1", "v7.x.2", "v7.1.2-invalid"] {
            assert_eq!(ProgressMode::from_version(version), None, "{version}");
        }
    }

    #[test]
    fn relative_progress_is_correct_even_for_a_late_first_status() {
        let mode = ProgressMode::from_version("v7.1.2-546-gc885beef").unwrap();

        assert_eq!(
            mode.basis_points(&status(54000, TOTAL), &chunk(9000), false),
            9000
        );
        assert_eq!(
            mode.basis_points(&status(TOTAL, TOTAL), &chunk(9000), false),
            10000
        );
    }

    #[test]
    fn older_versions_subtract_the_chunk_start() {
        let mode = ProgressMode::from_version("v7.1.2").unwrap();

        assert_eq!(
            mode.basis_points(&status(180000, 240000), &chunk(9000), false),
            0
        );
        assert_eq!(
            mode.basis_points(&status(210000, 240000), &chunk(9000), false),
            5000
        );
        assert_eq!(
            mode.basis_points(&status(240000, 240000), &chunk(9000), false),
            10000
        );
    }

    #[test]
    fn piped_runs_do_not_subtract_skip_in_either_version() {
        for mode in [ProgressMode::Absolute, ProgressMode::Relative] {
            assert_eq!(
                mode.basis_points(&status(6000, TOTAL), &chunk(6000), true),
                1000
            );
        }
    }

    #[test]
    fn zero_skip_and_unknown_total_work_in_either_version() {
        for mode in [ProgressMode::Absolute, ProgressMode::Relative] {
            assert_eq!(
                mode.basis_points(&status(6000, TOTAL), &chunk(0), false),
                1000
            );
            assert_eq!(mode.basis_points(&status(0, 0), &chunk(9000), false), 0);
        }
    }

    #[test]
    fn progress_is_bounded_by_the_chunk() {
        assert_eq!(
            ProgressMode::Absolute.basis_points(&status(1, 240000), &chunk(9000), false),
            0
        );

        for mode in [ProgressMode::Absolute, ProgressMode::Relative] {
            assert_eq!(
                mode.basis_points(&status(300000, 240000), &chunk(9000), false),
                10000
            );
        }
    }
}
