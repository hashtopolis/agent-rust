//! Scales hashcat `PROGRESS` into 0..=10000 basis points for the server.
//!
//! Before 7.1.2-546, `PROGRESS` includes skipped candidates. From that build
//! onward it is relative to the chunk's start. `CURKU` remains absolute.

use crate::model::Chunk;

use super::status::HashcatStatus;
use super::version::HashcatVersion;

/// The first build whose `PROGRESS` is relative to the chunk's start.
const RELATIVE_PROGRESS_SINCE: HashcatVersion = HashcatVersion::new(7, 1, 2, 546);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProgressMode {
    Absolute,
    Relative,
}

impl ProgressMode {
    /// Select the progress convention of a hashcat version.
    pub(super) fn for_version(version: HashcatVersion) -> Self {
        if version >= RELATIVE_PROGRESS_SINCE {
            Self::Relative
        } else {
            Self::Absolute
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

    fn mode(version: &str) -> ProgressMode {
        ProgressMode::for_version(HashcatVersion::parse(version).unwrap())
    }

    #[test]
    fn version_cutoff_includes_git_build_number() {
        for version in [
            "v6.2.6",
            "7.1.1-999-gabcdef",
            "v7.1.2",
            "v7.1.2-545-gc885beef",
        ] {
            assert_eq!(mode(version), ProgressMode::Absolute, "{version}");
        }

        for version in [
            "v7.1.2-546-gc885beef",
            "7.1.2-547-gabcdef",
            " v7.1.3\n",
            "v7.2.0",
            "v8.0.0",
        ] {
            assert_eq!(mode(version), ProgressMode::Relative, "{version}");
        }
    }

    #[test]
    fn relative_progress_is_correct_even_for_a_late_first_status() {
        let mode = mode("v7.1.2-546-gc885beef");

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
        let mode = mode("v7.1.2");

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
