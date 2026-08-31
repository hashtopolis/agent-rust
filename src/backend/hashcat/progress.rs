use crate::model::Chunk;

use super::status::HashcatStatus;

/// Which `PROGRESS current` convention a binary uses. See hashcat issue #4805.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgressMode {
    /// `current` spans `chunk_start..total` (pre-2026 binaries).
    Absolute,
    /// `current` spans `0..total` for this chunk (2026+ binaries).
    Relative,
}

/// Scales each status to basis points, latching the binary's [`ProgressMode`].
pub(super) struct ProgressScaler {
    mode: Option<ProgressMode>,
}

impl ProgressScaler {
    pub(super) fn new() -> Self {
        Self { mode: None }
    }

    /// The chunk's progress in basis points (0..=10000). Piped runs get no
    /// `--skip`, so the change never reaches them: they stay on `Absolute`.
    pub(super) fn basis_points(
        &mut self,
        status: &HashcatStatus,
        chunk: &Chunk,
        piped: bool,
    ) -> u64 {
        if !piped && self.mode.is_none() {
            self.mode = detect_progress_mode(status, chunk);
        }

        match self.mode {
            Some(ProgressMode::Relative) => relative_from_relative(status),
            _ => relative_from_absolute(status, chunk),
        }
    }
}

/// [`ProgressMode::Absolute`]: offset `current` by the chunk's start, then scale.
fn relative_from_absolute(status: &HashcatStatus, chunk: &Chunk) -> u64 {
    let total = status.progress_total();
    let chunk_start = absolute_chunk_start(total, chunk);

    if total > chunk_start {
        ((status.progress().saturating_sub(chunk_start) as u128) * 10_000
            / (total - chunk_start) as u128) as u64
    } else {
        0
    }
}

/// [`ProgressMode::Relative`]: `current` already spans `0..total`, a straight fraction.
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

/// Detect the [`ProgressMode`] from one status, or `None` if it can't tell yet.
///
/// `CURKU` is absolute in every version, so we compare the reported
/// `current / total` against the fraction each convention predicts from `curku`
/// and pick the closer one. The keyspace multiplier cancels in each ratio.
fn detect_progress_mode(status: &HashcatStatus, chunk: &Chunk) -> Option<ProgressMode> {
    let skip = chunk.skip;
    let length = chunk.length;

    // Without a skip the conventions coincide.
    if skip == 0 {
        return Some(ProgressMode::Absolute);
    }

    let total = status.progress_total();
    let curku = status.curku();
    let span = skip + length;

    // Need a usable restore point inside the chunk and a non-zero total; else defer.
    if total == 0 || length == 0 || curku < skip || curku > span {
        return None;
    }

    let reported = status.progress() as f64 / total as f64;
    let absolute = curku as f64 / span as f64;
    let relative = (curku - skip) as f64 / length as f64;

    if (reported - relative).abs() <= (reported - absolute).abs() {
        Some(ProgressMode::Relative)
    } else {
        Some(ProgressMode::Absolute)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 900 base words from word 100, over a 10x modifier: PROGRESS spans 1000..10000
    // absolute or 0..9000 relative; CURKU stays the base word 100..1000.
    const SKIP: u64 = 100;
    const LENGTH: u64 = 900;
    const MULT: u64 = 10;

    fn chunk() -> Chunk {
        Chunk {
            id: 1,
            skip: SKIP,
            length: LENGTH,
        }
    }

    fn status(curku: u64, current: u64, total: u64) -> HashcatStatus {
        HashcatStatus::parse(&format!(
            "STATUS\t3\tCURKU\t{curku}\tPROGRESS\t{current}\t{total}"
        ))
    }

    /// Pre-2026: PROGRESS counts the skipped words.
    fn absolute_status(curku: u64) -> HashcatStatus {
        status(curku, curku * MULT, (SKIP + LENGTH) * MULT)
    }

    /// 2026+: PROGRESS counts from the chunk start.
    fn relative_status(curku: u64) -> HashcatStatus {
        status(curku, (curku - SKIP) * MULT, LENGTH * MULT)
    }

    #[test]
    fn detects_the_absolute_convention() {
        assert_eq!(
            detect_progress_mode(&absolute_status(550), &chunk()),
            Some(ProgressMode::Absolute)
        );
    }

    #[test]
    fn detects_the_relative_convention() {
        assert_eq!(
            detect_progress_mode(&relative_status(550), &chunk()),
            Some(ProgressMode::Relative)
        );
    }

    #[test]
    fn detection_holds_at_the_chunk_start() {
        // curku == skip is the hardest case; reported current still separates them.
        assert_eq!(
            detect_progress_mode(&absolute_status(SKIP), &chunk()),
            Some(ProgressMode::Absolute)
        );
        assert_eq!(
            detect_progress_mode(&relative_status(SKIP), &chunk()),
            Some(ProgressMode::Relative)
        );
    }

    #[test]
    fn a_zero_skip_needs_no_detection() {
        let chunk = Chunk {
            id: 1,
            skip: 0,
            length: LENGTH,
        };

        assert_eq!(
            detect_progress_mode(&status(0, 4500, 9000), &chunk),
            Some(ProgressMode::Absolute)
        );
    }

    #[test]
    fn detection_defers_without_a_usable_restore_point() {
        // curku 0 (below skip) can't decide.
        assert_eq!(detect_progress_mode(&status(0, 0, 9000), &chunk()), None);
    }

    #[test]
    fn both_conventions_scale_to_the_same_basis_points() {
        // Base word 550 is the chunk's halfway point: (550 - 100) / 900.
        assert_eq!(
            relative_from_absolute(&absolute_status(550), &chunk()),
            5000
        );
        assert_eq!(relative_from_relative(&relative_status(550)), 5000);
    }

    #[test]
    fn a_relative_binary_latches_and_reports_correctly() {
        let mut scaler = ProgressScaler::new();

        // First status settles the convention, then the halfway status scales.
        assert_eq!(
            scaler.basis_points(&relative_status(SKIP), &chunk(), false),
            0
        );
        assert_eq!(scaler.mode, Some(ProgressMode::Relative));

        assert_eq!(
            scaler.basis_points(&relative_status(550), &chunk(), false),
            5000
        );
    }

    #[test]
    fn piped_runs_keep_the_absolute_path_unchanged() {
        // No --skip reaches hashcat, so no mode is detected and the absolute
        // path stands (chunk_start = 900 over this 9000-unit stream).
        let mut scaler = ProgressScaler::new();

        assert_eq!(
            scaler.basis_points(&status(0, 4500, 9000), &chunk(), true),
            4444
        );
        assert_eq!(scaler.mode, None);
    }
}
