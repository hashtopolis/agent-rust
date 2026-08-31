//! Scales a chunk's hashcat `PROGRESS` into 0..=10000 basis points for the
//! server.
//!
//! hashcat counts `PROGRESS current` two ways: pre-2026 from the whole keyspace
//! (skipped candidates included), since 2026 from the chunk's own start. `CURKU`
//! is always absolute. See hashcat issue #4805.
//!
//! We detect which convention from the data and remember it per cracker (see
//! [`ProgressCalibration`]). Once the new hashcat version is released, we
//! can replace this with a version check.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use crate::model::Chunk;

use super::status::HashcatStatus;

/// One verdict per cracker, shared across its chunks and tasks.
static CALIBRATIONS: LazyLock<Mutex<HashMap<u64, ProgressCalibration>>> =
    LazyLock::new(Default::default);

/// The shared calibration for one cracker, created on first use.
pub(super) fn calibration_for(cracker_id: u64) -> ProgressCalibration {
    CALIBRATIONS
        .lock()
        .expect("progress calibration mutex poisoned")
        .entry(cracker_id)
        .or_default()
        .clone()
}

/// Whether this cracker reports `PROGRESS` relative to `--skip`. Only ever flips
/// false -> true: once a chunk proves relative, later chunks trust it instead of
/// re-guessing (a fast chunk can miss the early status that proves it).
#[derive(Clone, Default)]
pub(super) struct ProgressCalibration(Arc<AtomicBool>);

impl ProgressCalibration {
    fn is_relative(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    fn mark_relative(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Scales each status to basis points against the cracker's calibration.
pub(super) struct ProgressScaler {
    calibration: ProgressCalibration,
}

impl ProgressScaler {
    pub(super) fn new(calibration: ProgressCalibration) -> Self {
        Self { calibration }
    }

    /// The chunk's progress in basis points (0..=10000).
    ///
    /// Piped runs get no `--skip`, so their `PROGRESS` is already chunk-relative;
    /// they never calibrate and take the absolute path (offset zero there).
    pub(super) fn basis_points(
        &mut self,
        status: &HashcatStatus,
        chunk: &Chunk,
        piped: bool,
    ) -> u64 {
        if !piped && !self.calibration.is_relative() && looks_relative(status, chunk) {
            self.calibration.mark_relative();
        }

        let relative = !piped && self.calibration.is_relative();

        let basis_points = if relative {
            relative_from_relative(status)
        } else {
            relative_from_absolute(status, chunk)
        };

        tracing::debug!(
            chunk = chunk.id,
            piped,
            relative,
            curku = status.curku(),
            progress = status.progress(),
            total = status.progress_total(),
            basis_points,
            "chunk progress scaled"
        );

        basis_points
    }
}

/// Proves the relative convention: `PROGRESS` sits below where an absolute run
/// would even begin, which an absolute run never does. A late first status
/// (already past the start) just fails to prove it and defers to calibration.
fn looks_relative(status: &HashcatStatus, chunk: &Chunk) -> bool {
    if chunk.skip == 0 || chunk.length == 0 {
        return false;
    }

    let total = status.progress_total();

    total > 0 && status.progress() < absolute_chunk_start(total, chunk)
}

/// Absolute convention: `current` runs from the chunk's start up to `total`, so
/// offset by that start and scale the rest.
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

    // From a real 2026+ run (-m 3200 -a 3): 3000-word chunks over a x20
    // amplifier, so total = 60000 per chunk.
    const LENGTH: u64 = 3000;
    const TOTAL: u64 = 60000;

    fn chunk(skip: u64) -> Chunk {
        Chunk {
            id: skip / LENGTH,
            skip,
            length: LENGTH,
        }
    }

    fn status(curku: u64, current: u64, total: u64) -> HashcatStatus {
        HashcatStatus::parse(&format!(
            "STATUS\t3\tCURKU\t{curku}\tPROGRESS\t{current}\t{total}"
        ))
    }

    #[test]
    fn an_early_status_proves_the_relative_convention() {
        // chunk 11 in the trace: skip 6000, first status progress 6000 < 36000.
        assert!(looks_relative(&status(6000, 6000, TOTAL), &chunk(6000)));
    }

    #[test]
    fn an_advanced_status_cannot_prove_it() {
        // A late first status (progress 54000, above chunk_start) looks the same
        // as an absolute run, so it proves nothing.
        assert!(!looks_relative(&status(9000, 54000, TOTAL), &chunk(9000)));
    }

    #[test]
    fn the_absolute_convention_never_looks_relative() {
        // Old convention: total = span x mult = 240000, current starts at
        // chunk_start (180000) and never dips below it.
        assert!(!looks_relative(&status(9000, 180000, 240000), &chunk(9000)));
        assert!(!looks_relative(
            &status(12000, 240000, 240000),
            &chunk(9000)
        ));
    }

    #[test]
    fn a_zero_skip_never_calibrates() {
        assert!(!looks_relative(&status(0, 0, TOTAL), &chunk(0)));
    }

    #[test]
    fn a_relative_chunk_calibrates_and_scales() {
        let calibration = ProgressCalibration::default();
        let mut scaler = ProgressScaler::new(calibration.clone());

        // Early status proves relative and scales as a straight fraction.
        assert_eq!(
            scaler.basis_points(&status(6000, 6000, TOTAL), &chunk(6000), false),
            1000
        );
        assert!(calibration.is_relative());

        assert_eq!(
            scaler.basis_points(&status(9000, 60000, TOTAL), &chunk(6000), false),
            10000
        );
    }

    #[test]
    fn a_fast_chunk_inherits_the_calibration() {
        let calibration = ProgressCalibration::default();

        // An earlier chunk already proved the relative convention.
        calibration.mark_relative();

        // This fast chunk's first status is already advanced (54000), so it
        // can't tell on its own, but it inherits the verdict and scales to the
        // true 90% instead of 60%.
        let mut scaler = ProgressScaler::new(calibration);
        assert_eq!(
            scaler.basis_points(&status(9000, 54000, TOTAL), &chunk(9000), false),
            9000
        );
    }

    #[test]
    fn a_fresh_scaler_defaults_to_absolute() {
        // Same status with no prior verdict falls back to absolute (60%). This is
        // the gap a lone fast chunk can't close.
        let mut scaler = ProgressScaler::new(ProgressCalibration::default());
        assert_eq!(
            scaler.basis_points(&status(9000, 54000, TOTAL), &chunk(9000), false),
            6000
        );
    }

    #[test]
    fn an_absolute_binary_never_calibrates_and_scales() {
        let calibration = ProgressCalibration::default();
        let mut scaler = ProgressScaler::new(calibration.clone());

        assert_eq!(
            scaler.basis_points(&status(9000, 180000, 240000), &chunk(9000), false),
            0
        );
        assert_eq!(
            scaler.basis_points(&status(12000, 240000, 240000), &chunk(9000), false),
            10000
        );
        assert!(!calibration.is_relative());
    }

    #[test]
    fn piped_runs_never_calibrate() {
        let calibration = ProgressCalibration::default();
        let mut scaler = ProgressScaler::new(calibration.clone());

        // A relative-looking status on a piped run must not calibrate; it stays
        // on the absolute path (chunk_start 36000 here).
        assert_eq!(
            scaler.basis_points(&status(6000, 6000, TOTAL), &chunk(6000), true),
            0
        );
        assert!(!calibration.is_relative());
    }
}
