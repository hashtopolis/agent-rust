//! The slow-hash auto-pipe decision: whether a direct chunk run should restart
//! as a self-pipe to keep the GPU fed. [`preconditions_met`] is the static
//! gate; [`should_repipe`] is the live gate driven by GPU telemetry.

use std::ops::Range;

use crate::model::TaskAssignment;

/// The per-device GPU utilisation floor (percent) below which the auto-pipe
/// switches a starved chunk to a self-pipe.
#[derive(Debug, Clone, Copy)]
pub struct AutoPipePolicy {
    pub util_threshold: u8,
}

/// The first status is skipped while hashcat spins up, and arming stops after a
/// short warmup so a brief mid-run dip cannot trigger a restart.
const WARMUP_WINDOW: Range<u32> = 2..10;

/// hashcat reports `-1` when it cannot read a device's utilisation; never treat
/// that as starved.
const UTIL_UNAVAILABLE: i64 = -1;

pub(super) struct Probe {
    pub threshold: u8,
}

/// Mean of the per-device utilisation readings, or
/// `None` when hashcat reported none.
pub(super) fn mean_util(utils: &[i64]) -> Option<i64> {
    if utils.is_empty() {
        return None;
    }

    let sum: i64 = utils.iter().sum();
    Some(sum / utils.len() as i64)
}

pub(super) fn should_repipe(status_count: u32, util: Option<i64>, threshold: u8) -> bool {
    WARMUP_WINDOW.contains(&status_count)
        && matches!(util, Some(u) if u != UTIL_UNAVAILABLE && u < i64::from(threshold))
}

pub(super) fn preconditions_met(task: &TaskAssignment) -> bool {
    task.slow_hash && task.brain.is_none() && !task.files.is_empty() && !uses_slow_candidates(task)
}

/// A structured token scan, so `-S` inside a filename or a longer flag never
/// matches the way the Python agent's substring check does.
fn uses_slow_candidates(task: &TaskAssignment) -> bool {
    task.attack_command
        .split_whitespace()
        .chain(task.cmd_parameters.split_whitespace())
        .any(|token| token == "-S")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_util_averages_and_reports_absence() {
        assert_eq!(mean_util(&[]), None);
        assert_eq!(mean_util(&[90]), Some(90));
        assert_eq!(mean_util(&[80, 100]), Some(90));
    }

    #[test]
    fn repipes_only_inside_warmup_with_low_known_util() {
        assert!(should_repipe(5, Some(50), 95));

        assert!(!should_repipe(1, Some(50), 95));
        assert!(!should_repipe(10, Some(50), 95));

        assert!(!should_repipe(5, Some(95), 95));
        assert!(!should_repipe(5, Some(96), 95));

        assert!(!should_repipe(5, None, 95));
        assert!(!should_repipe(5, Some(-1), 95));
    }
}
