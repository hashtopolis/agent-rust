use std::path::Path;

use crate::cracker::CrackerError;
use crate::model::{ResolvedPreprocessor, TaskAssignment};
use crate::process;

use crate::backend::args::Args;

use super::HashcatCracker;
use super::argv;

/// The largest keyspace that fits the signed 64-bit `sendKeyspace` wire field. A
/// count above this cannot be reported as-is, so it is treated as unbounded
/// (`None`, which the client encodes as `-1`).
const MAX_REPORTABLE_KEYSPACE: u128 = i64::MAX as u128;

pub(super) async fn measure(
    cracker: &HashcatCracker,
    task: &TaskAssignment,
    preprocessor: Option<&ResolvedPreprocessor>,
) -> Result<Option<u64>, CrackerError> {
    match preprocessor {
        Some(pp) => measure_preprocessor(cracker, pp).await,
        None => measure_hashcat(cracker, task).await,
    }
}

async fn measure_hashcat(
    cracker: &HashcatCracker,
    task: &TaskAssignment,
) -> Result<Option<u64>, CrackerError> {
    // A keyspace measure runs without the hashlist, so the alias token is dropped.
    let args = Args::new()
        .arg("--keyspace")
        .arg("--quiet")
        .args(cracker.resolve_attack(&task.attack_command, &task.hashlist_alias, None))
        .args(argv::split_parameters(&task.cmd_parameters))
        .arg_if(task.brain.is_some(), "-S")
        .build();

    let captured = process::run_capture(cracker.program(), &args, cracker.cwd())
        .await
        .map_err(|error| CrackerError::Process(error.to_string()))?;

    // Warnings may share the output; the keyspace is the last line that parses
    // as an integer.
    let keyspace = captured
        .stdout
        .lines()
        .filter_map(|line| line.trim().parse::<u64>().ok())
        .next_back();

    keyspace.map(Some).ok_or_else(|| {
        CrackerError::UnparsableStatus(format!(
            "no keyspace in hashcat output: {}",
            captured.stderr.trim()
        ))
    })
}

/// The preprocessor reports its own keyspace via its `keyspaceCommand`. Without
/// one there is no bound to report (`None`); a value too large to represent is
/// likewise treated as unbounded.
async fn measure_preprocessor(
    cracker: &HashcatCracker,
    preprocessor: &ResolvedPreprocessor,
) -> Result<Option<u64>, CrackerError> {
    let Some(keyspace_command) = preprocessor.keyspace_command.as_deref() else {
        return Ok(None);
    };

    let args = Args::new()
        .arg(keyspace_command)
        .args(cracker.resolve_attack(&preprocessor.command, "", None))
        .build();

    let cwd = preprocessor
        .binary_path
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let captured = process::run_capture(&preprocessor.binary_path, &args, cwd)
        .await
        .map_err(|error| CrackerError::Process(error.to_string()))?;

    let keyspace = captured
        .stdout
        .lines()
        .filter_map(|line| line.trim().parse::<u128>().ok())
        .next_back()
        .ok_or_else(|| {
            CrackerError::UnparsableStatus(format!(
                "no keyspace in preprocessor output: {}",
                captured.stderr.trim()
            ))
        })?;

    Ok(classify(keyspace))
}

/// A keyspace that fits the wire field is reported as-is; anything larger is
/// unbounded (`None`).
fn classify(keyspace: u128) -> Option<u64> {
    if keyspace > MAX_REPORTABLE_KEYSPACE {
        None
    } else {
        Some(keyspace as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_REPORTABLE_KEYSPACE, classify};

    #[test]
    fn representable_keyspaces_pass_through() {
        assert_eq!(classify(0), Some(0));
        assert_eq!(classify(568_000), Some(568_000));
        assert_eq!(
            classify(MAX_REPORTABLE_KEYSPACE),
            Some(i64::MAX as u64),
            "the boundary value itself still fits"
        );
    }

    #[test]
    fn keyspaces_beyond_the_wire_field_are_unbounded() {
        assert_eq!(classify(MAX_REPORTABLE_KEYSPACE + 1), None);
        assert_eq!(classify(u128::MAX), None);
    }
}
