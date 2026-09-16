use crate::cracker::CrackerError;
use crate::model::TaskAssignment;
use crate::process;

use crate::backend::args::Args;

use super::GenericCracker;

/// The largest keyspace that fits the signed 64-bit `sendKeyspace` wire field. A
/// larger count is treated as unbounded (`None`, encoded as `-1`), matching the
/// hashcat backend's convention.
const MAX_REPORTABLE_KEYSPACE: u128 = i64::MAX as u128;

/// Run `<binary> keyspace <attack, with the "-a <alias> " pair removed>` and
/// parse the keyspace as the last non-empty stdout line.
pub(super) async fn measure(
    cracker: &GenericCracker,
    task: &TaskAssignment,
) -> Result<Option<u64>, CrackerError> {
    let args = Args::new()
        .arg("keyspace")
        .args(cracker.resolve_keyspace_attack(&task.attack_command, &task.hashlist_alias))
        .build();

    let captured = process::run_capture(cracker.program(), &args, cracker.cwd())
        .await
        .map_err(|error| CrackerError::Process(error.to_string()))?;

    // The reference keeps the last non-empty line and parses it; an empty output
    // defaults to zero.
    let last_line = captured
        .stdout
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .unwrap_or("0");

    let keyspace = last_line.parse::<u128>().map_err(|_| {
        CrackerError::UnparsableStatus(format!(
            "no keyspace in generic cracker output: {}",
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
        assert_eq!(classify(MAX_REPORTABLE_KEYSPACE), Some(i64::MAX as u64));
    }

    #[test]
    fn keyspaces_beyond_the_wire_field_are_unbounded() {
        assert_eq!(classify(MAX_REPORTABLE_KEYSPACE + 1), None);
        assert_eq!(classify(u128::MAX), None);
    }
}
