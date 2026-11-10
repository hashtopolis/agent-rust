use std::path::Path;

use crate::cracker::CrackerError;
use crate::model::{ResolvedPreprocessor, TaskAssignment};
use crate::process::{self, Captured};

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
        .args(cracker.cache_arg())
        .args(argv::split_parameters(&task.cmd_parameters))
        .arg_if(task.brain.is_some(), "-S")
        .build();

    let captured = process::run_capture(cracker.program(), &args, cracker.cwd())
        .await
        .map_err(|error| CrackerError::Process(error.to_string()))?;

    ensure_success(&captured)?;

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

    ensure_success(&captured)?;

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

/// A run that exits non-zero measured nothing, whatever it printed: hashcat
/// builds after 7.1.2 still print a keyspace of `0` when they reject the attack.
/// Reporting that `0` would leave the task unmeasured on the server, which then
/// asks for the keyspace again, endlessly.
fn ensure_success(captured: &Captured) -> Result<(), CrackerError> {
    if captured.status.success() {
        return Ok(());
    }

    Err(CrackerError::Process(format!(
        "keyspace run failed ({}): {} {}",
        captured.status,
        captured.stdout.trim(),
        captured.stderr.trim()
    )))
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
    #[cfg(unix)]
    use super::{measure_hashcat, measure_preprocessor};
    #[cfg(unix)]
    use crate::backend::hashcat::tests::{cracker, fake_hashcat, task};
    #[cfg(unix)]
    use crate::cracker::CrackerError;
    #[cfg(unix)]
    use crate::model::ResolvedPreprocessor;

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

    /// hashcat builds after 7.1.2 print a keyspace of `0` when they reject the
    /// attack (here: a mask shorter than the hash mode's minimum password
    /// length) and signal the failure only through the exit code.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_hashcat_run_is_an_error_despite_a_keyspace_line() {
        let tmp = tempfile::TempDir::new().unwrap();

        let mut cracker = cracker();
        cracker.binary_path = fake_hashcat(
            tmp.path(),
            "#!/bin/sh\necho \"Skipping mask '?l?l?l?l?l' because it is smaller than the minimum password length.\"\necho\necho 0\nexit 255\n",
        );

        let error = measure_hashcat(&cracker, &task(None)).await.unwrap_err();

        assert!(
            matches!(&error, CrackerError::Process(message) if message.contains("Skipping mask")),
            "{error:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_successful_hashcat_run_yields_the_last_integer_line() {
        let tmp = tempfile::TempDir::new().unwrap();

        let mut cracker = cracker();
        cracker.binary_path = fake_hashcat(
            tmp.path(),
            "#!/bin/sh\necho 'some warning'\necho 11881376\n",
        );

        let keyspace = measure_hashcat(&cracker, &task(None)).await.unwrap();

        assert_eq!(keyspace, Some(11_881_376));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_preprocessor_run_is_an_error_despite_a_keyspace_line() {
        let tmp = tempfile::TempDir::new().unwrap();

        let preprocessor = ResolvedPreprocessor {
            command: String::new(),
            binary_path: fake_hashcat(
                tmp.path(),
                "#!/bin/sh\necho 0\necho 'bad input' >&2\nexit 1\n",
            ),
            keyspace_command: Some("--keyspace".into()),
            skip_command: None,
            limit_command: None,
        };

        let error = measure_preprocessor(&cracker(), &preprocessor)
            .await
            .unwrap_err();

        assert!(
            matches!(&error, CrackerError::Process(message) if message.contains("bad input")),
            "{error:?}"
        );
    }
}
