use crate::cracker::CrackerError;
use crate::model::TaskAssignment;
use crate::process;

use crate::backend::args::Args;

use super::GenericCracker;
use super::status::GenericStatus;

/// Run `<binary> crack <attack> -s 0 -l <keyspace> --timeout=<bench>` and report
/// the fraction of the keyspace covered, from the last valid status line.
///
/// The reference ignores `benchType` entirely: a generic benchmark has no speed
/// branch. The keyspace bound comes from `task.keyspace`, which the server has
/// already measured and stored; a zero bound simply yields no usable result.
pub(super) async fn run(
    cracker: &GenericCracker,
    task: &TaskAssignment,
) -> Result<Option<String>, CrackerError> {
    let hashlist = cracker.hashlist_file(task.hashlist_id);

    let args = Args::new()
        .arg("crack")
        .args(cracker.resolve_attack(&task.attack_command, &task.hashlist_alias, &hashlist))
        .arg("-s")
        .arg("0")
        .arg("-l")
        .arg(task.keyspace.to_string())
        .arg(format!("--timeout={}", task.benchmark))
        .build();

    let captured = process::run_capture(cracker.program(), &args, cracker.cwd())
        .await
        .map_err(|error| CrackerError::Process(error.to_string()))?;

    let last = captured
        .stdout
        .lines()
        .map(GenericStatus::parse)
        .rfind(GenericStatus::is_valid);

    let Some(status) = last else {
        return Ok(None);
    };

    // Progress is in basis points; the benchmark result is a 0..1 fraction.
    let fraction = status.progress() as f64 / GenericStatus::COMPLETE as f64;

    Ok(Some(fraction.to_string()))
}
