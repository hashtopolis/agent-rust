use crate::cracker::CrackerError;
use crate::model::TaskAssignment;
use crate::process;

use crate::backend::args::Args;

use super::HashcatCracker;
use super::argv;

pub(super) async fn measure(
    cracker: &HashcatCracker,
    task: &TaskAssignment,
) -> Result<u64, CrackerError> {
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

    keyspace.ok_or_else(|| {
        CrackerError::UnparsableStatus(format!(
            "no keyspace in hashcat output: {}",
            captured.stderr.trim()
        ))
    })
}
