use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cracker::{CrackerError, HealthCheckOutcome};
use crate::process;

use crate::backend::args::Args;

use super::HashcatCracker;
use super::argv;
use super::status::{self, HashcatStatus};

const HASHLIST_NAME: &str = "health_check.txt";
const OUTFILE_NAME: &str = "health_check.out";

pub(super) async fn run(
    cracker: &HashcatCracker,
    attack: &str,
    hashlist_alias: &str,
    hashes: &[String],
) -> Result<HealthCheckOutcome, CrackerError> {
    let hashlist = cracker.hashlists_path(HASHLIST_NAME);
    let outfile = cracker.hashlists_path(OUTFILE_NAME);

    tokio::fs::write(&hashlist, format!("{}\n", hashes.join("\n")))
        .await
        .map_err(|error| {
            CrackerError::Process(format!("could not write health-check hashlist: {error}"))
        })?;

    remove_if_present(&outfile).await?;

    let args = Args::new()
        .arg("--machine-readable")
        .arg("--quiet")
        .arg("--restore-disable")
        .arg("--potfile-disable")
        .arg("--session=health")
        .args(cracker.resolve_attack(attack, hashlist_alias, Some(&hashlist)))
        .arg("-o")
        .arg(argv::path_arg(&outfile))
        .build();

    let start = unix_secs();

    let captured = process::run_capture(cracker.program(), &args, cracker.cwd())
        .await
        .map_err(|error| CrackerError::Process(error.to_string()))?;

    let end = unix_secs();

    let mut errors: Vec<String> = captured
        .stderr
        .lines()
        .map(status::strip_ansi)
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect();

    let states: Vec<HashcatStatus> = captured
        .stdout
        .lines()
        .map(HashcatStatus::parse)
        .filter(|status| status.is_valid())
        .collect();

    // The number of devices is read off the first successful status; without one
    // the run effectively failed, which the server should hear about.
    let num_gpus = match states.first() {
        Some(state) => state.temps().len() as u32,
        None => {
            errors.push(
                "Failed to retrieve one successful cracker state, most likely due to failing."
                    .to_owned(),
            );

            0
        }
    };

    let num_cracked = count_cracked(&outfile).await;

    Ok(HealthCheckOutcome {
        start,
        end,
        num_gpus,
        num_cracked,
        errors,
    })
}

fn unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn remove_if_present(path: &Path) -> Result<(), CrackerError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CrackerError::Process(format!(
            "could not clear old health-check outfile {}: {error}",
            path.display()
        ))),
    }
}

async fn count_cracked(outfile: &Path) -> u64 {
    match tokio::fs::read_to_string(outfile).await {
        Ok(contents) => contents.lines().filter(|line| !line.is_empty()).count() as u64,
        Err(_) => 0,
    }
}
