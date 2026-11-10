use crate::cracker::CrackerError;
use crate::model::{BenchmarkType, ResolvedPreprocessor, TaskAssignment};
use crate::process::{self, Captured};

use crate::backend::args::Args;

use super::HashcatCracker;
use super::argv;
use super::status::{self, HashcatStatus};

pub(super) async fn run(
    cracker: &HashcatCracker,
    task: &TaskAssignment,
    preprocessor: Option<&ResolvedPreprocessor>,
) -> Result<Option<String>, CrackerError> {
    match task.bench_type {
        BenchmarkType::Speed => run_speed(cracker, task, preprocessor).await,
        BenchmarkType::Run => run_runtime(cracker, task, preprocessor).await,
    }
}

/// Run the attack for `task.benchmark` seconds and report the fraction of the
/// keyspace covered, derived from the last valid status line.
async fn run_runtime(
    cracker: &HashcatCracker,
    task: &TaskAssignment,
    preprocessor: Option<&ResolvedPreprocessor>,
) -> Result<Option<String>, CrackerError> {
    let hashlist = cracker.hashlist_file(task.hashlist_id);

    let args = Args::new()
        .arg("--machine-readable")
        .arg("--quiet")
        .arg(format!("--runtime={}", task.benchmark))
        .args([
            "--restore-disable",
            "--potfile-disable",
            "--session=hashtopolis",
            "-p",
            "\t",
        ])
        .args(cracker.resolve_attack(&task.attack_command, &task.hashlist_alias, Some(&hashlist)))
        .arg_if(preprocessor.is_some(), "example.dict")
        .args(cracker.cache_arg())
        .args(argv::split_parameters(&task.cmd_parameters))
        .arg("-o")
        .arg(argv::path_arg(&cracker.hashlist_outfile(task.hashlist_id)))
        .build();

    let captured = process::run_capture(cracker.program(), &args, cracker.cwd())
        .await
        .map_err(|error| CrackerError::Process(error.to_string()))?;

    log_stderr(&captured.stderr);

    let last = captured
        .stdout
        .lines()
        .map(HashcatStatus::parse)
        .rfind(|status| status.is_valid());

    let Some(status) = last else {
        return Ok(None);
    };

    let total = status.progress_total();

    if total == 0 {
        return Ok(None);
    }

    let covered = status.progress().saturating_sub(status.rejected()) as f64 / total as f64;

    Ok(Some(covered.to_string()))
}

/// `--progress-only` prints per-device `?:count:time` lines; the result is the
/// total count and the count-weighted average time, as `count:avg_time`.
async fn run_speed(
    cracker: &HashcatCracker,
    task: &TaskAssignment,
    preprocessor: Option<&ResolvedPreprocessor>,
) -> Result<Option<String>, CrackerError> {
    let hashlist = cracker.hashlist_file(task.hashlist_id);

    let args = Args::new()
        .arg("--machine-readable")
        .arg("--quiet")
        .arg("--progress-only")
        .args([
            "--restore-disable",
            "--potfile-disable",
            "--session=hashtopolis",
            "-p",
            "\t",
        ])
        .args(cracker.resolve_attack(&task.attack_command, &task.hashlist_alias, Some(&hashlist)))
        // A preprocessor task has no wordlist of its own (candidates would come from
        // the pipe), so the benchmark stands one in from the cracker directory.
        // (example.dict is part of standard hashcat distribution)
        .arg_if(preprocessor.is_some(), "example.dict")
        .args(cracker.cache_arg())
        .args(argv::split_parameters(&task.cmd_parameters))
        .arg_if(task.brain.is_some(), "-S")
        .arg("-o")
        .arg(argv::path_arg(&cracker.hashlist_outfile(task.hashlist_id)))
        .build();

    let captured = process::run_capture(cracker.program(), &args, cracker.cwd())
        .await
        .map_err(|error| CrackerError::Process(error.to_string()))?;

    log_stderr(&captured.stderr);

    ensure_success(&captured)?;

    let mut count_sum: u64 = 0;
    let mut weighted_time: f64 = 0.0;

    for line in captured.stdout.lines() {
        let parts: Vec<&str> = line.split(':').collect();

        if parts.len() != 3 {
            continue;
        }

        let (Ok(count), Ok(time)) = (parts[1].parse::<u64>(), parts[2].parse::<f64>()) else {
            continue;
        };

        count_sum += count;
        weighted_time += time * count as f64;
    }

    if count_sum == 0 {
        return Ok(None);
    }

    Ok(Some(format!(
        "{count_sum}:{}",
        weighted_time / count_sum as f64
    )))
}

/// A speed run that exits non-zero has no trustworthy result, whatever lines it
/// printed. The Python agent gets the same strictness from
/// `subprocess.check_output`.
fn ensure_success(captured: &Captured) -> Result<(), CrackerError> {
    if captured.status.success() {
        return Ok(());
    }

    Err(CrackerError::Process(format!(
        "speed benchmark failed ({}): {} {}",
        captured.status,
        captured.stdout.trim(),
        captured.stderr.trim()
    )))
}

/// Unlike the Python agent, benchmark stderr is logged rather than forwarded to
/// the server per line: the benchmark path has no progress sink, and the result
/// (or its absence) is what the server acts on.
fn log_stderr(stderr: &str) {
    for line in stderr.lines() {
        let line = status::strip_ansi(line);
        let line = line.trim();

        if !line.is_empty() {
            tracing::warn!(line, "hashcat benchmark stderr");
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use crate::backend::hashcat::tests::{cracker, fake_hashcat, task};
    use crate::cracker::CrackerError;

    use super::run_speed;

    #[tokio::test]
    async fn a_failed_speed_run_is_an_error_despite_result_lines() {
        let tmp = tempfile::TempDir::new().unwrap();

        let mut cracker = cracker();
        cracker.binary_path = fake_hashcat(
            tmp.path(),
            "#!/bin/sh\necho '1:166:3998.88'\necho 'device 2 failed' >&2\nexit 255\n",
        );

        let error = run_speed(&cracker, &task(None), None).await.unwrap_err();

        assert!(
            matches!(&error, CrackerError::Process(message) if message.contains("exit status: 255")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_successful_speed_run_sums_counts_and_weights_the_time() {
        let tmp = tempfile::TempDir::new().unwrap();

        let mut cracker = cracker();
        cracker.binary_path =
            fake_hashcat(tmp.path(), "#!/bin/sh\necho '1:100:10'\necho '2:300:20'\n");

        let result = run_speed(&cracker, &task(None), None).await.unwrap();

        assert_eq!(result.as_deref(), Some("400:17.5"));
    }
}
