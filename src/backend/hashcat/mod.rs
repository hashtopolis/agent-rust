mod argv;
mod auto_pipe;
mod benchmark;
mod chunk;
mod healthcheck;
mod keyspace;
mod paths;
mod producer;
mod progress;
pub mod status;

use std::path::PathBuf;

use crate::config::Paths;
use crate::cracker::{ChunkOutcome, Cracker, CrackerError, HealthCheckOutcome, ProgressSink};
use crate::model::{Chunk, CrackerId, ResolvedPreprocessor, TaskAssignment};

use chunk::ChunkResult;

pub use auto_pipe::AutoPipePolicy;

/// Modern hashcat (v6+) crack-record format `hash:plain:hex_plain:crack_pos`.
/// The old `15` format for pre-6.0 binaries is not supported.
pub(super) const OUTFILE_FORMAT: &str = "1,2,3,4";

pub struct HashcatCracker {
    cracker_id: CrackerId,
    binary_path: PathBuf,
    paths: Paths,
    progress_mode: progress::ProgressMode,
    auto_pipe: Option<AutoPipePolicy>,
}

impl HashcatCracker {
    #[tracing::instrument(skip_all, fields(cracker_id = cracker_id))]
    pub async fn new(
        cracker_id: CrackerId,
        binary_path: PathBuf,
        paths: Paths,
        auto_pipe: Option<AutoPipePolicy>,
    ) -> Result<Self, CrackerError> {
        let progress_mode = progress::ProgressMode::detect(&binary_path).await?;

        Ok(Self {
            cracker_id,
            binary_path,
            paths,
            progress_mode,
            auto_pipe,
        })
    }
}

/// Which candidate source feeds a chunk run. Chosen inside [`HashcatCracker::run_chunk`]
/// and passed to [`HashcatCracker::build_invocation`]; the run loop never sees it.
enum ChunkSource<'a> {
    /// hashcat seeks the wordlist or mask itself, bounded by `-s`/`-l`.
    Direct,
    /// A preprocessor binary emits candidates on stdout that hashcat consumes.
    Preprocessor(&'a ResolvedPreprocessor),
    /// hashcat feeds itself: `hashcat --stdout ... | hashcat ...`.
    SelfPipe,
}

/// Everything a chunk run needs from command assembly: what to spawn, where, and
/// the two files the run reads back from and writes zaps into. `program`/`args`
/// describe hashcat itself; `producer`, when set, is a stage whose stdout feeds
/// hashcat's stdin.
struct HashcatInvocation {
    program: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    outfile: PathBuf,
    zaps_dir: PathBuf,
    producer: Option<ProducerStage>,
}

/// The producer half of a piped run: a preprocessor binary or a self-piping
/// hashcat. `window` is set only when the producer lacks native skip/limit
/// flags, in which case the `(skip, length)` range is applied to its output
/// stream in-process.
struct ProducerStage {
    program: PathBuf,
    args: Vec<String>,
    window: Option<(u64, u64)>,
}

impl Cracker for HashcatCracker {
    async fn measure_keyspace(
        &self,
        task: &TaskAssignment,
        preprocessor: Option<&ResolvedPreprocessor>,
    ) -> Result<Option<u64>, CrackerError> {
        keyspace::measure(self, task, preprocessor).await
    }

    async fn run_benchmark(
        &self,
        task: &TaskAssignment,
        preprocessor: Option<&ResolvedPreprocessor>,
    ) -> Result<Option<String>, CrackerError> {
        benchmark::run(self, task, preprocessor).await
    }

    #[tracing::instrument(skip_all, fields(cracker_id = self.cracker_id))]
    async fn run_chunk<S: ProgressSink>(
        &self,
        task: &TaskAssignment,
        chunk: Chunk,
        preprocessor: Option<&ResolvedPreprocessor>,
        sink: &S,
    ) -> Result<ChunkOutcome, CrackerError> {
        let source = initial_source(task, preprocessor);

        // Arm the slow-hash auto-pipe only for a direct run, when the policy is
        // set and the task qualifies. A run already piped for any other reason
        // must never switch again.
        let probe = if let Some(policy) = self.auto_pipe
            && matches!(source, ChunkSource::Direct)
            && auto_pipe::preconditions_met(task)
        {
            Some(auto_pipe::Probe {
                threshold: policy.util_threshold,
            })
        } else {
            None
        };

        let invocation = self.build_invocation(task, &chunk, source)?;

        // The first attempt, armed if the task qualified above.
        if let ChunkResult::Done(outcome) =
            chunk::run(invocation, chunk, self.progress_mode, probe, sink).await?
        {
            return Ok(outcome);
        }

        // The GPU was starved: restart the same chunk as a self-pipe, this time
        // unarmed so it cannot loop.
        tracing::info!("gpu underutilised; restarting chunk as a self-pipe");

        let invocation = self.build_invocation(task, &chunk, ChunkSource::SelfPipe)?;

        let ChunkResult::Done(outcome) =
            chunk::run(invocation, chunk, self.progress_mode, None, sink).await?
        else {
            unreachable!("a self-pipe run is never armed for auto-pipe")
        };

        Ok(outcome)
    }

    async fn run_health_check(
        &self,
        attack: &str,
        hashlist_alias: &str,
        hashes: &[String],
    ) -> Result<HealthCheckOutcome, CrackerError> {
        healthcheck::run(self, attack, hashlist_alias, hashes).await
    }

    fn found_hashes_path(&self) -> Option<PathBuf> {
        Some(self.potfile())
    }
}

/// Pick the candidate source before any live telemetry: a preprocessor if the
/// task has one, else a self-pipe when `enforce_pipe` is set, else direct.
fn initial_source<'a>(
    task: &TaskAssignment,
    preprocessor: Option<&'a ResolvedPreprocessor>,
) -> ChunkSource<'a> {
    match preprocessor {
        Some(pp) => ChunkSource::Preprocessor(pp),
        None if task.enforce_pipe => ChunkSource::SelfPipe,
        None => ChunkSource::Direct,
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::config::Paths;
    use crate::model::{BenchmarkType, BrainConfig, Chunk, TaskAssignment};

    use super::argv::path_arg;
    use super::auto_pipe::preconditions_met;
    use super::progress::ProgressMode;
    use super::{ChunkSource, HashcatCracker, initial_source};

    const CRACKER_ID: u64 = 4;

    fn cracker() -> HashcatCracker {
        HashcatCracker {
            cracker_id: CRACKER_ID,
            binary_path: PathBuf::from("/opt/crackers/4/hashcat.bin"),
            paths: Paths::default(),
            progress_mode: ProgressMode::Absolute,
            auto_pipe: None,
        }
    }

    fn task(brain: Option<BrainConfig>) -> TaskAssignment {
        TaskAssignment {
            task_id: 1,
            cracker_id: CRACKER_ID,
            attack_command: "#HL# -a 3 ?a?a?a".into(),
            cmd_parameters: String::new(),
            hashlist_id: 7,
            benchmark: 30,
            status_timer: 5,
            files: Vec::new(),
            bench_type: BenchmarkType::Speed,
            hashlist_alias: "#HL#".into(),
            keyspace: 0,
            enforce_pipe: false,
            slow_hash: false,
            preprocessor: None,
            brain,
        }
    }

    const CHUNK: Chunk = Chunk {
        id: 1,
        skip: 10,
        length: 20,
    };

    fn brain() -> BrainConfig {
        BrainConfig {
            host: "brain.example".into(),
            port: 6863,
            pass: "secret".into(),
            features: 3,
        }
    }

    /// The value hashcat takes as the separate argv token after `flag` (as in
    /// `-s 10`). Panics if the flag is absent or has no following token.
    fn value_after<'a>(args: &'a [String], flag: &str) -> &'a str {
        let index = args
            .iter()
            .position(|arg| arg == flag)
            .unwrap_or_else(|| panic!("no {flag} in {args:?}"));

        args.get(index + 1)
            .unwrap_or_else(|| panic!("{flag} has no value in {args:?}"))
    }

    #[test]
    fn a_plain_chunk_run_emits_the_baseline_flags() {
        let cracker = cracker();

        let invocation = cracker
            .build_invocation(&task(None), &CHUNK, ChunkSource::Direct)
            .unwrap();
        let args = &invocation.args;

        // Static flags every chunk run carries.
        for flag in [
            "--machine-readable",
            "--quiet",
            "--status",
            "--restore-disable",
            "--session=hashtopolis",
            "--outfile-format=1,2,3,4",
        ] {
            assert!(
                args.iter().any(|arg| arg == flag),
                "missing {flag}: {args:?}"
            );
        }

        // Both timers are driven by the task's status_timer (5 here).
        assert!(args.contains(&"--status-timer=5".to_string()));
        assert!(args.contains(&"--outfile-check-timer=5".to_string()));

        // The chunk window becomes -s (skip) and -l (length).
        assert_eq!(value_after(args, "-s"), "10");
        assert_eq!(value_after(args, "-l"), "20");

        // -p is the tab separator; -o points at the hashlist outfile; zaps are
        // watched in the outfile-check-dir.
        assert_eq!(value_after(args, "-p"), "\t");
        assert_eq!(value_after(args, "-o"), path_arg(&invocation.outfile));
        assert!(args.contains(&format!(
            "--outfile-check-dir={}",
            path_arg(&invocation.zaps_dir)
        )));
    }

    #[test]
    fn the_attack_and_extra_parameters_are_appended() {
        let cracker = cracker();

        // Flag and mask tokens only, so nothing resolves against the files dir;
        // file-token resolution is covered by the resolve_attack tests.
        let mut task = task(None);
        task.attack_command = "#HL# -a 3 ?a?a?a".into();
        task.cmd_parameters = "-O -w 4".into();

        let args = cracker
            .build_invocation(&task, &CHUNK, ChunkSource::Direct)
            .unwrap()
            .args;

        // The alias is replaced by the hashlist path and the attack tokens follow.
        assert!(args.iter().any(|arg| Path::new(arg).ends_with("7")));
        assert!(args.iter().any(|arg| arg == "?a?a?a"));

        // Extra parameters are split into tokens and appended.
        for token in ["-O", "-w", "4"] {
            assert!(
                args.iter().any(|arg| arg == token),
                "missing extra parameter {token}: {args:?}"
            );
        }
    }

    #[test]
    fn a_brain_run_pins_the_potfile_path_and_leaves_it_enabled() {
        let cracker = cracker();

        let invocation = cracker
            .build_invocation(&task(Some(brain())), &CHUNK, ChunkSource::Direct)
            .unwrap();

        let args = &invocation.args;

        // The full brain connection is described from the task's BrainConfig.
        for flag in [
            "--brain-client",
            "--brain-host=brain.example",
            "--brain-port=6863",
            "--brain-password=secret",
            "--brain-client-features=3",
            &format!("--potfile-path={}", path_arg(&cracker.potfile())),
        ] {
            assert!(
                args.iter().any(|arg| arg == flag),
                "missing {flag}: {args:?}"
            );
        }

        // Brain consults the potfile, so it must never be disabled, nor should the
        // non-brain removal flags appear.
        assert!(!args.iter().any(|arg| arg == "--potfile-disable"));
        assert!(!args.iter().any(|arg| arg == "--remove"));
    }

    #[test]
    fn a_non_brain_run_disables_the_potfile_and_removes_cracked_hashes() {
        let cracker = cracker();

        let args = cracker
            .build_invocation(&task(None), &CHUNK, ChunkSource::Direct)
            .unwrap()
            .args;

        // The non-brain branch strips cracked hashes from the list itself.
        assert!(args.iter().any(|arg| arg == "--potfile-disable"));
        assert!(args.iter().any(|arg| arg == "--remove"));
        assert!(args.contains(&"--remove-timer=5".to_string()));

        // None of the brain wiring leaks into a plain run.
        assert!(!args.iter().any(|arg| arg == "--brain-client"));
        assert!(
            !args.iter().any(|arg| arg.starts_with("--potfile-path=")),
            "a non-brain run has no downloaded potfile to point at"
        );
    }

    fn qualifying() -> TaskAssignment {
        let mut task = task(None);
        task.slow_hash = true;
        task.files = vec!["rockyou.txt".into()];
        task
    }

    #[test]
    fn initial_source_prefers_preprocessor_then_enforced_pipe_then_direct() {
        use crate::model::ResolvedPreprocessor;

        let pp = ResolvedPreprocessor {
            command: "--pw-min=1".into(),
            binary_path: PathBuf::from("/pp/1/pp.bin"),
            keyspace_command: None,
            skip_command: None,
            limit_command: None,
        };

        // A preprocessor wins even when enforce_pipe is also set.
        {
            let mut task = task(None);
            task.enforce_pipe = true;
            assert!(matches!(
                initial_source(&task, Some(&pp)),
                ChunkSource::Preprocessor(_)
            ));
        }

        // No preprocessor and enforce_pipe set: a self-pipe.
        {
            let mut task = task(None);
            task.enforce_pipe = true;
            assert!(matches!(initial_source(&task, None), ChunkSource::SelfPipe));
        }

        // Nothing set: direct.
        assert!(matches!(
            initial_source(&task(None), None),
            ChunkSource::Direct
        ));
    }

    #[test]
    fn arming_requires_slow_hash_files_no_brain_and_no_slow_candidates() {
        assert!(preconditions_met(&qualifying()));

        let mut task = qualifying();
        task.slow_hash = false;
        assert!(!preconditions_met(&task));

        let mut task = qualifying();
        task.files.clear();
        assert!(!preconditions_met(&task));

        let mut task = qualifying();
        task.brain = Some(brain());
        assert!(!preconditions_met(&task));

        let mut task = qualifying();
        task.attack_command = "#HL# -a 0 -S rockyou.txt".into();
        assert!(!preconditions_met(&task));
    }

    #[test]
    fn a_standalone_slow_candidate_flag_disarms_but_a_prefix_does_not() {
        // `-S` in the extra parameters disarms an otherwise-qualifying task.
        let mut task = qualifying();
        task.cmd_parameters = "-w 4 -S".into();
        assert!(!preconditions_met(&task));

        // `-S` as a prefix of a longer token in either field does not.
        let mut task = qualifying();
        task.attack_command = "#HL# -a 0 -Slow.txt".into();
        task.cmd_parameters = "-Sx".into();
        assert!(preconditions_met(&task));
    }
}
