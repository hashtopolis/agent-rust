mod argv;
mod benchmark;
mod chunk;
mod healthcheck;
mod keyspace;
mod paths;
mod preprocessor;
mod progress;
pub mod status;

use std::path::PathBuf;

use crate::config::Paths;
use crate::cracker::{ChunkOutcome, Cracker, CrackerError, HealthCheckOutcome, ProgressSink};
use crate::model::{Chunk, CrackerId, ResolvedPreprocessor, TaskAssignment};

use crate::backend::args::Args;
use argv::path_arg;

/// Modern hashcat (v6+) crack-record format `hash:plain:hex_plain:crack_pos`.
/// The old `15` format for pre-6.0 binaries is not supported.
pub(super) const OUTFILE_FORMAT: &str = "1,2,3,4";

pub struct HashcatCracker {
    cracker_id: CrackerId,
    binary_path: PathBuf,
    paths: Paths,
    progress_mode: progress::ProgressMode,
}

impl HashcatCracker {
    #[tracing::instrument(skip_all, fields(cracker_id = cracker_id))]
    pub async fn new(
        cracker_id: CrackerId,
        binary_path: PathBuf,
        paths: Paths,
    ) -> Result<Self, CrackerError> {
        let progress_mode = progress::ProgressMode::detect(&binary_path).await?;

        Ok(Self {
            cracker_id,
            binary_path,
            paths,
            progress_mode,
        })
    }

    /// Assemble the argv and paths for a plain (non-preprocessor) chunk run. The
    /// preprocessor pipe variant lives in [`preprocessor`].
    fn build_command(
        &self,
        task: &TaskAssignment,
        chunk: &Chunk,
    ) -> Result<HashcatInvocation, CrackerError> {
        let hashlist = self.hashlist_file(task.hashlist_id);
        let outfile = self.hashlist_outfile(task.hashlist_id);
        let zaps_dir = self.zaps_dir(task.hashlist_id);

        let builder = Args::new()
            .arg("--machine-readable")
            .arg("--quiet")
            .arg("--status")
            .arg("--restore-disable")
            .arg("--session=hashtopolis")
            .arg(format!("--status-timer={}", task.status_timer))
            .arg(format!("--outfile-check-timer={}", task.status_timer))
            .arg(format!("--outfile-check-dir={}", path_arg(&zaps_dir)))
            .arg("-o")
            .arg(path_arg(&outfile))
            .arg(format!("--outfile-format={OUTFILE_FORMAT}"))
            .arg("-p")
            .arg("\t")
            .arg("-s")
            .arg(chunk.skip.to_string())
            .arg("-l")
            .arg(chunk.length.to_string());

        // With brain, hashcat coordinates work centrally and consults a potfile
        // instead of removing cracked hashes from the list. We point it at the
        // exact file the provisioner filled via getFound, rather than trusting
        // hashcat's version- and platform-dependent default potfile location.
        // Without brain we disable the potfile and let hashcat strip cracked
        // hashes from the list itself.
        let builder = match &task.brain {
            Some(brain) => builder
                .arg("--brain-client")
                .arg(format!("--brain-host={}", brain.host))
                .arg(format!("--brain-port={}", brain.port))
                .arg(format!("--brain-password={}", brain.pass))
                .arg(format!("--brain-client-features={}", brain.features))
                .arg(format!("--potfile-path={}", path_arg(&self.potfile()))),
            None => builder
                .arg("--potfile-disable")
                .arg("--remove")
                .arg(format!("--remove-timer={}", task.status_timer)),
        };

        let args = builder
            .args(self.resolve_attack(&task.attack_command, &task.hashlist_alias, Some(&hashlist)))
            .args(argv::split_parameters(&task.cmd_parameters))
            .build();

        Ok(HashcatInvocation {
            program: self.program().to_path_buf(),
            args,
            cwd: self.cwd().to_path_buf(),
            outfile,
            zaps_dir,
            preprocessor: None,
        })
    }
}

/// Everything a chunk run needs from command assembly: what to spawn, where, and
/// the two files the run reads back from and writes zaps into. `program`/`args`
/// describe hashcat itself; `preprocessor`, when set, is a stage whose stdout
/// feeds hashcat's stdin.
struct HashcatInvocation {
    program: PathBuf,
    args: Vec<String>,
    cwd: PathBuf,
    outfile: PathBuf,
    zaps_dir: PathBuf,
    preprocessor: Option<PreprocessorSpec>,
}

/// The preprocessor half of a piped run. `window` is set only when the
/// preprocessor lacks native skip/limit flags, in which case the `(skip, length)`
/// range is applied to its output stream in-process.
struct PreprocessorSpec {
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
        let invocation = match preprocessor {
            Some(pp) => self.build_preprocessor_command(task, &chunk, pp)?,
            None => self.build_command(task, &chunk)?,
        };

        chunk::run(invocation, chunk, self.progress_mode, sink).await
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::config::Paths;
    use crate::model::{BenchmarkType, BrainConfig, Chunk, TaskAssignment};

    use super::progress::ProgressMode;
    use super::{HashcatCracker, path_arg};

    const CRACKER_ID: u64 = 4;

    fn cracker() -> HashcatCracker {
        HashcatCracker {
            cracker_id: CRACKER_ID,
            binary_path: PathBuf::from("/opt/crackers/4/hashcat.bin"),
            paths: Paths::default(),
            progress_mode: ProgressMode::Absolute,
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

        let invocation = cracker.build_command(&task(None), &CHUNK).unwrap();
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

        let args = cracker.build_command(&task, &CHUNK).unwrap().args;

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

        let invocation = cracker.build_command(&task(Some(brain())), &CHUNK).unwrap();

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

        let args = cracker.build_command(&task(None), &CHUNK).unwrap().args;

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
}
