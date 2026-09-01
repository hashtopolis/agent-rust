mod argv;
mod benchmark;
mod chunk;
mod healthcheck;
mod keyspace;
mod paths;
mod preprocessor;
pub mod status;

use std::path::PathBuf;

use crate::config::Paths;
use crate::cracker::{ChunkOutcome, Cracker, CrackerError, HealthCheckOutcome, ProgressSink};
use crate::model::{Chunk, ResolvedPreprocessor, TaskAssignment};

use crate::backend::args::Args;
use argv::path_arg;

/// Modern hashcat (v6+) crack-record format `hash:plain:hex_plain:crack_pos`.
/// Deferred: the old `15` format for pre-6.0 binaries, which needs version
/// detection at construction.
pub(super) const OUTFILE_FORMAT: &str = "1,2,3,4";

pub struct HashcatCracker {
    #[allow(dead_code)]
    cracker_id: u64,
    binary_path: PathBuf,
    paths: Paths,
}

impl HashcatCracker {
    pub fn new(cracker_id: u64, binary_path: PathBuf, paths: Paths) -> Self {
        Self {
            cracker_id,
            binary_path,
            paths,
        }
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

        // With brain, hashcat coordinates work centrally; without it we disable
        // the potfile and let hashcat strip cracked hashes from the list itself.
        let builder = match &task.brain {
            Some(brain) => builder
                .arg("--brain-client")
                .arg(format!("--brain-host={}", brain.host))
                .arg(format!("--brain-port={}", brain.port))
                .arg(format!("--brain-password={}", brain.pass))
                .arg(format!("--brain-client-features={}", brain.features)),
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

        chunk::run(invocation, chunk, sink).await
    }

    async fn run_health_check(
        &self,
        attack: &str,
        hashlist_alias: &str,
        hashes: &[String],
    ) -> Result<HealthCheckOutcome, CrackerError> {
        healthcheck::run(self, attack, hashlist_alias, hashes).await
    }
}
