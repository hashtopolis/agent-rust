use std::path::Path;

use crate::backend::args::Args;
use crate::cracker::CrackerError;
use crate::model::{Chunk, ResolvedPreprocessor, TaskAssignment};

use super::argv::{self, path_arg};
use super::{ChunkSource, HashcatCracker, HashcatInvocation, OUTFILE_FORMAT, ProducerStage};

impl HashcatCracker {
    /// The flag block shared by every hashcat consumer, whatever feeds it:
    /// machine-readable status, quiet, the outfile and zap wiring, and the tab
    /// separator. Skip/limit, the removal or brain flags, the hashlist, and the
    /// candidate source are layered on per [`ChunkSource`] by
    /// [`Self::build_invocation`].
    fn consumer_base_args(&self, task: &TaskAssignment, outfile: &Path, zaps_dir: &Path) -> Args {
        Args::new()
            .arg("--machine-readable")
            .arg("--quiet")
            .arg("--status")
            .arg("--restore-disable")
            .arg("--session=hashtopolis")
            .arg(format!("--status-timer={}", task.status_timer))
            .arg(format!("--outfile-check-timer={}", task.status_timer))
            .arg(format!("--outfile-check-dir={}", path_arg(zaps_dir)))
            .arg("-o")
            .arg(path_arg(outfile))
            .arg(format!("--outfile-format={OUTFILE_FORMAT}"))
            .arg("-p")
            .arg("\t")
    }

    /// Disable the potfile, strip cracked hashes from the list, and re-check on
    /// the task's status timer. Every piped consumer uses this; a direct run
    /// uses it only without brain (brain consults the staged potfile instead).
    fn remove_flags(&self, builder: Args, task: &TaskAssignment) -> Args {
        builder
            .arg("--potfile-disable")
            .arg("--remove")
            .arg(format!("--remove-timer={}", task.status_timer))
    }

    /// Assemble the full invocation for a chunk from its [`ChunkSource`]. The
    /// consumer flag block is shared; the skip/limit bounds, hash-removal or
    /// brain wiring, candidate source, and whether an attack command is passed
    /// all vary by source.
    pub(super) fn build_invocation(
        &self,
        task: &TaskAssignment,
        chunk: &Chunk,
        source: ChunkSource,
    ) -> Result<HashcatInvocation, CrackerError> {
        let hashlist = self.hashlist_file(task.hashlist_id);
        let outfile = self.hashlist_outfile(task.hashlist_id);
        let zaps_dir = self.zaps_dir(task.hashlist_id);

        let base = self.consumer_base_args(task, &outfile, &zaps_dir);

        let (args, producer) = match source {
            // hashcat seeks the wordlist or mask itself, bounded by -s/-l. With
            // brain it consults the staged potfile; without brain it removes
            // cracked hashes from the list. The attack keeps its hashlist alias.
            ChunkSource::Direct => {
                let builder = base
                    .arg("-s")
                    .arg(chunk.skip.to_string())
                    .arg("-l")
                    .arg(chunk.length.to_string());

                // With brain, hashcat coordinates work centrally and consults a
                // potfile instead of removing cracked hashes. We point it at the
                // exact file the provisioner filled via getFound, rather than
                // trusting hashcat's version- and platform-dependent default.
                let builder = match &task.brain {
                    Some(brain) => builder
                        .arg("--brain-client")
                        .arg(format!("--brain-host={}", brain.host))
                        .arg(format!("--brain-port={}", brain.port))
                        .arg(format!("--brain-password={}", brain.pass))
                        .arg(format!("--brain-client-features={}", brain.features))
                        .arg(format!("--potfile-path={}", path_arg(&self.potfile()))),
                    None => self.remove_flags(builder, task),
                };

                let args = builder
                    .args(self.resolve_attack(
                        &task.attack_command,
                        &task.hashlist_alias,
                        Some(&hashlist),
                    ))
                    .args(argv::split_parameters(&task.cmd_parameters))
                    .build();

                (args, None)
            }

            // A preprocessor emits candidates on stdin, so hashcat gets no
            // wordlist of its own: the alias is dropped for an explicit hashlist
            // positional, but the leftover attack tokens (e.g. `-a 0`) stay.
            // Brain never applies to a piped run.
            ChunkSource::Preprocessor(preprocessor) => {
                let args = self
                    .remove_flags(base, task)
                    .arg(path_arg(&hashlist))
                    .args(self.resolve_attack(&task.attack_command, &task.hashlist_alias, None))
                    .args(argv::split_parameters(&task.cmd_parameters))
                    .build();

                (args, Some(self.preprocessor_producer(chunk, preprocessor)))
            }

            // hashcat feeds itself. The consumer reads straight candidates from
            // stdin, so it carries no attack command and no `-a` at all. The
            // hash type must therefore live in cmd_parameters, not the attack
            // string, a long-standing server contract (see self_producer).
            ChunkSource::SelfPipe => {
                if task.brain.is_some() {
                    tracing::warn!(
                        "task requests brain but is running as a self-pipe; brain is dropped while piping"
                    );
                }

                let args = self
                    .remove_flags(base, task)
                    .arg(path_arg(&hashlist))
                    .args(argv::split_parameters(&task.cmd_parameters))
                    .build();

                (args, Some(self.self_producer(task, chunk)))
            }
        };

        Ok(HashcatInvocation {
            program: self.program().to_path_buf(),
            args,
            cwd: self.cwd().to_path_buf(),
            outfile,
            zaps_dir,
            producer,
        })
    }

    /// The self-pipe producer: hashcat with `--stdout`, bounded natively by
    /// `-s`/`-l`, emitting the chunk's final candidates for the consumer. The
    /// attack keeps its wordlist and rules but drops the hashlist alias; no
    /// in-process window is needed since hashcat honours skip/limit itself.
    fn self_producer(&self, task: &TaskAssignment, chunk: &Chunk) -> ProducerStage {
        let args = Args::new()
            .arg("--stdout")
            .arg("-s")
            .arg(chunk.skip.to_string())
            .arg("-l")
            .arg(chunk.length.to_string())
            .args(self.resolve_attack(&task.attack_command, &task.hashlist_alias, None))
            .build();

        ProducerStage {
            program: self.program().to_path_buf(),
            args,
            window: None,
        }
    }

    /// Build the preprocessor producer. When it exposes native skip/limit flags
    /// they carry the chunk bounds; otherwise the bounds become an in-process
    /// window over its output (see [`crate::process::spawn_pipeline`]). The
    /// preprocessor runs with the cracker directory as its cwd, matching how
    /// relative tokens (e.g. `../../crackers/<id>/example.dict`) are authored.
    fn preprocessor_producer(
        &self,
        chunk: &Chunk,
        preprocessor: &ResolvedPreprocessor,
    ) -> ProducerStage {
        let native = preprocessor
            .skip_command
            .as_deref()
            .zip(preprocessor.limit_command.as_deref());

        let mut builder = Args::new();

        if let Some((skip_command, limit_command)) = native {
            builder = builder
                .arg(skip_command)
                .arg(chunk.skip.to_string())
                .arg(limit_command)
                .arg(chunk.length.to_string());
        }

        let args = builder
            .args(self.resolve_attack(&preprocessor.command, "", None))
            .build();

        let window = native.is_none().then_some((chunk.skip, chunk.length));

        ProducerStage {
            program: preprocessor.binary_path.clone(),
            args,
            window,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::config::Paths;
    use crate::model::{BenchmarkType, Chunk, ResolvedPreprocessor, TaskAssignment};

    use super::super::{ChunkSource, HashcatCracker};

    fn cracker() -> HashcatCracker {
        let dir = tempfile::tempdir().unwrap();

        let paths = Paths {
            files: dir.path().join("files"),
            hashlists: dir.path().join("hashlists"),
            zaps: dir.path().join("zaps"),
            ..Default::default()
        };

        HashcatCracker {
            cracker_id: 1,
            binary_path: dir.path().join("crackers/1/hashcat.bin"),
            paths,
            progress_mode: super::super::progress::ProgressMode::Absolute,
            auto_pipe: None,
        }
    }

    fn task() -> TaskAssignment {
        TaskAssignment {
            task_id: 1,
            cracker_id: 1,
            attack_command: "#HL# -a 0".into(),
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
            brain: None,
        }
    }

    fn preprocessor(skip: Option<&str>, limit: Option<&str>) -> ResolvedPreprocessor {
        ResolvedPreprocessor {
            command: "--pw-min=1 --pw-max=2".into(),
            binary_path: PathBuf::from("/pp/1/pp.bin"),
            keyspace_command: Some("--keyspace".into()),
            skip_command: skip.map(Into::into),
            limit_command: limit.map(Into::into),
        }
    }

    const CHUNK: Chunk = Chunk {
        id: 1,
        skip: 10,
        length: 20,
    };

    /// The value hashcat takes as the separate argv token after `flag`.
    fn value_after<'a>(args: &'a [String], flag: &str) -> &'a str {
        let index = args
            .iter()
            .position(|arg| arg == flag)
            .unwrap_or_else(|| panic!("no {flag} in {args:?}"));

        &args[index + 1]
    }

    #[test]
    fn native_skip_limit_go_to_the_producer_and_leave_no_window() {
        let cracker = cracker();

        let invocation = cracker
            .build_invocation(
                &task(),
                &CHUNK,
                ChunkSource::Preprocessor(&preprocessor(Some("--skip"), Some("--limit"))),
            )
            .unwrap();

        let stage = invocation.producer.unwrap();

        assert_eq!(stage.program, PathBuf::from("/pp/1/pp.bin"));
        assert_eq!(
            stage.args,
            ["--skip", "10", "--limit", "20", "--pw-min=1", "--pw-max=2"]
        );
        assert_eq!(stage.window, None);
    }

    #[test]
    fn missing_skip_or_limit_falls_back_to_an_in_process_window() {
        let cracker = cracker();

        for pp in [
            preprocessor(None, None),
            preprocessor(Some("--skip"), None),
            preprocessor(None, Some("--limit")),
        ] {
            let invocation = cracker
                .build_invocation(&task(), &CHUNK, ChunkSource::Preprocessor(&pp))
                .unwrap();

            let stage = invocation.producer.unwrap();

            assert_eq!(stage.args, ["--pw-min=1", "--pw-max=2"]);
            assert_eq!(stage.window, Some((10, 20)));
        }
    }

    #[test]
    fn preprocessor_consumer_drops_the_alias_and_keeps_the_attack() {
        let cracker = cracker();

        let invocation = cracker
            .build_invocation(
                &task(),
                &CHUNK,
                ChunkSource::Preprocessor(&preprocessor(Some("--skip"), Some("--limit"))),
            )
            .unwrap();

        // The alias is gone; the hashlist is an explicit positional instead.
        assert!(!invocation.args.iter().any(|arg| arg == "#HL#"));
        assert!(invocation.args.iter().any(|arg| arg.ends_with("/7")));

        assert!(invocation.args.iter().any(|arg| arg == "--remove"));
        assert!(invocation.args.iter().any(|arg| arg == "--potfile-disable"));

        // A preprocessor consumer keeps the leftover attack tokens.
        assert!(invocation.args.iter().any(|arg| arg == "-a"));

        // Skip/limit belong to the preprocessor here, never to hashcat.
        assert!(!invocation.args.iter().any(|arg| arg == "-s" || arg == "-l"));
    }

    #[test]
    fn self_pipe_producer_emits_stdout_with_native_bounds_and_no_window() {
        let cracker = cracker();

        // A wordlist attack so the producer has candidates to expand.
        let mut task = task();
        task.attack_command = "#HL# -a 0 example.dict".into();

        let stage = cracker
            .build_invocation(&task, &CHUNK, ChunkSource::SelfPipe)
            .unwrap()
            .producer
            .unwrap();

        // The producer is hashcat itself in --stdout mode, bounded natively.
        assert!(stage.args.iter().any(|arg| arg == "--stdout"));
        assert_eq!(value_after(&stage.args, "-s"), "10");
        assert_eq!(value_after(&stage.args, "-l"), "20");
        assert_eq!(stage.window, None);

        // It keeps the attack (minus the alias) so it emits final candidates.
        assert!(stage.args.iter().any(|arg| arg == "-a"));
        assert!(!stage.args.iter().any(|arg| arg == "#HL#"));
    }

    #[test]
    fn self_pipe_consumer_has_no_attack_and_no_skip_limit() {
        let cracker = cracker();

        let mut task = task();
        task.attack_command = "#HL# -a 0 example.dict".into();
        task.cmd_parameters = "-m 1000".into();

        let invocation = cracker
            .build_invocation(&task, &CHUNK, ChunkSource::SelfPipe)
            .unwrap();

        // The hashlist is an explicit positional; the alias is gone.
        assert!(!invocation.args.iter().any(|arg| arg == "#HL#"));
        assert!(invocation.args.iter().any(|arg| arg.ends_with("/7")));

        // The consumer reads candidates from stdin, so no attack command and no
        // chunk bounds appear on it.
        assert!(!invocation.args.iter().any(|arg| arg == "-a"));
        assert!(!invocation.args.iter().any(|arg| arg == "-s" || arg == "-l"));

        // The hash type from cmd_parameters is carried through.
        assert!(invocation.args.iter().any(|arg| arg == "-m"));

        // Removal flags are fixed for a piped consumer.
        assert!(invocation.args.iter().any(|arg| arg == "--remove"));
        assert!(invocation.args.iter().any(|arg| arg == "--potfile-disable"));
    }
}
