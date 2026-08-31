use crate::backend::args::Args;
use crate::cracker::CrackerError;
use crate::model::{Chunk, ResolvedPreprocessor, TaskAssignment};

use super::argv::{self, path_arg};
use super::{HashcatCracker, HashcatInvocation, OUTFILE_FORMAT, PreprocessorSpec};

impl HashcatCracker {
    /// Assemble a piped run: `<preprocessor> ... | hashcat ...`. The preprocessor
    /// generates candidates on stdout that hashcat consumes on stdin, so hashcat
    /// gets no wordlist of its own and the attack's hashlist alias is dropped in
    /// favour of an explicit positional. Brain never applies here (the server
    /// excludes it when a preprocessor is set), so the removal flags are fixed.
    pub(super) fn build_preprocessor_command(
        &self,
        task: &TaskAssignment,
        chunk: &Chunk,
        preprocessor: &ResolvedPreprocessor,
    ) -> Result<HashcatInvocation, CrackerError> {
        let hashlist = self.hashlist_file(task.hashlist_id);
        let outfile = self.hashlist_outfile(task.hashlist_id);
        let zaps_dir = self.zaps_dir(task.hashlist_id);

        let consumer_args = Args::new()
            .arg("--machine-readable")
            .arg("--quiet")
            .arg("--status")
            .arg("--remove")
            .arg("--restore-disable")
            .arg("--potfile-disable")
            .arg("--session=hashtopolis")
            .arg(format!("--status-timer={}", task.status_timer))
            .arg(format!("--outfile-check-timer={}", task.status_timer))
            .arg(format!("--outfile-check-dir={}", path_arg(&zaps_dir)))
            .arg("-o")
            .arg(path_arg(&outfile))
            .arg(format!("--outfile-format={OUTFILE_FORMAT}"))
            .arg("-p")
            .arg("\t")
            .arg(format!("--remove-timer={}", task.status_timer))
            .arg(path_arg(&hashlist))
            .args(self.resolve_attack(&task.attack_command, &task.hashlist_alias, None))
            .args(argv::split_parameters(&task.cmd_parameters))
            .build();

        let stage = self.build_preprocessor_stage(chunk, preprocessor);

        Ok(HashcatInvocation {
            program: self.program().to_path_buf(),
            args: consumer_args,
            cwd: self.cwd().to_path_buf(),
            outfile,
            zaps_dir,
            preprocessor: Some(stage),
        })
    }

    /// Build the preprocessor half. When it exposes native skip/limit flags they
    /// carry the chunk bounds; otherwise the bounds become an in-process window
    /// over its output (see [`crate::process::spawn_pipeline`]). The preprocessor
    /// runs with the cracker directory as its cwd, matching how relative tokens
    /// (e.g. `../../crackers/<id>/example.dict`) are authored.
    fn build_preprocessor_stage(
        &self,
        chunk: &Chunk,
        preprocessor: &ResolvedPreprocessor,
    ) -> PreprocessorSpec {
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

        PreprocessorSpec {
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

    use super::HashcatCracker;

    fn cracker() -> HashcatCracker {
        let dir = tempfile::tempdir().unwrap();

        let paths = Paths {
            files: dir.path().join("files"),
            hashlists: dir.path().join("hashlists"),
            zaps: dir.path().join("zaps"),
            ..Default::default()
        };

        HashcatCracker::new(1, dir.path().join("crackers/1/hashcat.bin"), paths)
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

    #[test]
    fn native_skip_limit_go_to_the_producer_and_leave_no_window() {
        let cracker = cracker();

        let invocation = cracker
            .build_preprocessor_command(
                &task(),
                &CHUNK,
                &preprocessor(Some("--skip"), Some("--limit")),
            )
            .unwrap();

        let stage = invocation.preprocessor.unwrap();

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
                .build_preprocessor_command(&task(), &CHUNK, &pp)
                .unwrap();

            let stage = invocation.preprocessor.unwrap();

            assert_eq!(stage.args, ["--pw-min=1", "--pw-max=2"]);
            assert_eq!(stage.window, Some((10, 20)));
        }
    }

    #[test]
    fn consumer_drops_the_alias_and_forces_removal_flags() {
        let cracker = cracker();

        let invocation = cracker
            .build_preprocessor_command(
                &task(),
                &CHUNK,
                &preprocessor(Some("--skip"), Some("--limit")),
            )
            .unwrap();

        // The alias is gone; the hashlist is an explicit positional instead.
        assert!(!invocation.args.iter().any(|arg| arg == "#HL#"));
        assert!(invocation.args.iter().any(|arg| arg.ends_with("/7")));

        assert!(invocation.args.iter().any(|arg| arg == "--remove"));
        assert!(invocation.args.iter().any(|arg| arg == "--potfile-disable"));

        // Skip/limit belong to the preprocessor here, never to hashcat.
        assert!(!invocation.args.iter().any(|arg| arg == "-s" || arg == "-l"));
    }
}
