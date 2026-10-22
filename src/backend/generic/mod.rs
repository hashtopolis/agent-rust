//! The generic cracker backend: any non-hashcat binary the server hands out.
//!
//! # Binary
//!
//! - Path: `<crackers-path>/<crackerId>/<executable>` (server-announced
//!   filename), passed as an absolute path. No version probe, no per-OS variants.
//!
//! # Invocation (all sub-commands)
//!
//! - Working directory: the files directory (`<files-path>`).
//! - No shell: argv is spawned directly. Tokens are not re-quoted or word-split;
//!   spaces are safe. The reference's Windows `/`→`\` rewrite is not reproduced.
//! - Argument resolution: the attack string contains a hashlist alias (e.g.
//!   `#HL#`) for the hash file. A token naming a file under the files directory
//!   is rewritten to its absolute path; other tokens pass through in order.
//!
//! # Sub-commands
//!
//! - `keyspace <attack, with the -a/alias pair removed>`: measure keyspace.
//!   The agent drops the `-a` flag and its alias argument token-wise, then
//!   resolves the rest. The binary prints the keyspace as an integer; the agent
//!   parses the last non-empty stdout line. A value above `i64::MAX` is reported
//!   as unbounded.
//! - `crack ...`: run an attack (benchmark and chunk). The alias is replaced by
//!   the absolute hashlist path; `-a` is kept.
//!   - Benchmark argv: `crack <attack> -s 0 -l <keyspace> --timeout=<seconds>`.
//!     Runs ~`--timeout` seconds. Result: the last valid status's progress as a
//!     `0.0..=1.0` fraction. `benchType` is ignored (no speed variant).
//!   - Chunk argv: `crack -s <skip> -l <length> <attack>`. (`-s`/`-l` precede the
//!     attack here, follow it in the benchmark; order is immaterial to the binary.)
//!
//! # Stdout during a `crack` run
//!
//! Each line is one of:
//!
//! - Status line: `STATUS <progress> <speed>`, three tokens split on a single
//!   space, both integers. `progress` is basis points, `0..=10000` (10000 =
//!   100%). `speed` is an opaque integer. Grammar: [`status`].
//! - Cracked hash: any non-status line containing `:`. Sent to the server as a
//!   raw, unsplit string (the server splits it with the hashlist's field
//!   separator), stored trimmed. The binary emits `hash<sep>plain`.
//! - Other: a non-status line without `:` is logged and discarded.
//!
//! Stderr is logged only; never sent to the server, never aborts the run.
//!
//! # Progress updates
//!
//! One update per valid status line:
//!
//! - `relativeProgress` = `progress` (basis points).
//! - `speed` = `speed`.
//! - `state` = 4 if `progress == 10000`, else 2.
//! - `keyspaceProgress` = `skip + length * progress / 10000`, an absolute cursor
//!   within the chunk. The reference agent pins this to `skip`; we compute it so
//!   the server (which stores it as the chunk checkpoint) reports real task
//!   progress and can trim the chunk on resume instead of restarting it.
//! - `cracks` = those accumulated since the last update, batched ≤ 1000 per
//!   request. Cracks arriving after the final status are flushed at process exit.
//! - No GPU/CPU telemetry.
//!
//! A keepalive heartbeat is sent before the first status. Server-returned zaps
//! are written to `<files-path>/zap`, newline-joined, overwrite mode (parity;
//! not fed back to the binary).
//!
//! # Not supported
//!
//! No preprocessor, brain, found-hashes staging, piping, health check, or
//! telemetry. Health check requests return an error. A server stop mid-run is
//! honoured (the process group is killed).

mod benchmark;
mod chunk;
mod keyspace;
mod paths;
pub mod status;

use std::path::{Path, PathBuf};

use crate::backend::args::Args;
use crate::backend::paths::resolve_file_token;
use crate::cracker::{ChunkOutcome, Cracker, CrackerError, HealthCheckOutcome, ProgressSink};
use crate::model::{Chunk, CrackerId, ResolvedPreprocessor, TaskAssignment};

use chunk::GenericInvocation;

pub struct GenericCracker {
    #[allow(dead_code)]
    cracker_id: CrackerId,
    binary_path: PathBuf,
    paths: crate::config::Paths,
}

impl GenericCracker {
    pub fn new(cracker_id: CrackerId, binary_path: PathBuf, paths: crate::config::Paths) -> Self {
        Self {
            cracker_id,
            binary_path,
            paths,
        }
    }

    /// Resolve the attack for a crack or benchmark run: swap the hashlist alias
    /// for the absolute hashlist path and resolve any token naming a file under
    /// the files dir to its absolute path, including a `key=value` token whose
    /// value names a file. `-a` and every other token pass through
    fn resolve_attack(&self, attack: &str, alias: &str, hashlist: &Path) -> Vec<String> {
        attack
            .split_whitespace()
            .map(|token| {
                if token == alias {
                    path_arg(hashlist)
                } else {
                    self.resolve_file_token(token)
                }
            })
            .collect()
    }

    /// Resolve the attack for a keyspace measure: drop the `-a <alias>` pair (the
    /// generic cracker's hash-file argument, which the `keyspace` sub-command does
    /// not want), then resolve remaining file tokens.
    fn resolve_keyspace_attack(&self, attack: &str, alias: &str) -> Vec<String> {
        let mut tokens = attack.split_whitespace().peekable();
        let mut args = Vec::new();

        while let Some(token) = tokens.next() {
            if token == "-a" && tokens.peek() == Some(&alias) {
                tokens.next();
                continue;
            }

            args.push(self.resolve_file_token(token));
        }

        args
    }

    fn resolve_file_token(&self, token: &str) -> String {
        resolve_file_token(&self.paths.files, token)
    }
}

/// Render a path as an argv token. No quoting: argv carries spaces natively.
fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

impl Cracker for GenericCracker {
    async fn measure_keyspace(
        &self,
        task: &TaskAssignment,
        _preprocessor: Option<&ResolvedPreprocessor>,
    ) -> Result<Option<u64>, CrackerError> {
        keyspace::measure(self, task).await
    }

    async fn run_benchmark(
        &self,
        task: &TaskAssignment,
        _preprocessor: Option<&ResolvedPreprocessor>,
    ) -> Result<Option<String>, CrackerError> {
        benchmark::run(self, task).await
    }

    async fn run_chunk<S: ProgressSink>(
        &self,
        task: &TaskAssignment,
        chunk: Chunk,
        _: Option<&ResolvedPreprocessor>,
        sink: &S,
    ) -> Result<ChunkOutcome, CrackerError> {
        let hashlist = self.hashlist_file(task.hashlist_id);

        // `crack -s <skip> -l <length> <attack>`; note the window flags precede
        // the attack here, and follow it in the benchmark.
        let args = Args::new()
            .arg("crack")
            .arg("-s")
            .arg(chunk.skip.to_string())
            .arg("-l")
            .arg(chunk.length.to_string())
            .args(self.resolve_attack(&task.attack_command, &task.hashlist_alias, &hashlist))
            .build();

        let invocation = GenericInvocation {
            program: self.program().to_path_buf(),
            args,
            cwd: self.cwd().to_path_buf(),
            zap_file: self.zap_file(),
        };

        chunk::run(invocation, chunk, sink).await
    }

    async fn run_health_check(
        &self,
        _attack: &str,
        _hashlist_alias: &str,
        _hashes: &[String],
    ) -> Result<HealthCheckOutcome, CrackerError> {
        Err(CrackerError::Other(
            "generic crackers do not support health checks".into(),
        ))
    }

    fn found_hashes_path(&self) -> Option<PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::Paths;
    use tempfile::TempDir;

    const ALIAS: &str = "#HL#";

    fn cracker_with_files(files: &[&str]) -> (TempDir, GenericCracker) {
        let dir = tempfile::tempdir().unwrap();

        for name in files {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }

        let paths = Paths {
            files: dir.path().to_path_buf(),
            hashlists: PathBuf::from("/data/hashlists"),
            ..Default::default()
        };

        let cracker = GenericCracker::new(1, PathBuf::from("/opt/crackers/1/cracker.bin"), paths);

        (dir, cracker)
    }

    fn seeded(dir: &TempDir, name: &str) -> String {
        path_arg(&dir.path().join(name))
    }

    #[test]
    fn crack_attack_swaps_alias_for_the_hashlist_path() {
        let (_dir, cracker) = cracker_with_files(&[]);
        let hashlist = PathBuf::from("/data/hashlists/42");

        let args = cracker.resolve_attack("-a #HL# ?a?a?a", ALIAS, &hashlist);

        assert_eq!(args, ["-a", "/data/hashlists/42", "?a?a?a"]);
    }

    #[test]
    fn crack_attack_resolves_file_tokens_to_absolute_paths() {
        let (dir, cracker) = cracker_with_files(&["rockyou.txt"]);
        let hashlist = PathBuf::from("/data/hashlists/1");

        let args = cracker.resolve_attack("-a #HL# rockyou.txt", ALIAS, &hashlist);

        assert_eq!(
            args,
            [
                "-a".to_owned(),
                "/data/hashlists/1".to_owned(),
                seeded(&dir, "rockyou.txt"),
            ]
        );
    }

    #[test]
    fn crack_attack_resolves_key_value_file_tokens() {
        let (dir, cracker) = cracker_with_files(&["hint.hcstat2"]);
        let hashlist = PathBuf::from("/data/hashlists/1");

        let args = cracker.resolve_attack("-a #HL# hintfile=hint.hcstat2", ALIAS, &hashlist);

        assert_eq!(
            args,
            [
                "-a".to_owned(),
                "/data/hashlists/1".to_owned(),
                format!("hintfile={}", seeded(&dir, "hint.hcstat2")),
            ]
        );
    }

    #[test]
    fn keyspace_attack_resolves_key_value_file_tokens() {
        let (dir, cracker) = cracker_with_files(&["hint.hcstat2"]);

        let args = cracker.resolve_keyspace_attack("-a #HL# hintfile=hint.hcstat2", ALIAS);

        assert_eq!(args, [format!("hintfile={}", seeded(&dir, "hint.hcstat2"))]);
    }

    #[test]
    fn crack_attack_passes_unknown_tokens_through_in_order() {
        let (_dir, cracker) = cracker_with_files(&[]);
        let hashlist = PathBuf::from("/hl/7");

        let args = cracker.resolve_attack("-a #HL# missing.txt ?d?d", ALIAS, &hashlist);

        assert_eq!(args, ["-a", "/hl/7", "missing.txt", "?d?d"]);
    }

    #[test]
    fn keyspace_attack_strips_the_alias_pair() {
        let (_dir, cracker) = cracker_with_files(&[]);

        let args = cracker.resolve_keyspace_attack("-a #HL# ?a?a?a", ALIAS);

        // The whole `-a #HL# ` pair is gone; the rest of the attack remains.
        assert_eq!(args, ["?a?a?a"]);
    }

    #[test]
    fn keyspace_attack_resolves_remaining_file_tokens() {
        let (dir, cracker) = cracker_with_files(&["wl.txt"]);

        let args = cracker.resolve_keyspace_attack("-a #HL# wl.txt", ALIAS);

        assert_eq!(args, [seeded(&dir, "wl.txt")]);
    }

    #[test]
    fn keyspace_attack_strips_the_pair_regardless_of_position_or_spacing() {
        let (_dir, cracker) = cracker_with_files(&[]);

        // The reference's substring replace misses both of these (alias at the
        // end with no trailing space; a double space between flag and alias); the
        // token-wise strip handles them.
        assert_eq!(
            cracker.resolve_keyspace_attack("?a?a?a -a #HL#", ALIAS),
            ["?a?a?a"]
        );
        assert_eq!(
            cracker.resolve_keyspace_attack("-a  #HL#  ?d?d", ALIAS),
            ["?d?d"]
        );
    }
}
