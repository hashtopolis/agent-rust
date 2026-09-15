pub mod status;

use std::path::PathBuf;

use crate::cracker::{ChunkOutcome, Cracker, CrackerError, HealthCheckOutcome, ProgressSink};
use crate::model::{Chunk, CrackerId, ResolvedPreprocessor, TaskAssignment};

pub struct GenericCracker {
    #[allow(dead_code)]
    cracker_id: CrackerId,
    #[allow(dead_code)]
    binary_path: PathBuf,
    #[allow(dead_code)]
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
}

impl Cracker for GenericCracker {
    async fn measure_keyspace(
        &self,
        _task: &TaskAssignment,
        _preprocessor: Option<&ResolvedPreprocessor>,
    ) -> Result<Option<u64>, CrackerError> {
        todo!("generic keyspace measurement")
    }

    async fn run_benchmark(
        &self,
        _task: &TaskAssignment,
        _preprocessor: Option<&ResolvedPreprocessor>,
    ) -> Result<Option<String>, CrackerError> {
        todo!("generic benchmark")
    }

    async fn run_chunk<S: ProgressSink>(
        &self,
        _task: &TaskAssignment,
        _chunk: Chunk,
        _preprocessor: Option<&ResolvedPreprocessor>,
        _sink: &S,
    ) -> Result<ChunkOutcome, CrackerError> {
        todo!("generic chunk run")
    }

    async fn run_health_check(
        &self,
        _attack: &str,
        _hashlist_alias: &str,
        _hashes: &[String],
    ) -> Result<HealthCheckOutcome, CrackerError> {
        todo!("generic health check")
    }

    fn found_hashes_path(&self) -> Option<PathBuf> {
        None
    }
}
