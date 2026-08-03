pub mod status;

use std::path::PathBuf;

use crate::cracker::{ChunkOutcome, Cracker, CrackerError, HealthCheckOutcome, ProgressSink};
use crate::model::{Chunk, TaskAssignment};

pub struct GenericCracker {
    #[allow(dead_code)]
    cracker_id: u64,
    #[allow(dead_code)]
    binary_path: PathBuf,
}

impl GenericCracker {
    pub fn new(cracker_id: u64, binary_path: PathBuf) -> Self {
        Self {
            cracker_id,
            binary_path,
        }
    }
}

impl Cracker for GenericCracker {
    async fn measure_keyspace(&self, _task: &TaskAssignment) -> Result<u64, CrackerError> {
        todo!("generic keyspace measurement")
    }

    async fn run_benchmark(
        &self,
        _task: &TaskAssignment,
        _measured_keyspace: Option<u64>,
    ) -> Result<Option<String>, CrackerError> {
        todo!("generic benchmark")
    }

    async fn run_chunk<S: ProgressSink>(
        &self,
        _task: &TaskAssignment,
        _chunk: Chunk,
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
}
