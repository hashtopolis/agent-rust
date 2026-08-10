pub mod commands;
pub mod status;

use std::path::PathBuf;

use crate::cracker::{ChunkOutcome, Cracker, CrackerError, HealthCheckOutcome, ProgressSink};
use crate::model::{Chunk, TaskAssignment};

pub struct HashcatCracker {
    #[allow(dead_code)]
    cracker_id: u64,
    #[allow(dead_code)]
    binary_path: PathBuf,
}

impl HashcatCracker {
    pub fn new(cracker_id: u64, binary_path: PathBuf) -> Self {
        Self {
            cracker_id,
            binary_path,
        }
    }
}

impl Cracker for HashcatCracker {
    async fn measure_keyspace(&self, _task: &TaskAssignment) -> Result<u64, CrackerError> {
        todo!("hashcat keyspace measurement")
    }

    async fn run_benchmark(
        &self,
        _task: &TaskAssignment,
        _measured_keyspace: Option<u64>,
    ) -> Result<Option<String>, CrackerError> {
        todo!("hashcat benchmark")
    }

    async fn run_chunk<S: ProgressSink>(
        &self,
        _task: &TaskAssignment,
        _chunk: Chunk,
        _sink: &S,
    ) -> Result<ChunkOutcome, CrackerError> {
        // spawn hashcat (own process group), then 3 watcher tasks feeding one
        // mpsc channel of:
        //   enum Event { StatusUpdate(HashcatStatus), Debug(String), Stderr(String), Crack(Vec<String>) }
        // stdout -> StatusUpdate/Debug, stderr -> sink.report_error (never kills),
        // outfile tail -> Crack. Run loop select!s over that channel + a keepalive
        // interval (until first status). On StatusUpdate: drain cracks in <=1000 batches via
        // sink.send_progress; Continue -> write zaps, Stop -> kill + stopped, Err -> keep
        // batch and retry. Channel close == process exit.
        todo!("hashcat chunk run")
    }

    async fn run_health_check(
        &self,
        _attack: &str,
        _hashlist_alias: &str,
        _hashes: &[String],
    ) -> Result<HealthCheckOutcome, CrackerError> {
        todo!("hashcat health check")
    }
}
