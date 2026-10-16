# Architecture

Crude, first-pass architecture for the Rust rewrite of the Hashtopolis agent.

## Goals

- Type safety end to end: config, wire DTOs, tasks (no stringly-typed `config.get("key")`, no dicts for request/response bodies).
- Two cracker backends (hashcat + generic) behind a common trait, with helpers scoped to each binary.
- Async throughout via tokio.

## Tech stack

| Concern        | Crate                          |
| -------------- | ------------------------------ |
| Async runtime  | tokio                          |
| HTTP client    | reqwest                        |
| Logging        | tracing / tracing-subscriber   |
| CLI            | clap (args + env)              |
| Serialization  | serde                          |
| Archives       | sevenz-rust2, zip              |
| Self-update    | self-replace                   |

## File structure

```
src/
  main.rs          # CLI entry point (clap)
  lib.rs           # crate root, module list

  agent/
    mod.rs         # AgentError, Session, Agent struct, bootstrap, deregister
    run.rs         # the work loop: Step, LoopState, run/tick, shutdown signal
    progress.rs    # ClientSink: adapts Client into the backends' ProgressSink

  archive.rs       # in-process 7z extraction (sevenz-rust2)
  cli.rs           # clap argument parser -> config Overrides
  client.rs        # typed server API: getFileStatus, getTask, getChunk, ...
  config.rs        # typesafe config
  cracker.rs       # Cracker trait + factory (chooses backend)
  download.rs      # Downloader trait + reqwest impl: url -> file on disk
  identity.rs      # agent type, version and client signature
  process.rs       # process helpers, stdio stream handling / reporting
  provisioner.rs   # Provisioner trait + DiskProvisioner: assets onto disk
  sysinfo.rs       # OS + device inventory
  transport.rs     # low-level HTTP: Transport trait, reqwest impl
  update.rs        # self-update machinery

  model/
    mod.rs         # domain types: task assignment, Chunk, response types, ...
    raw.rs         # wire DTOs (serde): requests, responses, actions (crate-internal)
    convert.rs     # raw <-> domain translation, ProtocolError
    tests/         # unit tests for wire (de)serialization and conversion

  backend/
    mod.rs           # backend module list
    args.rs          # fluent argv builder
    hashcat/
      mod.rs         # HashcatCracker, run_chunk orchestration, ChunkSource, Cracker impl
      chunk.rs       # one chunk run: spawn, multiplex stdout/stderr/outfile, report back
      producer.rs    # command assembly per ChunkSource; the producer half of a piped run
      auto_pipe.rs   # slow-hash auto-pipe: policy, static gate and live utilisation probe
      keyspace.rs    # --keyspace measurement
      benchmark.rs   # speed and runtime benchmarks
      healthcheck.rs # health-check run over a known hashlist
      paths.rs       # filesystem layout: binary cwd, hashlist/outfile/zap paths
      argv.rs        # attack string -> argv tokens, parameter splitting
      status.rs      # hashcat status parser + ANSI stripping
      progress.rs    # scale hashcat PROGRESS to basis points; pin the reporting convention
    generic/
      mod.rs         # GenericCracker, Cracker impl
      chunk.rs       # one chunk run: spawn, read status/cracks, report back
      keyspace.rs    # keyspace measurement
      benchmark.rs   # benchmark run
      paths.rs       # filesystem layout: binary cwd, hashlist/zap paths
      status.rs      # generic status parser (STATUS <progress> <speed>)

tests/
  agent/           # integration tests for bootstrap, deregister and the loop
  client/          # integration tests for client against a mock Transport
```

## Module responsibilities

- **agent/** — orchestrator, split so the startup path and the steady-state loop stay separable:
  - **agent/mod.rs** — `AgentError`, the retry macro, `Session`, the `Agent` struct and its startup path (`bootstrap`, token resolution, registration, directory creation), plus `deregister`.
  - **agent/run.rs** — the run loop, in a second `impl Agent` block. Asks `client` for work, dispatches tasks/chunks to a backend via the `Cracker` trait, reports progress, holds the state machine. `tick` performs one iteration and returns a `Step` (continue / sleep / shutdown) instead of sleeping itself, so `run` owns all timing and the shutdown signal and the loop stays testable.
  - **agent/progress.rs** — `ClientSink`, which adapts the `Client` into the `ProgressSink` the backends report through.
- **cli.rs** — clap argument parser; maps flags to config `Overrides`.
- **cracker.rs** — defines the `Cracker` trait and a factory that selects the hashcat or generic backend, forwarding the auto-pipe policy (derived from config, threaded via the provisioner) to the hashcat backend.
- **provisioner.rs** — the `Provisioner` trait plus its on-disk implementation. Everything the `Client` does not cover: crackers, preprocessors, task files, hashlists and founds fetched and placed where the backend expects them. A trait so the loop can run against a fake. The associated `Cracker` type lets that fake hand the loop a fake cracker.
- **download.rs** — the `Downloader` trait and its reqwest implementation: a url streamed to a path. Separate from `transport.rs` because the JSON API is one POST endpoint while assets are GETs against arbitrary urls with no useful request timeout.
- **http.rs** - turns the `server` config section into validated `HttpSettings` (client certificate, proxy, basic auth) at startup. Both the transport and the downloader build their reqwest client from it; only the transport adds a timeout. Basic auth goes on every API call, but on downloads only for the server's own origin.
- **archive.rs**: in-process 7z extraction via `sevenz-rust2`. `extract_into` drops an archive's contents at the destination root (wordlists); `extract_flattened` collapses a single wrapping folder (crackers, preprocessors).
- **identity.rs** — what this build calls itself: agent type, version, and the `clientSignature` sent on login.
- **backend/** — one submodule per supported binary, plus **backend/args.rs**: the fluent `Args` builder both backends use to assemble an argv (accepts borrowed or owned tokens, allocates once on `build`).
  - **hashcat/mod.rs** — `HashcatCracker` and the `Cracker` impl that routes each operation to its module. `run_chunk` is the piping-aware orchestrator: it picks a `ChunkSource` (direct, preprocessor, or self-pipe), runs the chunk, and on a slow-hash starvation signal rebuilds the same chunk as a self-pipe and runs it once more. Piping never leaks past this function.
  - **hashcat/chunk.rs** — a single chunk run: spawn hashcat (and its producer, if any) as process groups, multiplex stdout, stderr and the tailed outfile onto one channel, and report progress and cracks until the process exits, the server orders a stop, or the auto-pipe probe asks to restart (`ChunkResult::Underutilised`).
  - **hashcat/producer.rs** — command assembly. `build_invocation` turns a `ChunkSource` into the full argv from a shared consumer flag block, and builds the producer stage for a piped run: a preprocessor binary, or hashcat itself with `--stdout` for `enforce_pipe` and the slow-hash auto-pipe.
  - **hashcat/auto_pipe.rs** — the slow-hash auto-pipe decision, kept out of the run loop. `AutoPipePolicy` (from `Behavior`) is the on/off plus utilisation threshold; `preconditions_met` is the static gate on the task; `should_repipe` is the live gate on per-status GPU utilisation.
  - **hashcat/keyspace.rs**, **benchmark.rs**, **healthcheck.rs** — the one-shot operations (keyspace measure; speed and runtime benchmarks; health check), each capturing the process output and parsing a result.
  - **hashcat/paths.rs** — the input-side filesystem layout: where the binary runs and where hashlists, outfiles and zap dirs live.
  - **hashcat/argv.rs** — the input-side token building: the server's attack string and extra parameters turned into argv tokens, with file references resolved to absolute paths.
  - **hashcat/status.rs** — the output side: parsing hashcat's machine-readable status lines into `HashcatStatus`, plus `strip_ansi` for cleaning its coloured output.
  - **generic/** — the generic backend (any non-hashcat binary) behind the same `Cracker` trait, split into the same per-operation modules as hashcat: `mod.rs` (the backend and `Cracker` impl), `chunk.rs` (one chunk run over a simpler `STATUS <progress> <speed>` grammar, with no piping, brain, or preprocessor), `keyspace.rs`, `benchmark.rs`, `paths.rs`, and `status.rs`.
- **model/** — core domain types shared across modules (`TaskAssignment`, `Chunk`, response types, etc.) plus the wire layer they are decoded from:
  - **model/raw.rs** — serde-serializable wire DTOs for every server request/response and action: exactly what goes over the wire, before any interpretation.
  - **model/convert.rs** — translation between `raw` and the domain types
- **transport.rs** — low-level HTTP: the `Transport` trait (one `post_json` call) and its reqwest implementation.
- **client.rs** — typed, high-level API over `Transport` (`getFileStatus`, `getTask`, `getChunk`, ...). No raw JSON leaks past this layer. Integration-tested in `tests/client/` against a mock `Transport`. Is allowed to use `model::raw` module 
- **config.rs** — typesafe config, no string-keyed lookups. Two files with distinct owners: `config.json` holds the user's settings and is **only ever read** by the agent (so it is safe to re-read every loop iteration, and hand edits survive); `state.json` is agent-owned and holds the token and uuid, rewritten atomically when either changes. CLI flags live in `Overrides`, applied over the settings on load and re-applied after every reload, and are never persisted back.
- **sysinfo.rs** — OS and device inventory for registration / status reporting.
- **process.rs** — spawning child processes, streaming stdio, reporting.
- **update.rs**: self-update. On a `checkClientVersion` "NEW" reply the agent downloads the server's `rust-agent.zip`, reads `manifest.json`, picks the binary whose `triples` include this build's `agent_target()`, swaps the running executable (`self-replace`) and re-execs. Opt-out via `behavior.disable_update`. Integrity rests on the TLS download: the endpoint carries no hash, so there is no signature check yet.

## Open questions / notes

- **uftpd**: dropped. Multicast download will not be implemented.
