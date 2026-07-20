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

## Proposed file structure

```
src/
  main.rs          # CLI entry point (clap)
  lib.rs           # crate root, wiring

  agent.rs         # main loop + task/chunk dispatch / state machine
  cracker.rs       # Cracker trait + factory (chooses backend)
  model.rs         # domain types: Task enum, Chunk, etc.
  protocol.rs      # wire DTOs (serde): requests, responses, actions
  transport.rs     # http client + auth + retry (+ uftpd?)
  client.rs        # typed server API: getFileStatus, getTask, getChunk, ...
  config.rs        # typesafe config
  sysinfo.rs       # OS + device inventory
  process.rs       # process helpers, stdio stream handling / reporting
  update.rs        # self-update machinery
  assets.rs        # helper binaries (uftpd?)

  backend/
    mod.rs
    hashcat/
      mod.rs
      status.rs    # hashcat status parser
      commands.rs  # keyspace, etc.
    generic/
      mod.rs
      status.rs    # generic status parser
```

## Module responsibilities

- **agent.rs** — orchestrator. Owns the run loop, asks `client` for work, dispatches tasks/chunks to a backend via the `Cracker` trait, reports progress. Holds the state machine.
- **cracker.rs** — defines the `Cracker` trait and a factory that selects the hashcat or generic backend.
- **backend/** — one submodule per supported binary. Each owns its own status parser and binary-specific helpers (keyspace calc, command building).
- **model.rs** — core domain types shared across modules (`Task` as a tagged union / enum, `Chunk`, etc.).
- **protocol.rs** — serde-serializable wire DTOs for every server request/response and action. Kept separate from `model.rs` so the domain model isn't coupled to the wire format.
- **transport.rs** — low-level HTTP: reqwest client, auth, retry. Possibly uftp for multicast download.
- **client.rs** — typed, high-level API over `transport` (`getFileStatus`, `getTask`, `getChunk`, ...). No raw JSON leaks past this layer.
- **config.rs** — typesafe config, no string-keyed lookups.
- **sysinfo.rs** — OS and device inventory for registration / status reporting.
- **process.rs** — spawning child processes, streaming stdio, reporting.
- **update.rs** — self-update. Lower priority; disabled in Docker. No ephemeral state (only files on disk). Reports platform target so the server delivers the correct binary; SHA check before applying (supply-chain).
- **assets.rs** — management of bundled helper binaries (e.g. uftp).

## Open questions / notes

- **uftpd**: probably stays for multicast download — no in-process replacement found yet. Could be dropped.
- **7z**: replace with in-process Rust code (existing code by pwrbob).
- **Self-update packaging**: `rust` agent type → version → zip with binaries for 2-3 target platforms (x64 primary; Linux / Windows / macOS).
