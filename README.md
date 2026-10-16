# Hashtopolis Agent (Rust)

A Hashtopolis agent written in Rust.

## Prerequisites

- Rust (edition 2024) and a C compiler. `ring`
  (pulled in by rustls) compiles C sources, so you need `cc`/`clang` on the
  build host.
- hashcat itself is provisioned by the server, you do not install it yourself.
  The exception is macOS, where the official hashcat archive ships no
  `hashcat.osx`, so you point the agent at a local hashcat (see Configure).

## Build

```sh
cargo build --release
```

The binary lands at `target/release/htp-agent`.


## Release

A full release bundle is `dist/rust-agent.zip`: the three platform binaries
(linux-musl, windows-msvc, macos-aarch64) plus a `manifest.json` and the
`run.sh` / `run.bat` launchers. This is the artifact the backend serves as the
`rust` agent type.

**Via CI (the normal path).** Push a `v*` tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

`release.yml` builds each target natively on its own runner, packages them, and
attaches `rust-agent.zip` to the GitHub release. You can also trigger the
workflow manually, which builds the zip without attaching it anywhere.

## Run

```sh
./htp-agent
```

The agent reads two JSON files side by side:

- `config.json`. The agent only reads it, never writes it. Missing file
  means all defaults.
- `state.json`. It holds the token and uuid and is
  rewritten when they change. Do not edit it.

Both default to the working directory, override with `--config` / `--state` (or
`HTP_CONFIG` / `HTP_STATE`).

### Register

On the first run with no token, the agent registers using a voucher and stores
the token it gets back in `state.json`. After that the voucher is not needed
again.

```sh
./htp-agent --url https://server.example/api/server.php --voucher 89GD78tf
```

The agent registers under the machine hostname unless you set `agent.name` in
the config. URL and voucher can equally come from the config file or from
`HTP_URL` / `HTP_VOUCHER`.

To unregister the agent from the server and delete the local `state.json`:

```sh
./htp-agent --de-register
```

### Configure

A minimal `config.json`:

```json
{
  "server": {
    "url": "https://server.example/api/server.php",
    "voucher": "89GD78tf"
  }
}
```

A fuller one:

```jsonc
{
  "server": {
    "url": "https://server.example/api/server.php",
    "voucher": "89GD78tf",
    "client_cert": "/etc/htp/client.pem",   // certificate + key for mutual TLS
    "proxy": "http://proxy:3128",
    "basic_auth": { "user": "agent", "password": "secret" }
  },
  "agent": {
    "name": "cruncher"
  },
  "paths": {
    "files": "files",
    "crackers": "crackers",
    "hashlists": "hashlists",
    "preprocessors": "preprocessors",
    "zaps": "zaps"
  },
  "behavior": {
    "cpu_only": false,
    "disable_update": false,
    "allow_piping": false,
    "piping_threshold": 95,
    "file_deletion_interval": 600
  },
  "cracker": {
    "hashcat_path": "/opt/homebrew/bin/hashcat"
  }
}
```

`paths` sets where the agent keeps everything it downloads, one directory per
kind:

- `files` - wordlists, rules and other task files
- `crackers` - the cracker binaries (hashcat) fetched from the server
- `hashlists` - the hashlists to crack, plus their output files
- `preprocessors` - preprocessor binaries (PRINCE and the like)
- `zaps` - zap files, the already-cracked hashes the agent skips

The python agent fixed these next to the binary. Here each one is relocatable
on its own, so you can keep large wordlists on a separate volume, or point
several agents on one host at a shared crackers directory. They default to
these names under the working directory, and each has a CLI override
(`--files-path`, `--crackers-path`, and so on).

`cracker.hashcat_path` is the macOS-only hashcat fallback and is ignored
elsewhere. Official hashcat releases ship no macOS build, so the cracker archive
the server hands out has no `hashcat.osx`. On macOS the agent falls back to this
local hashcat instead. It can be the binary itself, or a directory (such as a
hashcat checkout) containing a hashcat binary. Unknown keys are rejected, so a
typo fails loudly at startup.

Common settings also have CLI flags, which win over the config file:

- `--cpu-only`
- `--disable-update`
- `--client-cert` (`--cert` also works, as in the python agent)
- `--proxy` (or `HTP_PROXY`)
- `--auth-user` (or `HTP_AUTH_USER`); the password comes only from the
  `HTP_AUTH_PASSWORD` environment variable, so it never shows in the process
  list
- `--hashcat-path`
- per-directory overrides like `--files-path`

`--debug` (`-d`) turns on debug logging. `--trace` goes one step further and
also logs full API request and response bodies, including the agent token, so
keep it to local debugging. Dependencies such as the HTTP stack always log less
than the agent itself, so they don't drown it out. Setting `RUST_LOG` overrides all of this
with a standard tracing filter, and an empty `RUST_LOG` logs everything.

### Server connection

- **Server certificates** are checked against the operating system's trust
  store plus a bundled set of public roots. A server signed by an internal CA
  works once that CA is installed on the host (`update-ca-certificates` on
  Debian/Ubuntu, the Keychain on macOS, the Windows certificate store). On
  any platform you can instead point `SSL_CERT_FILE` (or `SSL_CERT_DIR`) at a
  PEM bundle with the CA; the system store is then skipped, but the bundled
  public roots stay trusted. Trusting the OS store also means trusting any
  CA an administrator installed there, including TLS-inspecting corporate
  proxies.
- **`server.client_cert`** is a client certificate for servers that require mutual
  TLS: one PEM file holding the certificate and its unencrypted private key.
  It must be an X.509 v3 certificate (older LibreSSL `openssl req -x509`
  produces v1 certificates, which are rejected). This is not a CA bundle.
- **`server.proxy`** is one proxy URL for all traffic, credentials included if
  needed (`http://user:pass@proxy:3128`). Keep credentials in the config file
  or `HTP_PROXY` rather than `--proxy`, which shows in the process list.
  `NO_PROXY` is honoured. Without it, the usual `HTTP_PROXY`/`HTTPS_PROXY`/
  `ALL_PROXY` variables apply. The python agent's per-scheme `proxies` map
  becomes this single URL.
- **`server.basic_auth`** (`{ "user": ..., "password": ... }`) turns on HTTP
  basic auth. Both are needed; the password may instead come from
  `HTP_AUTH_PASSWORD`, so it can stay out of the file. The credentials go
  with every API call and with downloads from the server itself, never to
  other hosts such as cracker download URLs (the python agent sent them
  everywhere). Over a plain `http://` server URL they travel unencrypted, and
  the agent warns at startup.

## hashcat compatibility

Only hashcat 6.0 and newer is supported. The agent runs hashcat with
`--machine-readable` and reads back its tab-separated `STATUS` lines for
progress, speed, temperature and GPU utilisation, and it collects cracks with
`--outfile-format=1,2,3,4`. The comma-separated outfile format follows the hashcat 6.0 outfile changes,
so any earlier version may fail to report progress or even crash.

## Notes

- The agent self-updates from the server by default. `--disable-update` (or
  `behavior.disable_update`) turns that off.
