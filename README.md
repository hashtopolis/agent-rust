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
    "zaps": "zaps",
    "cache": "/var/cache/hashcat"
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
  },
  "log": {
    "file": "htp-agent.log",
    "max_size": "10MB",
    "max_files": 5,
    "level": "debug"
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
- `cache` - optional, where hashcat keeps its caches (see below)

The python agent fixed these next to the binary. Here each one is relocatable
on its own, so you can keep large wordlists on a separate volume, or point
several agents on one host at a shared crackers directory. They default to
these names under the working directory, and each has a CLI override
(`--files-path`, `--crackers-path`, and so on).

`paths.cache` (or `--cache-path`) is handed to hashcat as `--cache-path`. hashcat
keeps a seek database per wordlist there, which is what makes the `--skip` of
every chunk cheap, plus its compiled kernels. By default those live in the
cracker directory, so they go cold after every cracker update. Seek databases
are named after a hash of their wordlist, so agents sharing one location build
each only once. It has no default; unset, hashcat keeps its own location.

- Only hashcat builds that know the option get it: `7.1.2-627-g6570a49f2` and
  later, and any release after 7.1.2. Older ones, including 7.1.2 itself, are
  left alone, since hashcat stops on an option it does not know.
- Use a local, writable directory. hashcat tolerates a read-only location for
  the wordlist caches, but a failed kernel cache write aborts the run. To share
  between agents, point `cache` at a local directory and mount or symlink only
  its `cache/feeds/wordlist` to the share.
- The agent creates the directory at startup. If that fails, or the directory
  is missing when hashcat runs (a share that is down, say), the option is left
  off and hashcat uses its own location. If it points at a mountpoint that is
  down, startup creates an empty local directory there, so check the log.
- It is never removed by the agent, since other agents may share it.

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
- per-directory overrides like `--files-path` and `--cache-path`
- `--log-file`, `--log-max-size`, `--log-max-files` and `--log-file-level`

`--debug` (`-d`) turns on debug logging. `--trace` goes one step further and
also logs full API request and response bodies, including the agent token, so
keep it to local debugging. Dependencies such as the HTTP stack always log less
than the agent itself, so they don't drown it out. Setting `RUST_LOG` overrides all of this
with a standard tracing filter, and an empty `RUST_LOG` logs everything.

### Log file

The agent always logs to the console. Where no service manager collects that
output, Windows in particular, `log.file` (or `--log-file`) also writes it to a
file, without colour codes. A relative path is resolved against the working
directory, and a missing directory is created.

Before a line would take the file past `log.max_size` (default `10MB`; `KB`,
`MB` and `GB` count in 1024s, a bare number is bytes), the agent moves it to
`htp-agent.log.1.gz`, compressed, and starts a new one. Older files shift up to
`.2.gz` and so on, and only the newest `log.max_files` (default 5) are kept;
older ones, say after lowering the limit, are deleted at startup. A line is
never split between two files, and a restart keeps appending to the current
file.

If a rotation fails, say because another program holds one of the files open
on Windows, the agent warns on stderr, keeps writing to the current file and
tries again 10 seconds later. A log file that cannot be opened at startup stops
the agent with an error. If the config file itself cannot be loaded, the error
still goes to the file given with `--log-file`. The size, count and level flags
need a log file, from either the config file or `--log-file`.

The file gets the same output as the console unless `log.level` (or
`--log-file-level`) says otherwise, so the console can stay quiet while the file
records more. `normal`, `debug` and `trace` mean what the console flags mean;
anything else is a `RUST_LOG`-style filter, such as
`htp_agent=trace,hyper=debug`. `RUST_LOG` then affects only the console. Trace
output includes full request and response bodies with the agent token, so the
agent warns at startup when the file records it.

### Active hours

On machines that are used for other work during the day, such as office
workstations, a `schedule.json` next to the config file says when the
agent may ask the server for work. Without that file, the agent works at any
time.

The file names either the hours the agent may work (`active`) or the hours it
must leave the machine alone (`inactive`), never both. Office hours are a
single line:

```json
{ "inactive": ["Mon-Fri 07:00-18:00"] }
```

Nights only, every day:

```json
{ "active": ["22:00-06:00"] }
```

Each entry is `[DAYS ]FROM-TO`:

- `DAYS` is a comma-separated list of days or day ranges, such as `Mon`,
  `Mon-Fri`, `Mon,Wed,Fri` or `Fri-Mon` (a range may wrap past Sunday). Days
  are the three-letter English abbreviations `Mon` to `Sun`. Without days, the
  entry applies to every day.
- `FROM` and `TO` are 24-hour times (`7:00` or `07:00`). `TO` may be `24:00`.
  A window that ends before it starts runs past midnight and belongs to the day
  it starts on: `Fri 18:00-07:00` runs from Friday evening to Saturday morning,
  and `18:00-00:00` means until midnight. `FROM` and `TO` must differ.
- A window starts at `FROM` and is over at `TO`. Windows may overlap.
- Times are the machine's local time. Case and spaces don't matter.
- Any key other than `active` or `inactive` is an error.

`{"active": []}` never works and `{"inactive": []}` always does.

The schedule only stops the agent from asking for new work: a chunk that is
running when the window closes finishes normally. While paused, the agent also
skips update checks, so it never updates or restarts during blocked hours, but
it still deletes files the server no longer needs. It makes no other calls, so
the server shows it as offline. Paused agents keep their task assignment, so
they still hold small tasks and count towards a task's maximum number of
agents.

The file can be created, edited or deleted while the agent runs. A paused agent
notices a change within a second and resumes as soon as the new schedule
allows; a working agent picks it up before it next asks for work, so a running
chunk still finishes first. Deleting the file lifts the schedule. An edit that
can't be read or parsed keeps the previous schedule and logs a warning. An
invalid file at startup stops the agent with an error.

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
- **`server.client_cert`** (formerly `cert`, which still works) is a client
  certificate for servers that require mutual TLS: one PEM file holding the
  certificate and its unencrypted private key.
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
