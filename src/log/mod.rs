//! Logging for the agent: subscriber setup plus the self-rendering field types
//! that give the log its shape.

mod file;

pub use file::LogGuard;

use std::fmt;
use std::io;
use std::path::Path;

use tracing::Subscriber;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::{LogFileConfig, LogLevel};

use file::{BackgroundWriter, RotatingFile};

/// How verbose the agent's own logging should be when `RUST_LOG` is unset.
#[derive(Debug, Clone, Copy)]
pub enum Verbosity {
    Normal,
    Debug,
    Trace,
}

/// Install the tracing subscriber: the console always, plus `file` when one is
/// configured. Keep the returned guard alive until the end: dropping it waits
/// for the last lines to reach the file.
///
/// With no `RUST_LOG` the filter keeps the agent's own output in the foreground
/// and dependency chatter (hyper, reqwest, rustls, h2, ...) in the background,
/// even in debug or trace mode. An explicit `RUST_LOG` takes full control, and
/// an empty `RUST_LOG` is the "log absolutely everything" escape hatch. The file
/// gets the same unless its config sets a `level` of its own.
///
/// If the log file cannot be opened, console logging is still installed so the
/// caller can report the error.
pub fn init(verbosity: Verbosity, file: Option<&LogFileConfig>) -> io::Result<LogGuard> {
    let rust_log = std::env::var("RUST_LOG").ok();
    let console_filter = console_filter(verbosity, rust_log.as_deref());

    let file_filter =
        file.map(|file| file_filter(verbosity, rust_log.as_deref(), file.level.as_ref()));
    let file_traces = file_filter
        .as_ref()
        .is_some_and(|filter| filter.max_level_hint() == Some(LevelFilter::TRACE));

    let opened = file.map(open_file).transpose();

    let (writer, guard, error) = match opened {
        Ok(Some((writer, guard))) => (Some(writer), guard, None),
        Ok(None) => (None, LogGuard::console_only(), None),
        Err(error) => (None, LogGuard::console_only(), Some(error)),
    };

    let file_layer = writer
        .zip(file_filter)
        .map(|(writer, filter)| file_layer(writer).with_filter(filter));

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(console_filter))
        .with(file_layer)
        .init();

    if file_traces && error.is_none() {
        tracing::warn!(
            "the log file records trace output, including full request and response bodies with the agent token"
        );
    }

    match error {
        Some(error) => Err(error),
        None => Ok(guard),
    }
}

fn open_file(config: &LogFileConfig) -> io::Result<(BackgroundWriter, LogGuard)> {
    RotatingFile::open(
        &config.file,
        config.max_size.bytes(),
        config.max_files.get(),
    )
    .and_then(file::spawn)
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("opening log file {}: {error}", config.file.display()),
        )
    })
}

fn file_layer<S>(writer: BackgroundWriter) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(move || writer.clone())
}

fn console_filter(verbosity: Verbosity, rust_log: Option<&str>) -> EnvFilter {
    match rust_log {
        Some(value) if !value.trim().is_empty() => EnvFilter::new(value),
        Some(_) => EnvFilter::new("trace"),
        None => EnvFilter::new(default_filter(verbosity)),
    }
}

/// The file's own `level` if it has one, the console's filter otherwise.
fn file_filter(
    verbosity: Verbosity,
    rust_log: Option<&str>,
    level: Option<&LogLevel>,
) -> EnvFilter {
    match level {
        None => console_filter(verbosity, rust_log),
        Some(LogLevel::Normal) => EnvFilter::new(default_filter(Verbosity::Normal)),
        Some(LogLevel::Debug) => EnvFilter::new(default_filter(Verbosity::Debug)),
        Some(LogLevel::Trace) => EnvFilter::new(default_filter(Verbosity::Trace)),
        Some(LogLevel::Filter(filter)) => EnvFilter::new(filter),
    }
}

/// The default log filter when `RUST_LOG` is unset: the agent's own crate at the
/// requested verbosity, everything else a notch quieter so the HTTP stack does
/// not drown out what the agent is actually doing.
fn default_filter(verbosity: Verbosity) -> &'static str {
    match verbosity {
        Verbosity::Trace => "info,htp_agent=trace",
        Verbosity::Debug => "info,htp_agent=debug",
        Verbosity::Normal => "warn,htp_agent=info",
    }
}

/// A process invocation, rendered as a single copy-pasteable POSIX command line:
/// the binary followed by its arguments, each quoted so the line can be copied
/// straight from the log and re-run.
pub(crate) struct Invocation<'a, A: AsRef<str>> {
    pub program: &'a Path,
    pub args: &'a [A],
}

impl<A: AsRef<str>> fmt::Display for Invocation<'_, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", ShellToken(&self.program.to_string_lossy()))?;

        for arg in self.args {
            write!(f, " {}", ShellToken(arg.as_ref()))?;
        }

        Ok(())
    }
}

/// One token of a command line: written bare when it holds only shell-safe
/// characters, single-quoted otherwise (with any embedded single quote escaped
/// as `'\''`).
struct ShellToken<'a>(&'a str);

impl fmt::Display for ShellToken<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = self.0;

        let safe = !token.is_empty()
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@%+=:,./-_".contains(&b));

        if safe {
            return f.write_str(token);
        }

        f.write_str("'")?;

        for part in token.split('\'') {
            if part.as_ptr() != token.as_ptr() {
                f.write_str("'\\''")?;
            }

            f.write_str(part)?;
        }

        f.write_str("'")
    }
}

/// A hashes-per-second rate, rendered with a decimal SI unit so a log reads
/// `12.34 MH/s` instead of `12340000`. Rates below 1000 keep the bare `H/s`.
pub(crate) struct HashRate(pub u64);

impl fmt::Display for HashRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: [&str; 7] = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];

        let mut value = self.0 as f64;
        let mut unit = 0;

        while value >= 1000.0 && unit < UNITS.len() - 1 {
            value /= 1000.0;
            unit += 1;
        }

        if unit == 0 {
            write!(f, "{value:.0} {}", UNITS[unit])
        } else {
            write!(f, "{value:.2} {}", UNITS[unit])
        }
    }
}

/// A progress value given in basis points (`0..=10000`), rendered as a
/// percentage with two decimals (`4545` -> `45.45%`).
pub(crate) struct Percent(pub u64);

impl fmt::Display for Percent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}%", self.0 as f64 / 100.0)
    }
}

/// A measured keyspace, rendered as its value, or `unbounded` when the attack
/// has no finite keyspace (`None`, which the server stores as -1).
pub(crate) struct Keyspace(pub Option<u64>);

impl fmt::Display for Keyspace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(keyspace) => write!(f, "{keyspace}"),
            None => f.write_str("unbounded"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use tempfile::TempDir;

    #[test]
    fn the_log_file_gets_each_event_without_colour_codes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent.log");
        let (writer, guard) = file::spawn(RotatingFile::open(&path, 1 << 20, 5).unwrap()).unwrap();
        let subscriber = tracing_subscriber::registry().with(file_layer(writer));

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(task_id = 7, "chunk failed");
        });
        guard.flush();

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("WARN"), "{text:?}");
        assert!(text.contains("chunk failed task_id=7"), "{text:?}");
        assert!(!text.contains('\x1b'), "{text:?}");
    }

    /// What reaches the file of an agent whose console runs at `verbosity`
    /// under `rust_log`, with the file at `level`.
    fn logged_to_file(verbosity: Verbosity, rust_log: Option<&str>, level: Option<&str>) -> String {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent.log");
        let (writer, guard) = file::spawn(RotatingFile::open(&path, 1 << 20, 5).unwrap()).unwrap();
        let level = level.map(|level| level.parse().unwrap());
        let filter = file_filter(verbosity, rust_log, level.as_ref());
        let subscriber =
            tracing_subscriber::registry().with(file_layer(writer).with_filter(filter));

        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("agent debug");
            tracing::trace!("agent trace");
            tracing::info!(target: "hyper", "dependency info");
            tracing::trace!(target: "hyper", "dependency trace");
        });
        guard.flush();

        fs::read_to_string(&path).unwrap()
    }

    #[test]
    fn without_a_level_of_its_own_the_file_gets_what_the_console_gets() {
        let normal = logged_to_file(Verbosity::Normal, None, None);
        let debug = logged_to_file(Verbosity::Debug, None, None);
        let rust_log = logged_to_file(Verbosity::Normal, Some("hyper=trace"), None);

        assert!(!normal.contains("agent debug"), "{normal}");
        assert!(debug.contains("agent debug"), "{debug}");
        assert!(!debug.contains("agent trace"), "{debug}");
        assert!(rust_log.contains("dependency trace"), "{rust_log}");
    }

    #[test]
    fn a_trace_file_gets_the_agents_trace_but_keeps_dependencies_quieter() {
        let text = logged_to_file(Verbosity::Normal, Some("hyper=trace"), Some("trace"));

        assert!(text.contains("agent trace"), "{text}");
        assert!(text.contains("dependency info"), "{text}");
        assert!(!text.contains("dependency trace"), "{text}");
    }

    #[test]
    fn a_filter_level_is_used_as_given() {
        let text = logged_to_file(Verbosity::Trace, None, Some("hyper=trace"));

        assert!(text.contains("dependency trace"), "{text}");
        assert!(!text.contains("agent debug"), "{text}");
    }

    #[test]
    fn hash_rate_scales_to_a_sensible_unit() {
        assert_eq!(HashRate(0).to_string(), "0 H/s");
        assert_eq!(HashRate(500).to_string(), "500 H/s");
        assert_eq!(HashRate(570_000).to_string(), "570.00 kH/s");
        assert_eq!(HashRate(12_340_000).to_string(), "12.34 MH/s");
        assert_eq!(HashRate(2_500_000_000).to_string(), "2.50 GH/s");
        assert_eq!(HashRate(4_000_000_000_000).to_string(), "4.00 TH/s");
    }

    #[test]
    fn percent_is_rendered_from_basis_points() {
        assert_eq!(Percent(0).to_string(), "0.00%");
        assert_eq!(Percent(4545).to_string(), "45.45%");
        assert_eq!(Percent(10000).to_string(), "100.00%");
    }

    #[test]
    fn keyspace_renders_value_or_unbounded() {
        assert_eq!(Keyspace(Some(10000)).to_string(), "10000");
        assert_eq!(Keyspace(None).to_string(), "unbounded");
    }

    #[test]
    fn invocation_quotes_only_the_tokens_that_need_it() {
        let invocation = Invocation {
            program: Path::new("/opt/hashcat/hashcat.bin"),
            args: &[
                "-m",
                "1000",
                "--session=foo",
                "/data/my hashlist.txt",
                "?a?a",
            ],
        };

        assert_eq!(
            invocation.to_string(),
            "/opt/hashcat/hashcat.bin -m 1000 --session=foo '/data/my hashlist.txt' '?a?a'"
        );
    }

    #[test]
    fn invocation_escapes_embedded_single_quotes() {
        let invocation = Invocation {
            program: Path::new("/bin/echo"),
            args: &["it's"],
        };

        assert_eq!(invocation.to_string(), "/bin/echo 'it'\\''s'");
    }

    #[test]
    fn invocation_without_args_is_just_the_program() {
        let invocation = Invocation {
            program: Path::new("/bin/hashcat"),
            args: &[] as &[&str],
        };

        assert_eq!(invocation.to_string(), "/bin/hashcat");
    }
}
