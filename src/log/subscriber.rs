//! Which events are logged where: the console, and the log file when one is
//! configured.

use std::io;

use tracing::Subscriber;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::{LogFileConfig, LogLevel};

use super::file::RotatingFile;
use super::writer::{self, BackgroundWriter, LogGuard};

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
    let console = console_filter(verbosity, rust_log.as_deref());

    let file_filter =
        file.map(|file| file_filter(verbosity, rust_log.as_deref(), file.level.as_ref()));
    let file_traces = file_filter.as_ref().is_some_and(records_trace);

    let opened = file.map(open_file).transpose();

    let (writer, guard, error) = match opened {
        Ok(Some((writer, guard))) => (Some(writer), guard, None),
        Ok(None) => (None, LogGuard::console_only(), None),
        Err(error) => (None, LogGuard::console_only(), Some(error)),
    };

    subscriber(io::stdout, console, writer.zip(file_filter)).init();

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

/// The console layer and, when there is a file, the file layer. The file layer
/// goes first: both share a span's rendered fields, and whichever renders them
/// first decides whether they carry colour codes.
fn subscriber<W>(
    console: W,
    console_filter: EnvFilter,
    file: Option<(BackgroundWriter, EnvFilter)>,
) -> impl Subscriber + Send + Sync
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let file_layer = file.map(|(writer, filter)| file_layer(writer).with_filter(filter));

    tracing_subscriber::registry().with(file_layer).with(
        tracing_subscriber::fmt::layer()
            .with_writer(console)
            .with_filter(console_filter),
    )
}

/// Whether `filter` lets trace output through, which carries full request and
/// response bodies with the agent token.
fn records_trace(filter: &EnvFilter) -> bool {
    filter.max_level_hint() == Some(LevelFilter::TRACE)
}

fn open_file(config: &LogFileConfig) -> io::Result<(BackgroundWriter, LogGuard)> {
    RotatingFile::open(
        &config.file,
        config.max_size.bytes(),
        config.max_files.get(),
    )
    .and_then(writer::spawn)
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use tempfile::TempDir;

    #[test]
    fn the_log_file_gets_each_event_without_colour_codes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent.log");
        let (writer, guard) =
            writer::spawn(RotatingFile::open(&path, 1 << 20, 5).unwrap()).unwrap();
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
        let (writer, guard) =
            writer::spawn(RotatingFile::open(&path, 1 << 20, 5).unwrap()).unwrap();
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
    fn debug_and_normal_files_get_the_agent_at_that_level() {
        let debug = logged_to_file(Verbosity::Trace, None, Some("debug"));
        let normal = logged_to_file(Verbosity::Trace, None, Some("normal"));

        assert!(debug.contains("agent debug"), "{debug}");
        assert!(!debug.contains("agent trace"), "{debug}");
        assert!(!normal.contains("agent debug"), "{normal}");
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
    fn span_fields_reach_the_file_without_colour_codes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("agent.log");
        let (writer, guard) =
            writer::spawn(RotatingFile::open(&path, 1 << 20, 5).unwrap()).unwrap();
        let subscriber = subscriber(
            io::sink,
            EnvFilter::new("trace"),
            Some((writer, EnvFilter::new("trace"))),
        );

        tracing::subscriber::with_default(subscriber, || {
            let _span = tracing::info_span!("connection", peer = "client").entered();
            tracing::info!("handshake");
        });
        guard.flush();

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("handshake"), "{text:?}");
        assert!(!text.contains('\x1b'), "{text:?}");
    }

    #[test]
    fn only_a_filter_that_lets_trace_through_records_trace() {
        assert!(records_trace(&EnvFilter::new("info,htp_agent=trace")));
        assert!(!records_trace(&EnvFilter::new("info,htp_agent=debug")));
    }
}
