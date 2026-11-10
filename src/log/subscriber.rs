//! Which events are logged where: the console, and the log file when one is
//! configured.

use std::io;

use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::LogFileConfig;

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
/// gets the same.
///
/// If the log file cannot be opened, console logging is still installed so the
/// caller can report the error.
pub fn init(verbosity: Verbosity, file: Option<&LogFileConfig>) -> io::Result<LogGuard> {
    let rust_log = std::env::var("RUST_LOG").ok();
    let console = console_filter(verbosity, rust_log.as_deref());

    // The file gets what the console gets, through a filter of its own.
    let file_filter = file.map(|_| console_filter(verbosity, rust_log.as_deref()));

    let opened = file.map(open_file).transpose();

    let (writer, guard, error) = match opened {
        Ok(Some((writer, guard))) => (Some(writer), guard, None),
        Ok(None) => (None, LogGuard::console_only(), None),
        Err(error) => (None, LogGuard::console_only(), Some(error)),
    };

    subscriber(io::stdout, console, writer.zip(file_filter)).init();

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
}
