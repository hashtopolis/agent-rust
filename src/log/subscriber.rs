//! Which events are logged, and at what verbosity.

use tracing_subscriber::EnvFilter;

/// How verbose the agent's own logging should be when `RUST_LOG` is unset.
#[derive(Debug, Clone, Copy)]
pub enum Verbosity {
    Normal,
    Debug,
    Trace,
}

/// Install the tracing subscriber.
///
/// With no `RUST_LOG` the filter keeps the agent's own output in the foreground
/// and dependency chatter (hyper, reqwest, rustls, h2, ...) in the background,
/// even in debug or trace mode. An explicit `RUST_LOG` takes full control, and
/// an empty `RUST_LOG` is the "log absolutely everything" escape hatch.
pub fn init(verbosity: Verbosity) {
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) if !value.trim().is_empty() => EnvFilter::new(value),
        Ok(_) => EnvFilter::new("trace"),
        Err(_) => EnvFilter::new(default_filter(verbosity)),
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();
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
