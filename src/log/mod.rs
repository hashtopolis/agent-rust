//! Logging for the agent: subscriber setup, the rotated log file and the thread
//! that writes it, plus the self-rendering field types that give the log its
//! shape.

mod fields;
mod file;
mod subscriber;
mod writer;

pub use subscriber::{Verbosity, init};
pub use writer::LogGuard;

pub(crate) use fields::{HashRate, Invocation, Keyspace, Percent};

use std::fmt;
use std::io::{self, Write};

/// Writes to stderr directly. `tracing` would queue the message for the file
/// that has the problem, and `eprintln!` panics when stderr fails, which would
/// kill the writer thread.
fn warn_on_stderr(message: fmt::Arguments) {
    let _ = writeln!(io::stderr(), "warning: {message}");
}
