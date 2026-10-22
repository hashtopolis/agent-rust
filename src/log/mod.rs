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

/// Report a problem with the log file on stderr. A failing stderr is ignored:
/// `eprintln!` would panic and take the writer thread down with it.
fn warn(message: fmt::Arguments) {
    let _ = writeln!(io::stderr(), "warning: {message}");
}
