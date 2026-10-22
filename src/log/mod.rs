//! Logging for the agent: subscriber setup plus the self-rendering field types
//! that give the log its shape.

mod fields;
mod subscriber;

pub use subscriber::{Verbosity, init};

pub(crate) use fields::{HashRate, Invocation, Keyspace, Percent};
