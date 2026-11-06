//! Active hours: a schedule file that says when the agent may ask the server
//! for work. Times are on the machine's local wall clock, as a point in the
//! week.

mod active_hours;
mod file;
mod rules;
mod week;

pub use active_hours::{ActiveHours, Activity};
pub use file::{Reload, ScheduleFile, ScheduleFileError};
pub use rules::{Schedule, ScheduleError};
pub use week::WeekSecond;

const DAY: u32 = 86_400;
const WEEK: u32 = 7 * DAY;
