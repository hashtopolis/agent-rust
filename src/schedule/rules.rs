//! The schedule file's format and what it means.
//!
//! The file is a JSON object with exactly one of two keys, each holding a list
//! of windows:
//!
//! ```json
//! { "inactive": ["Mon-Fri 07:00-18:00"] }
//! { "active": ["Mon-Fri 18:00-07:00", "Sat-Sun 00:00-24:00"] }
//! ```
//!
//! - `active`: the agent works only inside the windows. `{"active": []}`
//!   means never.
//! - `inactive`: the agent works everywhere except inside the windows.
//!   `{"inactive": []}` means always.
//!
//! Windows are combined, and may overlap: `["Mon 10:00-12:00",
//! "Mon 11:00-13:00"]` covers Monday 10:00 to 13:00. A leading UTF-8 byte
//! order mark is ignored, and unknown keys are an error.
//!
//! A window is `[DAYS ]FROM-TO`:
//!
//! - `DAYS` is a comma-separated list of days (`Mon` to `Sun`, any case) or day
//!   ranges: `Mon`, `Mon-Fri`, `Mon,Wed,Fri`, `sat-sun`. A range may wrap past
//!   Sunday: `Fri-Mon` is Friday, Saturday, Sunday and Monday. Without days,
//!   the window applies to every day: `12:00-13:00` is every lunch hour.
//! - `FROM` and `TO` are `H:MM` or `HH:MM` on the 24-hour clock: `7:00`,
//!   `07:00`, `18:30`. `TO` may be `24:00`, the end of the day; `FROM` may not.
//! - A `TO` earlier than `FROM` runs past midnight and belongs to the day it
//!   starts on: `Fri 18:00-07:00` runs from Friday 18:00 to Saturday 07:00,
//!   and `Sun 22:00-02:00` into Monday. A `TO` of `00:00` is therefore the
//!   same as `24:00`.
//! - `FROM` equal to `TO` is an error: `Mon 18:00-18:00` could mean nothing
//!   or the whole day.
//! - Whitespace is ignored anywhere in the entry: `mon - fri 7:00 - 18:00` is
//!   `Mon-Fri 07:00-18:00`.
//! - Windows are half-open: in `Mon-Fri 07:00-18:00`, 07:00 is inside and
//!   18:00 is outside.
//!
//! Times are on the machine's local wall clock.
//!
//! Some complete schedules:
//!
//! ```json
//! // Office workstation: off during business hours, on otherwise.
//! { "inactive": ["Mon-Fri 07:00-18:00"] }
//!
//! // Nights and weekends only, written the other way round.
//! { "active": ["Mon-Thu 18:00-07:00", "Fri 18:00-24:00", "Sat-Sun 00:00-24:00", "Mon 00:00-07:00"] }
//!
//! // Off over lunch and during the Wednesday meeting.
//! { "inactive": ["12:00-13:00", "Wed 14:00-15:30"] }
//! ```

use std::ops::Range;
use std::str::FromStr;
use std::time::Duration;

use jiff::civil::{Time, Weekday};
use serde::Deserialize;
use thiserror::Error;

use super::{DAY, WeekSecond};

const FULL_DAY: Duration = Duration::from_secs(DAY as u64);

#[derive(Debug, Error)]
pub enum ScheduleError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("expected exactly one of \"active\" or \"inactive\"")]
    Mode,
    #[error("invalid window {entry:?}: {reason}")]
    Window { entry: String, reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Active,
    Inactive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    mode: Mode,
    spans: Vec<Span>,
}

/// A stretch of the week, half-open, that may wrap past Sunday into Monday.
/// Never empty and never a full week, since every window is longer than zero
/// and at most a day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    start: WeekSecond,
    end: WeekSecond,
}

impl Span {
    fn contains(self, at: WeekSecond) -> bool {
        self.start.until(at) < self.start.until(self.end)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSchedule {
    active: Option<Vec<String>>,
    inactive: Option<Vec<String>>,
}

impl Schedule {
    pub fn is_active(&self, at: WeekSecond) -> bool {
        let inside = self.spans.iter().any(|span| span.contains(at));

        match self.mode {
            Mode::Active => inside,
            Mode::Inactive => !inside,
        }
    }

    /// How long until `is_active` gives a different answer; `None` if it never
    /// does.
    pub fn until_change_from(&self, at: WeekSecond) -> Option<Duration> {
        let now = self.is_active(at);

        self.spans
            .iter()
            .flat_map(|span| [span.start, span.end])
            .filter(|&boundary| self.is_active(boundary) != now)
            .map(|boundary| at.until(boundary))
            .min()
    }
}

impl FromStr for Schedule {
    type Err = ScheduleError;

    /// Parse the schedule file's JSON. A leading byte order mark (e.g. written by Windows Notepad) is ignored.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let raw: RawSchedule = serde_json::from_str(text)?;

        let (mode, entries) = match (raw.active, raw.inactive) {
            (Some(entries), None) => (Mode::Active, entries),
            (None, Some(entries)) => (Mode::Inactive, entries),
            _ => return Err(ScheduleError::Mode),
        };

        let mut spans = Vec::new();
        for entry in &entries {
            let window = Window::parse(entry).map_err(|reason| ScheduleError::Window {
                entry: entry.clone(),
                reason,
            })?;
            spans.extend(window.spans());
        }

        Ok(Self { mode, spans })
    }
}

/// One `[DAYS ]FROM-TO` entry. On each of its days it starts at `start` and
/// lasts `length`, which is more than zero and at most a day.
struct Window {
    days: Vec<Weekday>,
    start: Time,
    length: Duration,
}

impl Window {
    fn parse(entry: &str) -> Result<Self, String> {
        let compact: String = entry.chars().filter(|c| !c.is_whitespace()).collect();
        let split = compact
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(compact.len());
        let (days, times) = compact.split_at(split);

        let (from, to) = times
            .split_once('-')
            .ok_or_else(|| "expected [DAYS ]FROM-TO".to_string())?;
        let from = parse_time(from)?;
        let to = parse_time(to)?;

        if from == FULL_DAY {
            return Err("24:00 is only valid as an end time".to_string());
        }

        if from == to {
            return Err("start equals end".to_string());
        }

        // A window that ends before it starts runs past midnight into the
        // next day.
        let length = if to > from {
            to - from
        } else {
            FULL_DAY - from + to
        };

        Ok(Self {
            days: parse_days(days)?,
            start: Time::midnight().wrapping_add(from),
            length,
        })
    }

    /// One span per day. A span that runs past Sunday continues on Monday.
    fn spans(&self) -> impl Iterator<Item = Span> + '_ {
        self.days.iter().map(|&day| {
            let start = WeekSecond::from_civil(day, self.start);

            Span {
                start,
                end: start + self.length,
            }
        })
    }
}

/// `H:MM` or `HH:MM`, up to `24:00`, as the time since midnight.
fn parse_time(text: &str) -> Result<Duration, String> {
    let invalid = || format!("invalid time {text:?}");

    if text.is_empty() {
        return Err("expected [DAYS ]FROM-TO".to_string());
    }

    let (hours, minutes) = text.split_once(':').ok_or_else(invalid)?;
    let digits = |part: &str, lengths: Range<usize>| {
        lengths.contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit())
    };

    if !digits(hours, 1..3) || !digits(minutes, 2..3) {
        return Err(invalid());
    }

    let hours: u64 = hours.parse().map_err(|_| invalid())?;
    let minutes: u64 = minutes.parse().map_err(|_| invalid())?;

    if hours > 24 || minutes > 59 || (hours == 24 && minutes > 0) {
        return Err(invalid());
    }

    Ok(Duration::from_secs(hours * 3_600 + minutes * 60))
}

/// Comma-separated days or day ranges, in the order written. A range may wrap
/// past Sunday. No days at all means every day.
///
/// - `Mon` is Monday.
/// - `Mon,Wed,Fri` is Monday, Wednesday and Friday.
/// - `Mon-Fri` is Monday to Friday.
/// - `Fri-Mon` is Friday, Saturday, Sunday and Monday.
/// - `Mon-Wed,Sat` is Monday, Tuesday, Wednesday and Saturday.
/// - An empty string is Monday to Sunday.
///
/// Names are matched case-insensitively. Assumes whitespace is stripped.
fn parse_days(text: &str) -> Result<Vec<Weekday>, String> {
    if text.is_empty() {
        return Ok(Weekday::Monday.cycle_forward().take(7).collect());
    }

    let mut days = Vec::new();
    for item in text.split(',') {
        match item.split_once('-') {
            Some((first, last)) => {
                let first = parse_day(first)?;
                let last = parse_day(last)?;
                let length = last.since(first) as usize + 1;
                days.extend(first.cycle_forward().take(length));
            }
            None => days.push(parse_day(item)?),
        }
    }

    Ok(days)
}

fn parse_day(name: &str) -> Result<Weekday, String> {
    const NAMES: [(&str, Weekday); 7] = [
        ("mon", Weekday::Monday),
        ("tue", Weekday::Tuesday),
        ("wed", Weekday::Wednesday),
        ("thu", Weekday::Thursday),
        ("fri", Weekday::Friday),
        ("sat", Weekday::Saturday),
        ("sun", Weekday::Sunday),
    ];

    let lower = name.to_ascii_lowercase();

    NAMES
        .iter()
        .find(|(day, _)| *day == lower)
        .map(|&(_, weekday)| weekday)
        .ok_or_else(|| format!("unknown day {name:?}"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jiff::civil::{
        self,
        Weekday::{self, *},
    };

    use super::*;
    use crate::schedule::WeekSecond;

    fn at(day: Weekday, hh: i8, mm: i8) -> WeekSecond {
        WeekSecond::from_civil(day, civil::time(hh, mm, 0, 0))
    }

    fn week() -> impl Iterator<Item = Weekday> {
        (0..7).map(|offset| Weekday::from_monday_zero_offset(offset).unwrap())
    }

    fn schedule(json: &str) -> Schedule {
        json.parse().unwrap()
    }

    #[test]
    fn office_hours_in_inactive_form() {
        let s = schedule(r#"{"inactive": ["Mon-Fri 07:00-18:00"]}"#);
        let just_before_seven = WeekSecond::from_civil(Monday, civil::time(6, 59, 59, 0));

        assert!(s.is_active(just_before_seven));
        assert!(!s.is_active(at(Monday, 7, 0)));
        assert!(!s.is_active(at(Friday, 17, 59)));
        assert!(s.is_active(at(Friday, 18, 0)));
        assert!(s.is_active(at(Saturday, 12, 0)));
        assert!(s.is_active(at(Monday, 0, 0)));
    }

    #[test]
    fn a_window_crossing_midnight_belongs_to_its_start_day() {
        let s = schedule(r#"{"active": ["Fri 18:00-07:00"]}"#);

        assert!(s.is_active(at(Saturday, 6, 59)));
        assert!(!s.is_active(at(Saturday, 7, 0)));
        assert!(!s.is_active(at(Friday, 6, 59)));
    }

    #[test]
    fn end_at_midnight_equals_end_of_day() {
        assert_eq!(
            schedule(r#"{"active": ["Mon 18:00-00:00"]}"#),
            schedule(r#"{"active": ["Mon 18:00-24:00"]}"#)
        );
    }

    #[test]
    fn a_window_wraps_from_sunday_into_monday() {
        let s = schedule(r#"{"active": ["Sun 22:00-02:00"]}"#);

        assert!(s.is_active(at(Monday, 1, 0)));
        assert!(!s.is_active(at(Monday, 2, 0)));
        assert!(s.is_active(at(Sunday, 23, 0)));
    }

    #[test]
    fn day_lists_and_wrapping_ranges() {
        let s = schedule(r#"{"active": ["Fri-Mon 12:00-13:00", "Wed 12:00-13:00"]}"#);

        let active_days: Vec<Weekday> =
            week().filter(|&day| s.is_active(at(day, 12, 30))).collect();
        assert_eq!(active_days, [Monday, Wednesday, Friday, Saturday, Sunday]);
    }

    #[test]
    fn no_days_means_every_day() {
        let s = schedule(r#"{"active": ["12:00-13:00"]}"#);

        assert!(week().all(|day| s.is_active(at(day, 12, 30))));
    }

    #[test]
    fn entries_are_case_and_whitespace_insensitive() {
        assert_eq!(
            schedule(r#"{"active": ["mon - fri 7:00 - 18:00"]}"#),
            schedule(r#"{"active": ["Mon-Fri 07:00-18:00"]}"#)
        );
    }

    #[test]
    fn a_byte_order_mark_is_ignored() {
        assert_eq!(
            schedule("\u{feff}{\"active\": []}"),
            schedule(r#"{"active": []}"#)
        );
    }

    #[test]
    fn empty_lists_mean_never_or_always() {
        let never = schedule(r#"{"active": []}"#);
        let always = schedule(r#"{"inactive": []}"#);

        assert!(!never.is_active(at(Wednesday, 12, 0)));
        assert!(always.is_active(at(Wednesday, 12, 0)));
        assert_eq!(never.until_change_from(at(Monday, 0, 0)), None);
        assert_eq!(always.until_change_from(at(Monday, 0, 0)), None);
    }

    #[test]
    fn until_change_finds_the_next_flip() {
        let office = schedule(r#"{"inactive": ["Mon-Fri 07:00-18:00"]}"#);
        let overlap = schedule(r#"{"active": ["Mon 10:00-12:00", "Mon 11:00-13:00"]}"#);
        let monday_hour = schedule(r#"{"active": ["Mon 00:00-01:00"]}"#);
        let sunday_night = schedule(r#"{"active": ["Sun 22:00-02:00"]}"#);

        assert_eq!(
            office.until_change_from(at(Monday, 6, 0)),
            Some(Duration::from_secs(3_600))
        );
        assert_eq!(
            office.until_change_from(at(Friday, 18, 0)),
            Some(Duration::from_secs(2 * 86_400 + 13 * 3_600))
        );
        assert_eq!(
            overlap.until_change_from(at(Monday, 10, 30)),
            Some(Duration::from_secs(9_000))
        );
        assert_eq!(
            monday_hour.until_change_from(at(Sunday, 23, 59)),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            sunday_night.until_change_from(at(Sunday, 23, 0)),
            Some(Duration::from_secs(3 * 3_600))
        );
    }

    #[test]
    fn invalid_schedules_name_the_problem() {
        let cases = [
            (
                r#"{"active": [], "inactive": []}"#,
                r#"expected exactly one of "active" or "inactive""#,
            ),
            (r#"{}"#, r#"expected exactly one of "active" or "inactive""#),
            (r#"{"active": [], "extra": 1}"#, "invalid JSON"),
            (
                r#"{"active": ["Mon 18:00-18:00"]}"#,
                r#"invalid window "Mon 18:00-18:00": start equals end"#,
            ),
            (
                r#"{"active": ["Mon 24:00-02:00"]}"#,
                "24:00 is only valid as an end time",
            ),
            (
                r#"{"active": ["Mon 18:60-20:00"]}"#,
                r#"invalid time "18:60""#,
            ),
            (r#"{"active": ["Mox 18:00-20:00"]}"#, r#"unknown day "Mox""#),
            (r#"{"active": ["Mon 18:00"]}"#, "expected [DAYS ]FROM-TO"),
            (r#"{"active": ["Mon-Fri"]}"#, "expected [DAYS ]FROM-TO"),
            (r#"{"active": [""]}"#, "expected [DAYS ]FROM-TO"),
        ];

        for (json, expected) in cases {
            let error = json.parse::<Schedule>().unwrap_err().to_string();

            assert!(error.contains(expected), "{json}: got {error:?}");
        }
    }
}
