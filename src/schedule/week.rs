use std::ops::Add;
use std::time::Duration;

use jiff::civil::{DateTime, Time, Weekday};

use super::{DAY, WEEK};

/// A point in the week on the local wall clock, as seconds since Monday 00:00.
/// Always less than a week.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WeekSecond(u32);

impl WeekSecond {
    /// `None` for a full week or more.
    pub fn new(seconds: u32) -> Option<Self> {
        (seconds < WEEK).then_some(Self(seconds))
    }

    pub fn from_civil(weekday: Weekday, time: Time) -> Self {
        let day = weekday.to_monday_zero_offset() as u32;
        let seconds = time.hour() as u32 * 3_600 + time.minute() as u32 * 60 + time.second() as u32;

        Self(day * DAY + seconds)
    }

    pub fn get(self) -> u32 {
        self.0
    }

    /// How long from here forward to the next occurrence of `later`, wrapping
    /// past Sunday. Zero when both are the same point.
    pub fn until(self, later: WeekSecond) -> Duration {
        let seconds = (later.0 + WEEK - self.0) % WEEK;

        Duration::from_secs(seconds.into())
    }
}

/// Continues past Sunday into Monday.
impl Add<Duration> for WeekSecond {
    type Output = Self;

    fn add(self, duration: Duration) -> Self {
        let seconds = (u64::from(self.0) + duration.as_secs()) % u64::from(WEEK);

        // Less than a week, so it fits.
        Self(seconds as u32)
    }
}

impl From<DateTime> for WeekSecond {
    fn from(datetime: DateTime) -> Self {
        Self::from_civil(datetime.weekday(), datetime.time())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jiff::civil::{self, Weekday};

    use super::*;

    #[test]
    fn new_rejects_a_full_week_or_more() {
        assert_eq!(WeekSecond::new(604_799).map(WeekSecond::get), Some(604_799));
        assert_eq!(WeekSecond::new(604_800), None);
    }

    #[test]
    fn adding_continues_past_sunday_into_monday() {
        let sunday = WeekSecond::from_civil(Weekday::Sunday, civil::time(23, 0, 0, 0));
        let wednesday = WeekSecond::from_civil(Weekday::Wednesday, civil::time(12, 0, 0, 0));

        assert_eq!(
            sunday + Duration::from_secs(1_800),
            WeekSecond::new(604_800 - 1_800).unwrap()
        );
        assert_eq!(
            sunday + Duration::from_secs(3_600),
            WeekSecond::new(0).unwrap()
        );
        assert_eq!(
            sunday + Duration::from_secs(3 * 3_600),
            WeekSecond::new(7_200).unwrap()
        );
        assert_eq!(wednesday + Duration::from_secs(7 * 86_400), wednesday);
    }

    #[test]
    fn from_civil_counts_from_monday_midnight() {
        let sunday_late = WeekSecond::from_civil(Weekday::Sunday, civil::time(23, 59, 59, 0));

        assert_eq!(
            WeekSecond::from_civil(Weekday::Monday, civil::time(0, 0, 0, 0)),
            WeekSecond::new(0).unwrap()
        );
        assert_eq!(sunday_late, WeekSecond::new(604_799).unwrap());
    }

    #[test]
    fn until_wraps_forward_past_sunday() {
        let sunday = WeekSecond::from_civil(Weekday::Sunday, civil::time(23, 0, 0, 0));
        let monday = WeekSecond::from_civil(Weekday::Monday, civil::time(1, 0, 0, 0));

        assert_eq!(sunday.until(monday), Duration::from_secs(7_200));
        assert_eq!(
            monday.until(sunday),
            Duration::from_secs(7 * 86_400 - 7_200)
        );
        assert_eq!(monday.until(monday), Duration::ZERO);
    }
}
