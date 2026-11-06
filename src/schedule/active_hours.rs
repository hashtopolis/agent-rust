use std::mem;
use std::time::Duration;

use jiff::{SignedDuration, Zoned};
use tokio::time::{Instant, sleep};

use super::{ScheduleFile, WeekSecond};

const SCHEDULE_FILE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Whether the agent may ask for work right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Active,
    /// `resumes_in` is how long until the schedule allows work again; `None`
    /// if it never does, because the schedule blocks the whole week (e.g.
    /// `{"active": []}`).
    Inactive {
        resumes_in: Option<Duration>,
    },
}

type Clock = Box<dyn Fn() -> WeekSecond + Send + Sync>;

pub struct ActiveHours {
    file: ScheduleFile,
    clock: Clock,
    paused: bool,
}

impl ActiveHours {
    pub fn new(file: ScheduleFile) -> Self {
        Self::with_clock(file, || WeekSecond::from(Zoned::now().datetime()))
    }

    pub fn with_clock(
        file: ScheduleFile,
        clock: impl Fn() -> WeekSecond + Send + Sync + 'static,
    ) -> Self {
        Self {
            file,
            clock: Box::new(clock),
            paused: false,
        }
    }

    /// Pick up an edited schedule, then say whether the agent may work now.
    /// Only a change between active and inactive is logged.
    pub fn check(&mut self) -> Activity {
        self.file.reload_if_changed();

        let activity = self.activity_now();
        self.log_change(activity);

        activity
    }

    fn activity_now(&self) -> Activity {
        let Some(schedule) = self.file.schedule() else {
            return Activity::Active;
        };

        let now = (self.clock)();

        if schedule.is_active(now) {
            Activity::Active
        } else {
            Activity::Inactive {
                resumes_in: schedule.until_change_from(now),
            }
        }
    }

    fn log_change(&mut self, activity: Activity) {
        let inactive = matches!(activity, Activity::Inactive { .. });
        let was_paused = mem::replace(&mut self.paused, inactive);

        match (activity, was_paused) {
            (Activity::Inactive { resumes_in }, false) => tracing::info!(
                resumes_in = resumes_in.map_or("never".to_string(), |duration| {
                    format!("{:#}", friendly(duration))
                }),
                "outside active hours, pausing"
            ),
            (Activity::Active, true) => tracing::info!("active hours started, resuming"),
            _ => {}
        }
    }

    /// Sleep for `max`, or less if the schedule file changes in the meantime.
    ///
    /// A change only ends the wait early. The new schedule is read by the next
    /// call to [`check`](Self::check).
    pub async fn wait(&self, max: Duration) {
        let deadline = Instant::now() + max;

        loop {
            if self.file.changed() {
                return;
            }

            let now = Instant::now();

            if now >= deadline {
                return;
            }

            sleep((deadline - now).min(SCHEDULE_FILE_POLL_INTERVAL)).await;
        }
    }
}

/// A pause lasts less than a week, so the seconds always fit.
fn friendly(duration: Duration) -> SignedDuration {
    SignedDuration::from_secs(duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use tempfile::TempDir;

    use super::*;

    const MONDAY_19: u32 = 19 * 3_600;
    const MONDAY_21: u32 = 21 * 3_600;

    /// Active hours over a temporary schedule file, with a clock the test
    /// moves by storing raw week seconds.
    struct Rig {
        _dir: TempDir,
        path: PathBuf,
        now: Arc<AtomicU32>,
        hours: ActiveHours,
    }

    impl Rig {
        fn new(json: &str) -> Self {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("schedule.json");
            fs::write(&path, json).unwrap();

            let now = Arc::new(AtomicU32::new(0));
            let clock = Arc::clone(&now);
            let file = ScheduleFile::load(&path).unwrap();
            let hours = ActiveHours::with_clock(file, move || {
                WeekSecond::new(clock.load(Ordering::SeqCst)).unwrap()
            });

            Self {
                _dir: dir,
                path,
                now,
                hours,
            }
        }

        fn at(&self, seconds: u32) {
            self.now.store(seconds, Ordering::SeqCst);
        }
    }

    #[test]
    fn check_is_active_without_a_file() {
        let dir = TempDir::new().unwrap();
        let file = ScheduleFile::load(dir.path().join("schedule.json")).unwrap();
        let mut hours = ActiveHours::with_clock(file, || WeekSecond::new(0).unwrap());

        let activity = hours.check();

        assert_eq!(activity, Activity::Active);
    }

    #[test]
    fn check_follows_the_clock() {
        let mut rig = Rig::new(r#"{"active": ["Mon 18:00-20:00"]}"#);

        rig.at(MONDAY_19);
        let active = rig.hours.check();
        rig.at(MONDAY_21);
        let inactive = rig.hours.check();

        assert_eq!(active, Activity::Active);
        assert_eq!(
            inactive,
            Activity::Inactive {
                resumes_in: Some(Duration::from_secs(6 * 86_400 + 21 * 3_600))
            }
        );
    }

    #[test]
    fn check_picks_up_an_edit() {
        let mut rig = Rig::new(r#"{"active": []}"#);

        let before = rig.hours.check();
        fs::write(&rig.path, r#"{"inactive": []}"#).unwrap();
        let after = rig.hours.check();

        assert_eq!(before, Activity::Inactive { resumes_in: None });
        assert_eq!(after, Activity::Active);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_runs_to_max_when_nothing_changes() {
        let rig = Rig::new(r#"{"active": []}"#);
        let start = Instant::now();

        rig.hours.wait(Duration::from_secs(60)).await;

        assert_eq!(start.elapsed(), Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn wait_ends_early_when_the_file_changes() {
        let rig = Rig::new(r#"{"active": []}"#);
        fs::write(&rig.path, r#"{"inactive": []}"#).unwrap();
        let start = Instant::now();

        rig.hours.wait(Duration::from_secs(60)).await;

        assert!(start.elapsed() <= Duration::from_secs(1));
    }
}
