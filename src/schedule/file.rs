use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use thiserror::Error;

use super::{Schedule, ScheduleError};

/// The cause is part of the message and deliberately not a `source`: the
/// agent prints its exit error with every source appended, which would repeat
/// it.
#[derive(Debug, Error)]
pub enum ScheduleFileError {
    #[error("failed to read {}: {error}", path.display())]
    Read { path: PathBuf, error: io::Error },
    #[error("{}: {error}", path.display())]
    Invalid { path: PathBuf, error: ScheduleError },
}

/// What [`ScheduleFile::reload_if_changed`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Reload {
    Unchanged,
    Reloaded,
    /// The file is gone, and with it the schedule.
    Removed,
    /// The file changed but could not be read or parsed; the previous
    /// schedule stays in force.
    Rejected,
}

/// Modification time and length, or `None` when the file cannot be looked at
/// (deleted, say).
type Stamp = Option<(SystemTime, u64)>;

/// The schedule file on disk and the last schedule read from it. The file is
/// optional: without it there is no schedule. A change is noticed by the
/// file's modification time and length, so two edits of the same length within
/// the file system's timestamp resolution look like one.
#[derive(Debug)]
pub struct ScheduleFile {
    path: PathBuf,
    stamp: Stamp,
    schedule: Option<Schedule>,
}

impl ScheduleFile {
    /// A missing file is fine; one that is there but cannot be read or parsed
    /// is an error.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, ScheduleFileError> {
        let path = path.into();
        let stamp = stamp(&path);
        let schedule = read(&path)?;

        Ok(Self {
            path,
            stamp,
            schedule,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn schedule(&self) -> Option<&Schedule> {
        self.schedule.as_ref()
    }

    pub fn changed(&self) -> bool {
        stamp(&self.path) != self.stamp
    }

    /// Re-read the file if it changed since it was last looked at. A deleted
    /// file removes the schedule. A file that fails to load keeps the previous
    /// schedule and is not tried again until it changes once more, so each bad
    /// edit is reported once.
    pub fn reload_if_changed(&mut self) -> Reload {
        // Taken before reading: a write racing the read then shows up as
        // another change next time.
        let stamp = stamp(&self.path);

        if stamp == self.stamp {
            return Reload::Unchanged;
        }

        self.stamp = stamp;

        match read(&self.path) {
            Ok(Some(schedule)) => {
                tracing::info!(path = %self.path.display(), "active hours loaded");
                self.schedule = Some(schedule);

                Reload::Reloaded
            }
            Ok(None) => {
                tracing::info!(
                    path = %self.path.display(),
                    "active hours file removed, working at any time"
                );
                self.schedule = None;

                Reload::Removed
            }
            Err(error) => {
                tracing::warn!(%error, "schedule change rejected, keeping the previous schedule");

                Reload::Rejected
            }
        }
    }
}

fn stamp(path: &Path) -> Stamp {
    let metadata = fs::metadata(path).ok()?;

    Some((metadata.modified().ok()?, metadata.len()))
}

/// `None` when there is no file.
fn read(path: &Path) -> Result<Option<Schedule>, ScheduleFileError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ScheduleFileError::Read {
                path: path.to_path_buf(),
                error,
            });
        }
    };

    text.parse()
        .map(Some)
        .map_err(|error| ScheduleFileError::Invalid {
            path: path.to_path_buf(),
            error,
        })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    const NEVER: &str = r#"{"active": []}"#;
    const INVALID: &str = r#"{"active": ["Mon 18:60-20:00"]}"#;

    fn write(path: &Path, json: &str) {
        fs::write(path, json).unwrap();
    }

    fn schedule(json: &str) -> Schedule {
        json.parse().unwrap()
    }

    /// A temporary directory and the active hours path inside it, with no file
    /// there yet.
    fn empty() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("schedule.json");

        (dir, path)
    }

    /// A loaded schedule file that starts out as "never active". Every edit a
    /// test makes changes the file's length, since modification times may
    /// only have one-second resolution.
    fn loaded() -> (TempDir, PathBuf, ScheduleFile) {
        let (dir, path) = empty();
        write(&path, NEVER);

        let file = ScheduleFile::load(&path).unwrap();

        (dir, path, file)
    }

    #[test]
    fn load_reads_a_valid_file() {
        let (_dir, path, file) = loaded();

        assert_eq!(file.schedule(), Some(&schedule(NEVER)));
        assert_eq!(file.path(), path);
    }

    #[test]
    fn load_without_a_file_has_no_schedule() {
        let (_dir, path) = empty();

        let file = ScheduleFile::load(&path).unwrap();

        assert_eq!(file.schedule(), None);
    }

    #[test]
    fn load_fails_on_an_unreadable_file() {
        let (dir, _path) = empty();

        let error = ScheduleFile::load(dir.path()).unwrap_err();

        assert!(matches!(error, ScheduleFileError::Read { .. }));
        assert!(error.to_string().starts_with("failed to read "));
        assert!(
            error
                .to_string()
                .contains(&dir.path().display().to_string())
        );
    }

    #[test]
    fn load_fails_on_an_invalid_file_naming_it() {
        let (_dir, path) = empty();
        write(&path, INVALID);

        let error = ScheduleFile::load(&path).unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "{}: invalid window \"Mon 18:60-20:00\": invalid time \"18:60\"",
                path.display()
            )
        );
    }

    #[test]
    fn load_errors_do_not_repeat_their_cause_when_chained() {
        let (dir, invalid) = empty();
        write(&invalid, INVALID);

        for path in [dir.path(), invalid.as_path()] {
            let error = ScheduleFile::load(path).unwrap_err();
            let message = error.to_string();

            // main prints errors through anyhow with `{:#}`, which appends
            // every source in the chain.
            assert_eq!(format!("{:#}", anyhow::Error::from(error)), message);
        }
    }

    #[test]
    fn an_unchanged_file_is_not_reloaded() {
        let (_dir, _path, mut file) = loaded();

        assert!(!file.changed());
        assert_eq!(file.reload_if_changed(), Reload::Unchanged);
    }

    #[test]
    fn a_changed_file_is_reloaded() {
        let (_dir, path, mut file) = loaded();
        let office = r#"{"inactive": ["Mon-Fri 07:00-18:00"]}"#;
        write(&path, office);

        assert!(file.changed());
        assert_eq!(file.reload_if_changed(), Reload::Reloaded);
        assert_eq!(file.schedule(), Some(&schedule(office)));
    }

    #[test]
    fn a_file_created_later_is_loaded() {
        let (_dir, path) = empty();
        let mut file = ScheduleFile::load(&path).unwrap();
        write(&path, NEVER);

        assert!(file.changed());
        assert_eq!(file.reload_if_changed(), Reload::Reloaded);
        assert_eq!(file.schedule(), Some(&schedule(NEVER)));
    }

    #[test]
    fn an_invalid_edit_keeps_the_last_good_schedule() {
        let (_dir, path, mut file) = loaded();
        write(&path, INVALID);

        assert_eq!(file.reload_if_changed(), Reload::Rejected);
        assert_eq!(file.schedule(), Some(&schedule(NEVER)));
        assert_eq!(file.reload_if_changed(), Reload::Unchanged);
    }

    #[test]
    fn a_deleted_file_removes_the_schedule() {
        let (_dir, path, mut file) = loaded();
        fs::remove_file(&path).unwrap();

        assert_eq!(file.reload_if_changed(), Reload::Removed);
        assert_eq!(file.schedule(), None);
        assert_eq!(file.reload_if_changed(), Reload::Unchanged);
    }

    #[test]
    fn a_truncated_file_mid_write_is_rejected_then_picked_up() {
        let (_dir, path, mut file) = loaded();
        let always = r#"{"inactive": []}"#;
        write(&path, "");

        assert_eq!(file.reload_if_changed(), Reload::Rejected);
        assert_eq!(file.schedule(), Some(&schedule(NEVER)));

        write(&path, always);

        assert_eq!(file.reload_if_changed(), Reload::Reloaded);
        assert_eq!(file.schedule(), Some(&schedule(always)));
    }
}
