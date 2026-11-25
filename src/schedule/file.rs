use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use thiserror::Error;

use super::{Schedule, ScheduleError};

/// The cause is part of the message and deliberately not a `source`: the
/// error is only ever logged through its `Display`, which leaves sources out.
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
    /// The file changed and is missing or unusable, which may be a save still
    /// in progress. The schedule stays in force for now.
    Pending,
    /// The file is gone, and with it the schedule.
    Removed,
    /// The file can't be read or parsed, so there is no schedule.
    Rejected,
}

/// Modification time and length, or `None` when the file cannot be looked at
/// (deleted, say).
type Stamp = Option<(SystemTime, u64)>;

/// The schedule file on disk and the schedule in force. Without a usable file
/// there is no schedule. A change is noticed by the file's modification time
/// and length, so two edits of the same length within the file system's
/// timestamp resolution look like one.
#[derive(Debug)]
pub struct ScheduleFile {
    path: PathBuf,
    stamp: Stamp,
    schedule: Option<Schedule>,
    /// The last check found the file changed and missing or unusable.
    pending: bool,
    /// The last read failed. Making the file readable changes neither its
    /// modification time nor its length, so it is read again on every check.
    unreadable: bool,
}

impl ScheduleFile {
    /// A missing file means no schedule. So does one that can't be read or
    /// parsed, with a warning.
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let stamp = stamp(&path);
        let result = read(&path);
        let unreadable = matches!(result, Err(ScheduleFileError::Read { .. }));

        let schedule = result.unwrap_or_else(|error| {
            tracing::warn!(%error, "schedule file rejected, working at any time");

            None
        });

        Self {
            path,
            stamp,
            schedule,
            pending: false,
            unreadable,
        }
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

    /// Re-read the file if it changed since it was last looked at. A usable
    /// file takes effect at once. A missing or unusable one only takes effect
    /// once a check finds it unchanged since the last, so that a save in
    /// progress does not lift the schedule. Each such change is logged once.
    pub fn reload_if_changed(&mut self) -> Reload {
        // Taken before reading: a write racing the read then shows up as
        // another change next time.
        let stamp = stamp(&self.path);

        if stamp == self.stamp && !self.pending && !self.unreadable {
            return Reload::Unchanged;
        }

        let result = read(&self.path);
        let unreadable = matches!(result, Err(ScheduleFileError::Read { .. }));
        let changed = stamp != self.stamp || unreadable != self.unreadable;

        self.stamp = stamp;
        self.unreadable = unreadable;

        match result {
            Ok(Some(schedule)) => {
                tracing::info!(path = %self.path.display(), "active hours loaded");
                self.schedule = Some(schedule);
                self.pending = false;

                Reload::Reloaded
            }
            _ if changed => {
                self.pending = true;

                Reload::Pending
            }
            // Still unreadable, and already reported.
            _ if !self.pending => Reload::Unchanged,
            Ok(None) => {
                tracing::info!(
                    path = %self.path.display(),
                    "active hours file removed, working at any time"
                );
                self.schedule = None;
                self.pending = false;

                Reload::Removed
            }
            Err(error) => {
                tracing::warn!(%error, "schedule file rejected, working at any time");
                self.schedule = None;
                self.pending = false;

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
    const ALWAYS: &str = r#"{"inactive": []}"#;
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

        let file = ScheduleFile::load(&path);

        (dir, path, file)
    }

    /// Takes away read permission; false when that has no effect, as for root.
    #[cfg(unix)]
    fn make_unreadable(path: &Path) -> bool {
        set_mode(path, 0o000);

        fs::read(path).is_err()
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
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

        let file = ScheduleFile::load(&path);

        assert_eq!(file.schedule(), None);
    }

    #[test]
    fn load_ignores_a_file_it_cannot_use() {
        let (dir, invalid) = empty();
        write(&invalid, INVALID);

        // A directory cannot be read as a file.
        for path in [dir.path(), invalid.as_path()] {
            let file = ScheduleFile::load(path);

            assert_eq!(file.schedule(), None);
        }
    }

    #[test]
    fn an_unreadable_file_is_named_in_the_error() {
        let (dir, _path) = empty();

        let error = read(dir.path()).unwrap_err();

        assert!(matches!(error, ScheduleFileError::Read { .. }));
        assert!(error.to_string().starts_with("failed to read "));
        assert!(
            error
                .to_string()
                .contains(&dir.path().display().to_string())
        );
    }

    #[test]
    fn an_invalid_file_is_named_in_the_error() {
        let (_dir, path) = empty();
        write(&path, INVALID);

        let error = read(&path).unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "{}: invalid window \"Mon 18:60-20:00\": invalid time \"18:60\"",
                path.display()
            )
        );
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
        let mut file = ScheduleFile::load(&path);
        write(&path, NEVER);

        assert!(file.changed());
        assert_eq!(file.reload_if_changed(), Reload::Reloaded);
        assert_eq!(file.schedule(), Some(&schedule(NEVER)));
    }

    #[test]
    fn a_file_created_invalid_is_rejected_once_it_stays_so() {
        let (_dir, path) = empty();
        let mut file = ScheduleFile::load(&path);
        write(&path, INVALID);

        assert_eq!(file.reload_if_changed(), Reload::Pending);
        assert_eq!(file.reload_if_changed(), Reload::Rejected);
        assert_eq!(file.schedule(), None);
        assert_eq!(file.reload_if_changed(), Reload::Unchanged);
    }

    #[test]
    fn an_invalid_edit_lifts_the_schedule_once_it_stays_so() {
        let (_dir, path, mut file) = loaded();
        write(&path, INVALID);

        assert_eq!(file.reload_if_changed(), Reload::Pending);
        assert_eq!(file.schedule(), Some(&schedule(NEVER)));
        assert_eq!(file.reload_if_changed(), Reload::Rejected);
        assert_eq!(file.schedule(), None);
        assert_eq!(file.reload_if_changed(), Reload::Unchanged);
    }

    #[test]
    fn a_deleted_file_lifts_the_schedule_once_it_stays_gone() {
        let (_dir, path, mut file) = loaded();
        fs::remove_file(&path).unwrap();

        assert_eq!(file.reload_if_changed(), Reload::Pending);
        assert_eq!(file.schedule(), Some(&schedule(NEVER)));
        assert_eq!(file.reload_if_changed(), Reload::Removed);
        assert_eq!(file.schedule(), None);
        assert_eq!(file.reload_if_changed(), Reload::Unchanged);
    }

    #[test]
    fn a_save_that_truncates_first_keeps_the_schedule() {
        let (_dir, path, mut file) = loaded();
        write(&path, "");

        assert_eq!(file.reload_if_changed(), Reload::Pending);
        assert_eq!(file.schedule(), Some(&schedule(NEVER)));

        write(&path, ALWAYS);

        assert_eq!(file.reload_if_changed(), Reload::Reloaded);
        assert_eq!(file.schedule(), Some(&schedule(ALWAYS)));
    }

    #[test]
    fn a_save_that_deletes_first_keeps_the_schedule() {
        let (_dir, path, mut file) = loaded();
        fs::remove_file(&path).unwrap();

        assert_eq!(file.reload_if_changed(), Reload::Pending);
        assert_eq!(file.schedule(), Some(&schedule(NEVER)));

        write(&path, ALWAYS);

        assert_eq!(file.reload_if_changed(), Reload::Reloaded);
        assert_eq!(file.schedule(), Some(&schedule(ALWAYS)));
    }

    #[test]
    fn a_file_still_being_written_keeps_the_schedule() {
        let (_dir, path, mut file) = loaded();
        write(&path, "");

        assert_eq!(file.reload_if_changed(), Reload::Pending);

        write(&path, "{");

        assert_eq!(file.reload_if_changed(), Reload::Pending);
        assert_eq!(file.schedule(), Some(&schedule(NEVER)));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_made_readable_is_loaded() {
        let (_dir, path) = empty();
        write(&path, NEVER);

        if !make_unreadable(&path) {
            return;
        }

        let mut file = ScheduleFile::load(&path);

        assert_eq!(file.schedule(), None);
        assert_eq!(file.reload_if_changed(), Reload::Unchanged);

        set_mode(&path, 0o644);

        assert!(!file.changed());
        assert_eq!(file.reload_if_changed(), Reload::Reloaded);
        assert_eq!(file.schedule(), Some(&schedule(NEVER)));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_made_readable_but_invalid_is_rejected() {
        let (_dir, path) = empty();
        write(&path, INVALID);

        if !make_unreadable(&path) {
            return;
        }

        let mut file = ScheduleFile::load(&path);
        set_mode(&path, 0o644);

        assert_eq!(file.reload_if_changed(), Reload::Pending);
        assert_eq!(file.reload_if_changed(), Reload::Rejected);
        assert_eq!(file.schedule(), None);
    }
}
