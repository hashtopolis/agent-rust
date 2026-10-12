//! Path helpers shared across the cracker backends.

use std::path::{Path, PathBuf};

/// Make `path` absolute without touching the filesystem, falling back to the
/// original on the (platform-specific) error paths.
pub(crate) fn absolute(path: PathBuf) -> PathBuf {
    std::path::absolute(&path).unwrap_or(path)
}

/// Resolve a single attack-command token to its argv form, replacing a file
/// name with its absolute path when the token names a file under `files_dir`.
///
/// Three forms are handled:
/// - a bare token that names a file becomes that file's absolute path;
/// - a `key=value` token whose value names a file becomes `key=<absolute path>`
///   (hashcat's `-a 4` PCFG hint files use this form), with matching surrounding
///   quotes stripped from the value first;
/// - anything else passes through unchanged.
pub(crate) fn resolve_file_token(files_dir: &Path, token: &str) -> String {
    let candidate = files_dir.join(token);

    if candidate.is_file() {
        return absolute(candidate).to_string_lossy().into_owned();
    }

    if let Some((key, value)) = token.split_once('=') {
        let value = strip_matching_quotes(value);

        if !value.is_empty() {
            let candidate = files_dir.join(value);

            if candidate.is_file() {
                let path = absolute(candidate);

                return format!("{key}={}", path.to_string_lossy());
            }
        }
    }

    token.to_owned()
}

/// Strip one layer of matching surrounding single or double quotes from `value`,
/// mirroring the way the server may quote a `key="value"` argument.
fn strip_matching_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();

    let quoted = bytes.len() > 1
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0];

    if quoted {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    fn files_with(names: &[&str]) -> TempDir {
        let dir = tempfile::tempdir().unwrap();

        for name in names {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }

        dir
    }

    fn seeded(dir: &TempDir, name: &str) -> String {
        dir.path().join(name).to_string_lossy().into_owned()
    }

    #[test]
    fn bare_file_token_resolves_to_absolute_path() {
        let dir = files_with(&["rockyou.txt"]);

        let resolved = resolve_file_token(dir.path(), "rockyou.txt");

        assert_eq!(resolved, seeded(&dir, "rockyou.txt"));
    }

    #[test]
    fn key_value_token_resolves_the_value() {
        let dir = files_with(&["hint.hcstat2"]);

        let resolved = resolve_file_token(dir.path(), "hintfile=hint.hcstat2");

        assert_eq!(
            resolved,
            format!("hintfile={}", seeded(&dir, "hint.hcstat2"))
        );
    }

    #[test]
    fn quoted_key_value_token_resolves_the_value() {
        let dir = files_with(&["hint file.hcstat2"]);

        let double = resolve_file_token(dir.path(), "hintfile=\"hint file.hcstat2\"");
        let single = resolve_file_token(dir.path(), "hintfile='hint file.hcstat2'");

        let expected = format!("hintfile={}", seeded(&dir, "hint file.hcstat2"));
        assert_eq!(double, expected);
        assert_eq!(single, expected);
    }

    #[test]
    fn key_value_token_with_missing_file_passes_through_unchanged() {
        let dir = files_with(&[]);

        let resolved = resolve_file_token(dir.path(), "hintfile=missing.hcstat2");

        assert_eq!(resolved, "hintfile=missing.hcstat2");
    }

    #[test]
    fn non_file_key_value_flag_passes_through_unchanged() {
        let dir = files_with(&[]);

        let resolved = resolve_file_token(dir.path(), "--hash-type=0");

        assert_eq!(resolved, "--hash-type=0");
    }

    #[test]
    fn empty_value_passes_through_unchanged() {
        let dir = files_with(&[]);

        let resolved = resolve_file_token(dir.path(), "hintfile=");

        assert_eq!(resolved, "hintfile=");
    }

    #[test]
    fn a_bare_file_takes_precedence_over_key_value_parsing() {
        let dir = files_with(&["weird=name.txt"]);

        let resolved = resolve_file_token(dir.path(), "weird=name.txt");

        assert_eq!(resolved, seeded(&dir, "weird=name.txt"));
    }
}
