use std::path::Path;

use crate::backend::paths::absolute;

use super::HashcatCracker;

impl HashcatCracker {
    /// Split the server's attack string into argv tokens, resolving each: the
    /// hashlist alias becomes `hashlist`, or is dropped entirely when `None` (a
    /// keyspace measure runs without the hashlist). Any token naming a file under
    /// the files dir becomes that file's absolute path; everything else passes
    /// through unchanged. No quoting — argv carries spaces natively.
    pub(super) fn resolve_attack(
        &self,
        attack: &str,
        alias: &str,
        hashlist: Option<&Path>,
    ) -> Vec<String> {
        let mut resolved = Vec::new();

        for token in attack.split_whitespace() {
            if token == alias {
                if let Some(hashlist) = hashlist {
                    resolved.push(path_arg(hashlist));
                }

                continue;
            }

            let candidate = self.paths.files.join(token);

            if candidate.is_file() {
                resolved.push(path_arg(&absolute(candidate)));
            } else {
                resolved.push(token.to_owned());
            }
        }

        resolved
    }
}

/// Split extra command parameters into argv tokens.
pub(super) fn split_parameters(parameters: &str) -> impl Iterator<Item = &str> {
    parameters.split_whitespace()
}

pub(super) fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::backend::hashcat::progress;
    use crate::config::Paths;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const ALIAS: &str = "#HL#";

    fn cracker_with_files(files: &[&str]) -> (TempDir, HashcatCracker) {
        let dir = tempfile::tempdir().unwrap();

        for name in files {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }

        let paths = Paths {
            files: dir.path().to_path_buf(),
            ..Default::default()
        };

        let cracker = HashcatCracker {
            cracker_id: 1,
            binary_path: PathBuf::from("/opt/hashcat/hashcat"),
            paths,
            progress_mode: progress::ProgressMode::Absolute,
            auto_pipe: None,
        };

        (dir, cracker)
    }

    fn seeded(dir: &TempDir, name: &str) -> String {
        path_arg(&dir.path().join(name))
    }

    #[test]
    fn alias_becomes_the_hashlist_path() {
        let (_dir, cracker) = cracker_with_files(&[]);
        let hashlist = PathBuf::from("/data/hashlists/42");

        let args = cracker.resolve_attack("#HL# -a 3 ?a?a?a?a", ALIAS, Some(&hashlist));

        assert_eq!(args, ["/data/hashlists/42", "-a", "3", "?a?a?a?a"]);
    }

    #[test]
    fn alias_is_dropped_when_no_hashlist() {
        let (_dir, cracker) = cracker_with_files(&[]);

        let args = cracker.resolve_attack("#HL# -a 3 ?a?a?a?a", ALIAS, None);

        assert_eq!(args, ["-a", "3", "?a?a?a?a"]);
    }

    #[test]
    fn file_tokens_resolve_to_absolute_paths() {
        let (dir, cracker) = cracker_with_files(&["rockyou.txt"]);
        let hashlist = PathBuf::from("/data/hashlists/1");

        let args = cracker.resolve_attack("#HL# -a 0 rockyou.txt", ALIAS, Some(&hashlist));

        let expected = vec![
            "/data/hashlists/1".to_owned(),
            "-a".to_owned(),
            "0".to_owned(),
            seeded(&dir, "rockyou.txt"),
        ];

        assert_eq!(args, expected);
    }

    #[test]
    fn unknown_tokens_pass_through_unchanged() {
        let (_dir, cracker) = cracker_with_files(&[]);
        let hashlist = PathBuf::from("/hl");

        let args = cracker.resolve_attack("-a 0 missing.txt ?d?d", ALIAS, Some(&hashlist));

        assert_eq!(args, ["-a", "0", "missing.txt", "?d?d"]);
    }

    #[test]
    fn preserves_order_with_alias_mid_command() {
        let (dir, cracker) = cracker_with_files(&["wl.txt"]);
        let hashlist = PathBuf::from("/hl/7");

        let args = cracker.resolve_attack("-a 0 #HL# wl.txt", ALIAS, Some(&hashlist));

        let expected = vec![
            "-a".to_owned(),
            "0".to_owned(),
            "/hl/7".to_owned(),
            seeded(&dir, "wl.txt"),
        ];

        assert_eq!(args, expected);
    }
}
