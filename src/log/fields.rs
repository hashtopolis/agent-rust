//! Field types that render themselves the way the log should read them.

use std::fmt;
use std::path::Path;

/// A process invocation, rendered as a single copy-pasteable POSIX command line:
/// the binary followed by its arguments, each quoted so the line can be copied
/// straight from the log and re-run.
pub(crate) struct Invocation<'a, A: AsRef<str>> {
    pub program: &'a Path,
    pub args: &'a [A],
}

impl<A: AsRef<str>> fmt::Display for Invocation<'_, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", ShellToken(&self.program.to_string_lossy()))?;

        for arg in self.args {
            write!(f, " {}", ShellToken(arg.as_ref()))?;
        }

        Ok(())
    }
}

/// One token of a command line: written bare when it holds only shell-safe
/// characters, single-quoted otherwise (with any embedded single quote escaped
/// as `'\''`).
struct ShellToken<'a>(&'a str);

impl fmt::Display for ShellToken<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = self.0;

        let safe = !token.is_empty()
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@%+=:,./-_".contains(&b));

        if safe {
            return f.write_str(token);
        }

        f.write_str("'")?;

        for part in token.split('\'') {
            if part.as_ptr() != token.as_ptr() {
                f.write_str("'\\''")?;
            }

            f.write_str(part)?;
        }

        f.write_str("'")
    }
}

/// A hashes-per-second rate, rendered with a decimal SI unit so a log reads
/// `12.34 MH/s` instead of `12340000`. Rates below 1000 keep the bare `H/s`.
pub(crate) struct HashRate(pub u64);

impl fmt::Display for HashRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: [&str; 7] = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];

        let mut value = self.0 as f64;
        let mut unit = 0;

        while value >= 1000.0 && unit < UNITS.len() - 1 {
            value /= 1000.0;
            unit += 1;
        }

        if unit == 0 {
            write!(f, "{value:.0} {}", UNITS[unit])
        } else {
            write!(f, "{value:.2} {}", UNITS[unit])
        }
    }
}

/// A progress value given in basis points (`0..=10000`), rendered as a
/// percentage with two decimals (`4545` -> `45.45%`).
pub(crate) struct Percent(pub u64);

impl fmt::Display for Percent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}%", self.0 as f64 / 100.0)
    }
}

/// A measured keyspace, rendered as its value, or `unbounded` when the attack
/// has no finite keyspace (`None`, which the server stores as -1).
pub(crate) struct Keyspace(pub Option<u64>);

impl fmt::Display for Keyspace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(keyspace) => write!(f, "{keyspace}"),
            None => f.write_str("unbounded"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_rate_scales_to_a_sensible_unit() {
        assert_eq!(HashRate(0).to_string(), "0 H/s");
        assert_eq!(HashRate(500).to_string(), "500 H/s");
        assert_eq!(HashRate(570_000).to_string(), "570.00 kH/s");
        assert_eq!(HashRate(12_340_000).to_string(), "12.34 MH/s");
        assert_eq!(HashRate(2_500_000_000).to_string(), "2.50 GH/s");
        assert_eq!(HashRate(4_000_000_000_000).to_string(), "4.00 TH/s");
    }

    #[test]
    fn percent_is_rendered_from_basis_points() {
        assert_eq!(Percent(0).to_string(), "0.00%");
        assert_eq!(Percent(4545).to_string(), "45.45%");
        assert_eq!(Percent(10000).to_string(), "100.00%");
    }

    #[test]
    fn keyspace_renders_value_or_unbounded() {
        assert_eq!(Keyspace(Some(10000)).to_string(), "10000");
        assert_eq!(Keyspace(None).to_string(), "unbounded");
    }

    #[test]
    fn invocation_quotes_only_the_tokens_that_need_it() {
        let invocation = Invocation {
            program: Path::new("/opt/hashcat/hashcat.bin"),
            args: &[
                "-m",
                "1000",
                "--session=foo",
                "/data/my hashlist.txt",
                "?a?a",
            ],
        };

        assert_eq!(
            invocation.to_string(),
            "/opt/hashcat/hashcat.bin -m 1000 --session=foo '/data/my hashlist.txt' '?a?a'"
        );
    }

    #[test]
    fn invocation_escapes_embedded_single_quotes() {
        let invocation = Invocation {
            program: Path::new("/bin/echo"),
            args: &["it's"],
        };

        assert_eq!(invocation.to_string(), "/bin/echo 'it'\\''s'");
    }

    #[test]
    fn invocation_without_args_is_just_the_program() {
        let invocation = Invocation {
            program: Path::new("/bin/hashcat"),
            args: &[] as &[&str],
        };

        assert_eq!(invocation.to_string(), "/bin/hashcat");
    }
}
