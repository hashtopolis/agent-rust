//! The one-line status grammar a generic cracker prints on stdout.
//!
//! A valid status line is exactly `STATUS <progress> <speed>`, split on a
//! single space into three tokens, both trailing values integers. `progress` is
//! in basis points, `0..=10000` (10000 == 100%). `speed` is an opaque integer
//! forwarded verbatim. Any stdout line that is not a valid status line is either
//! a cracked hash (if it contains `:`) or diagnostic noise; that classification
//! is the caller's job, not this parser's.

/// A parsed generic status line. Constructed via [`GenericStatus::parse`], which
/// never fails: an unparsable line yields an invalid status ([`is_valid`] is
/// `false`) rather than an error, mirroring the reference agent.
///
/// [`is_valid`]: GenericStatus::is_valid
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenericStatus {
    valid: bool,
    progress: u64,
    speed: u64,
}

impl GenericStatus {
    /// The basis-point value denoting a finished chunk (100%).
    pub const COMPLETE: u64 = 10000;

    /// Parse one stdout line. Unlike the reference, a non-integer field yields an
    /// invalid status instead of panicking.
    pub fn parse(line: &str) -> Self {
        let invalid = Self {
            valid: false,
            progress: 0,
            speed: 0,
        };

        // The reference splits on a single space (no whitespace collapsing) and
        // requires exactly three tokens.
        let tokens: Vec<&str> = line.split(' ').collect();

        if tokens.len() != 3 || tokens[0] != "STATUS" {
            return invalid;
        }

        // `trim` tolerates a trailing carriage return or newline the line reader
        // may have left on the final token, matching Python's `int()` leniency.
        let (Ok(progress), Ok(speed)) = (tokens[1].trim().parse(), tokens[2].trim().parse()) else {
            return invalid;
        };

        Self {
            valid: true,
            progress,
            speed,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Progress in basis points, `0..=10000`.
    pub fn progress(&self) -> u64 {
        self.progress
    }

    pub fn speed(&self) -> u64 {
        self.speed
    }
}

#[cfg(test)]
mod tests {
    use super::GenericStatus;

    #[test]
    fn parses_a_well_formed_status_line() {
        let status = GenericStatus::parse("STATUS 5000 12345");

        assert!(status.is_valid());
        assert_eq!(status.progress(), 5000);
        assert_eq!(status.speed(), 12345);
    }

    #[test]
    fn accepts_the_completion_boundary() {
        let status = GenericStatus::parse("STATUS 10000 0");

        assert!(status.is_valid());
        assert_eq!(status.progress(), GenericStatus::COMPLETE);
    }

    #[test]
    fn tolerates_a_trailing_carriage_return() {
        let status = GenericStatus::parse("STATUS 100 200\r");

        assert!(status.is_valid());
        assert_eq!(status.speed(), 200);
    }

    #[test]
    fn rejects_a_wrong_keyword() {
        assert!(!GenericStatus::parse("PROGRESS 100 200").is_valid());
    }

    #[test]
    fn rejects_the_wrong_token_count() {
        assert!(!GenericStatus::parse("STATUS 100").is_valid());
        assert!(!GenericStatus::parse("STATUS 100 200 300").is_valid());
        // A double space is two splits, so this is four tokens, not three.
        assert!(!GenericStatus::parse("STATUS  100 200").is_valid());
    }

    #[test]
    fn rejects_non_integer_fields() {
        assert!(!GenericStatus::parse("STATUS abc 200").is_valid());
        assert!(!GenericStatus::parse("STATUS 100 xyz").is_valid());
    }

    #[test]
    fn rejects_a_tab_separated_line() {
        // The grammar is space-separated; a tab-joined line is not a status line
        // and would instead be inspected as a possible crack.
        assert!(!GenericStatus::parse("STATUS\t100\t200").is_valid());
    }

    #[test]
    fn a_crack_line_is_not_a_status_line() {
        assert!(!GenericStatus::parse("5f4dcc3b5aa765d61d8327deb882cf99:password").is_valid());
    }
}
