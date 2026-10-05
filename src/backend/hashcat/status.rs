//! Parser for hashcat's `--machine-readable` STATUS lines. A line is a
//! tab-separated `STATUS <code> KEY values... KEY values...` record; we keep
//! only the fields the progress loop reports and skip the rest.

#[derive(Debug, Clone)]
pub struct HashcatStatus {
    status: i64,
    speed: Vec<(u64, u64)>,
    curku: u64,
    progress: (u64, u64),
    rejected: u64,
    util: Vec<i64>,
    temp: Vec<i64>,
    valid: bool,
}

impl HashcatStatus {
    pub fn parse(line: &str) -> Self {
        let mut parsed = Self::invalid();

        let fields: Vec<&str> = line.trim().split('\t').collect();

        if fields.first() != Some(&"STATUS") {
            return parsed;
        }

        let Some(code) = fields.get(1).and_then(|f| f.parse::<i64>().ok()) else {
            return parsed;
        };

        parsed.status = code;
        parsed.valid = code >= 0;

        let mut i = 2;

        while i < fields.len() {
            let key = fields[i];
            i += 1;

            match key {
                "SPEED" => {
                    while i + 1 < fields.len() {
                        let (Ok(hashes), Ok(period_ms)) =
                            (fields[i].parse::<u64>(), fields[i + 1].parse::<u64>())
                        else {
                            break;
                        };

                        parsed.speed.push((hashes, period_ms));
                        i += 2;
                    }
                }
                "CURKU" => {
                    parsed.curku = fields.get(i).and_then(|f| f.parse().ok()).unwrap_or(0);
                    i += 1;
                }
                "PROGRESS" => {
                    let current = fields.get(i).and_then(|f| f.parse().ok()).unwrap_or(0);
                    let total = fields.get(i + 1).and_then(|f| f.parse().ok()).unwrap_or(0);
                    parsed.progress = (current, total);
                    i += 2;
                }
                "TEMP" => {
                    while i < fields.len() {
                        let Ok(value) = fields[i].parse::<i64>() else {
                            break;
                        };

                        parsed.temp.push(value);
                        i += 1;
                    }
                }
                "UTIL" => {
                    while i < fields.len() {
                        let Ok(value) = fields[i].parse::<i64>() else {
                            break;
                        };

                        parsed.util.push(value);
                        i += 1;
                    }
                }
                "REJECTED" => {
                    parsed.rejected = fields.get(i).and_then(|f| f.parse().ok()).unwrap_or(0);
                    i += 1;
                }
                // Known-but-unused double-valued fields: advance past their two
                // values so the cursor stays aligned on the next key. BRAIN_REJECTED
                // (brain_rejects_attacks, brain_rejects_hashes) is emitted by every
                // WITH_BRAIN hashcat build, right before UTIL, so skipping it is what
                // keeps UTIL reachable.
                "RECHASH" | "RECSALT" | "BRAIN_REJECTED" => i += 2,
                "EXEC_RUNTIME" | "POWER" => {
                    while i < fields.len() && fields[i].parse::<f64>().is_ok() {
                        i += 1;
                    }
                }
                // Unknown key: we can no longer know how many values follow, so
                // stop rather than misread them. The reported fields come first.
                _ => break,
            }
        }

        parsed
    }

    fn invalid() -> Self {
        Self {
            status: -1,
            speed: Vec::new(),
            curku: 0,
            progress: (0, 0),
            rejected: 0,
            util: Vec::new(),
            temp: Vec::new(),
            valid: false,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// The server-facing state is hashcat's status code minus one.
    pub fn state(&self) -> u32 {
        (self.status - 1).max(0) as u32
    }

    pub fn curku(&self) -> u64 {
        self.curku
    }

    pub fn progress(&self) -> u64 {
        self.progress.0
    }

    pub fn progress_total(&self) -> u64 {
        self.progress.1
    }

    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Sum of per-device hashes-per-second, each derived from its (hashes, ms)
    /// pair.
    pub fn speed(&self) -> u64 {
        self.speed
            .iter()
            .filter(|(_, period_ms)| *period_ms > 0)
            .map(|(hashes, period_ms)| ((*hashes as u128) * 1000 / (*period_ms as u128)) as u64)
            .sum()
    }

    pub fn temps(&self) -> &[i64] {
        &self.temp
    }

    pub fn utils(&self) -> &[i64] {
        &self.util
    }
}

/// Strip ANSI CSI escape sequences (`ESC [ ... final`, or the single-byte CSI
/// `0x9B`) so hashcat's coloured output arrives as plain text.
pub(super) fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        let is_csi = c == '\u{9b}' || (c == '\u{1b}' && chars.peek() == Some(&'['));

        if !is_csi {
            out.push(c);
            continue;
        }

        if c == '\u{1b}' {
            chars.next();
        }

        for next in chars.by_ref() {
            if ('@'..='~').contains(&next) {
                break;
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_status_line() {
        let line = "STATUS\t3\tSPEED\t100000\t1000\tEXEC_RUNTIME\t0.50\tCURKU\t2048\t\
                    PROGRESS\t5000\t10000\tRECHASH\t0\t1\tRECSALT\t0\t1\t\
                    TEMP\t60\tREJECTED\t0\tUTIL\t95";

        let status = HashcatStatus::parse(line);

        assert!(status.is_valid());
        assert_eq!(status.state(), 2);
        assert_eq!(status.curku(), 2048);
        assert_eq!(status.progress(), 5000);
        assert_eq!(status.progress_total(), 10000);
        assert_eq!(status.speed(), 100_000);
        assert_eq!(status.temps(), &[60]);
        assert_eq!(status.utils(), &[95]);
    }

    #[test]
    fn parses_util_after_brain_rejected() {
        // The real machine-readable line from any WITH_BRAIN hashcat build (the
        // default): BRAIN_REJECTED sits between REJECTED and UTIL. Parsing must
        // not stop at it, or UTIL is lost and the slow-hash auto-pipe can never
        // read GPU utilisation.
        let line = "STATUS\t3\tSPEED\t178\t1000\tEXEC_RUNTIME\t13.26\tCURKU\t0\t\
                    PROGRESS\t0\t40000\tRECHASH\t0\t4\tRECSALT\t0\t4\tTEMP\t-1\t\
                    REJECTED\t0\tBRAIN_REJECTED\t0\t0\tUTIL\t100\tPOWER\t8519";

        let status = HashcatStatus::parse(line);

        assert!(status.is_valid());
        assert_eq!(status.temps(), &[-1]);
        assert_eq!(status.utils(), &[100]);
    }

    #[test]
    fn parses_multi_device_util_after_brain_rejected() {
        let line = "STATUS\t3\tREJECTED\t0\tBRAIN_REJECTED\t0\t0\tUTIL\t90\t100";

        let status = HashcatStatus::parse(line);

        assert_eq!(status.utils(), &[90, 100]);
    }

    #[test]
    fn multi_device_speed_sums() {
        let line = "STATUS\t3\tSPEED\t100\t1000\t200\t1000\tPROGRESS\t0\t0";

        let status = HashcatStatus::parse(line);

        assert_eq!(status.speed(), 300);
    }

    #[test]
    fn non_status_line_is_invalid() {
        assert!(!HashcatStatus::parse("Cracking finished").is_valid());
        assert!(!HashcatStatus::parse("").is_valid());
    }
}
