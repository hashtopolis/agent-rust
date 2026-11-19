//! The RFC 9530 `Repr-Digest` header.
//!
//! The server announces the BLAKE3 digest of the file it is about to serve as
//! `Repr-Digest: blake3=:<base64 of the 32 raw bytes>:`, which lets the agent
//! check the bytes it received rather than only their count. The header is
//! absent until the server's checksum job has run, so reading it has to report
//! "nothing to verify" as a first-class outcome rather than as an error.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// The algorithm key the server uses. RFC 9530 keys are lowercase.
const BLAKE3: &str = "blake3";

/// What a `Repr-Digest` field value had to say about BLAKE3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReprDigest {
    /// A digest to verify the downloaded bytes against.
    Blake3([u8; 32]),
    /// No BLAKE3 member: there is nothing to verify, which is the normal state
    /// until the server has computed the file's checksum.
    Absent,
    /// A BLAKE3 member the agent could not read. Carries why, for the warning.
    Unreadable(&'static str),
}

/// Reads the BLAKE3 digest out of a `Repr-Digest` field value.
///
/// RFC 9530 makes the field a structured-field dictionary whose members are
/// byte sequences, so several algorithms may be offered at once
/// (`sha-256=:…:, blake3=:…:`) and each member may carry parameters. The server
/// only ever sends the one BLAKE3 member, but parsing the general shape costs
/// nothing and keeps a future second algorithm from looking like corruption.
/// Algorithms other than BLAKE3 are ignored.
pub fn parse_repr_digest(value: &str) -> ReprDigest {
    for member in value.split(',') {
        let Some((key, encoded)) = member.split_once('=') else {
            continue;
        };

        if key.trim().eq_ignore_ascii_case(BLAKE3) {
            return decode(encoded);
        }
    }

    ReprDigest::Absent
}

/// Decodes the byte-sequence half of a `blake3=…` member.
fn decode(encoded: &str) -> ReprDigest {
    // Structured-field parameters (`;q=1`) are not part of the byte sequence.
    let encoded = encoded.split(';').next().unwrap_or_default().trim();

    let Some(encoded) = encoded
        .strip_prefix(':')
        .and_then(|rest| rest.strip_suffix(':'))
    else {
        return ReprDigest::Unreadable("not a `:base64:` byte sequence");
    };

    let Ok(bytes) = STANDARD.decode(encoded) else {
        return ReprDigest::Unreadable("not valid base64");
    };

    match <[u8; 32]>::try_from(bytes.as_slice()) {
        Ok(digest) => ReprDigest::Blake3(digest),
        Err(_) => ReprDigest::Unreadable("not a 32 byte digest"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published BLAKE3 vector for `hello`, in the two encodings the server
    /// uses: hex in its database, base64 in the header. Hard-coding both sides
    /// is what proves this crate agrees with the server's `b3sum`.
    const HELLO_HEX: &str = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";
    const HELLO_B64: &str = "6o8WPbOGgpJeRJHF5Y1Ls1Bu+MFOt4qG6QjFYkpnIA8=";

    fn hello() -> [u8; 32] {
        *blake3::hash(b"hello").as_bytes()
    }

    #[test]
    fn the_crate_agrees_with_b3sum() {
        assert_eq!(blake3::hash(b"hello").to_hex().as_str(), HELLO_HEX);
        assert_eq!(STANDARD.encode(hello()), HELLO_B64);
    }

    #[test]
    fn the_servers_own_form_parses() {
        assert_eq!(
            parse_repr_digest(&format!("blake3=:{HELLO_B64}:")),
            ReprDigest::Blake3(hello())
        );
    }

    #[test]
    fn whitespace_and_key_case_are_tolerated() {
        for value in [
            format!("  blake3=:{HELLO_B64}:  "),
            format!("BLAKE3=:{HELLO_B64}:"),
            format!("Blake3= :{HELLO_B64}: "),
        ] {
            assert_eq!(
                parse_repr_digest(&value),
                ReprDigest::Blake3(hello()),
                "{value}"
            );
        }
    }

    #[test]
    fn blake3_is_picked_out_of_several_algorithms() {
        let sha256 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

        for value in [
            format!("sha-256=:{sha256}:, blake3=:{HELLO_B64}:"),
            format!("blake3=:{HELLO_B64}:, sha-256=:{sha256}:"),
        ] {
            assert_eq!(
                parse_repr_digest(&value),
                ReprDigest::Blake3(hello()),
                "{value}"
            );
        }
    }

    #[test]
    fn member_parameters_are_skipped() {
        assert_eq!(
            parse_repr_digest(&format!("blake3=:{HELLO_B64}:;q=1")),
            ReprDigest::Blake3(hello())
        );
    }

    #[test]
    fn a_header_without_blake3_has_nothing_to_verify() {
        for value in [
            "",
            "sha-256=:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:",
            "sha-512=:AAEC:, md5=:AAEC:",
            // No `=` at all, so no member to read.
            "blake3",
        ] {
            assert_eq!(parse_repr_digest(value), ReprDigest::Absent, "{value:?}");
        }
    }

    #[test]
    fn a_broken_blake3_member_is_unreadable() {
        // Bare base64 with no colons, an unterminated sequence, non-base64
        // content, and base64 of 31 bytes.
        for value in [
            format!("blake3={HELLO_B64}"),
            format!("blake3=:{HELLO_B64}"),
            "blake3=:not base64!:".to_owned(),
            "blake3=:6o8WPbOGgpJeRJHF5Y1Ls1Bu+MFOt4qG6QjFYkpnIA==:".to_owned(),
            "blake3=::".to_owned(),
        ] {
            assert!(
                matches!(parse_repr_digest(&value), ReprDigest::Unreadable(_)),
                "{value}"
            );
        }
    }
}
