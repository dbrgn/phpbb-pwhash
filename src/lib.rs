//! A re-implementation of the `phpbb_check_hash` function (from phpBB 3) in
//! Rust. It allows verifying a salted hash against a password.
//!
//! ## Usage
//!
//! To verify a hash against a password:
//!
//! ```rust
//! use phpbb_pwhash::{check_hash, CheckHashResult};
//!
//! let hash = "$H$9/O41.qQjQNlleivjbckbSNpfS4xgh0";
//! assert_eq!(
//!     check_hash(hash, "pass1234"),
//!     CheckHashResult::Valid
//! );
//! assert_eq!(
//!     check_hash(hash, "pass1235"),
//!     CheckHashResult::Invalid
//! );
//! ```

/// The result type returned by [`check_hash`](crate::check_hash).
#[derive(Debug, PartialEq)]
pub enum CheckHashResult {
    Valid,
    PasswordTooLong,
    InvalidHash(InvalidHash),
    Invalid,
}

/// The error returned if the encoded hash is invalid.
#[derive(Debug, PartialEq)]
pub enum InvalidHash {
    BadLength,
    UnsupportedHashType,
    InvalidRounds,
    InvalidBase64(base64::DecodeError),
}

/// A parsed encoded phpBB3 hash
#[derive(Debug)]
pub struct PhpbbHash<'a> {
    hash_type: &'a str,
    rounds: usize,
    salt: &'a str,
    hashed: &'a str,
}

// Base64 alphabet
static ALPHABET: &str = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Parse a phpBB3 hash.
///
/// A hash for the password "pass1234" can look like this:
///
/// ```text
/// $H$9/O41.qQjQNlleivjbckbSNpfS4xgh0
/// ```
///
/// Details:
///
/// - The first three characters are the hash type, should be '$H$'.
/// - The fourth character encodes the number of hashing rounds, as a power of
///   two. For example, if the value is '9' as above, then (1 << 11) rounds are
///   used (because the offset from the start of the alphabet for '9' is 11).
///   The offset must be between 7 and 30.
/// - Characters 5-13 are the 8-byte salt.
/// - Characters 13 and onwards are the encoded hash.
pub fn parse_hash(salted_hash: &str) -> Result<PhpbbHash, InvalidHash> {
    // Check for unsalted MD5 hashes
    if salted_hash.len() != 34 {
        return Err(InvalidHash::BadLength);
    }

    // Validate prefix
    let hash_type = &salted_hash[0..3];
    if hash_type != "$H$" {
        return Err(InvalidHash::UnsupportedHashType);
    };

    // Determine rounds
    let rounds = match ALPHABET.find(salted_hash.chars().nth(3).unwrap()) {
        None => return Err(InvalidHash::InvalidRounds),
        Some(offset) if offset < 7 || offset > 30 => return Err(InvalidHash::InvalidRounds),
        Some(offset) => 1 << offset,
    };

    // Determine salt and hashed data
    let salt = &salted_hash[4..12];
    let hashed = &salted_hash[12..];

    Ok(PhpbbHash {
        hash_type,
        rounds,
        salt,
        hashed,
    })
}

/// Decoding function.
///
/// Code taken from phpass re-implementation by Joshua Koudys, licensed under
/// the MIT license (https://github.com/clausehound/phpass).
fn decode64(val: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    // We pad by 0s, encoded as .
    let len = val.len();
    let bytes = base64::decode_config(
        std::iter::repeat(b'.')
            // Base64 encodes on 3-byte boundaries
            .take(3 - len % 3)
            .chain(val.iter().cloned().rev())
            .collect::<Vec<_>>(),
        base64::CRYPT,
    )?
    .iter()
    // Then those backwards-fed inputs need their outputs reversed.
    .rev()
    .take(16)
    .copied()
    .collect::<Vec<_>>();

    Ok(bytes)
}

/// Validate a password against a phpBB3 salted hash.
pub fn check_hash(salted_hash: &str, password: &str) -> CheckHashResult {
    // Limit password length
    if password.len() > 4096 {
        return CheckHashResult::PasswordTooLong;
    }
    let password_bytes = password.as_bytes();
    let password_bytes_len = password_bytes.len();

    // Parse salted hash
    let parsed = match parse_hash(salted_hash) {
        Ok(p) => p,
        Err(e) => return CheckHashResult::InvalidHash(e),
    };

    // Decode hash
    let decoded_hashed = match decode64(parsed.hashed.as_bytes()) {
        Ok(d) => d,
        Err(e) => return CheckHashResult::InvalidHash(InvalidHash::InvalidBase64(e)),
    };

    // Initial hash
    let mut buf: Vec<u8> = Vec::with_capacity(8 + password_bytes_len);
    buf.extend_from_slice(parsed.salt.as_bytes());
    buf.extend_from_slice(password.as_bytes());
    let mut hash = md5::compute(&buf);

    // Some additional rounds of hashing
    // (Yeah, this re-allocates a buffer for every round, could be improved.)
    for _ in 0..parsed.rounds {
        let mut buf: Vec<u8> = Vec::with_capacity(16 /* md5 */ + password_bytes_len);
        buf.extend_from_slice(&hash.0);
        buf.extend_from_slice(password_bytes);
        hash = md5::compute(&buf);
    }

    if hash.0.as_ref() == decoded_hashed {
        CheckHashResult::Valid
    } else {
        CheckHashResult::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestCase {
        encoded_hash: &'static str,
        password: &'static str,
        result: CheckHashResult,
    }

    #[test]
    fn test_validation() {
        let test_cases = [
            TestCase {
                encoded_hash: "$H$9/O41.qQjQNlleivjbckbSNpfS4xgh0",
                password: "pass1234",
                result: CheckHashResult::Valid,
            },
            TestCase {
                encoded_hash: "$H$9PoEptdBNUJZuamBBKOr/KPdi1ZmSw1",
                password: "pass1234",
                result: CheckHashResult::Valid,
            },
            TestCase {
                encoded_hash: "$H$94VS2e40wcTQ38TK2P2yBc0TnmMfLC1",
                password: "pass1234",
                result: CheckHashResult::Valid,
            },
            TestCase {
                encoded_hash: "$H$9/O41.qQjQNlleivjbckbSNpfS4xgh0",
                password: "pass1235",
                result: CheckHashResult::Invalid,
            },
            TestCase {
                encoded_hash: "$H$9/O41.qQjQNlleivjbckbSNpfS4xgh012",
                password: "pass1234",
                result: CheckHashResult::InvalidHash(InvalidHash::BadLength),
            },
            TestCase {
                encoded_hash: "$X$9/O41.qQjQNlleivjbckbSNpfS4xgh0",
                password: "pass1234",
                result: CheckHashResult::InvalidHash(InvalidHash::UnsupportedHashType),
            },
            TestCase {
                encoded_hash: "$H$1/O41.qQjQNlleivjbckbSNpfS4xgh0",
                password: "pass1234",
                result: CheckHashResult::InvalidHash(InvalidHash::InvalidRounds),
            },
        ];
        for case in &test_cases {
            let result = check_hash(case.encoded_hash, case.password);
            assert_eq!(result, case.result, "{:?}", case);
        }
    }
}
