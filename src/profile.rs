//! The post-quantum crypto profile a node runs, the counterpart of macula's
//! `macula_crypto_profile` and macula-go's `profile`. A realm runs one profile
//! and every node in it is configured with that one: there is no default, no
//! negotiation and no classical fallback.

use std::fmt;

/// A crypto profile, by the name a node is configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// The CNSA 2.0 profile: ML-DSA-87 signatures, with no classical half.
    PqPure,
    /// The hybrid profile, the fleet's: ML-DSA-87 alone in TLS, and every
    /// other signature the LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512,
    /// valid only if both halves verify.
    PqHybrid,
}

/// A configured value that names no profile: empty, or not exactly one of
/// `pq_pure` and `pq_hybrid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// No profile is configured.
    Missing,
    /// The value is not exactly one known profile.
    Unknown(String),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::Missing => f.write_str("no crypto profile is configured"),
            ProfileError::Unknown(value) => write!(f, "not a known crypto profile: {value:?}"),
        }
    }
}

impl std::error::Error for ProfileError {}

impl Profile {
    /// The profile `value` names, exactly.
    pub fn parse(value: &str) -> Result<Profile, ProfileError> {
        match value {
            "" => Err(ProfileError::Missing),
            "pq_pure" => Ok(Profile::PqPure),
            "pq_hybrid" => Ok(Profile::PqHybrid),
            other => Err(ProfileError::Unknown(other.to_owned())),
        }
    }

    /// The name a node is configured with, and that node_ids are derived
    /// over.
    pub fn name(self) -> &'static str {
        match self {
            Profile::PqPure => "pq_pure",
            Profile::PqHybrid => "pq_hybrid",
        }
    }

    /// Whether identity, CONNECT and status signatures pair ML-DSA-87 with
    /// RSA-PSS-4096.
    pub fn hybrid(self) -> bool {
        self == Profile::PqHybrid
    }

    /// The signature algorithm's name, as signed structures carry it.
    pub fn sig_alg(self) -> &'static str {
        match self {
            Profile::PqPure => "ML-DSA-87",
            Profile::PqHybrid => "ML-DSA-87-PS384",
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
