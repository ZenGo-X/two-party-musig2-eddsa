//!    Module handling signature objects for musig2 computation

use crate::aggregate::AggregatedNonce;
use crate::common::{edwards_from_bytes, scalar_from_bytes};
use crate::partialsig::PartialSignature;
use core::fmt;
use curve25519_dalek::constants;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// An Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    R: EdwardsPoint,
    pub(crate) s: Scalar,
}

/// An invalid signature error
#[derive(Debug, Ord, PartialOrd, PartialEq, Eq)]
pub struct InvalidSignature;

impl fmt::Display for InvalidSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Invalid Signature")
    }
}

impl std::error::Error for InvalidSignature {}

impl Signature {
    /// Aggregate 2 partial signatures together into a single valid ed25519 signature.
    pub fn aggregate_partial_signatures(
        aggregated_nonce: AggregatedNonce,
        partial_sigs: [PartialSignature; 2],
    ) -> Self {
        Self {
            R: aggregated_nonce.0,
            s: partial_sigs[0].0 + partial_sigs[1].0,
        }
    }
    /// Verify an ed25519 signature, this is a strict verification and requires both the public key
    /// and the signature's nonce to only be in the big prime-order sub group.
    pub fn verify(&self, message: &[u8], public_key: [u8; 32]) -> Result<(), InvalidSignature> {
        let A = edwards_from_bytes(&public_key).ok_or(InvalidSignature)?;
        let k = Self::k(&self.R, &A, message);

        let kA = A * k;
        let R_plus_kA = kA + self.R;
        let sG = &self.s * &constants::ED25519_BASEPOINT_TABLE;

        if R_plus_kA == sG {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }

    // This is the Fiat-Shamir hash of all protocol state before signing.
    pub(crate) fn k(R: &EdwardsPoint, PK: &EdwardsPoint, message: &[u8]) -> Scalar {
        Scalar::from_hash(
            Sha512::new()
                .chain(R.compress().as_bytes())
                .chain(PK.compress().as_bytes())
                .chain(message),
        )
    }

    /// Serialize the signature
    pub fn serialize(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.R.compress().0[..]);
        out[32..].copy_from_slice(&self.s.as_bytes()[..]);
        out
    }

    /// Deserialize a signature, returns None if the bytes cannot represent a signature.
    pub fn deserialize(bytes: [u8; 64]) -> Option<Self> {
        Some(Self {
            R: edwards_from_bytes(&bytes[..32])?,
            s: scalar_from_bytes(&bytes[32..64])?,
        })
    }
}
