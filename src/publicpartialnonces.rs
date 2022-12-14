//!    Module for public nonces
use crate::common::edwards_from_bytes;
use curve25519_dalek::edwards::EdwardsPoint;

/// Public partial nonces, they should be transmitted to the other party in order to generate the aggregated nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicPartialNonces(pub(crate) [EdwardsPoint; 2]);

impl PublicPartialNonces {
    /// Serialize the public partial nonces in order to transmit the other party.
    pub fn serialize(&self) -> [u8; 64] {
        let mut output = [0u8; 64];
        output[..32].copy_from_slice(&self.0[0].compress().0[..]);
        output[32..64].copy_from_slice(&self.0[1].compress().0[..]);
        output
    }

    /// Deserialize the public partial nonces.
    pub fn deserialize(bytes: [u8; 64]) -> Option<Self> {
        Some(Self([
            edwards_from_bytes(&bytes[..32])?,
            edwards_from_bytes(&bytes[32..64])?,
        ]))
    }
}
