use crate::common::scalar_from_bytes;
use curve25519_dalek::scalar::Scalar;

/// A partial signature, should be aggregated with another partial signature under the same aggregated public key and message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSignature(pub(crate) Scalar);

impl PartialSignature {
    /// Serialize the partial signature
    pub fn serialize(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Deserialize the partial signature, returns None if the bytes cannot represent a signature.
    pub fn deserialize(bytes: [u8; 32]) -> Option<Self> {
        scalar_from_bytes(&bytes).map(Self)
    }
}
