//!    Module for private nonces
use crate::common::scalar_from_bytes;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

#[derive(Debug, PartialEq, Eq)]
/// Private Partial Nonces, they should be kept until partially signing a message and then they should be discarded.
///
/// SECURITY: Reusing them across signatures will cause the private key to leak
pub struct PrivatePartialNonces(pub(crate) [Scalar; 2]);

impl PrivatePartialNonces {
    /// Serialize the private partial nonces for storage.
    ///
    /// SECURITY: Do not reuse the nonces across signing instances. reusing the nonces will leak the private key.
    pub fn serialize(&self) -> [u8; 64] {
        let mut output = [0u8; 64];
        output[..32].copy_from_slice(&self.0[0].to_bytes());
        output[32..64].copy_from_slice(&self.0[1].to_bytes());
        output
    }

    /// Deserialize the private nonces,
    /// Will return `None` if they're invalid.
    pub fn deserialize(bytes: [u8; 64]) -> Option<Self> {
        Some(Self([
            scalar_from_bytes(&bytes[..32])?,
            scalar_from_bytes(&bytes[32..64])?,
        ]))
    }
}

impl zeroize::ZeroizeOnDrop for PrivatePartialNonces {}

impl zeroize::Zeroize for PrivatePartialNonces {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl Drop for PrivatePartialNonces {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
