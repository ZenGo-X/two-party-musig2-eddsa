use std::convert::TryInto;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use crate::{derive, Error};
use crate::common::{edwards_from_bytes, KeySortedLocation, scalar_from_bytes};

impl std::error::Error for Error {}

/// This is useful since when aggregating all public keys we also compute our musig coefficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggPublicKeyAndMusigCoeff {
    pub(crate) agg_public_key: EdwardsPoint,
    pub(crate) musig_coefficient: Scalar,
    pub(crate) location: KeySortedLocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Data required to sign for the derived public key, this is generated when [`AggPublicKeyAndMusigCoeff::derive_key`] is called,
/// and this needs to be passed to [`KeyPair::partial_sign_derived`] when signing
pub struct DerivationData(pub(crate) Scalar);

impl AggPublicKeyAndMusigCoeff {
    /// Aggregate public keys. This creates a combined public key that requires both parties in order to sign messages.
    pub fn aggregate_public_keys(
        my_public_key: [u8; 32],
        other_public_key: [u8; 32],
    ) -> Result<Self, Error> {
        // keys should never be equal since we want the server and client to have different shares of the private key.
        if my_public_key == other_public_key {
            return Err(Error::PublicKeysAreEqual);
        }
        // By section B of the paper, we sort the public keys and set the musig coefficient for the second one as 1.
        let mut keys = [my_public_key, other_public_key];
        keys.sort_unstable();
        let location = if keys[0] == my_public_key {
            KeySortedLocation::First
        } else {
            KeySortedLocation::Second
        };

        let edwards_keys = [
            edwards_from_bytes(&keys[0]).ok_or(Error::InvalidPublicKey)?,
            edwards_from_bytes(&keys[1]).ok_or(Error::InvalidPublicKey)?,
        ];

        let first_musig_coefficient = Scalar::from_hash(
            Sha512::new()
                .chain("musig2 public key aggregation")
                .chain(keys[0])
                .chain(keys[1])
                .chain(keys[0]),
        );

        let agg_public_key = first_musig_coefficient * edwards_keys[0] + edwards_keys[1];

        let musig_coefficient = if location == KeySortedLocation::First {
            first_musig_coefficient
        } else {
            Scalar::one()
        };

        Ok(Self {
            agg_public_key,
            musig_coefficient,
            location,
        })
    }

    /// Derive a child public key
    pub fn derive_key(&self, path: &[u32]) -> (Self, DerivationData) {
        let (delta, agg_public_key) =
            derive::derive_delta_and_public_key_from_path(self.agg_public_key, path);
        (
            Self {
                agg_public_key,
                musig_coefficient: self.musig_coefficient,
                location: self.location,
            },
            DerivationData(delta),
        )
    }

    /// Returns the serialized aggregated public key.
    pub fn aggregated_pubkey(&self) -> [u8; 32] {
        self.agg_public_key.compress().0
    }

    /// Serialize the aggregated public key and the musig coefficient for storage.
    pub fn serialize(&self) -> [u8; 65] {
        let mut output = [0u8; 65];
        output[..32].copy_from_slice(&self.agg_public_key.compress().0[..]);
        output[32..64].copy_from_slice(&self.musig_coefficient.as_bytes()[..]);
        output[64] = self.location as u8;
        output
    }

    /// Deserialize from bytes as [agg_public_key, musig_coefficient].
    pub fn deserialize(bytes: [u8; 65]) -> Option<Self> {
        Some(Self {
            agg_public_key: edwards_from_bytes(&bytes[..32])?,
            musig_coefficient: scalar_from_bytes(&bytes[32..64])?,
            location: bytes[64].try_into().ok()?,
        })
    }
}



/// The aggregated nonce of both parties, required for aggregating the signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedNonce(pub(crate) EdwardsPoint);

impl AggregatedNonce {
    /// Serialize the aggregated nonce
    pub fn serialize(&self) -> [u8; 32] {
        self.0.compress().0
    }

    /// Deserialize the aggregated nonce
    pub fn deserialize(bytes: [u8; 32]) -> Option<Self> {
        edwards_from_bytes(&bytes).map(Self)
    }
}