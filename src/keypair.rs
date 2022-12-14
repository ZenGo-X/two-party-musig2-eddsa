//!    Module handling the public,secret keypair for musis2

use super::partialsig::*;
use crate::aggregate::{AggPublicKeyAndMusigCoeff, AggregatedNonce, DerivationData};
use crate::common::*;
use crate::privatepartialnonces::PrivatePartialNonces;
use crate::publicpartialnonces::PublicPartialNonces;
use crate::signature::Signature;
use curve25519_dalek::constants;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha512};

/// An ed25519 keypair
pub struct KeyPair {
    public_key: EdwardsPoint,
    prefix: [u8; 32],
    private_key: Scalar,
}

impl KeyPair {
    /// Create a new random keypair,
    /// returns the KeyPair, and the Secret Key.
    /// restoring a KeyPair from the secret key can be done using [`KeyPair::create_from_private_key`]
    pub fn create() -> (KeyPair, [u8; 32]) {
        let secret = thread_rng().gen();
        (Self::create_from_private_key(secret), secret)
    }

    /// Create a KeyPair from an existing secret
    pub fn create_from_private_key(secret: [u8; 32]) -> KeyPair {
        // This is according to the ed25519 spec,
        // we use the first half of the hash as the actual private key
        // and the other half as deterministic randomness for the nonce PRF.
        let h = Sha512::new().chain(secret).finalize();
        let mut private_key_bits: [u8; 32] = [0u8; 32];
        let mut prefix: [u8; 32] = [0u8; 32];
        prefix.copy_from_slice(&h[32..64]);
        private_key_bits.copy_from_slice(&h[0..32]);
        private_key_bits[0] &= 248;
        private_key_bits[31] &= 63;
        private_key_bits[31] |= 64;
        let private_key = Scalar::from_bits(private_key_bits);
        let public_key = &private_key * &constants::ED25519_BASEPOINT_TABLE;
        Self {
            public_key,
            prefix,
            private_key,
        }
    }

    /// Exactly like [`Self::partial_sign`] but for a derived key.
    /// Create a partial ed25519 signature,
    /// Combining this with the other party's partial signature will result in a valid ed25519 signature
    pub fn partial_sign_derived(
        &self,
        private_partial_nonce: PrivatePartialNonces,
        public_partial_nonce: [PublicPartialNonces; 2],
        agg_public_key: &AggPublicKeyAndMusigCoeff,
        message: &[u8],
        derived_data: &DerivationData,
    ) -> (PartialSignature, AggregatedNonce) {
        let (mut sig, nonce) = self.partial_sign(
            private_partial_nonce,
            public_partial_nonce,
            agg_public_key,
            message,
        );

        // Only one party needs to adjust the signature, so we limit to just the "first" party in the ordered set.
        if agg_public_key.location == KeySortedLocation::First {
            let challenge = Signature::k(&nonce.0, &agg_public_key.agg_public_key, message);
            sig.0 += derived_data.0 * challenge;
        }
        (sig, nonce)
    }

    /// Create a partial ed25519 signature,
    /// Combining this with the other party's partial signature will result in a valid ed25519 signature
    pub fn partial_sign(
        &self,
        private_partial_nonce: PrivatePartialNonces,
        public_partial_nonce: [PublicPartialNonces; 2],
        agg_public_key: &AggPublicKeyAndMusigCoeff,
        message: &[u8],
    ) -> (PartialSignature, AggregatedNonce) {
        // Sum up the partial nonces from both parties index-wise, meaning,  R[i]
        // is the sum of partial_nonces[i] from both parties
        // NOTE: the number of nonces is v = 2 here!
        let sum_R = [
            public_partial_nonce[0].0[0] + public_partial_nonce[1].0[0],
            public_partial_nonce[0].0[1] + public_partial_nonce[1].0[1],
        ];

        // Compute b as hash of nonces
        // `Scalar::from_hash` reduces the output mod order.
        let b = Scalar::from_hash(
            Sha512::new()
                .chain("musig2 aggregated nonce generation")
                .chain(agg_public_key.agg_public_key.compress().as_bytes())
                .chain(sum_R[0].compress().as_bytes())
                .chain(sum_R[1].compress().as_bytes())
                .chain(message),
        );

        // Compute effective nonce
        // The idea is to compute R and r s.t. R = R_0 + b•R_1 and r = r_0 + b•r_1
        let effective_R = sum_R[0] + b * sum_R[1];
        let effective_r = private_partial_nonce.0[0] + b * private_partial_nonce.0[1];

        // Compute Fiat-Shamir challenge of signature
        let sig_challenge = Signature::k(&effective_R, &agg_public_key.agg_public_key, message);

        let partial_signature =
            effective_r + (agg_public_key.musig_coefficient * self.private_key * sig_challenge);
        (
            PartialSignature(partial_signature),
            AggregatedNonce(effective_R),
        )
    }

    /// Return the public key associated with the KeyPair
    pub fn pubkey(&self) -> [u8; 32] {
        self.public_key.compress().0
    }
    /// Generate partial nonces, make sure to call this again for every signing session.
    pub fn generate_partial_nonces(
        &self,
        message: Option<&[u8]>,
    ) -> (PrivatePartialNonces, PublicPartialNonces) {
        // generate_partial_nonces_internal(keys, message, &mut thread_rng())
        // here we deviate from the spec, by introducing  non-deterministic element (random number)
        // to the nonce, this is important for MPC implementations
        let r: [Scalar; 2] = [(); 2].map(|_| {
            Scalar::from_hash(
                Sha512::new()
                    .chain("musig2 private nonce generation")
                    .chain(self.prefix)
                    .chain(message.unwrap_or(&[]))
                    .chain(thread_rng().gen::<[u8; 32]>()),
            )
        });
        let R: [EdwardsPoint; 2] = r.map(|scalar| &scalar * &constants::ED25519_BASEPOINT_TABLE);
        (PrivatePartialNonces(r), PublicPartialNonces(R))
    }
}
impl zeroize::ZeroizeOnDrop for KeyPair {}

impl zeroize::Zeroize for KeyPair {
    fn zeroize(&mut self) {
        self.private_key.zeroize()
    }
}

impl zeroize::ZeroizeOnDrop for KeyPair {}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}
