/*
    Two-party implementation of the Musig2 protocol for multi-signatures of EdDSA - Schnorr signatures over Ed25519.
    Musig2 paper: (https://eprint.iacr.org/2020/1261.pdf)
    We implement here a two party version.
    The number of nonces that each party uses (denoted v in the paper) is set to 2.
    We also implement the Musig2* variant (appendix B in the paper) where one of the musig coefficients is set to 1
    in order to save some scalar multiplication, this doesn't affect security.
*/
#![allow(non_snake_case, dead_code)]
use core::fmt;

use curve25519_dalek::constants;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::{thread_rng, Rng};
use sha2::digest::Update;
use sha2::{Digest, Sha512};

#[derive(Debug)]
pub enum Error {
    PublicKeysAreEqual,
    InvalidPublicKey,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeysAreEqual => f.write_str("Public keys Are Equal"),
            Self::InvalidPublicKey => f.write_str("Invalid public key"),
        }
    }
}
impl std::error::Error for Error {}

pub struct KeyPair {
    public_key: EdwardsPoint,
    prefix: [u8; 32],
    private_key: Scalar,
}

impl KeyPair {
    pub fn create() -> (KeyPair, [u8; 32]) {
        let secret = thread_rng().gen();
        (Self::create_from_private_key(secret), secret)
    }

    pub fn create_from_private_key(secret: [u8; 32]) -> KeyPair {
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

    pub fn partial_sign(
        &self,
        other_public_partial_nonces: &PublicPartialNonces,
        my_public_partial_nonces: &PublicPartialNonces,
        my_private_partial_nonces: &PrivatePartialNonces,
        agg_public_key: &AggPublicKeyAndMusigCoeff,
        message: &[u8],
    ) -> (PartialSignature, AggregatedNonce) {
        // Sum up the partial nonces from both parties index-wise, meaning,  R[i]
        // is the sum of partial_nonces[i] from both parties
        // NOTE: the number of nonces is v = 2 here!
        let sum_R = [
            my_public_partial_nonces.0[0] + other_public_partial_nonces.0[0],
            my_public_partial_nonces.0[1] + other_public_partial_nonces.0[1],
        ];

        // Compute b as hash of nonces
        let mut result_as_array = [0u8; 64];
        let hash_result = &Sha512::new()
            .chain("musig2 aggregated nonce generation")
            .chain(agg_public_key.agg_public_key.compress().as_bytes())
            .chain(sum_R[0].compress().as_bytes())
            .chain(sum_R[1].compress().as_bytes())
            .chain(message)
            .finalize();
        result_as_array.copy_from_slice(hash_result);
        let b = Scalar::from_bytes_mod_order_wide(&result_as_array);

        // Compute effective nonce
        // The idea is to compute R and r s.t. R = R_0 + b•R_1 and r = r_0 + b•r_1
        let effective_R = sum_R[0] + b * sum_R[1];
        let effective_r = my_private_partial_nonces.0[0] + b * my_private_partial_nonces.0[1];

        // Compute Fiat-Shamir challenge of signature
        let sig_challenge = Signature::k(&effective_R, &agg_public_key.agg_public_key, message);

        let partial_signature =
            sig_challenge * agg_public_key.musig_coefficient * self.private_key + effective_r;

        (
            PartialSignature(partial_signature),
            AggregatedNonce(effective_R),
        )
    }

    pub fn pubkey(&self) -> [u8; 32] {
        self.public_key.compress().0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PrivatePartialNonces([Scalar; 2]);

impl PrivatePartialNonces {
    pub fn serialize(&self) -> [u8; 64] {
        let mut output = [0u8; 64];
        output[..32].copy_from_slice(&self.0[0].to_bytes());
        output[32..64].copy_from_slice(&self.0[1].to_bytes());
        output
    }

    pub fn deserialize(bytes: [u8; 64]) -> Option<Self> {
        Some(Self([
            scalar_from_bytes(&bytes[..32])?,
            scalar_from_bytes(&bytes[32..64])?,
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicPartialNonces([EdwardsPoint; 2]);

impl PublicPartialNonces {
    pub fn serialize(&self) -> [u8; 64] {
        let mut output = [0u8; 64];
        output[..32].copy_from_slice(&self.0[0].compress().0[..]);
        output[32..64].copy_from_slice(&self.0[1].compress().0[..]);
        output
    }

    pub fn deserialize(bytes: [u8; 64]) -> Option<Self> {
        Some(Self([
            edwards_from_bytes(&bytes[..32])?,
            edwards_from_bytes(&bytes[32..64])?,
        ]))
    }
}

pub fn generate_partial_nonces(
    keys: &KeyPair,
    message: Option<&[u8]>,
) -> (PrivatePartialNonces, PublicPartialNonces) {
    let mut rng = rand::thread_rng();
    generate_partial_nonces_internal(keys, message, &mut rng)
}

fn generate_partial_nonces_internal(
    keys: &KeyPair,
    message: Option<&[u8]>,
    rng: &mut impl Rng,
) -> (PrivatePartialNonces, PublicPartialNonces) {
    // here we deviate from the spec, by introducing  non-deterministic element (random number)
    // to the nonce, this is important for MPC implementations
    let r: [Scalar; 2] = [(); 2].map(|_| {
        let mut result_as_array = [0u8; 64];
        let hash_result = &Sha512::new()
            .chain("musig2 private nonce generation")
            .chain(&keys.prefix)
            .chain(message.unwrap_or(&[]))
            .chain(rng.gen::<[u8; 32]>())
            .finalize();
        result_as_array.copy_from_slice(hash_result);
        Scalar::from_bytes_mod_order_wide(&result_as_array)
    });
    let R: [EdwardsPoint; 2] = r.map(|scalar| &scalar * &constants::ED25519_BASEPOINT_TABLE);
    (PrivatePartialNonces(r), PublicPartialNonces(R))
}

// This is useful since when aggregating all public keys we also compute our musig coefficient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggPublicKeyAndMusigCoeff {
    agg_public_key: EdwardsPoint,
    musig_coefficient: Scalar,
}

impl AggPublicKeyAndMusigCoeff {
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

        let edwards_keys = [
            edwards_from_bytes(&keys[0]).ok_or(Error::InvalidPublicKey)?,
            edwards_from_bytes(&keys[1]).ok_or(Error::InvalidPublicKey)?,
        ];

        let mut result_as_array = [0u8; 64];
        let hash_result = &Sha512::new()
            .chain("musig2 public key aggregation")
            .chain(keys[0])
            .chain(keys[1])
            .chain(keys[0])
            .finalize();
        result_as_array.copy_from_slice(hash_result);
        let first_musig_coefficient = Scalar::from_bytes_mod_order_wide(&result_as_array);

        let agg_public_key = first_musig_coefficient * edwards_keys[0] + edwards_keys[1];

        let musig_coefficient = if keys[0] == my_public_key {
            first_musig_coefficient
        } else {
            Scalar::one()
        };

        Ok(Self {
            agg_public_key,
            musig_coefficient,
        })
    }

    pub fn aggregated_pubkey(&self) -> [u8; 32] {
        self.agg_public_key.compress().0
    }
}

// EdDSA Signature
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    R: EdwardsPoint,
    s: Scalar,
}

impl Signature {
    pub fn aggregate_partial_signatures(
        aggregated_nonce: AggregatedNonce,
        partial_sigs: [PartialSignature; 2],
    ) -> Self {
        Self {
            R: aggregated_nonce.0,
            s: partial_sigs[0].0 + partial_sigs[1].0,
        }
    }
    pub fn verify(&self, message: &[u8], public_key: &EdwardsPoint) -> Result<(), &'static str> {
        let k = Self::k(&self.R, public_key, message);
        let A = public_key;

        let kA = A * k;
        let R_plus_kA = kA + self.R;
        let sG = &self.s * &constants::ED25519_BASEPOINT_TABLE;

        if R_plus_kA == sG {
            Ok(())
        } else {
            Err("EdDSA Signature verification failed")
        }
    }

    // This is the Fiat-Shamir hash of all protocol state before signing.
    fn k(R: &EdwardsPoint, PK: &EdwardsPoint, message: &[u8]) -> Scalar {
        let mut result_as_array = [0u8; 64];
        let hash_result = &Sha512::new()
            .chain(R.compress().as_bytes())
            .chain(PK.compress().as_bytes())
            .chain(message)
            .finalize();
        result_as_array.copy_from_slice(hash_result);
        Scalar::from_bytes_mod_order_wide(&result_as_array)
    }

    pub fn serialize(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.R.compress().0[..]);
        out[32..].copy_from_slice(&self.s.as_bytes()[..]);
        out
    }

    pub fn deserialize(bytes: [u8; 64]) -> Option<Self> {
        Some(Self {
            R: edwards_from_bytes(&bytes[..32])?,
            s: scalar_from_bytes(&bytes[32..64])?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSignature(Scalar);

impl PartialSignature {
    pub fn serialize(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn deserialize(bytes: [u8; 32]) -> Option<Self> {
        scalar_from_bytes(&bytes).map(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatedNonce(EdwardsPoint);

impl AggregatedNonce {
    pub fn serialize(&self) -> [u8; 32] {
        self.0.compress().0
    }

    pub fn deserialize(bytes: [u8; 32]) -> Option<Self> {
        edwards_from_bytes(&bytes).map(Self)
    }
}

/// Converts 32 bytes into a Scalar, checking that the scalar is fully reduced.
///
/// # Panics
/// If the input `bytes` slice does not have a length of 32.
#[inline(always)]
fn scalar_from_bytes(bytes: &[u8]) -> Option<Scalar> {
    // Source: https://github.com/dalek-cryptography/ed25519-dalek/blob/ad461f4/src/signature.rs#L85
    let bytes: [u8; 32] = bytes.try_into().unwrap();
    // Since this is only used in signature deserialisation (i.e. upon
    // verification), we can do a "succeed fast" trick by checking that the most
    // significant 4 bits are unset.  If they are unset, we can succeed fast
    // because we are guaranteed that the scalar is fully reduced.  However, if
    // the 4th most significant bit is set, we must do the full reduction check,
    // as the order of the basepoint is roughly a 2^(252.5) bit number.
    //
    // This succeed-fast trick should succeed for roughly half of all scalars.
    if bytes[31] & 240 == 0 {
        Some(Scalar::from_bits(bytes))
    } else {
        Scalar::from_canonical_bytes(bytes)
    }
}

/// Converts 32 bytes into an edwards point.
/// Checks both that the Y coordinate is on the curve, and that the resulting point is torsion free.
///
/// # Panics
/// If the input `bytes` slice does not have a length of 32.
#[inline(always)]
fn edwards_from_bytes(bytes: &[u8]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY::from_slice(bytes).decompress()?;
    // We require that the point will be 0 in the small subgroup,
    // `is_small_order()` checks if the point is *only* in the small subgroup,
    // while `is_torsion_free()` makes sure the point is 0 in the small subgroup.
    point.is_torsion_free().then(|| point)
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::protocol::{
        aggregate_partial_signatures, aggregate_public_keys, generate_partial_nonces_internal,
        partial_sign,
    };
    use crate::protocol::{ExpandedKeyPair, Signature};
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::Scalar;
    use ed25519_dalek::Verifier;
    use hex::decode;
    use rand::{thread_rng, Rng};
    use rand_xoshiro::rand_core::{RngCore, SeedableRng};
    use rand_xoshiro::Xoshiro256PlusPlus;

    /// This will generate a fast deterministic rng and will print the seed,
    /// if a test fails, pass in the printed seed to reproduce.
    pub fn deterministic_fast_rand(name: &str, seed: Option<u64>) -> impl Rng {
        let seed = seed.unwrap_or_else(|| thread_rng().gen());
        println!("{} seed: {}", name, seed);
        Xoshiro256PlusPlus::seed_from_u64(seed)
    }

    pub fn verify_dalek(pk: &EdwardsPoint, sig: &Signature, msg: &[u8]) -> bool {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(sig.R.compress().as_bytes());
        sig_bytes[32..].copy_from_slice(sig.s.as_bytes());

        let dalek_pub = ed25519_dalek::PublicKey::from_bytes(pk.compress().as_bytes()).unwrap();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes).unwrap();

        dalek_pub.verify(msg, &dalek_sig).is_ok()
    }

    #[test]
    fn test_generate_pubkey_dalek() {
        let mut rng = deterministic_fast_rand("test_generate_pubkey_dalek", None);

        let mut privkey = [0u8; 32];
        for _ in 0..4096 {
            rng.fill_bytes(&mut privkey);
            let zengo_keypair = ExpandedKeyPair::create_from_private_key(privkey);
            let dalek_secret = ed25519_dalek::SecretKey::from_bytes(&privkey)
                .expect("Can only fail if bytes.len()<32");
            let dalek_pub = ed25519_dalek::PublicKey::from(&dalek_secret);

            let zengo_compressed_pub = zengo_keypair.public_key.compress();
            let zengo_pub_serialized = zengo_compressed_pub.as_bytes();
            let dalek_pub_serialized = dalek_pub.to_bytes();

            assert_eq!(zengo_pub_serialized, &dalek_pub_serialized);
        }
    }

    #[test]
    fn test_ed25519_generate_keypair_from_seed() {
        let priv_str = "48ab347b2846f96b7bcd00bf985c52b83b92415c5c914bc1f3b09e186cf2b14f"; // Private Key
        let priv_dec: [u8; 32] = decode(priv_str).unwrap().try_into().unwrap();

        let expected_pubkey_hex =
            "c7d17a93f129527bf7ca413f34a0f23c8462a9c3a3edd4f04550a43cdd60b27a";
        let expected_pubkey: [u8; 32] = decode(expected_pubkey_hex).unwrap().try_into().unwrap();

        let keypair = ExpandedKeyPair::create_from_private_key(priv_dec);
        let pubkey = keypair.public_key;
        assert_eq!(
            pubkey.compress().as_bytes(),
            &expected_pubkey,
            "Public keys do not match!"
        );
    }

    #[test]
    fn test_multiparty_signing_for_two_parties() {
        let mut rng = deterministic_fast_rand("test_multiparty_signing_for_two_parties", None);
        for _i in 0..50 {
            test_multiparty_signing_for_two_parties_internal(&mut rng);
        }
    }

    fn test_multiparty_signing_for_two_parties_internal(rng: &mut impl Rng) {
        let message: [u8; 12] = [79, 77, 69, 82, 60, 61, 100, 156, 109, 125, 3, 19];

        // generate signing keys and partial nonces
        let party0_key = ExpandedKeyPair::create();
        let party1_key = ExpandedKeyPair::create();

        let (p0_private_nonces, p0_public_nonces) =
            generate_partial_nonces_internal(&party0_key, Option::Some(&message), rng);
        let (p1_private_nonces, p1_public_nonces) =
            generate_partial_nonces_internal(&party1_key, Option::Some(&message), rng);

        // compute aggregated public key:
        let party0_key_agg =
            match aggregate_public_keys(&party0_key.public_key, &party1_key.public_key) {
                Some(pub_key_agg) => pub_key_agg,
                None => panic!("Both public keys are the same"),
            };
        let party1_key_agg =
            match aggregate_public_keys(&party1_key.public_key, &party0_key.public_key) {
                Some(pub_key_agg) => pub_key_agg,
                None => panic!("Both public keys are the same"),
            };
        assert_eq!(party0_key_agg.agg_public_key, party1_key_agg.agg_public_key);
        assert!(
            (party0_key_agg.musig_coefficient == Scalar::one()
                || party1_key_agg.musig_coefficient == Scalar::one())
                && (party0_key_agg.musig_coefficient != Scalar::one()
                    || party1_key_agg.musig_coefficient != Scalar::one())
        );
        // Compute partial signatures
        let s0 = partial_sign(
            &p1_public_nonces,
            &p0_public_nonces,
            &p0_private_nonces,
            &party0_key_agg,
            &party0_key,
            &message,
        );
        let s1 = partial_sign(
            &p0_public_nonces,
            &p1_public_nonces,
            &p1_private_nonces,
            &party1_key_agg,
            &party1_key,
            &message,
        );

        let signature0 = aggregate_partial_signatures(&s0, &s1.my_partial_s);
        let signature1 = aggregate_partial_signatures(&s1, &s0.my_partial_s);
        assert!(s0.R == s1.R, "Different partial nonce aggregation!");
        assert!(signature0.s == signature1.s);
        // debugging asserts
        assert!(
            s0.my_partial_s + s1.my_partial_s == signature0.s,
            "signature aggregation failed!"
        );
        // verify:
        assert!(
            signature0
                .verify(&message, &party0_key_agg.agg_public_key)
                .is_ok(),
            "Verification failed!"
        );
        // Verify result against dalek
        assert!(
            verify_dalek(&party0_key_agg.agg_public_key, &signature0, &message),
            "Dalek signature verification failed!"
        );
    }
}
