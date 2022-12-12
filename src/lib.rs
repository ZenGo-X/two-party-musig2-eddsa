//!    Two-party implementation of the Musig2 protocol for multi-signatures of EdDSA - Schnorr signatures over Ed25519.
//!
//!    Musig2 paper: <https://eprint.iacr.org/2020/1261.pdf>
//!
//!    We implement here a two party version.
//!
//!    The number of nonces that each party uses (denoted v in the paper) is set to 2.
//!
//!    We also implement the Musig2* variant (appendix B in the paper) where one of the musig coefficients is set to 1
//!
//!    in order to save some scalar multiplication, this doesn't affect security.

#![allow(non_snake_case)]
#![warn(missing_docs, unsafe_code, future_incompatible)]
mod derive;
mod serde;
use core::fmt;
pub mod aggregate;
pub mod common;
pub mod keypair;
pub mod partialsig;
pub mod privatepartialnonces;
pub mod publicpartialnonces;
pub mod signature;

/// Errors that may occur while processing signatures and keys
#[derive(Debug)]
pub enum Error {
    /// aggregating 2 pubkeys that are equal is disallowed
    PublicKeysAreEqual,
    /// Public Keys must be valid ed25519 prime order points.
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

#[cfg(test)]
mod tests {
    use crate::aggregate::{AggPublicKeyAndMusigCoeff, DerivationData};
    use crate::keypair::KeyPair;
    use crate::signature::Signature;
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

    pub fn verify_dalek(pk: [u8; 32], sig: [u8; 64], msg: &[u8]) -> bool {
        let dalek_pub = ed25519_dalek::PublicKey::from_bytes(&pk).unwrap();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig).unwrap();

        dalek_pub.verify(msg, &dalek_sig).is_ok()
    }

    #[test]
    fn test_generate_pubkey_dalek() {
        let mut rng = deterministic_fast_rand("test_generate_pubkey_dalek", None);

        let mut privkey = [0u8; 32];
        for _ in 0..4096 {
            rng.fill_bytes(&mut privkey);
            let zengo_keypair = KeyPair::create_from_private_key(privkey);
            let dalek_secret = ed25519_dalek::SecretKey::from_bytes(&privkey)
                .expect("Can only fail if bytes.len()<32");
            let dalek_pub = ed25519_dalek::PublicKey::from(&dalek_secret);

            assert_eq!(zengo_keypair.pubkey(), dalek_pub.to_bytes());
        }
    }

    #[test]
    fn test_sign_dalek_verify_zengo() {
        let mut rng = deterministic_fast_rand("test_sign_dalek_verify_zengo", None);

        let mut privkey = [0u8; 32];
        let mut msg = [0u8; 512];
        for msg_len in 0..msg.len() {
            let msg = &mut msg[..msg_len];
            rng.fill_bytes(&mut privkey);
            rng.fill_bytes(msg);
            let dalek_secret = ed25519_dalek::SecretKey::from_bytes(&privkey)
                .expect("Can only fail if bytes.len()<32");
            let dalek_expanded_secret = ed25519_dalek::ExpandedSecretKey::from(&dalek_secret);
            let dalek_pub = ed25519_dalek::PublicKey::from(&dalek_expanded_secret);
            let dalek_sig = dalek_expanded_secret.sign(msg, &dalek_pub);

            let zengo_sig = Signature::deserialize(dalek_sig.to_bytes()).unwrap();
            zengo_sig.verify(msg, dalek_pub.to_bytes()).unwrap();
        }
    }

    #[test]
    fn test_ed25519_generate_keypair_from_seed() {
        let priv_str = "48ab347b2846f96b7bcd00bf985c52b83b92415c5c914bc1f3b09e186cf2b14f"; // Private Key
        let priv_dec: [u8; 32] = decode(priv_str).unwrap().try_into().unwrap();

        let expected_pubkey_hex =
            "c7d17a93f129527bf7ca413f34a0f23c8462a9c3a3edd4f04550a43cdd60b27a";
        let expected_pubkey: [u8; 32] = decode(expected_pubkey_hex).unwrap().try_into().unwrap();

        let keypair = KeyPair::create_from_private_key(priv_dec);
        assert_eq!(
            keypair.pubkey(),
            expected_pubkey,
            "Public keys do not match!"
        );
    }

    #[test]
    fn test_two_party_signing_with_derivation() {
        let mut rng = deterministic_fast_rand("test_two_party_signing_with_derivation", None);

        let mut msg = [0u8; 256];
        let mut derivation = [0u32; 16];
        for msg_len in 0..msg.len() {
            let msg = &mut msg[..msg_len];
            let derivation = &mut derivation[..(msg_len & 0b111)];
            rng.fill(msg);
            rng.fill(derivation);

            let mut simulator = Musig2Simulator::gen_rand(&mut rng);
            simulator.derive_key(derivation);
            let sig = simulator.simulate_sign(msg, &mut rng);

            sig.verify(msg, simulator.agg_pubkey()).unwrap();
            // Verify result against dalek
            assert!(verify_dalek(simulator.agg_pubkey(), sig.serialize(), msg));
        }
    }

    #[test]
    fn test_two_party_signing() {
        let mut rng = deterministic_fast_rand("test_two_party_signing", None);

        let mut msg = [0u8; 256];
        for msg_len in 0..msg.len() {
            let msg = &mut msg[..msg_len];
            rng.fill_bytes(msg);
            let simulator = Musig2Simulator::gen_rand(&mut rng);
            let sig = simulator.simulate_sign(msg, &mut rng);

            sig.verify(msg, simulator.agg_pubkey()).unwrap();
            // Verify result against dalek
            assert!(verify_dalek(simulator.agg_pubkey(), sig.serialize(), msg));
        }
    }

    #[test]
    fn test_invalid_sig() {
        let mut rng = deterministic_fast_rand("test_invalid_sig", None);
        let msg: [u8; 32] = rng.gen();
        let simulator = Musig2Simulator::gen_rand(&mut rng);
        let mut sig = simulator.simulate_sign(&msg, &mut rng);
        sig.s += Scalar::from(1u32);
        sig.verify(&msg, simulator.agg_pubkey()).unwrap_err();
    }

    #[test]
    fn test_equal_pubkeys() {
        let mut rng = deterministic_fast_rand("test_equal_pubkeys", None);
        let keypair = KeyPair::create_from_private_key(rng.gen());
        let pubkey = keypair.pubkey();
        AggPublicKeyAndMusigCoeff::aggregate_public_keys(pubkey, pubkey).unwrap_err();
    }

    pub struct Musig2Simulator {
        keypair1: KeyPair,
        keypair2: KeyPair,
        pub(crate) aggpubkey1: AggPublicKeyAndMusigCoeff,
        pub(crate) aggpubkey2: AggPublicKeyAndMusigCoeff,
        derivation_data: Option<DerivationData>,
    }

    impl Musig2Simulator {
        fn gen_rand(rng: &mut impl Rng) -> Self {
            let keypair1 = KeyPair::create_from_private_key(rng.gen());
            let keypair2 = KeyPair::create_from_private_key(rng.gen());
            let aggpubkey1 = AggPublicKeyAndMusigCoeff::aggregate_public_keys(
                keypair1.pubkey(),
                keypair2.pubkey(),
            )
            .unwrap();
            let aggpubkey2 = AggPublicKeyAndMusigCoeff::aggregate_public_keys(
                keypair2.pubkey(),
                keypair1.pubkey(),
            )
            .unwrap();

            let sim = Self {
                keypair1,
                keypair2,
                aggpubkey1,
                aggpubkey2,
                derivation_data: None,
            };
            sim.assert_correct_aggkeys();
            sim
        }

        fn assert_correct_aggkeys(&self) {
            assert_eq!(
                self.aggpubkey1.agg_public_key,
                self.aggpubkey2.agg_public_key
            );
            // only one of them should be equal to 1.
            assert_ne!(
                self.aggpubkey1.musig_coefficient == Scalar::one(),
                self.aggpubkey2.musig_coefficient == Scalar::one()
            );
        }

        fn agg_pubkey(&self) -> [u8; 32] {
            self.aggpubkey1.aggregated_pubkey()
        }

        fn derive_key(&mut self, path: &[u32]) {
            let (aggpubkey1, derivation_data1) = self.aggpubkey1.derive_key(path);
            let (aggpubkey2, derivation_data2) = self.aggpubkey2.derive_key(path);
            self.aggpubkey1 = aggpubkey1;
            self.aggpubkey2 = aggpubkey2;
            assert_eq!(derivation_data1, derivation_data2);
            self.derivation_data = Some(derivation_data1);
            self.assert_correct_aggkeys();
        }

        fn simulate_sign(&self, msg: &[u8], rng: &mut impl Rng) -> Signature {
            // randomly either pass `Some(msg)` or `None`.
            let (private_nonces1, public_nonces1) =
                self.keypair1.generate_partial_nonces(Some(msg));

            let (private_nonces2, public_nonces2) =
                self.keypair1.generate_partial_nonces(Some(msg));

            let sign_function = |keypair, nonce, nonces, agg, msg| match &self.derivation_data {
                Some(derivation_data) => {
                    KeyPair::partial_sign_derived(keypair, nonce, nonces, agg, msg, derivation_data)
                }
                None => KeyPair::partial_sign(keypair, nonce, nonces, agg, msg),
            };

            // Compute partial signatures
            let (partial_sig1, aggregated_nonce1) = sign_function(
                &self.keypair1,
                private_nonces1,
                [public_nonces1.clone(), public_nonces2.clone()],
                &self.aggpubkey1,
                msg,
            );
            let (partial_sig2, aggregated_nonce2) = sign_function(
                &self.keypair2,
                private_nonces2,
                [public_nonces1, public_nonces2],
                &self.aggpubkey2,
                msg,
            );
            assert_eq!(aggregated_nonce1, aggregated_nonce2);
            assert_eq!(aggregated_nonce1.serialize(), aggregated_nonce2.serialize());

            let signature0 = Signature::aggregate_partial_signatures(
                aggregated_nonce1,
                [partial_sig1.clone(), partial_sig2.clone()],
            );
            let signature1 = Signature::aggregate_partial_signatures(
                aggregated_nonce2,
                [partial_sig2, partial_sig1],
            );
            assert_eq!(signature0, signature1);
            assert_eq!(signature0.serialize(), signature1.serialize());
            signature0
        }
    }
}
