use curve25519_dalek::constants;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{thread_rng, Rng};
use sha2::digest::Update;
use sha2::{Digest, Sha512};

#[derive(Clone, Debug)]
pub struct ExpandedPrivateKey {
    pub prefix: [u8; 32],
    private_key: Scalar,
}

#[derive(Clone, Debug)]
pub struct ExpandedKeyPair {
    pub public_key: EdwardsPoint,
    expanded_private_key: ExpandedPrivateKey,
}

impl ExpandedKeyPair {
    pub fn create() -> ExpandedKeyPair {
        let secret = thread_rng().gen();
        Self::create_from_private_key(secret)
    }

    pub fn create_from_private_key(secret: [u8; 32]) -> ExpandedKeyPair {
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
        ExpandedKeyPair {
            public_key,
            expanded_private_key: ExpandedPrivateKey {
                prefix,
                private_key,
            },
        }
    }
}

pub fn aggregate_public_key(
    my_public_key: &EdwardsPoint,
    other_public_key: &EdwardsPoint,
) -> Option<(EdwardsPoint, Scalar)> {
    // keys should never be equal since we want the server and client to have different shares of the private key.
    if my_public_key == other_public_key {
        return None;
    }
    let first_pub_key: &EdwardsPoint;
    let second_pub_key: &EdwardsPoint;
    let mut my_musig_coefficient = Scalar::one();

    if my_public_key.compress().as_bytes() > other_public_key.compress().as_bytes() {
        first_pub_key = other_public_key;
        second_pub_key = my_public_key;
    } else {
        first_pub_key = my_public_key;
        second_pub_key = other_public_key;
    }

    let mut result_as_array = [0u8; 64];
    let hash_result = &Sha512::new()
        .chain_update("musig2 public key aggregation")
        .chain_update(first_pub_key.compress().as_bytes())
        .chain_update(second_pub_key.compress().as_bytes())
        .chain_update(first_pub_key.compress().as_bytes())
        .finalize();
    result_as_array.copy_from_slice(hash_result);
    let first_musig_coefficient = Scalar::from_bytes_mod_order_wide(&result_as_array);
    let agg_public_key = first_musig_coefficient * first_pub_key + second_pub_key;
    if second_pub_key == my_public_key {
        my_musig_coefficient = first_musig_coefficient;
    }

    Some((agg_public_key, my_musig_coefficient))
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::protocol::ExpandedKeyPair;
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
}
