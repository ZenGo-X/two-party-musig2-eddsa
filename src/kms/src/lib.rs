//! # KMS-Edwards25519
//! The `kms-edwards25519` crate is intended to provide an HD-wallet functionality
//! working in a [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
//! like fashion for [Ed25519](https://datatracker.ietf.org/doc/html/rfc8032) keys.
//!
//! **This crate supports only non-hardened derivation mode.**
//!
//! In BIP-32 non-hardened key derivation scheme, a private key $x$ can be used to derive a series of private keys
//! $x_1,x_2,...$. Similarly, $x$'s matching public key $Y=x\cdot B$ (for some bapoint $B$ of the curve) can
//! be used to derive a series of public keys $Y_1,Y_2,...$ such that $Y_i$ is $x_i$'s matching public key. (i.e. $Y_i=x_i \cdot B$ for all $i$)
//!
//! Given the private key $x$ any key $x_i$ can be computed as follows:
//! \\[ x_i = x + h((x\cdot B) || i) \\]
//!
//! Similarly, from the public key $Y$ each $Y_i$ can be computed as follows:
//! \\[ Y_i = Y + h(Y || i)\cdot B \\]
//!
//! Since this crate is expected to be used with ZenGo's MPC implementation[^impl_musig_link]
//! of MuSig2[^musig2_paper] we are not allows the derivation of the private key.
//!
//! [^impl_musig_link]: <https://github.com/ZenGo-X/two-party-musig2-eddsa>
//!
//! [^musig2_paper]: <https://eprint.iacr.org/2020/1261.pdf>
//!
//! # Why no private key derivation?
//! Ed25519, a signature scheme over Edwards25519 curve based on Schnorr's Zero-Knowledge protocol for the knowledge of a
//! discrete logarithm, yields a signature of the form $(R,s)$ for a message $M$ associated with key pair $(x,Y)$ such that:
//!
//! 1. $R = r \cdot B$ for some scalar $r$.
//! 2. $s = r + H(R||Y||M) \cdot x$
//!
//! Now, given keypair $(x,Y)$ say we want to sign a message $M$ using a derived key $(x_i,Y_i)$ derived in non-hardened mode.
//! The derived keys are:
//! \\[
//! \begin{aligned}
//! x_i &= x + \overbrace{h((x\cdot B) || i)}^{\delta_i} \\\\
//! Y_i &= Y + \overbrace{h(Y || i)}^{\delta_i}\cdot B
//! \end{aligned}
//! \\]
//! By denoting $\delta_i = h(Y || i)$ we can write the derived keys as follows:
//! \\[
//! \begin{aligned}
//! x_i &= x + \delta_i \\\\
//! Y_i &= Y + \delta_i\cdot B
//! \end{aligned}
//! \\]
//!
//! Assuming $Y$ is known to all signing parties (if only one party, it is true, in multiparty setting it may not
//! always be the case) then each signing party can compute $\delta_i$ locally from $Y$.
//!
//! A signature for $(x_i,Y_i)$ on message $M$ would therefore be $(R,s)$ such that:
//! - $R = r \cdot B$ for some scalar $r$.
//! - $s = r + H(R || Y_i || M)\cdot x_i$
//!
//! For convenience, let's denote the Fiat-Shamir challenge as $c = H(R || Y_i || M)$,
//! notice that just like $\delta_i$ each signing party can also compute locally $c$.
//! By giving a deeper look into $s$ we get:
//! \\[
//! \begin{aligned}
//! s &= r + c \cdot x_i \\\\
//!  &= \underbrace{r + c \cdot x}_{A} + \underbrace{c \cdot \delta_i}_B \\\\
//! \end{aligned}
//! \\]
//!
//! Now, $A$ can be computed using any regular signature scheme using the **original** private key $x$ (without any derivation),
//! we just have to make sure the Fiat-Shamir challenge used to sign is computed using the derived public key $Y_i$
//! instead of the original public key $Y$.
//!
//! To the resulting value of $A$, we can add $B$ which can be computed by any party owning $Y$ since both $c$ and $\delta_i$
//! can be computed locally by and party owning $Y$.
//!
//! Therefore, we don't need to derive the private key in any point to sign a message for a derived key which is why this library doesn't export a function deriving a private key.
//!
//! # Compatability
//! Notice that no exact specification has been published for a standard HD key derivation for Ed25519.
//! Therefore, the derived keys are not expected to be compatible with any other existing library on the internet.
use blake2::{Blake2s256, Digest};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

fn compute_delta(p: &EdwardsPoint, i: u32) -> Scalar {
    let mut hasher = Blake2s256::new();
    hasher.update(p.compress().0);
    hasher.update(i.to_be_bytes());
    let hash_bits: [u8; 32] = hasher.finalize().try_into().unwrap();

    // Despite BIP-32 parse_256 considers bytes as big endian.
    // Ed25519 considers scalars as little endian so we will
    // go with little endian here.
    if hash_bits[0] & 240 == 0 {
        Scalar::from_bits(hash_bits)
    } else {
        Scalar::from_bytes_mod_order(hash_bits)
    }
}

fn derive_delta_and_public_key_from_path(
    pk: &EdwardsPoint,
    path: &[u32],
) -> (Scalar, EdwardsPoint) {
    path.iter()
        .fold((Scalar::zero(), *pk), |(delta_sum, pk_derived), &i| {
            let delta = compute_delta(&pk_derived, i);
            (
                delta_sum + delta,
                pk_derived + delta * ED25519_BASEPOINT_POINT,
            )
        })
}

/// Computes the delta of a derivation path given a path `path` and a public key `pk`.
///
/// # Arguments
///
/// * `pk` - The public key from which to make the derivation.
/// * `path` - The derivation path represented as a `u32` slice, each entry represents the next derivation level.
///
/// # Example
/// ```
/// use kms_edwards25519::derive_delta_path;
/// use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
/// use curve25519_dalek::scalar::Scalar;
///
/// let scalar_bytes = [1u8; 32];
/// let sk: Scalar = Scalar::from_bytes_mod_order(scalar_bytes);
/// let pk = sk * ED25519_BASEPOINT_POINT;
/// let path = [1,2];
/// let delta = derive_delta_path(&pk, &path);
/// let derived_private_key = sk + delta;
/// let derived_public_key = pk + delta * ED25519_BASEPOINT_POINT;
///
/// ```
pub fn derive_delta_path(pk: &EdwardsPoint, path: &[u32]) -> Scalar {
    derive_delta_and_public_key_from_path(pk, path).0
}

/// Derives a public key from an existing public key and a derivation path.
///
/// # Arguments
///
/// - `pk` - A public key.
/// - `path` - The derivation path.
pub fn derive_public_path(pk: &EdwardsPoint, path: &[u32]) -> EdwardsPoint {
    derive_delta_and_public_key_from_path(pk, path).1
}

#[cfg(test)]
mod tests {

    use crate::{derive_delta_path, derive_public_path};
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use rand_xoshiro::{rand_core::RngCore, rand_core::SeedableRng, Xoshiro256PlusPlus};
    use std::assert_eq;

    fn sample_scalar(rng: &mut Xoshiro256PlusPlus) -> Scalar {
        let mut bytes: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order(bytes)
    }
    #[test]
    fn test_public_and_delta_sanity_empty_path() {
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(0);
        let sk = sample_scalar(&mut rng);
        let pk = sk * ED25519_BASEPOINT_POINT;
        assert_eq!(derive_delta_path(&pk, &[]), Scalar::zero());
        assert_eq!(derive_public_path(&pk, &[]), pk);
    }
    #[test]
    fn test_public_and_delta_sanity_path_length_one() {
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        let sk = sample_scalar(&mut rng);
        let pk = sk * ED25519_BASEPOINT_POINT;
        let path = [1];
        let delta = derive_delta_path(&pk, &path);
        let derived_pk = derive_public_path(&pk, &path);
        assert_ne!(delta, Scalar::zero());
        assert_eq!(derived_pk, pk + delta * ED25519_BASEPOINT_POINT);
    }
    #[test]
    fn test_public_and_delta_sanity_path_length_two() {
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        let sk = sample_scalar(&mut rng);
        let pk = sk * ED25519_BASEPOINT_POINT;
        let path = [1, u32::MAX];
        let delta = derive_delta_path(&pk, &path);
        let derived_pk = derive_public_path(&pk, &path);
        assert_ne!(delta, Scalar::zero());
        assert_eq!(derived_pk, pk + delta * ED25519_BASEPOINT_POINT);
    }
}
