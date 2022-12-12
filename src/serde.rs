#![cfg(feature = "serde")]

/// Here we implement serde serialization and deserialization in terms of the `serialize`/`deserialize` functions
/// This will promise us stable platform independent serialization that shouldn't break by modifying types
/// It will also make sure that everything passes the right validations (torsion free etc.)
use serde::{
    de::{Error, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;

use super::privatepartialnonces;
use crate::aggregate::AggPublicKeyAndMusigCoeff;
use crate::aggregate::AggregatedNonce;
use crate::common;
use crate::partialsig::PartialSignature;
use crate::privatepartialnonces::PrivatePartialNonces;
use crate::publicpartialnonces::PublicPartialNonces;
use crate::signature::Signature;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use std::fmt::{Display, Formatter};

macro_rules! serialization {
    ($({name: $name:ident, len: $len:expr, error: $error:expr}),+ $(,)?) => {
        $(
            impl Serialize for $name {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    let serialized = self.serialize();
                    let mut tup = serializer.serialize_tuple($len)?;
                    for byte in &serialized {
                        tup.serialize_element(byte)?;
                    }
                    tup.end()
                }
            }
            impl<'de> Deserialize<'de> for $name {
                fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                    let visitor = ArrayVisitor::<$len> {
                        purpose: stringify!($name),
                    };
                    let array = deserializer.deserialize_tuple($len, visitor)?;
                    Self::deserialize(array).ok_or_else(|| D::Error::custom($error))
                }
            }
        )+
    }
}

serialization!(
    {name: PrivatePartialNonces, len: 64, error: "Invalid private partial nonces"},
    {name: PublicPartialNonces, len: 64, error: "Invalid public partial nonces"},
    {name: AggPublicKeyAndMusigCoeff, len: 65, error: "Invalid aggregated public key or musig coefficient"},
    {name: Signature, len: 64, error: "Invalid signature"},
    {name: PartialSignature, len: 32, error: "Invalid partial signature"},
    {name: AggregatedNonce, len: 32, error: "Invalid aggregated nonce"},
);

/// This is a visitor made to simply deserialize arrays.
/// it is needed because serde doesn't support arrays longer than 32 bytes.
/// Source: https://github.com/serde-rs/serde/issues/631#issuecomment-322677033
struct ArrayVisitor<const N: usize> {
    purpose: &'static str,
}
impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a valid {} byte array representing a {}",
            N, self.purpose
        )
    }

    #[inline(always)]
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut bytes = [0u8; N];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seq
                .next_element()?
                .ok_or_else(|| A::Error::invalid_length(i, &self))?;
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::aggregate::{AggPublicKeyAndMusigCoeff, AggregatedNonce};
    use crate::partialsig::PartialSignature;
    use crate::privatepartialnonces::PrivatePartialNonces;
    use crate::publicpartialnonces::PublicPartialNonces;
    use crate::signature::Signature;
    use crate::{
        AggPublicKeyAndMusigCoeff, AggregatedNonce, PartialSignature, PrivatePartialNonces,
        PublicPartialNonces, Signature,
    };
    use serde::{de::DeserializeOwned, Serialize};
    use serde_test::{assert_de_tokens_error, assert_tokens, Token};
    use std::{any::Any, fmt::Debug};

    const ED25519_BASEPOINT: [u8; 32] = [
        88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
        102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
    ];
    const TORSION_POINT: [u8; 32] = [
        199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44,
        57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122,
    ];

    fn test_max_u8_is_invalid<T, F, const N: usize>(init: [u8; N], create: F, invalid_err: &str)
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug + Any,
        F: FnOnce([u8; N]) -> Option<T>,
    {
        let val = create(init).unwrap();

        // The expected tokens: [Tuple{len}, U8(first), U8(second)....TupleEnd]
        let mut expected_tokens = vec![Token::Tuple { len: N }];
        expected_tokens.extend(init.into_iter().map(Token::U8));
        expected_tokens.push(Token::TupleEnd);
        assert_tokens(&val, &expected_tokens);

        // Error paths:

        // last byte = u8::MAX is both an invalid scalar and an invalid point
        let mut bad_first_half = expected_tokens.clone();
        bad_first_half[1 + 31] = Token::U8(u8::MAX);
        assert_de_tokens_error::<T>(&bad_first_half, invalid_err);

        let mut bad_second_half = expected_tokens.clone();
        bad_second_half[N] = Token::U8(u8::MAX);
        assert_de_tokens_error::<T>(&bad_second_half, invalid_err);

        let invalid_len = [Token::Tuple { len: 1 }, Token::U8(1), Token::TupleEnd];
        let type_name = std::any::type_name::<T>().split("::").last().unwrap();
        assert_de_tokens_error::<T>(
            &invalid_len,
            &format!(
                "invalid length 1, expected a valid {N} byte array representing a {type_name}"
            ),
        );
        // put a torsion point in either, coincidentally it's also an invalid scalar, so this will pass even if the type is scalars.
        let mut torsion_first_half = expected_tokens.clone();
        for (token, byte) in torsion_first_half[1..33].iter_mut().zip(TORSION_POINT) {
            *token = Token::U8(byte);
        }
        assert_de_tokens_error::<T>(&torsion_first_half, invalid_err);

        if N >= 64 {
            let mut torsion_second_half = expected_tokens.clone();
            for (token, byte) in torsion_second_half[33..65].iter_mut().zip(TORSION_POINT) {
                *token = Token::U8(byte);
            }
            assert_de_tokens_error::<T>(&torsion_second_half, invalid_err);
        }
    }

    #[test]
    fn test_partial_private_nonces() {
        let mut i = 0u8;
        let mut serialized = [(); 64].map(|_| {
            i += 1;
            i - 1
        });
        // clear the MSB of both scalars so they'll pass validation
        serialized[31] = 0;
        serialized[63] = 0;
        test_max_u8_is_invalid::<PrivatePartialNonces, _, 64>(
            serialized,
            PrivatePartialNonces::deserialize,
            "Invalid private partial nonces",
        );
    }

    #[test]
    fn test_partial_public_nonces() {
        let mut serialized = [0u8; 64];
        serialized[0..32].copy_from_slice(&ED25519_BASEPOINT);
        serialized[32..64].copy_from_slice(&ED25519_BASEPOINT);

        test_max_u8_is_invalid::<PublicPartialNonces, _, 64>(
            serialized,
            PublicPartialNonces::deserialize,
            "Invalid public partial nonces",
        );
    }

    #[test]
    fn test_aggregated_pubkey() {
        let mut serialized = [0u8; 65];
        serialized[..32].copy_from_slice(&ED25519_BASEPOINT);
        // leave the MSB off so it will be a valid scalar
        for (i, byte) in serialized[32..63].iter_mut().enumerate() {
            *byte = i as u8;
        }
        test_max_u8_is_invalid::<AggPublicKeyAndMusigCoeff, _, 65>(
            serialized,
            AggPublicKeyAndMusigCoeff::deserialize,
            "Invalid aggregated public key or musig coefficient",
        );
    }

    #[test]
    fn test_signature() {
        let mut serialized = [0u8; 64];
        serialized[..32].copy_from_slice(&ED25519_BASEPOINT);
        // leave the MSB off so it will be a valid scalar
        for (i, byte) in serialized[32..63].iter_mut().enumerate() {
            *byte = i as u8;
        }
        test_max_u8_is_invalid::<Signature, _, 64>(
            serialized,
            Signature::deserialize,
            "Invalid signature",
        );
    }

    #[test]
    fn test_partial_signature() {
        let mut serialized = [0u8; 32];
        // leave the MSB off so it will be a valid scalar
        for (i, byte) in serialized[..31].iter_mut().enumerate() {
            *byte = i as u8;
        }
        test_max_u8_is_invalid::<PartialSignature, _, 32>(
            serialized,
            PartialSignature::deserialize,
            "Invalid partial signature",
        );
    }

    #[test]
    fn test_aggregate_nonce() {
        test_max_u8_is_invalid::<AggregatedNonce, _, 32>(
            ED25519_BASEPOINT,
            AggregatedNonce::deserialize,
            "Invalid aggregated nonce",
        );
    }
}
