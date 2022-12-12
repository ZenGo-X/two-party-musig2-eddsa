use std::convert::TryInto;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;



/// Converts 32 bytes into an edwards point.
/// Checks both that the Y coordinate is on the curve, and that the resulting point is torsion free.
///
/// # Panics
/// If the input `bytes` slice does not have a length of 32.
#[inline(always)]
pub fn edwards_from_bytes(bytes: &[u8]) -> Option<EdwardsPoint> {
    let point = CompressedEdwardsY::from_slice(bytes).decompress()?;
    // We require that the point will be 0 in the small subgroup,
    // `is_small_order()` checks if the point is *only* in the small subgroup,
    // while `is_torsion_free()` makes sure the point is 0 in the small subgroup.
    point.is_torsion_free().then_some(point)
}



/// Converts 32 bytes into a Scalar, checking that the scalar is fully reduced.
///
/// # Panics
/// If the input `bytes` slice does not have a length of 32.
#[inline(always)]
pub fn scalar_from_bytes(bytes: &[u8]) -> Option<Scalar> {
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum KeySortedLocation {
    First = 0,
    Second = 1,
}

impl TryFrom<u8> for KeySortedLocation {
    type Error = ();
    fn try_from(a: u8) -> Result<Self, Self::Error> {
        match a {
            a if a == Self::First as u8 => Ok(Self::First),
            a if a == Self::Second as u8 => Ok(Self::Second),
            _ => Err(()),
        }
    }
}