/*
    Two-party implementation of the Musig2 protocol for multi-signatures of EdDSA - Schnorr signatures over Ed25519.
    Musig2 paper: (https://eprint.iacr.org/2020/1261.pdf)
    We implement here a two party version.
    The number of nonces that each party uses (denoted v in the paper) is set to 2.
    We also implement the Musig2* variant (appendix B in the paper) where one of the musig coefficients is set to 1
    in order to save some scalar multiplication, this doesn't affect security.
*/

mod protocol;
