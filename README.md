# Two-Party Musig2 EdDSA
This is a 2 party specific implementation of the Musig2 protocol for multi-signatures of EdDSA - Schnorr signatures over Ed25519.

The aim is to write simple and secure code that does this.

The Musig2 paper can be found [here](https://eprint.iacr.org/2020/1261.pdf).

The number of nonces that each party uses (denoted v in the paper) is set to 2.

We also implement the Musig2* variant (appendix B in the paper) where one of the musig coefficients is set to 1 in order to save some scalar multiplication, this doesn't affect security.

## Running
We implemented a simple example for signing.
In order to run: `cargo run --release --example signing`