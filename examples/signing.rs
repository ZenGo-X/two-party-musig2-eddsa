use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use two_party_musig2_eddsa::{
    generate_partial_nonces, AggPublicKeyAndMusigCoeff, KeyPair, PartialSignature,
    PublicPartialNonces, Signature,
};

const MESSAGE: &[u8] = b"Message To Be signed";

fn launch_party(
    sender: mpsc::Sender<Vec<u8>>,
    receiver: mpsc::Receiver<Vec<u8>>,
) -> Result<Signature, &'static str> {
    // Generate a Key Pair
    let (keypair, _secret) = KeyPair::create();

    // Send your public key to the counterparty.
    sender.send(keypair.pubkey().to_vec()).unwrap();
    // Receive the counterparty's public key.
    let other_pubkey: [u8; 32] = receiver
        .recv_array()
        .map_err(|_| "Public keys are 32 bytes")?;

    // Aggregate your public keys together.
    let agg_pubkey =
        AggPublicKeyAndMusigCoeff::aggregate_public_keys(keypair.pubkey(), other_pubkey)
            .map_err(|_| "Received an invalid public key")?;

    // Generate nonces.
    // Note that the message is optional, so this can be done before you know what you're signing on.
    let (private_nonces, public_nonces) = generate_partial_nonces(&keypair, Some(MESSAGE));

    // Send your public nonces to the counterparty.
    sender.send(public_nonces.serialize().to_vec()).unwrap();
    // Receive the counterparty's nonces.
    let other_party_nonces = PublicPartialNonces::deserialize(
        receiver
            .recv_array()
            .map_err(|_| "Public nonces are 64 bytes")?,
    )
    .ok_or("Received invalid public nonces")?;

    // Create a partial signature
    let (partial_sig, agg_nonce) = keypair.partial_sign(
        private_nonces,
        [public_nonces, other_party_nonces],
        &agg_pubkey,
        MESSAGE,
    );

    // Send the partial signature to the counterparty.
    sender.send(partial_sig.serialize().to_vec()).unwrap();

    // Receive the partial signature from the counterparty.
    let other_partial_sig = PartialSignature::deserialize(
        receiver
            .recv_array()
            .map_err(|_| "Partial Signatures are 32 bytes")?,
    )
    .ok_or("Received invalid partial signature")?;

    // Aggregate the partial signatures together
    let sig = Signature::aggregate_partial_signatures(agg_nonce, [partial_sig, other_partial_sig]);

    // Make sure the signature verifies against the aggregated public key
    if sig.verify(MESSAGE, agg_pubkey.aggregated_pubkey()).is_err() {
        return Err("Resulted in a bad signature");
    }
    Ok(sig)
}

fn main() {
    let (sender1, receiver2) = mpsc::channel();
    let (sender2, receiver1) = mpsc::channel();
    let party1 = std::thread::spawn(move || launch_party(sender1, receiver1));
    let party2 = std::thread::spawn(move || launch_party(sender2, receiver2));
    let sig1 = party1.join().unwrap().unwrap();
    println!(
        "party 1 finished without an error! signature: {:?}",
        sig1.serialize()
    );
    let sig2 = party2.join().unwrap().unwrap();
    println!(
        "party 2 finished without an error! signature: {:?}",
        sig2.serialize()
    );
    assert_eq!(sig1, sig2);
}

trait ReceiveArray {
    fn recv_array<const N: usize>(&self) -> Result<[u8; N], Vec<u8>>;
}
impl ReceiveArray for Receiver<Vec<u8>> {
    fn recv_array<const N: usize>(&self) -> Result<[u8; N], Vec<u8>> {
        self.recv().unwrap().try_into()
    }
}

#[test]
fn test_main() {
    main()
}
