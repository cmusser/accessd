use crate::err::AccessError;
use sodiumoxide::crypto::box_;

pub fn open<'packet>(
    packet: &'packet [u8],
    secret_key: &box_::SecretKey,
    public_key: &box_::PublicKey,
) -> Result<Vec<u8>, AccessError> {
    match box_::Nonce::from_slice(&packet[..box_::NONCEBYTES]) {
        Some(nonce) => box_::open(
            &packet[box_::NONCEBYTES..],
            &nonce,
            &public_key,
            &secret_key,
        )
        .map_err(|_| AccessError::InvalidCiphertext),
        None => Err(AccessError::InvalidNonce),
    }
}

pub fn create(
    msg: &[u8],
    nonce: &box_::Nonce,
    secret_key: &box_::SecretKey,
    public_key: &box_::PublicKey,
) -> Vec<u8> {
    box_::seal(&msg, nonce, &public_key, &secret_key)
}
