use ::err::AccessError;
use ::keys::KeyData;
use sodiumoxide::crypto::box_;

pub fn open<'packet>(packet: &'packet[u8], key_data: &KeyData)
                   -> Result<Vec<u8>, AccessError> {
    if let Some(nonce) = box_::Nonce::from_slice(&packet[..box_::NONCEBYTES]) {
        box_::open(&packet[box_::NONCEBYTES..], &nonce, &key_data.peer_public,
                   &key_data.secret).map_err(|_| { AccessError::InvalidCiphertext })
    } else {
        return Err(AccessError::InvalidNonce);
    }
}

pub fn create(msg: &Vec<u8>, nonce: &box_::Nonce, key_data: &KeyData) -> Vec<u8>{
    box_::seal(&msg, nonce, &key_data.peer_public, &key_data.secret)
}
