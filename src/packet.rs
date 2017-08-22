use ::err::AccessError;
use ::keys::KeyData;
use ::state::State;
use sodiumoxide::crypto::box_;

pub fn open<'packet>(packet: &'packet[u8], state: &mut State, key_data: &KeyData)
                   -> Result<Vec<u8>, AccessError> {
    if let Some(nonce) = box_::Nonce::from_slice(&packet[..box_::NONCEBYTES]) {
        if nonce.lt(&state.remote_nonce) {
            return Err(AccessError::ReusedNonce)
        } else {
            state.remote_nonce = nonce;
            state.write()?;
            box_::open(&packet[box_::NONCEBYTES..], &nonce, &key_data.peer_public,
                       &key_data.secret).map_err(|_| { AccessError::InvalidCiphertext })
        }
    } else {
        return Err(AccessError::InvalidNonce);
    }
}

pub fn create(msg: &Vec<u8>, state: &mut State, key_data: &KeyData) -> Vec<u8>{
    box_::seal(&msg, &state.local_nonce, &key_data.peer_public, &key_data.secret)
}
