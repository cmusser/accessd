use ::err::AccessError;
use ::keys::KeyData;
use ::state::State;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{Nonce, NONCEBYTES};

pub struct Payload<'packet> {
    pub nonce: Nonce,
    pub encrypted_req: &'packet[u8],
}

impl<'packet> Payload<'packet> {
    pub fn from_packet(packet: &'packet[u8]) -> Result<Self, AccessError> {
        let nonce = Nonce::from_slice(&packet[..NONCEBYTES]);
        match nonce {
            Some(nonce) => Ok(Payload { nonce: nonce, encrypted_req: &packet[NONCEBYTES..] }),
            None => Err(AccessError::InvalidNonce),
        }
    }

    pub fn decrypt(&self, state: &mut State, key_data: &KeyData) -> Result<Vec<u8>, AccessError> {
        if self.nonce.lt(&state.remote_nonce) {
            Err(AccessError::ReusedNonce)
        } else {
            state.remote_nonce = self.nonce;
            state.write()?;
            box_::open(&self.encrypted_req, &self.nonce, &key_data.peer_public,
                       &key_data.secret).map_err(|_| { AccessError::InvalidCiphertext })
        }
    }
}
