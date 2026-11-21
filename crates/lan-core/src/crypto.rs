use base64::{engine::general_purpose::STANDARD as B64, Engine};
use snow::{Builder, HandshakeState, TransportState};
use thiserror::Error;

pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const MAX_NOISE_MSG_LEN: usize = 65535;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),
    #[error("untrusted remote peer")]
    UntrustedPeer,
    #[error("invalid key encoding")]
    InvalidKey,
}

#[derive(Clone)]
pub struct IdentityKeypair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

impl IdentityKeypair {
    pub fn generate() -> Result<Self, CryptoError> {
        let kp = Builder::new(NOISE_PATTERN.parse()?).generate_keypair()?;
        Ok(Self {
            private: kp.private,
            public: kp.public,
        })
    }

    pub fn public_b64(&self) -> String {
        B64.encode(&self.public)
    }

    pub fn decode_b64(encoded: &str) -> Result<Vec<u8>, CryptoError> {
        B64.decode(encoded).map_err(|_| CryptoError::InvalidKey)
    }
}

pub fn build_initiator(
    local_priv: &[u8],
    remote_pub: &[u8],
) -> Result<HandshakeState, CryptoError> {
    Ok(Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(local_priv)
        .remote_public_key(remote_pub)
        .build_initiator()?)
}

pub fn build_responder(local_priv: &[u8]) -> Result<HandshakeState, CryptoError> {
    Ok(Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(local_priv)
        .build_responder()?)
}

/// Verifies remote static key against allowed keys after first IK message
pub fn verify_remote_key(
    responder: &HandshakeState,
    allowed_pub_keys: &[Vec<u8>],
) -> Result<Vec<u8>, CryptoError> {
    let remote = responder
        .get_remote_static()
        .ok_or(CryptoError::UntrustedPeer)?;
    if allowed_pub_keys.iter().any(|k| k.as_slice() == remote) {
        Ok(remote.to_vec())
    } else {
        Err(CryptoError::UntrustedPeer)
    }
}

pub struct EncryptedChannel {
    state: TransportState,
}

impl EncryptedChannel {
    pub fn new(state: TransportState) -> Self {
        Self { state }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        let len = self.state.write_message(plaintext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self.state.read_message(ciphertext, &mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }
}
