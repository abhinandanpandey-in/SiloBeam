use crate::crypto::{
    build_initiator, build_responder, verify_remote_key, CryptoError, EncryptedChannel,
    MAX_NOISE_MSG_LEN,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid frame length: {0}")]
    InvalidFrameLen(usize),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Text,
    Link,
    FileMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub msg_id: String,
    pub sender_id: String,
    pub kind: MessageKind,
    pub content: String,
    pub filename: Option<String>,
    pub created_at: i64,
    pub ttl_sec: i64,
}

impl Envelope {
    pub fn new_text(sender_id: impl Into<String>, content: impl Into<String>, ttl_sec: i64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Self {
            msg_id: Uuid::new_v4().to_string(),
            sender_id: sender_id.into(),
            kind: MessageKind::Text,
            content: content.into(),
            filename: None,
            created_at: now,
            ttl_sec,
        }
    }
}

async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), ProtocolError> {
    if data.is_empty() || data.len() > MAX_NOISE_MSG_LEN {
        return Err(ProtocolError::InvalidFrameLen(data.len()));
    }
    stream.write_all(&(data.len() as u32).to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, ProtocolError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_NOISE_MSG_LEN {
        return Err(ProtocolError::InvalidFrameLen(len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

pub struct NoiseStream {
    stream: TcpStream,
    channel: EncryptedChannel,
}

impl NoiseStream {
    pub async fn connect(
        addr: &str,
        local_priv: &[u8],
        remote_pub: &[u8],
    ) -> Result<Self, ProtocolError> {
        let mut stream = TcpStream::connect(addr).await?;
        let mut hs = build_initiator(local_priv, remote_pub)?;

        let mut msg1 = vec![0u8; 1024];
        let len1 = hs.write_message(&[], &mut msg1).map_err(CryptoError::from)?;
        write_frame(&mut stream, &msg1[..len1]).await?;

        let msg2 = read_frame(&mut stream).await?;
        let mut out = vec![0u8; 1024];
        hs.read_message(&msg2, &mut out).map_err(CryptoError::from)?;

        let transport = hs.into_transport_mode().map_err(CryptoError::from)?;
        Ok(Self {
            stream,
            channel: EncryptedChannel::new(transport),
        })
    }

    pub async fn accept(
        mut stream: TcpStream,
        local_priv: &[u8],
        allowed_pub_keys: &[Vec<u8>],
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        let mut hs = build_responder(local_priv)?;

        let msg1 = read_frame(&mut stream).await?;
        let mut out = vec![0u8; 1024];
        hs.read_message(&msg1, &mut out).map_err(CryptoError::from)?;

        let remote_pub = verify_remote_key(&hs, allowed_pub_keys)?;

        let mut msg2 = vec![0u8; 1024];
        let len2 = hs.write_message(&[], &mut msg2).map_err(CryptoError::from)?;
        write_frame(&mut stream, &msg2[..len2]).await?;

        let transport = hs.into_transport_mode().map_err(CryptoError::from)?;
        Ok((
            Self {
                stream,
                channel: EncryptedChannel::new(transport),
            },
            remote_pub,
        ))
    }

    /// Used ONLY during an active 60s QR pairing window; caller MUST verify pairing token immediately
    pub async fn accept_for_pairing(
        mut stream: TcpStream,
        local_priv: &[u8],
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        let mut hs = build_responder(local_priv)?;

        let msg1 = read_frame(&mut stream).await?;
        let mut out = vec![0u8; 1024];
        hs.read_message(&msg1, &mut out).map_err(CryptoError::from)?;

        let remote_pub = hs
            .get_remote_static()
            .ok_or(CryptoError::UntrustedPeer)?
            .to_vec();

        let mut msg2 = vec![0u8; 1024];
        let len2 = hs.write_message(&[], &mut msg2).map_err(CryptoError::from)?;
        write_frame(&mut stream, &msg2[..len2]).await?;

        let transport = hs.into_transport_mode().map_err(CryptoError::from)?;
        Ok((
            Self {
                stream,
                channel: EncryptedChannel::new(transport),
            },
            remote_pub,
        ))
    }

    pub async fn send_envelope(&mut self, env: &Envelope) -> Result<(), ProtocolError> {
        let raw = serde_json::to_vec(env)?;
        let ct = self.channel.encrypt(&raw)?;
        write_frame(&mut self.stream, &ct).await
    }

    pub async fn recv_envelope(&mut self) -> Result<Envelope, ProtocolError> {
        let ct = read_frame(&mut self.stream).await?;
        let pt = self.channel.decrypt(&ct)?;
        Ok(serde_json::from_slice(&pt)?)
    }

    pub async fn send_raw_chunk(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        let ct = self.channel.encrypt(data)?;
        write_frame(&mut self.stream, &ct).await
    }

    pub async fn recv_raw_chunk(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let ct = read_frame(&mut self.stream).await?;
        Ok(self.channel.decrypt(&ct)?)
    }
}