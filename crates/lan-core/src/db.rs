use crate::crypto::IdentityKeypair;
use crate::protocol::{Envelope, MessageKind};
use rusqlite::{params, Connection};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

#[derive(Debug, Clone)]
pub struct PairedDevice {
    pub device_id: String,
    pub name: String,
    pub public_key_b64: String,
    pub created_at: i64,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<(), DbError> {
        self.conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS paired_devices (
                device_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                public_key_b64 TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                msg_id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                content TEXT NOT NULL,
                filename TEXT,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at);
            ",
        )?;
        Ok(())
    }

    pub fn add_device(&self, device_id: &str, name: &str, public_key_b64: &str) -> Result<(), DbError> {
        let now = now_unix();
        self.conn.execute(
            "INSERT OR REPLACE INTO paired_devices (device_id, name, public_key_b64, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![device_id, name, public_key_b64, now],
        )?;
        Ok(())
    }

    pub fn list_devices(&self) -> Result<Vec<PairedDevice>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, name, public_key_b64, created_at FROM paired_devices",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PairedDevice {
                device_id: row.get(0)?,
                name: row.get(1)?,
                public_key_b64: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn allowed_pub_keys(&self) -> Result<Vec<Vec<u8>>, DbError> {
        let mut stmt = self.conn.prepare("SELECT public_key_b64 FROM paired_devices")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut keys = Vec::new();
        for b64 in rows.flatten() {
            if let Ok(raw) = IdentityKeypair::decode_b64(&b64) {
                keys.push(raw);
            }
        }
        Ok(keys)
    }

    pub fn save_message(&self, env: &Envelope) -> Result<(), DbError> {
        let kind_str = match env.kind {
            MessageKind::Text => "text",
            MessageKind::Link => "link",
            MessageKind::FileMeta => "file_meta",
        };
        let expires_at = env.created_at + env.ttl_sec;
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (msg_id, sender_id, kind, content, filename, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                env.msg_id,
                env.sender_id,
                kind_str,
                env.content,
                env.filename,
                env.created_at,
                expires_at
            ],
        )?;
        Ok(())
    }

    pub fn list_active_messages(&self) -> Result<Vec<Envelope>, DbError> {
        let now = now_unix();
        let mut stmt = self.conn.prepare(
            "SELECT msg_id, sender_id, kind, content, filename, created_at, expires_at
             FROM messages
             WHERE expires_at > ?1
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![now], |row| {
            let kind_str: String = row.get(2)?;
            let kind = match kind_str.as_str() {
                "link" => MessageKind::Link,
                "file_meta" => MessageKind::FileMeta,
                _ => MessageKind::Text,
            };
            let created_at: i64 = row.get(5)?;
            let expires_at: i64 = row.get(6)?;
            Ok(Envelope {
                msg_id: row.get(0)?,
                sender_id: row.get(1)?,
                kind,
                content: row.get(3)?,
                filename: row.get(4)?,
                created_at,
                ttl_sec: expires_at - created_at,
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn purge_expired(&self) -> Result<usize, DbError> {
        let now = now_unix();
        let deleted = self.conn.execute("DELETE FROM messages WHERE expires_at <= ?1", params![now])?;
        Ok(deleted)
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
