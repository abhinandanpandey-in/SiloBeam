pub mod crypto;
pub mod db;
pub mod discovery;
pub mod protocol;

#[cfg(test)]
mod tests {
    use super::crypto::*;
    use super::db::Database;
    use super::protocol::{Envelope, NoiseStream};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_noise_tcp_envelope_and_db_storage() {
        let desktop_kp = IdentityKeypair::generate().unwrap();
        let android_kp = IdentityKeypair::generate().unwrap();

        let db = Database::open_in_memory().unwrap();
        db.add_device("android_1", "Pixel", &android_kp.public_b64()).unwrap();
        let allowed = db.allowed_pub_keys().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let desktop_priv = desktop_kp.private.clone();
        let server_task = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (mut ns, _peer_pub) = NoiseStream::accept(sock, &desktop_priv, &allowed)
                .await
                .unwrap();
            ns.recv_envelope().await.unwrap()
        });

        let mut client = NoiseStream::connect(&addr, &android_kp.private, &desktop_kp.public)
            .await
            .unwrap();
        let sent = Envelope::new_text("android_1", "OTP: 482910", 86400);
        client.send_envelope(&sent).await.unwrap();

        let received = server_task.await.unwrap();
        assert_eq!(received.content, "OTP: 482910");

        db.save_message(&received).unwrap();
        let active = db.list_active_messages().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].msg_id, sent.msg_id);
    }
}
