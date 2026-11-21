use base64::{engine::general_purpose::STANDARD as B64, Engine};
use lan_core::crypto::IdentityKeypair;
use lan_core::db::Database;
use lan_core::discovery::{DiscoveredPeer, LanDiscovery};
use lan_core::protocol::{Envelope, MessageKind, NoiseStream};
use qrcode::render::svg;
use qrcode::QrCode;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager, State};
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredIdentity {
    device_id: String,
    private_b64: String,
    public_b64: String,
}

struct AppState {
    db: Arc<Mutex<Database>>,
    device_id: String,
    keypair: IdentityKeypair,
    listen_port: u16,
    peers: Arc<Mutex<HashMap<String, DiscoveredPeer>>>,
    paired_keys: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    pairing_token: Arc<Mutex<Option<(String, Instant)>>>,
    active_uploads: Arc<tokio::sync::Mutex<HashMap<String, Vec<NoiseStream>>>>,
}

#[derive(serde::Serialize)]
struct DeviceInfo {
    device_id: String,
    public_key: String,
    port: u16,
    peer_count: usize,
    is_mobile: bool,
}

#[derive(serde::Serialize)]
struct QrPayload {
    svg: String,
    raw: String,
}

fn load_or_create_identity(dir: &Path) -> (String, IdentityKeypair) {
    let path = dir.join("identity.json");
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(stored) = serde_json::from_str::<StoredIdentity>(&raw) {
            if let (Ok(priv_k), Ok(pub_k)) = (
                IdentityKeypair::decode_b64(&stored.private_b64),
                IdentityKeypair::decode_b64(&stored.public_b64),
            ) {
                return (
                    stored.device_id,
                    IdentityKeypair {
                        private: priv_k,
                        public: pub_k,
                    },
                );
            }
        }
    }

    let kp = IdentityKeypair::generate().expect("keygen failed");
    let dev_id = format!("dev_{}", &kp.public_b64()[..8].replace(['/', '+'], "x"));
    let stored = StoredIdentity {
        device_id: dev_id.clone(),
        private_b64: B64.encode(&kp.private),
        public_b64: kp.public_b64(),
    };
    let _ = std::fs::write(path, serde_json::to_string_pretty(&stored).unwrap());
    (dev_id, kp)
}

#[tauri::command]
fn get_device_info(state: State<'_, AppState>) -> DeviceInfo {
    let count = state.peers.lock().map(|p| p.len()).unwrap_or(0);
    DeviceInfo {
        device_id: state.device_id.clone(),
        public_key: state.keypair.public_b64(),
        port: state.listen_port,
        peer_count: count,
        is_mobile: cfg!(any(target_os = "android", target_os = "ios")),
    }
}

#[tauri::command]
fn generate_pairing_qr(state: State<'_, AppState>) -> Result<QrPayload, String> {
    let ip = local_ip_address::local_ip()
        .map_err(|e| format!("LAN IP error: {}", e))?
        .to_string();
    let token = Uuid::new_v4().simple().to_string();

    if let Ok(mut guard) = state.pairing_token.lock() {
        *guard = Some((token.clone(), Instant::now() + Duration::from_secs(60)));
    }

    // Format: lanpad|device_id|public_key_b64|ip|port|token
    let raw = format!(
        "silobeam|{}|{}|{}|{}|{}",
        state.device_id,
        state.keypair.public_b64(),
        ip,
        state.listen_port,
        token
    );

    let code = QrCode::new(raw.as_bytes()).map_err(|e| e.to_string())?;
    let svg_str = code
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#e6edf3"))
        .light_color(svg::Color("#0b0d10"))
        .build();

    Ok(QrPayload { svg: svg_str, raw })
}

#[tauri::command]
async fn complete_qr_pairing(
    qr_raw: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let parts: Vec<&str> = qr_raw.trim().split('|').collect();
    if parts.len() != 6 || parts[0] != "silobeam" {
        return Err("Invalid SiloBeam QR code".into());
    }
    let (peer_id, peer_pub_b64, ip, port, token) =
        (parts[1], parts[2], parts[3], parts[4], parts[5]);
    let peer_pub = IdentityKeypair::decode_b64(peer_pub_b64).map_err(|_| "Invalid public key")?;
    let addr = format!("{}:{}", ip, port);

    // 1. Connect over Noise_IK and send single-use pairing token
    let mut stream = NoiseStream::connect(&addr, &state.keypair.private, &peer_pub)
        .await
        .map_err(|e| format!("Connect failed ({}): {}", addr, e))?;

    let pair_env = Envelope::new_text(
        &state.device_id,
        format!("__PAIR__|{}|{}|{}", token, state.keypair.public_b64(), state.listen_port),
        60,
    );
    stream
        .send_envelope(&pair_env)
        .await
        .map_err(|e| format!("Handshake send failed: {}", e))?;

    // 2. Pin Laptop's key locally
    {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        db.add_device(peer_id, peer_id, peer_pub_b64)
            .map_err(|e| e.to_string())?;
    }
    if let Ok(mut map) = state.paired_keys.lock() {
        map.insert(peer_id.to_string(), peer_pub);
    }
    if let Ok(p_num) = port.parse::<u16>() {
        if let Ok(mut pmap) = state.peers.lock() {
            pmap.insert(peer_id.to_string(), DiscoveredPeer {
                device_id: peer_id.to_string(),
                name: peer_id.to_string(),
                addr: ip.to_string(),
                port: p_num,
            });
        }
    }

    Ok(format!("Paired with {}!", peer_id))
}

#[tauri::command]
fn list_notes(state: State<'_, AppState>) -> Result<Vec<Envelope>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    let _ = db.purge_expired();
    db.list_active_messages().map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_note(
    content: String,
    ttl_hours: i64,
    state: State<'_, AppState>,
) -> Result<Envelope, String> {
    let trimmed = content.trim().to_string();
    if trimmed.is_empty() {
        return Err("Empty note".into());
    }
    let mut env = Envelope::new_text(&state.device_id, trimmed.clone(), ttl_hours * 3600);
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        env.kind = MessageKind::Link;
    }

    {
        let db = state.db.lock().map_err(|e| e.to_string())?;
        db.save_message(&env).map_err(|e| e.to_string())?;
    }

    let targets: Vec<(String, Vec<u8>)> = {
        let peers = state.peers.lock().unwrap();
        let paired = state.paired_keys.lock().unwrap();
        peers
            .values()
            .filter_map(|p| {
                paired
                    .get(&p.device_id)
                    .map(|pk| (format!("{}:{}", p.addr, p.port), pk.clone()))
            })
            .collect()
    };

    let local_priv = state.keypair.private.clone();
    let env_clone = env.clone();
    for (addr, remote_pub) in targets {
        let priv_k = local_priv.clone();
        let payload = env_clone.clone();
        tauri::async_runtime::spawn(async move {
            if let Ok(mut stream) = NoiseStream::connect(&addr, &priv_k, &remote_pub).await {
                let _ = stream.send_envelope(&payload).await;
            }
        });
    }

    Ok(env)
}

#[tauri::command]
async fn start_file_transfer(
    filename: String,
    file_size: u64,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let safe_name = std::path::Path::new(&filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file.bin")
        .to_string();

    let targets: Vec<(String, Vec<u8>)> = {
        let peers = state.peers.lock().unwrap();
        let paired = state.paired_keys.lock().unwrap();
        peers
            .values()
            .filter_map(|p| {
                paired
                    .get(&p.device_id)
                    .map(|pk| (format!("{}:{}", p.addr, p.port), pk.clone()))
            })
            .collect()
    };

    if targets.is_empty() {
        return Err("No paired peer online".into());
    }

    let mut env = Envelope::new_text(&state.device_id, file_size.to_string(), 24 * 3600);
    env.kind = MessageKind::FileMeta;
    env.filename = Some(safe_name.clone());

    let mut streams = Vec::new();
    for (addr, remote_pub) in targets {
        if let Ok(mut s) = NoiseStream::connect(&addr, &state.keypair.private, &remote_pub).await {
            if s.send_envelope(&env).await.is_ok() {
                streams.push(s);
            }
        }
    }

    if streams.is_empty() {
        return Err("Could not connect to peer".into());
    }

    let transfer_id = Uuid::new_v4().to_string();
    state.active_uploads.lock().await.insert(transfer_id.clone(), streams);

    // Save local record
    let mut local_env = env.clone();
    local_env.content = format!("Sent file: {} ({} bytes)", safe_name, file_size);
    if let Ok(db) = state.db.lock() {
        let _ = db.save_message(&local_env);
    }

    Ok(transfer_id)
}

#[tauri::command]
async fn send_file_chunk(
    transfer_id: String,
    chunk_b64: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let raw = B64.decode(&chunk_b64).map_err(|e| e.to_string())?;
    let mut uploads = state.active_uploads.lock().await;
    let streams = uploads.get_mut(&transfer_id).ok_or("Transfer not found")?;

    // Split into 48KB Noise-safe frames
    for part in raw.chunks(49152) {
        for s in streams.iter_mut() {
            s.send_raw_chunk(part).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[tauri::command]
fn open_file(path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(format!("/select,{}", path))
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn finish_file_transfer(
    transfer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.active_uploads.lock().await.remove(&transfer_id);
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    }

    builder
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let db = Arc::new(Mutex::new(
                Database::open(data_dir.join("lanpad.db")).expect("db open failed"),
            ));
            let (device_id, keypair) = load_or_create_identity(&data_dir);
            let peers = Arc::new(Mutex::new(HashMap::<String, DiscoveredPeer>::new()));
            let mut initial_paired = HashMap::<String, Vec<u8>>::new();
            if let Ok(d) = db.lock() {
                if let Ok(devs) = d.list_devices() {
                    for dev in devs {
                        if let Ok(raw) = IdentityKeypair::decode_b64(&dev.public_key_b64) {
                            initial_paired.insert(dev.device_id, raw);
                        }
                    }
                }
            }
            let paired_keys = Arc::new(Mutex::new(initial_paired));
            let pairing_token = Arc::new(Mutex::new(None::<(String, Instant)>));
            let active_uploads = Arc::new(tokio::sync::Mutex::new(HashMap::<String, Vec<NoiseStream>>::new()));

            let std_listener = std::net::TcpListener::bind("0.0.0.0:0")?;
            std_listener.set_nonblocking(true)?;
            let listen_port = std_listener.local_addr()?.port();

            // mDNS advertise + browse
            let my_id_mdns = device_id.clone();
            let peers_mdns = peers.clone();
            let handle_mdns = app.handle().clone();
            std::thread::spawn(move || {
                if let Ok(disc) = LanDiscovery::new() {
                    let _ = disc.advertise(&my_id_mdns, &my_id_mdns, listen_port);
                    if let Ok(rx) = disc.browse() {
                        while let Ok(evt) = rx.recv() {
                            if let Some(peer) = LanDiscovery::parse_event(evt) {
                                if peer.device_id != my_id_mdns {
                                    if let Ok(mut map) = peers_mdns.lock() {
                                        map.insert(peer.device_id.clone(), peer);
                                        let _ = handle_mdns.emit("peers-updated", map.len());
                                    }
                                }
                            }
                        }
                    }
                }
            });

            // Noise TCP server (handles both paired notes + 60s QR pairing)
            let db_srv = db.clone();
            let paired_srv = paired_keys.clone();
            let peers_srv = peers.clone();
            let token_srv = pairing_token.clone();
            let priv_srv = keypair.private.clone();
            let handle_srv = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Ok(listener) = TcpListener::from_std(std_listener) {
                    while let Ok((sock, peer_addr)) = listener.accept().await {
                        let db_c = db_srv.clone();
                        let paired_c = paired_srv.clone();
                        let peers_c = peers_srv.clone();
                        let tok_c = token_srv.clone();
                        let priv_c = priv_srv.clone();
                        let h_c = handle_srv.clone();
                        tauri::async_runtime::spawn(async move {
                            let pairing_open = tok_c
                                .lock()
                                .ok()
                                .and_then(|g| g.as_ref().map(|(_, exp)| Instant::now() < *exp))
                                .unwrap_or(false);

                            if pairing_open {
                                if let Ok((mut ns, remote_pub)) =
                                    NoiseStream::accept_for_pairing(sock, &priv_c).await
                                {
                                    if let Ok(env) = ns.recv_envelope().await {
                                        if let Some(rest) = env.content.strip_prefix("__PAIR__|") {
                                            let mut sp = rest.split('|');
                                            if let (Some(tok), Some(pub_b64), Some(p_port)) = (sp.next(), sp.next(), sp.next()) {
                                                let valid = tok_c
                                                    .lock()
                                                    .ok()
                                                    .map(|mut g| {
                                                        if let Some((expected, exp)) = g.as_ref() {
                                                            if expected == tok && Instant::now() < *exp {
                                                                *g = None; // Single-use consumed
                                                                return true;
                                                            }
                                                        }
                                                        false
                                                    })
                                                    .unwrap_or(false);

                                                if valid {
                                                    if let Ok(d) = db_c.lock() {
                                                        let _ = d.add_device(&env.sender_id, &env.sender_id, pub_b64);
                                                    }
                                                    if let Ok(mut m) = paired_c.lock() {
                                                        m.insert(env.sender_id.clone(), remote_pub);
                                                    }
                                                    if let Ok(port_num) = p_port.parse::<u16>() {
                                                        if let Ok(mut pm) = peers_c.lock() {
                                                            pm.insert(env.sender_id.clone(), DiscoveredPeer {
                                                                device_id: env.sender_id.clone(),
                                                                name: env.sender_id.clone(),
                                                                addr: peer_addr.ip().to_string(),
                                                                port: port_num,
                                                            });
                                                            let _ = h_c.emit("peers-updated", pm.len());
                                                        }
                                                    }
                                                    let _ = h_c.emit("paired-success", &env.sender_id);
                                                }
                                            }
                                            return;
                                        }
                                    }
                                }
                                return;
                            }

                            let allowed = db_c
                                .lock()
                                .ok()
                                .and_then(|d| d.allowed_pub_keys().ok())
                                .unwrap_or_default();
                            if let Ok((mut ns, _)) =
                                NoiseStream::accept(sock, &priv_c, &allowed).await
                            {
                                if let Ok(mut env) = ns.recv_envelope().await {
                                    if env.kind == MessageKind::FileMeta {
                                        let total_size: u64 = env.content.parse().unwrap_or(0);
                                        let safe_name = env
                                            .filename
                                            .as_deref()
                                            .and_then(|f| std::path::Path::new(f).file_name())
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("received_file.bin")
                                            .to_string();

                                        let dl_dir = {
                                            #[cfg(target_os = "android")]
                                            {
                                                let pub_dl = std::path::PathBuf::from("/storage/emulated/0/Download/SiloBeam");
                                                if std::fs::create_dir_all(&pub_dl).is_ok() {
                                                    pub_dl
                                                } else {
                                                    h_c.path()
                                                        .download_dir()
                                                        .or_else(|_| h_c.path().app_data_dir())
                                                        .unwrap_or_else(|_| std::path::PathBuf::from("."))
                                                        .join("SiloBeam")
                                                }
                                            }
                                            #[cfg(not(target_os = "android"))]
                                            {
                                                h_c.path()
                                                    .download_dir()
                                                    .or_else(|_| h_c.path().app_data_dir())
                                                    .unwrap_or_else(|_| std::path::PathBuf::from("."))
                                                    .join("SiloBeam")
                                            }
                                        };
                                        let _ = std::fs::create_dir_all(&dl_dir);
                                        let dest = dl_dir.join(&safe_name);

                                        if let Ok(mut file) = tokio::fs::File::create(&dest).await {
                                            use tokio::io::AsyncWriteExt;
                                            let mut received: u64 = 0;
                                            while received < total_size {
                                                match ns.recv_raw_chunk().await {
                                                    Ok(chunk) if !chunk.is_empty() => {
                                                        if file.write_all(&chunk).await.is_err() {
                                                            break;
                                                        }
                                                        received += chunk.len() as u64;
                                                        let pct = if total_size > 0 {
                                                            ((received * 100) / total_size).min(100)
                                                        } else {
                                                            100
                                                        };
                                                        let _ = h_c.emit("transfer-progress", serde_json::json!({
                                                            "name": safe_name,
                                                            "pct": pct,
                                                            "dir": "recv"
                                                        }));
                                                    }
                                                    _ => break,
                                                }
                                            }
                                            let _ = file.flush().await;
                                            env.content = format!("Saved: {} ({} bytes)", dest.display(), received);
                                        }
                                    }
                                    if let Ok(d) = db_c.lock() {
                                        let _ = d.save_message(&env);
                                    }
                                    let _ = h_c.emit("note-received", &env);
                                }
                            }
                        });
                    }
                }
            });

            app.manage(AppState {
                db,
                device_id,
                keypair,
                listen_port,
                peers,
                paired_keys,
                pairing_token,
                active_uploads,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_device_info,
            generate_pairing_qr,
            complete_qr_pairing,
            list_notes,
            add_note,
            start_file_transfer,
            send_file_chunk,
            finish_file_transfer,
            open_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}