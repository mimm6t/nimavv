use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber;
use gvbyh_worker_client::WorkerClient;
use bytes::{BytesMut, Buf};

// DoH 解析器
async fn resolve_with_doh(domain: &str) -> anyhow::Result<std::net::IpAddr> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    
    // 使用 Cloudflare DoH
    let url = format!("https://1.1.1.1/dns-query?name={}&type=A", domain);
    
    let resp = client
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await?;
    
    let json: serde_json::Value = resp.json().await?;
    
    if let Some(answers) = json["Answer"].as_array() {
        for answer in answers {
            if let Some(ip_str) = answer["data"].as_str() {
                if let Ok(ip) = ip_str.parse() {
                    tracing::debug!("DoH resolved {} to {}", domain, ip);
                    return Ok(ip);
                }
            }
        }
    }
    
    anyhow::bail!("No A record found for {}", domain)
}

// 解析域名:端口
async fn resolve_target(target: &str) -> anyhow::Result<SocketAddr> {
    // 如果已经是 IP:端口格式，直接解析
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(addr);
    }
    
    // 分离域名和端口
    let parts: Vec<&str> = target.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid target format: {}", target);
    }
    
    let port: u16 = parts[0].parse()?;
    let domain = parts[1];
    
    // 使用 DoH 解析
    let ip = resolve_with_doh(domain).await?;
    Ok(SocketAddr::new(ip, port))
}

#[derive(Parser)]
#[command(name = "gvbyh-server")]
#[command(about = "gvbyh-rust 服务端", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "http://mirrors.ustc.ip-ddns.com")]
    worker_url: String,
    
    #[arg(short, long)]
    server_ip: Option<String>,
    
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    tracing_subscriber::fmt()
        .with_max_level(match cli.log_level.as_str() {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        })
        .with_target(false)
        .init();
    
    tracing::info!("gvbyh-server v{} starting...", env!("CARGO_PKG_VERSION"));
    
    // Persist DH secret to maintain consistent keypair across restarts
    let dh_secret_file = ".gvbyh-server-dhsecret";
    let dh_secret_bytes = if std::path::Path::new(dh_secret_file).exists() {
        std::fs::read(dh_secret_file)?
    } else {
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut secret_bytes);
        std::fs::write(dh_secret_file, &secret_bytes)?;
        
        // Set file permissions to 600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(dh_secret_file)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(dh_secret_file, perms)?;
            tracing::info!("✓ DH secret file created with secure permissions (600)");
        }
        
        secret_bytes.to_vec()
    };
    
    let dh_secret_array: [u8; 32] = dh_secret_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid DH secret length"))?;
    let dh_secret = x25519_dalek::StaticSecret::from(dh_secret_array);
    let dh_public = x25519_dalek::PublicKey::from(&dh_secret);
    
    if tracing::enabled!(tracing::Level::DEBUG) {
        tracing::debug!("Server DH public key: {}...", &hex::encode(dh_public.as_bytes())[..16]);
    }
    
    // 持久化 UUID
    let uuid_file = ".gvbyh-server-uuid";
    let uuid = if std::path::Path::new(uuid_file).exists() {
        std::fs::read_to_string(uuid_file)?
    } else {
        let new_uuid = uuid::Uuid::new_v4().to_string();
        std::fs::write(uuid_file, &new_uuid)?;
        new_uuid
    };
    
    let server_ip = cli.server_ip.unwrap_or_else(|| {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(get_public_ip()).unwrap_or_else(|_| "0.0.0.0".to_string())
        })
    });
    
    // 尝试绑定常见邮件端口（伪装）
    let preferred_ports = vec![25, 587, 465, 143, 993, 110, 995];
    let bind_addr = find_available_port(&server_ip, &preferred_ports).await?;
    
    tracing::info!("Server UUID: {}", uuid);
    tracing::info!("Server IP: {}", server_ip);
    tracing::info!("Listening on: {}", bind_addr);
    
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    let encrypted_ip = BASE64.encode(bind_addr.to_string().as_bytes());
    let public_key = BASE64.encode(dh_public.as_bytes());
    
    let worker_client = WorkerClient::new(cli.worker_url.clone(), "default-key".to_string());
    
    tracing::info!("Registering to Worker...");
    
    // 尝试注册，如果失败则尝试更新
    let root_key = match worker_client.register(&uuid, &encrypted_ip, &public_key).await {
        Ok(key) => {
            tracing::info!("✓ Registered successfully");
            key
        }
        Err(gvbyh_worker_client::WorkerError::UuidConflict) => {
            tracing::warn!("UUID already exists, trying to update...");
            worker_client.update(&uuid, &encrypted_ip).await?;
            tracing::info!("✓ Updated successfully");
            
            // 从本地读取 root_key
            if let Ok(bytes) = std::fs::read(".gvbyh-server-rootkey") {
                BASE64.encode(&bytes)
            } else {
                anyhow::bail!("UUID exists but no local root_key found. Delete .gvbyh-server-uuid to re-register.");
            }
        }
        Err(e) => {
            tracing::error!("Registration failed: {}", e);
            return Err(e.into());
        }
    };
    
    // 保存 root_key 到文件
    let root_key_bytes = BASE64.decode(&root_key)?;
    std::fs::write(".gvbyh-server-rootkey", &root_key_bytes)?;
    
    // Set secure permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(".gvbyh-server-rootkey")?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(".gvbyh-server-rootkey", perms)?;
    }
    
    let root_key_array: [u8; 32] = root_key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid root_key length"))?;
    
    // 启动定期更新任务
    let worker_client_clone = worker_client.clone();
    let uuid_clone = uuid.clone();
    let encrypted_ip_clone = encrypted_ip.clone();
    let public_key_clone = public_key.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(900)); // 15 分钟
        interval.tick().await; // 跳过第一次立即触发
        
        loop {
            interval.tick().await;
            tracing::debug!("Updating server info to Worker...");
            match worker_client_clone.update(&uuid_clone, &encrypted_ip_clone).await {
                Ok(_) => tracing::debug!("✓ Server info updated"),
                Err(e) => {
                    if e.to_string().contains("UUID not found") {
                        tracing::warn!("UUID expired in Worker, re-registering...");
                        match worker_client_clone.reregister(&uuid_clone, &encrypted_ip_clone, &public_key_clone).await {
                            Ok(_) => tracing::info!("✓ Re-registered successfully"),
                            Err(re) => tracing::error!("Failed to re-register: {}", re),
                        }
                    } else {
                        tracing::warn!("Failed to update server info: {}", e);
                    }
                }
            }
        }
    });
    
    // 启动 QUIC 服务器
    tracing::info!("Starting QUIC server on {}...", bind_addr);
    
    // 创建全局 BufferPool (small: 100, medium: 50, large: 20)
    let buffer_pool = Arc::new(gvbyh_core::BufferPool::new(100, 50, 20));
    
    start_quic_server(bind_addr, dh_secret, dh_public, root_key_array, buffer_pool).await?;
    
    Ok(())
}

async fn start_quic_server(
    addr: SocketAddr,
    dh_secret: x25519_dalek::StaticSecret,
    dh_public: x25519_dalek::PublicKey,
    root_key: [u8; 32],
    buffer_pool: Arc<gvbyh_core::BufferPool>,
) -> Result<()> {
    use quinn::{Endpoint, ServerConfig};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    
    let cert = rcgen::generate_simple_self_signed(vec![
        "smtp.gmail.com".to_string(),
        "mail.google.com".to_string(),
        "gmail.com".to_string(),
    ]).map_err(|e| anyhow::anyhow!("Failed to generate certificate: {}", e))?;
    
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    
    let mut server_config = ServerConfig::with_single_cert(vec![cert_der], key_der)?;
    let transport_config = Arc::new(quinn::TransportConfig::default());
    server_config.transport_config(transport_config);
    
    let endpoint = Endpoint::server(server_config, addr)?;
    tracing::info!("✓ QUIC server listening on {} (SNI: smtp.gmail.com)", addr);
    
    let dh_secret = Arc::new(dh_secret);
    let root_key = Arc::new(root_key);
    
    while let Some(conn) = endpoint.accept().await {
        let dh_secret = dh_secret.clone();
        let dh_public = dh_public;
        let root_key = root_key.clone();
        let buffer_pool = buffer_pool.clone();
        
        tokio::spawn(async move {
            match conn.await {
                Ok(connection) => {
                    tracing::info!("New connection from {}", connection.remote_address());
                    handle_connection(connection, dh_secret, dh_public, root_key, buffer_pool).await;
                }
                Err(e) => {
                    tracing::error!("Connection failed: {}", e);
                }
            }
        });
    }
    
    Ok(())
}

async fn handle_connection(
    conn: quinn::Connection,
    dh_secret: Arc<x25519_dalek::StaticSecret>,
    dh_public: x25519_dalek::PublicKey,
    root_key: Arc<[u8; 32]>,
    buffer_pool: Arc<gvbyh_core::BufferPool>,
) {
    use gvbyh_core::CryptoContext;
    use std::sync::Mutex;
    
    let crypto_context: Arc<Mutex<Option<CryptoContext>>> = Arc::new(Mutex::new(None));
    
    let mut stream_count = 0;
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                stream_count += 1;
                tracing::info!("Accepted stream #{}", stream_count);
                
                let dh_secret = dh_secret.clone();
                let root_key = root_key.clone();
                let crypto_ctx = crypto_context.clone();
                let buffer_pool = buffer_pool.clone();
                
                tokio::spawn(async move {
                    handle_stream(send, recv, dh_secret, dh_public, root_key, crypto_ctx, buffer_pool).await;
                });
            }
            Err(e) => {
                tracing::error!("Accept stream error: {}", e);
                break;
            }
        }
    }
}

async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    dh_secret: Arc<x25519_dalek::StaticSecret>,
    dh_public: x25519_dalek::PublicKey,
    root_key: Arc<[u8; 32]>,
    crypto_context: Arc<std::sync::Mutex<Option<gvbyh_core::CryptoContext>>>,
    buffer_pool: Arc<gvbyh_core::BufferPool>,
) {
    use gvbyh_core::{SmtpPacket, CryptoContext};
    use bytes::Bytes;
    
    tracing::debug!("handle_stream started");
    
    // RAII: buffer 在作用域结束时自动归还
    struct BufferGuard {
        buffer: bytes::BytesMut,
        pool: Arc<gvbyh_core::BufferPool>,
    }
    
    impl Drop for BufferGuard {
        fn drop(&mut self) {
            let buf = std::mem::replace(&mut self.buffer, bytes::BytesMut::new());
            self.pool.put(buf);
        }
    }
    
    impl std::ops::Deref for BufferGuard {
        type Target = [u8];
        fn deref(&self) -> &Self::Target {
            &self.buffer
        }
    }
    
    impl std::ops::DerefMut for BufferGuard {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.buffer
        }
    }
    
    let mut buf = BufferGuard {
        buffer: buffer_pool.get(65536),
        pool: buffer_pool,
    };
    
    // 智能读取：先尝试读取开头判断包类型
    let mut header_buf = [0u8; 21];  // SMTP_EHLO 长度
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        recv.read_exact(&mut header_buf)
    ).await {
        Ok(Ok(())) => {},
        Ok(Err(e)) => {
            tracing::error!("Read header error: {}", e);
            return;
        }
        Err(_) => {
            tracing::debug!("Read timeout");
            return;
        }
    };
    
    // 检查是否是握手
    if &header_buf[..10] == b"HANDSHAKE\n" {
        // 握手：读取剩余 21 字节公钥 (42 - 21 = 21)
        let mut key_buf = [0u8; 21];
        if let Err(e) = recv.read_exact(&mut key_buf).await {
            tracing::error!("Failed to read public key: {}", e);
            return;
        }
        
        let mut request_data = Vec::with_capacity(42);
        request_data.extend_from_slice(&header_buf[..10]);  // HANDSHAKE\n
        request_data.extend_from_slice(&header_buf[10..21]); // 前 11 字节公钥
        request_data.extend_from_slice(&key_buf);            // 后 21 字节公钥
        
        tracing::info!("Read {} bytes from stream (handshake)", request_data.len());
        tracing::info!("Received data: {:?}... ({} bytes total)", &request_data[..10], request_data.len());
        tracing::info!("Detected HANDSHAKE prefix");
        tracing::info!("Processing handshake request");
        
        // 提取客户端公钥
        let client_public_bytes = &request_data[10..42];
        let client_public_array: [u8; 32] = match client_public_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                tracing::error!("Invalid client public key length");
                return;
            }
        };
        let client_public = x25519_dalek::PublicKey::from(client_public_array);
        
        if tracing::enabled!(tracing::Level::DEBUG) {
            tracing::debug!("=== Server Handshake ===");
            tracing::debug!("Client public key: {}...", &hex::encode(client_public.as_bytes())[..16]);
            tracing::debug!("Server public key: {}...", &hex::encode(dh_public.as_bytes())[..16]);
            tracing::debug!("Root key: {}...", &hex::encode(root_key.as_ref())[..16]);
        }
        
        // 使用统一的密钥派生方法
        let dh_secret_bytes: [u8; 32] = dh_secret.to_bytes();
        let keys = match CryptoContext::derive_keys_static(&dh_secret_bytes, &client_public, root_key.as_ref()) {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("Key derivation failed: {}", e);
                return;
            }
        };
        
        let crypto = CryptoContext::with_keys(keys, *root_key);
        tracing::info!("✓ Server keys derived");
        
        *crypto_context.lock().unwrap() = Some(crypto);
        
        // 发送握手响应
        if let Err(e) = send.write_all(b"HANDSHAKE\n").await {
            tracing::error!("Failed to write handshake header: {}", e);
            return;
        }
        if let Err(e) = send.write_all(dh_public.as_bytes()).await {
            tracing::error!("Failed to write public key: {}", e);
            return;
        }
        
        // 关闭发送端，确保数据被发送
        if let Err(e) = send.finish() {
            tracing::error!("Failed to finish handshake response: {}", e);
            return;
        }
        
        tracing::info!("Handshake response sent and flushed");
        return;
    }
    
    // 不是握手，应该是 SMTP 包
    // header_buf 已经读取了 21 字节（SMTP_EHLO）
    // 继续读取剩余的 SMTP 头部
    const SMTP_EHLO_LEN: usize = 21;
    const SMTP_MAIL_FROM_LEN: usize = 31;  // 实际长度
    const SMTP_RCPT_TO_LEN: usize = 26;    // 实际长度
    const SMTP_DATA_LEN: usize = 6;
    const SMTP_HEADER_LEN: usize = SMTP_EHLO_LEN + SMTP_MAIL_FROM_LEN + SMTP_RCPT_TO_LEN + SMTP_DATA_LEN;
    
    let mut full_header = Vec::with_capacity(SMTP_HEADER_LEN);
    full_header.extend_from_slice(&header_buf);  // 已读取的 21 字节
    
    // 读取剩余头部
    let remaining_header_len = SMTP_HEADER_LEN - SMTP_EHLO_LEN;
    let mut remaining_buf = vec![0u8; remaining_header_len];
    if let Err(e) = recv.read_exact(&mut remaining_buf).await {
        tracing::error!("Failed to read SMTP header: {}", e);
        return;
    }
    full_header.extend_from_slice(&remaining_buf);
    
    // 读取长度字段（4字节）
    let mut len_buf = [0u8; 4];
    if let Err(e) = recv.read_exact(&mut len_buf).await {
        tracing::error!("Failed to read length: {}", e);
        return;
    }
    let payload_len = u32::from_be_bytes(len_buf) as usize;
    
    tracing::debug!("SMTP packet payload length: {}", payload_len);
    
    // 读取 payload
    let mut payload_buf = vec![0u8; payload_len];
    if let Err(e) = recv.read_exact(&mut payload_buf).await {
        tracing::error!("Failed to read payload: {}", e);
        return;
    }
    
    // 计算填充长度（与编码逻辑一致）
    let padding_len = payload_len % 16;
    
    // 读取填充和结束标记
    const SMTP_END_LEN: usize = 5;  // "\r\n.\r\n"
    let end_section_len = padding_len + SMTP_END_LEN;
    let mut end_buf = vec![0u8; end_section_len];
    if let Err(e) = recv.read_exact(&mut end_buf).await {
        tracing::error!("Failed to read end marker: {}", e);
        return;
    }
    
    // 重新组装完整的 SMTP 包
    let mut full_packet = BytesMut::with_capacity(SMTP_HEADER_LEN + 4 + payload_len + end_section_len);
    full_packet.extend_from_slice(&full_header);
    full_packet.extend_from_slice(&len_buf);
    full_packet.extend_from_slice(&payload_buf);
    full_packet.extend_from_slice(&end_buf);
    
    tracing::info!("Read {} bytes from stream (SMTP packet)", full_packet.len());
    
    // 获取加密上下文
    let crypto = {
        let ctx_guard = crypto_context.lock().unwrap();
        match ctx_guard.as_ref() {
            Some(c) => c.clone(),
            None => {
                tracing::warn!("No crypto context, handshake required first");
                return;
            }
        }
    };
    
    // 尝试解析为加密的 SmtpPacket
    if let Ok((packet, _)) = SmtpPacket::decode(full_packet.freeze()) {
        match crypto.decrypt(&packet.payload) {
            Ok(decrypted) => {
                let decrypted_data = decrypted.as_ref();
                
                if decrypted_data == b"ping" {
                    tracing::debug!("Received encrypted ping");
                    if let Ok(encrypted_pong) = crypto.encrypt(b"pong") {
                        let response_packet = SmtpPacket::new(encrypted_pong);
                        let _ = send.write_all(&response_packet.encode()).await;
                        let _ = send.finish();
                    }
                    return;
                }
                
                if decrypted_data.starts_with(b"CONNECT ") {
                    if let Err(e) = handle_proxy_encrypted(decrypted_data, send, recv, crypto).await {
                        tracing::error!("Proxy error: {}", e);
                    }
                    return;
                }
            }
            Err(e) => {
                tracing::error!("Decryption failed: {}", e);
            }
        }
    }
    
    tracing::warn!("Unknown request type or decryption failed");
}

async fn handle_proxy_encrypted(
    request: &[u8],
    mut client_send: quinn::SendStream,
    mut client_recv: quinn::RecvStream,
    crypto: gvbyh_core::CryptoContext,
) -> Result<()> {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use gvbyh_core::SmtpPacket;
    
    // 解析目标地址
    let request_str = String::from_utf8_lossy(request);
    let target = request_str.strip_prefix("CONNECT ").unwrap_or("").trim();
    
    if target.is_empty() {
        let encrypted_err = crypto.encrypt(b"ERROR")?;
        let packet = SmtpPacket::new(encrypted_err);
        let _ = client_send.write_all(&packet.encode()).await;
        return Ok(());
    }
    
    tracing::info!("Proxying to {}", target);
    
    // 使用 DoH 解析目标地址
    let target_addr = match resolve_target(target).await {
        Ok(addr) => {
            tracing::info!("✓ Resolved {} to {}", target, addr);
            addr
        }
        Err(e) => {
            tracing::error!("Failed to resolve {}: {}", target, e);
            let encrypted_err = crypto.encrypt(b"ERROR")?;
            let packet = SmtpPacket::new(encrypted_err);
            let _ = client_send.write_all(&packet.encode()).await;
            return Ok(());
        }
    };
    
    // 连接目标服务器
    let mut target_stream = match tokio::net::TcpStream::connect(target_addr).await {
        Ok(s) => {
            tracing::info!("✓ Connected to {}", target_addr);
            s
        }
        Err(e) => {
            tracing::error!("Failed to connect to {}: {}", target_addr, e);
            let encrypted_err = crypto.encrypt(b"ERROR")?;
            let packet = SmtpPacket::new(encrypted_err);
            let _ = client_send.write_all(&packet.encode()).await;
            return Ok(());
        }
    };
    
    // 发送成功响应
    let encrypted_ok = crypto.encrypt(b"OK")?;
    let packet = SmtpPacket::new(encrypted_ok);
    client_send.write_all(&packet.encode()).await?;
    
    tracing::info!("✓ Proxy tunnel established, starting data relay");
    
    // 双向转发（需要处理加密/解密）
    let (mut target_read, mut target_write) = target_stream.split();
    
    let crypto_up = crypto.clone();
    let up = async move {
        let mut accumulated = bytes::BytesMut::new();
        let mut buf = vec![0u8; 8192];
        let mut transferred = 0u64;
        tracing::info!("Starting upload relay");
        loop {
            match client_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    tracing::debug!("Received {} bytes from client", n);
                    accumulated.extend_from_slice(&buf[..n]);
                    
                    // 处理所有完整的包
                    loop {
                        if accumulated.is_empty() {
                            break;
                        }
                        
                        match SmtpPacket::decode(accumulated.clone().freeze()) {
                            Ok((packet, consumed)) => {
                                if let Ok(decrypted) = crypto_up.decrypt(&packet.payload) {
                                    transferred += decrypted.len() as u64;
                                    tracing::debug!("Decrypted {} bytes, sending to target", decrypted.len());
                                    if let Err(e) = target_write.write_all(&decrypted).await {
                                        tracing::debug!("Target write error: {}", e);
                                        return;
                                    }
                                    
                                    // 移除已处理的字节
                                    accumulated.advance(consumed);
                                } else {
                                    tracing::warn!("Failed to decrypt client data");
                                    return;
                                }
                            }
                            Err(_) => {
                                // 需要更多数据
                                break;
                            }
                        }
                    }
                }
                Ok(None) => {
                    tracing::info!("Client closed connection");
                    break;
                }
                Err(e) => {
                    tracing::debug!("Client read error: {}", e);
                    break;
                }
            }
        }
        tracing::info!("Upload finished: {} bytes", transferred);
    };
    
    let crypto_down = crypto.clone();
    let down = async move {
        let mut buf = vec![0u8; 8192];
        let mut transferred = 0u64;
        tracing::info!("Starting download relay");
        
        // 立即尝试读取，看看是否有数据
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        tracing::debug!("Attempting first read from target");
        
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) => {
                    tracing::info!("Target closed connection (transferred {} bytes)", transferred);
                    break;
                }
                Ok(n) => {
                    transferred += n as u64;
                    tracing::info!("Received {} bytes from target (total: {}), encrypting", n, transferred);
                    // 加密目标数据
                    if let Ok(encrypted) = crypto_down.encrypt(&buf[..n]) {
                        let packet = SmtpPacket::new(encrypted);
                        let packet_bytes = packet.encode();
                        tracing::info!("Sending {} bytes encrypted packet to client", packet_bytes.len());
                        if let Err(e) = client_send.write_all(&packet_bytes).await {
                            tracing::warn!("Client write error: {}", e);
                            break;
                        }
                        tracing::info!("✓ Sent {} bytes to client", packet_bytes.len());
                    } else {
                        tracing::warn!("Failed to encrypt target data");
                    }
                }
                Err(e) => {
                    tracing::warn!("Target read error: {}", e);
                    break;
                }
            }
        }
        tracing::info!("Download finished: {} bytes", transferred);
        let _ = client_send.finish();
    };
    
    tokio::join!(up, down);
    
    tracing::info!("Proxy connection closed: {}", target);
    Ok(())
}

async fn get_public_ip() -> Result<String> {
    use tokio::process::Command;
    
    // 尝试 ip addr
    if let Ok(output) = Command::new("ip").arg("addr").output().await {
        if let Ok(text) = String::from_utf8(output.stdout) {
            let mut current_iface = String::new();
            for line in text.lines() {
                // 获取接口名
                if !line.starts_with(' ') && line.contains(':') {
                    current_iface = line.split(':').nth(1).unwrap_or("").trim().to_string();
                }
                // 跳过 lo、docker、br 接口
                if current_iface.starts_with("lo") 
                    || current_iface.starts_with("docker") 
                    || current_iface.starts_with("br") {
                    continue;
                }
                // 提取 IP
                if line.contains("inet ") && !line.contains("127.0.0.1") {
                    if let Some(ip) = line.split_whitespace().nth(1) {
                        if let Some(addr) = ip.split('/').next() {
                            // 过滤局域网 IP
                            if !is_private_ip(addr) {
                                return Ok(addr.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    
    Ok("0.0.0.0".to_string())
}

// 判断是否为私有/局域网 IP
fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return true;
    }
    
    let first: u8 = parts[0].parse().unwrap_or(0);
    let second: u8 = parts[1].parse().unwrap_or(0);
    
    // 10.0.0.0/8
    if first == 10 {
        return true;
    }
    // 172.16.0.0/12
    if first == 172 && (16..=31).contains(&second) {
        return true;
    }
    // 192.168.0.0/16
    if first == 192 && second == 168 {
        return true;
    }
    // 127.0.0.0/8 (loopback)
    if first == 127 {
        return true;
    }
    // 169.254.0.0/16 (link-local)
    if first == 169 && second == 254 {
        return true;
    }
    
    false
}

// 智能端口选择：优先使用邮件端口，否则随机
async fn find_available_port(ip: &str, preferred_ports: &[u16]) -> Result<SocketAddr> {
    use tokio::net::TcpListener;
    use rand::Rng;
    
    // 1. 尝试常见邮件端口
    for &port in preferred_ports {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr_parsed) = addr.parse::<SocketAddr>() {
            if TcpListener::bind(addr_parsed).await.is_ok() {
                tracing::info!("✓ Using mail port {} (disguise)", port);
                return Ok(addr_parsed);
            }
        }
    }
    
    tracing::warn!("All preferred mail ports occupied, using random port");
    
    // 2. 随机选择端口 (10111-55535)
    let mut rng = rand::thread_rng();
    for _ in 0..100 {
        let port = rng.gen_range(10111..=55535);
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr_parsed) = addr.parse::<SocketAddr>() {
            if TcpListener::bind(addr_parsed).await.is_ok() {
                tracing::info!("✓ Using random port {}", port);
                return Ok(addr_parsed);
            }
        }
    }
    
    anyhow::bail!("Failed to find available port")
}
