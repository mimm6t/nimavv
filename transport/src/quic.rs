use quinn::{Endpoint, Connection};
use rustls::pki_types::{CertificateDer, ServerName};
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;
use bytes::Bytes;
use anyhow::Result;
use gvbyh_core::{CryptoContext, SmtpPacket};

pub struct QuicClient {
    endpoint: Endpoint,
    crypto: Arc<CryptoContext>,
}

impl QuicClient {
    pub fn new(crypto: CryptoContext) -> Result<Self> {
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(256u32.into());
        transport.max_concurrent_uni_streams(256u32.into());
        transport.max_idle_timeout(Some(Duration::from_secs(120).try_into()?));
        transport.keep_alive_interval(Some(Duration::from_secs(25))); // SMTP心跳间隔
        
        // 隐藏QUIC特征
        transport.initial_mtu(1200); // 避免QUIC典型1280
        transport.min_mtu(1200);
        
        // BBR拥塞控制
        transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        
        let crypto_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerification))
            .with_no_client_auth();
        
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?
        ));
        client_config.transport_config(Arc::new(transport));
        
        endpoint.set_default_client_config(client_config);
        
        Ok(Self {
            endpoint,
            crypto: Arc::new(crypto),
        })
    }
    
    pub async fn connect(&self, addr: SocketAddr) -> Result<QuicConnection> {
        let sni_hostname = "smtp.gmail.com";
        tracing::debug!("Connecting to {} with SNI: {}", addr, sni_hostname);
        
        let conn = self.endpoint.connect(addr, sni_hostname)?.await?;
        
        Ok(QuicConnection {
            conn,
            crypto: self.crypto.clone(),
        })
    }
    
    pub async fn connect_with_keys(
        &self, 
        addr: SocketAddr, 
        server_public: &x25519_dalek::PublicKey,
        root_key: &[u8; 32]
    ) -> Result<QuicConnection> {
        let sni_hostname = "smtp.gmail.com";
        tracing::info!("Connecting to {} with SNI: {}", addr, sni_hostname);
        
        let conn = self.endpoint.connect(addr, sni_hostname)?.await
            .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))?;
        
        tracing::info!("QUIC connection established, opening handshake stream");
        
        // 发送客户端公钥进行握手
        let (mut send, mut recv) = conn.open_bi().await
            .map_err(|e| anyhow::anyhow!("Failed to open bidirectional stream: {}", e))?;
        
        tracing::info!("Sending handshake request");
        send.write_all(b"HANDSHAKE\n").await
            .map_err(|e| anyhow::anyhow!("Failed to write HANDSHAKE header: {}", e))?;
        send.write_all(self.crypto.public_key().as_bytes()).await
            .map_err(|e| anyhow::anyhow!("Failed to write public key: {}", e))?;
        send.finish()
            .map_err(|e| anyhow::anyhow!("Failed to finish send stream: {}", e))?;
        
        tracing::info!("Handshake request sent, waiting for server response");
        
        // 接收服务端公钥（验证）
        let mut buf = vec![0u8; 1024];
        let n = match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                tracing::info!("Received {} bytes from server", n);
                n
            }
            Ok(None) => {
                anyhow::bail!("Server closed connection without sending handshake response");
            }
            Err(e) => {
                anyhow::bail!("Failed to read handshake response: {}", e);
            }
        };
        
        if !buf.starts_with(b"HANDSHAKE\n") {
            anyhow::bail!("Invalid handshake response: expected HANDSHAKE header");
        }
        
        if n < 42 {
            anyhow::bail!("Handshake response too short: {} bytes (expected 42)", n);
        }
        
        let received_public = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(&buf[10..42])?);
        if received_public.as_bytes() != server_public.as_bytes() {
            anyhow::bail!("Server public key mismatch");
        }
        
        tracing::info!("Server public key verified, deriving session keys");
        
        // 使用 Worker 提供的 root_key 派生会话密钥
        let mut crypto = (*self.crypto).clone();
        crypto.derive_keys(server_public, root_key)?;
        
        tracing::info!("✓ Client handshake completed");
        
        Ok(QuicConnection {
            conn,
            crypto: Arc::new(crypto),
        })
    }
}

pub struct QuicConnection {
    pub conn: Connection,
    crypto: Arc<CryptoContext>,
}

impl QuicConnection {
    pub fn crypto(&self) -> &Arc<CryptoContext> {
        &self.crypto
    }
    
    pub async fn send(&self, data: &[u8]) -> Result<Bytes> {
        let encrypted = self.crypto.encrypt(data)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        let packet = SmtpPacket::new(encrypted);
        let encoded = packet.encode();
        
        let (mut send, mut recv) = self.conn.open_bi().await?;
        send.write_all(&encoded).await?;
        send.finish()?;
        
        let response = recv.read_to_end(65536).await?;
        let (packet, _) = SmtpPacket::decode(Bytes::from(response))
            .map_err(|e| anyhow::anyhow!("Protocol error: {}", e))?;
        let decrypted = self.crypto.decrypt(&packet.payload)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        
        Ok(decrypted)
    }
    
    pub async fn health_check(&self) -> Result<Duration> {
        let start = std::time::Instant::now();
        
        // 打开一个新的双向流进行健康检查
        let (mut send, mut recv) = self.conn.open_bi().await
            .map_err(|e| anyhow::anyhow!("Failed to open stream for health check: {}", e))?;
        
        // 发送 ping 消息
        let encrypted = self.crypto.encrypt(b"ping")?;
        let packet = SmtpPacket::new(encrypted);
        send.write_all(&packet.encode()).await
            .map_err(|e| anyhow::anyhow!("Failed to send ping: {}", e))?;
        send.finish()
            .map_err(|e| anyhow::anyhow!("Failed to finish send stream: {}", e))?;
        
        // 等待响应
        let mut buf = vec![0u8; 1024];
        let n = match recv.read(&mut buf).await {
            Ok(Some(n)) => n,
            Ok(None) => anyhow::bail!("connection lost"),
            Err(e) => anyhow::bail!("read error: {}", e),
        };
        
        // 验证响应
        let (response_packet, _) = SmtpPacket::decode(bytes::Bytes::from(buf[..n].to_vec()))
            .map_err(|e| anyhow::anyhow!("Failed to decode response: {}", e))?;
        let decrypted = self.crypto.decrypt(&response_packet.payload)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt response: {}", e))?;
        
        if &decrypted[..] != b"pong" {
            anyhow::bail!("Invalid health check response");
        }
        
        Ok(start.elapsed())
    }
    
    pub async fn proxy_tcp(&self, target: &str) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let request = format!("CONNECT {}", target);
        
        // 打开双向流
        let (mut send, mut recv) = self.conn.open_bi().await?;
        
        // 发送加密的 CONNECT 请求
        let encrypted = self.crypto.encrypt(request.as_bytes())?;
        let packet = SmtpPacket::new(encrypted);
        send.write_all(&packet.encode()).await?;
        // 不调用 finish()，保持流打开用于后续数据传输
        
        // 等待 OK 响应 - 读取一个包
        let mut buf = vec![0u8; 65536];
        let n = match recv.read(&mut buf).await? {
            Some(n) => n,
            None => anyhow::bail!("Server closed connection"),
        };
        
        let (response_packet, _) = SmtpPacket::decode(bytes::Bytes::from(buf[..n].to_vec()))?;
        let decrypted = self.crypto.decrypt(&response_packet.payload)?;
        
        if &decrypted[..] != b"OK" {
            anyhow::bail!("Proxy connection failed");
        }
        
        // 返回流供后续数据转发使用
        Ok((send, recv))
    }
    
    // UDP 代理：发送数据包并等待响应
    pub async fn proxy_udp(&self, target: &str, data: &[u8]) -> Result<Vec<u8>> {
        let request = format!("UDP {}\n", target);
        let mut payload = request.as_bytes().to_vec();
        payload.extend_from_slice(data);
        
        let encrypted = self.crypto.encrypt(&payload)?;
        let packet = SmtpPacket::new(encrypted);
        
        let (mut send, mut recv) = self.conn.open_bi().await?;
        send.write_all(&packet.encode()).await?;
        send.finish()?;
        
        let mut buf = vec![0u8; 65536];
        let n = match recv.read(&mut buf).await? {
            Some(n) => n,
            None => anyhow::bail!("Server closed connection"),
        };
        
        let (response_packet, _) = SmtpPacket::decode(bytes::Bytes::from(buf[..n].to_vec()))?;
        let decrypted = self.crypto.decrypt(&response_packet.payload)?;
        
        Ok(decrypted.to_vec())
    }
}

#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

impl Clone for QuicConnection {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            crypto: self.crypto.clone(),
        }
    }
}
