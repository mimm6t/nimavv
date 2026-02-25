use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::Result;
use gvbyh_transport::{QuicConnection, ConnectionPool};
use bytes::Buf;

pub struct Socks5Server {
    listen_addr: SocketAddr,
}

impl Socks5Server {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }
    
    pub async fn run(&self, connection: Arc<QuicConnection>) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        
        loop {
            let (stream, peer) = listener.accept().await?;
            let conn = connection.clone();
            
            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, conn).await {
                    tracing::debug!("Client {} error: {}", peer, e);
                }
            });
        }
    }
    
    pub async fn run_with_pool(&self, pool: Arc<ConnectionPool>) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        
        loop {
            let (stream, peer) = listener.accept().await?;
            let pool = pool.clone();
            
            tokio::spawn(async move {
                match pool.get().await {
                    Ok(conn) => {
                        if let Err(e) = handle_client(stream, Arc::new(conn)).await {
                            tracing::debug!("Client {} error: {}", peer, e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to get connection: {}", e);
                    }
                }
            });
        }
    }
}

async fn handle_client(mut stream: TcpStream, conn: Arc<QuicConnection>) -> Result<()> {
    let mut buf = [0u8; 512];
    
    stream.read_exact(&mut buf[..2]).await?;
    if buf[0] != 0x05 {
        anyhow::bail!("Unsupported SOCKS version");
    }
    
    let nmethods = buf[1] as usize;
    stream.read_exact(&mut buf[..nmethods]).await?;
    stream.write_all(&[0x05, 0x00]).await?;
    
    stream.read_exact(&mut buf[..4]).await?;
    if buf[1] != 0x01 {
        anyhow::bail!("Only CONNECT supported");
    }
    
    let target = match buf[3] {
        0x01 => {
            stream.read_exact(&mut buf[..6]).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            format!("{}:{}", ip, port)
        }
        0x03 => {
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len + 2]).await?;
            let domain = String::from_utf8_lossy(&buf[..len]);
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            format!("{}:{}", domain, port)
        }
        _ => anyhow::bail!("Unsupported address type"),
    };
    
    let (mut proxy_send, mut proxy_recv) = conn.proxy_tcp(&target).await?;
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    
    let (mut sr, mut sw) = stream.split();
    let crypto = conn.crypto().clone();
    
    let upload = async {
        let mut buf = vec![0u8; 8192];
        let mut total = 0;
        loop {
            let n = sr.read(&mut buf).await?;
            if n == 0 { 
                tracing::debug!("Upload: client finished sending {} bytes", total);
                break; 
            }
            total += n;
            tracing::debug!("Upload: read {} bytes from client (total: {})", n, total);
            // 加密并发送
            let encrypted = crypto.encrypt(&buf[..n])?;
            let packet = gvbyh_core::SmtpPacket::new(encrypted);
            proxy_send.write_all(&packet.encode()).await?;
            tracing::debug!("Upload: sent {} bytes packet to server", packet.encode().len());
        }
        // 关闭发送方向，但保持接收方向打开
        tracing::debug!("Upload: calling finish()");
        let _ = proxy_send.finish();
        tracing::debug!("Upload: finish() called, task ending");
        Ok::<_, anyhow::Error>(())
    };
    
    let download = async {
        let mut accumulated = bytes::BytesMut::new();
        let mut buf = vec![0u8; 8192];
        tracing::debug!("Download: starting to receive");
        
        loop {
            tracing::debug!("Download: waiting for data...");
            match proxy_recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    tracing::debug!("Download: received {} bytes chunk", n);
                    accumulated.extend_from_slice(&buf[..n]);
                    
                    // 尝试解析完整的 SMTP 包
                    loop {
                        if accumulated.is_empty() {
                            break;
                        }
                        
                        match gvbyh_core::SmtpPacket::decode(accumulated.clone().freeze()) {
                            Ok((packet, consumed)) => {
                                tracing::debug!("Download: decoded packet with {} bytes payload, consumed {} bytes", packet.payload.len(), consumed);
                                let decrypted = crypto.decrypt(&packet.payload)?;
                                tracing::debug!("Download: decrypted {} bytes, writing to client", decrypted.len());
                                sw.write_all(&decrypted).await?;
                                tracing::debug!("Download: wrote {} bytes to client", decrypted.len());
                                
                                // 移除已处理的字节
                                accumulated.advance(consumed);
                            }
                            Err(e) => {
                                tracing::debug!("Download: incomplete packet, need more data: {}", e);
                                break; // 需要更多数据
                            }
                        }
                    }
                }
                Ok(None) => {
                    tracing::debug!("Download: server closed");
                    break;
                }
                Err(e) => {
                    tracing::warn!("Download: read error: {}", e);
                    return Err(e.into());
                }
            }
        }
        tracing::debug!("Download: task ending");
        Ok::<_, anyhow::Error>(())
    };
    
    tracing::debug!("Starting upload and download tasks");
    tokio::try_join!(upload, download)?;
    tracing::debug!("Both tasks completed");
    
    Ok(())
}
