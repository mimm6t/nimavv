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
    // 整体超时 300 秒（5分钟）
    tokio::time::timeout(std::time::Duration::from_secs(300), async {
        let mut buf = [0u8; 512];
        
        // SOCKS5 握手超时 5 秒
        let target = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
            Ok::<_, anyhow::Error>(target)
        }).await??;
        
        // 代理连接超时 10 秒
        let (mut proxy_send, mut proxy_recv) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            conn.proxy_tcp(&target)
        ).await??;
        
        stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        
        let (mut sr, mut sw) = stream.split();
        let crypto = conn.crypto().clone();
        
        let upload = async {
            let mut buf = vec![0u8; 8192];
            loop {
                match sr.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let encrypted = crypto.encrypt(&buf[..n])?;
                        let packet = gvbyh_core::SmtpPacket::new(encrypted);
                        proxy_send.write_all(&packet.encode()).await?;
                    }
                    Err(_) => break,
                }
            }
            let _ = proxy_send.finish();
            Ok::<_, anyhow::Error>(())
        };
        
        let download = async {
            let mut accumulated = bytes::BytesMut::new();
            let mut buf = vec![0u8; 8192];
            
            loop {
                match proxy_recv.read(&mut buf).await {
                    Ok(Some(n)) => {
                        accumulated.extend_from_slice(&buf[..n]);
                        
                        loop {
                            if accumulated.is_empty() {
                                break;
                            }
                            
                            match gvbyh_core::SmtpPacket::decode(accumulated.clone().freeze()) {
                                Ok((packet, consumed)) => {
                                    let decrypted = crypto.decrypt(&packet.payload)?;
                                    if let Err(_) = sw.write_all(&decrypted).await {
                                        return Ok(()); // 客户端关闭，正常退出
                                    }
                                    accumulated.advance(consumed);
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        
        let _ = tokio::join!(upload, download);
        Ok::<_, anyhow::Error>(())
    }).await?
}
