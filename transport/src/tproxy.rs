use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use gvbyh_router::GeoRouter;
use super::pool::ConnectionPool;
use super::nat::LruNatTable;
use super::metrics::Metrics;
use std::time::{Duration, Instant};

pub struct TProxyHandler {
    addr: SocketAddr,
    router: Arc<GeoRouter>,
    pool: Arc<ConnectionPool>,
    metrics: Option<Arc<Metrics>>,
}

impl TProxyHandler {
    pub fn new(addr: SocketAddr, router: Arc<GeoRouter>, pool: Arc<ConnectionPool>) -> Self {
        Self { addr, router, pool, metrics: None }
    }
    
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }
    
    pub async fn run(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.run_linux().await
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("TProxy only supported on Linux")
        }
    }
    
    #[cfg(target_os = "linux")]
    async fn run_linux(&self) -> Result<()> {
        // 启动 TCP 透明代理
        let tcp_addr = self.addr;
        let tcp_router = self.router.clone();
        let tcp_pool = self.pool.clone();
        
        tokio::spawn(async move {
            if let Err(e) = run_tcp_tproxy(tcp_addr, tcp_router, tcp_pool).await {
                tracing::error!("TCP TProxy error: {}", e);
            }
        });
        
        // 启动 UDP 透明代理
        let udp_addr = self.addr;
        let udp_router = self.router.clone();
        let udp_pool = self.pool.clone();
        
        run_udp_tproxy(udp_addr, udp_router, udp_pool).await
    }
}

#[cfg(target_os = "linux")]
async fn run_tcp_tproxy(
    addr: SocketAddr,
    router: Arc<GeoRouter>,
    pool: Arc<ConnectionPool>,
) -> Result<()> {
    use socket2::{Socket, Domain, Type, Protocol};
    use std::os::unix::io::AsRawFd;
    
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    
    // 设置 IP_TRANSPARENT
    set_transparent(&socket, addr.is_ipv6())?;
    
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    
    let listener: std::net::TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    
    tracing::info!("TCP TProxy listening on {}", addr);
    
    loop {
        let (stream, peer) = listener.accept().await?;
        let orig_dst = get_original_dst_tcp(&stream)?;
        
        let router = router.clone();
        let pool = pool.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(stream, peer, orig_dst, router, pool).await {
                tracing::debug!("TCP connection error: {}", e);
            }
        });
    }
}

#[cfg(target_os = "linux")]
async fn run_udp_tproxy(
    addr: SocketAddr,
    router: Arc<GeoRouter>,
    pool: Arc<ConnectionPool>,
) -> Result<()> {
    use socket2::{Socket, Domain, Type, Protocol};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    
    // 设置 IP_TRANSPARENT 和 IP_RECVORIGDSTADDR
    set_transparent(&socket, addr.is_ipv6())?;
    set_recvorigdstaddr(&socket, addr.is_ipv6())?;
    
    socket.bind(&addr.into())?;
    
    let std_socket: std::net::UdpSocket = socket.into();
    std_socket.set_nonblocking(true)?;
    let udp_socket = UdpSocket::from_std(std_socket)?;
    
    tracing::info!("UDP TProxy listening on {}", addr);
    
    // UDP NAT 会话表 - 使用 LRU
    let nat_table = Arc::new(LruNatTable::new(10000, Duration::from_secs(300)));
    
    // 清理过期会话
    let nat_table_clone = nat_table.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            nat_table_clone.cleanup().await;
            let stats = nat_table_clone.stats().await;
            tracing::debug!("NAT stats: {:?}", stats);
        }
    });
    
    let udp_socket = Arc::new(udp_socket);
    
    let mut buf = vec![0u8; 65536];
    let mut control_buf = vec![0u8; 1024];
    
    loop {
        // 使用 recvmsg 接收 OOB 数据
        let (n, source, orig_dst) = recv_from_with_origdst(&udp_socket, &mut buf, &mut control_buf).await?;
        
        if n == 0 {
            continue;
        }
        
        let data = buf[..n].to_vec();
        let router = router.clone();
        let pool = pool.clone();
        let nat_table = nat_table.clone();
        let udp_socket = udp_socket.clone();
        
        tokio::spawn(async move {
            if let Err(e) = handle_udp_packet(
                udp_socket, data, source, orig_dst, router, pool, nat_table
            ).await {
                tracing::debug!("UDP packet error: {}", e);
            }
        });
    }
}

#[cfg(target_os = "linux")]
fn set_transparent(socket: &socket2::Socket, is_ipv6: bool) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    
    unsafe {
        let optval: libc::c_int = 1;
        
        // 设置 SO_REUSEADDR
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of_val(&optval) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow::anyhow!("Failed to set SO_REUSEADDR"));
        }
        
        // 设置 IP_TRANSPARENT
        let level = if is_ipv6 {
            libc::IPPROTO_IPV6
        } else {
            libc::SOL_IP
        };
        let optname = if is_ipv6 {
            libc::IPV6_TRANSPARENT
        } else {
            libc::IP_TRANSPARENT
        };
        
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            level,
            optname,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of_val(&optval) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(anyhow::anyhow!("Failed to set IP_TRANSPARENT"));
        }
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_recvorigdstaddr(socket: &socket2::Socket, is_ipv6: bool) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    
    unsafe {
        let optval: libc::c_int = 1;
        
        // IPv4: IP_RECVORIGDSTADDR
        if !is_ipv6 {
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_IP,
                libc::IP_RECVORIGDSTADDR,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(anyhow::anyhow!("Failed to set IP_RECVORIGDSTADDR"));
            }
        } else {
            // IPv6: IPV6_RECVORIGDSTADDR
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVORIGDSTADDR,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(anyhow::anyhow!("Failed to set IPV6_RECVORIGDSTADDR"));
            }
        }
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
fn get_original_dst_tcp(stream: &TcpStream) -> Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;
    use std::mem;
    
    unsafe {
        let mut addr: libc::sockaddr_storage = mem::zeroed();
        let mut addr_len: libc::socklen_t = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        
        // 尝试 IPv4
        let ret = libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut addr_len,
        );
        
        if ret == 0 && addr.ss_family == libc::AF_INET as u16 {
            let addr_in = &*((&addr) as *const _ as *const libc::sockaddr_in);
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
            let port = u16::from_be(addr_in.sin_port);
            return Ok(SocketAddr::new(ip.into(), port));
        }
        
        // 尝试 IPv6
        addr = mem::zeroed();
        addr_len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        
        let ret = libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IP6T_SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut addr_len,
        );
        
        if ret == 0 && addr.ss_family == libc::AF_INET6 as u16 {
            let addr_in6 = &*((&addr) as *const _ as *const libc::sockaddr_in6);
            let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
            let port = u16::from_be(addr_in6.sin6_port);
            return Ok(SocketAddr::new(ip.into(), port));
        }
        
        anyhow::bail!("Failed to get original destination")
    }
}

#[cfg(target_os = "linux")]
async fn recv_from_with_origdst(
    socket: &UdpSocket,
    buf: &mut [u8],
    control_buf: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr)> {
    use std::os::unix::io::AsRawFd;
    use std::mem;
    
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        
        let mut src_addr: libc::sockaddr_storage = mem::zeroed();
        
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control_buf.len() as _;
        
        let n = libc::recvmsg(socket.as_raw_fd(), &mut msg, 0);
        
        if n < 0 {
            return Err(anyhow::anyhow!("recvmsg failed"));
        }
        
        // 解析源地址
        let source = sockaddr_to_std(&src_addr)?;
        
        // 从控制消息中提取原始目标地址
        let orig_dst = parse_origdst_from_cmsg(&msg)?;
        
        Ok((n as usize, source, orig_dst))
    }
}

#[cfg(target_os = "linux")]
unsafe fn sockaddr_to_std(addr: &libc::sockaddr_storage) -> Result<SocketAddr> {
    use std::mem;
    
    if addr.ss_family == libc::AF_INET as u16 {
        let addr_in = &*(addr as *const _ as *const libc::sockaddr_in);
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
        let port = u16::from_be(addr_in.sin_port);
        Ok(SocketAddr::new(ip.into(), port))
    } else if addr.ss_family == libc::AF_INET6 as u16 {
        let addr_in6 = &*(addr as *const _ as *const libc::sockaddr_in6);
        let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
        let port = u16::from_be(addr_in6.sin6_port);
        Ok(SocketAddr::new(ip.into(), port))
    } else {
        anyhow::bail!("Unknown address family")
    }
}

#[cfg(target_os = "linux")]
unsafe fn parse_origdst_from_cmsg(msg: &libc::msghdr) -> Result<SocketAddr> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    
    while !cmsg.is_null() {
        let cm = &*cmsg;
        
        // IPv4: SOL_IP + IP_RECVORIGDSTADDR
        if cm.cmsg_level == libc::SOL_IP && cm.cmsg_type == libc::IP_RECVORIGDSTADDR {
            let data = libc::CMSG_DATA(cmsg);
            let addr_in = &*(data as *const libc::sockaddr_in);
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
            let port = u16::from_be(addr_in.sin_port);
            return Ok(SocketAddr::new(ip.into(), port));
        }
        
        // IPv6: IPPROTO_IPV6 + IPV6_RECVORIGDSTADDR
        if cm.cmsg_level == libc::IPPROTO_IPV6 && cm.cmsg_type == libc::IPV6_RECVORIGDSTADDR {
            let data = libc::CMSG_DATA(cmsg);
            let addr_in6 = &*(data as *const libc::sockaddr_in6);
            let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
            let port = u16::from_be(addr_in6.sin6_port);
            return Ok(SocketAddr::new(ip.into(), port));
        }
        
        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
    }
    
    anyhow::bail!("Original destination not found in control message")
}

async fn handle_tcp_connection(
    mut client: TcpStream,
    _peer: SocketAddr,
    orig_dst: SocketAddr,
    router: Arc<GeoRouter>,
    pool: Arc<ConnectionPool>,
) -> Result<()> {
    // 设置总超时 60 秒
    tokio::time::timeout(Duration::from_secs(60), async {
        if router.should_proxy(orig_dst.ip()) {
            // 代理模式 - 添加连接超时
            let conn = tokio::time::timeout(
                Duration::from_secs(5),
                pool.get()
            ).await??;
            
            tokio::time::timeout(
                Duration::from_secs(3),
                conn.proxy_tcp(&orig_dst.to_string())
            ).await??;
            
            let (mut send, mut recv) = conn.conn.open_bi().await?;
            let (mut client_read, mut client_write) = client.split();
            
            let up = async {
                let mut buf = vec![0u8; 8192];
                loop {
                    // 每次读取超时 30 秒
                    match tokio::time::timeout(Duration::from_secs(30), client_read.read(&mut buf)).await {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => send.write_all(&buf[..n]).await?,
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_) => break, // 超时，结束
                    }
                }
                send.finish()?;
                Ok::<_, anyhow::Error>(())
            };
            
            let down = async {
                let mut buf = vec![0u8; 8192];
                loop {
                    // 每次读取超时 30 秒
                    match tokio::time::timeout(Duration::from_secs(30), recv.read(&mut buf)).await {
                        Ok(Ok(Some(n))) => client_write.write_all(&buf[..n]).await?,
                        Ok(Ok(None)) => break,
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_) => break, // 超时，结束
                    }
                }
                Ok::<_, anyhow::Error>(())
            };
            
            tokio::try_join!(up, down)?;
        } else {
            // 直连模式 - 添加连接超时
            let mut target = tokio::time::timeout(
                Duration::from_secs(5),
                TcpStream::connect(orig_dst)
            ).await??;
            
            let (mut cr, mut cw) = client.split();
            let (mut tr, mut tw) = target.split();
            
            tokio::try_join!(
                tokio::io::copy(&mut cr, &mut tw),
                tokio::io::copy(&mut tr, &mut cw)
            )?;
        }
        
        Ok::<_, anyhow::Error>(())
    }).await?
}

#[cfg(target_os = "linux")]
async fn handle_udp_packet(
    socket: Arc<UdpSocket>,
    data: Vec<u8>,
    source: SocketAddr,
    orig_dst: SocketAddr,
    router: Arc<GeoRouter>,
    pool: Arc<ConnectionPool>,
    nat_table: Arc<LruNatTable>,
) -> Result<()> {
    // 更新 NAT 表
    nat_table.insert((source, orig_dst), data.len()).await;
    
    if router.should_proxy(orig_dst.ip()) {
        // 代理模式 - 添加超时控制
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let conn = pool.get().await?;
            conn.proxy_udp(&orig_dst.to_string(), &data).await
        }).await;
        
        match result {
            Ok(Ok(response)) => {
                if let Err(e) = send_udp_with_transparent(&socket, &response, source, orig_dst).await {
                    tracing::debug!("UDP response send failed: {}", e);
                }
            }
            Ok(Err(e)) => {
                tracing::debug!("UDP proxy failed: {}, fallback to direct", e);
                direct_udp_forward(&data, source, orig_dst, &socket).await?;
            }
            Err(_) => {
                tracing::debug!("UDP proxy timeout, fallback to direct");
                direct_udp_forward(&data, source, orig_dst, &socket).await?;
            }
        }
    } else {
        // 直连模式
        direct_udp_forward(&data, source, orig_dst, &socket).await?;
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
async fn direct_udp_forward(
    data: &[u8],
    source: SocketAddr,
    orig_dst: SocketAddr,
    socket: &Arc<UdpSocket>,
) -> Result<()> {
    let target_socket = UdpSocket::bind("0.0.0.0:0").await?;
    target_socket.send_to(data, orig_dst).await?;
    
    let mut buf = vec![0u8; 65536];
    match tokio::time::timeout(
        Duration::from_secs(5),
        target_socket.recv_from(&mut buf)
    ).await {
        Ok(Ok((n, _))) => {
            send_udp_with_transparent(socket, &buf[..n], source, orig_dst).await?;
        }
        Ok(Err(e)) => {
            tracing::debug!("UDP recv error: {}", e);
        }
        Err(_) => {
            tracing::debug!("UDP recv timeout");
        }
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
async fn send_udp_with_transparent(
    socket: &UdpSocket,
    data: &[u8],
    dest: SocketAddr,
    bind_addr: SocketAddr,
) -> Result<()> {
    use socket2::{Socket, Domain, Type, Protocol};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    
    // 创建新的 socket 用于回写，绑定到原始目标地址
    let domain = if bind_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    
    let send_socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    send_socket.set_reuse_address(true)?;
    send_socket.set_reuse_port(true)?;
    
    // 设置 IP_TRANSPARENT 以便从原始目标地址发送
    set_transparent(&send_socket, bind_addr.is_ipv6())?;
    
    // 绑定到原始目标地址
    send_socket.bind(&bind_addr.into())?;
    
    let std_socket: std::net::UdpSocket = send_socket.into();
    std_socket.set_nonblocking(true)?;
    let udp_socket = UdpSocket::from_std(std_socket)?;
    
    // 发送数据到源地址
    udp_socket.send_to(data, dest).await?;
    
    Ok(())
}

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

// IPv6 透明代理常量
#[cfg(target_os = "linux")]
const IPV6_TRANSPARENT: libc::c_int = 75;
#[cfg(target_os = "linux")]
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
