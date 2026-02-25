use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use anyhow::Result;

/// TCP 性能优化配置
pub fn optimize_tcp_socket(stream: &TcpStream) -> Result<()> {
    let fd = stream.as_raw_fd();
    
    unsafe {
        // 1. TCP_NODELAY - 禁用 Nagle 算法，减少延迟
        let nodelay: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &nodelay as *const _ as *const libc::c_void,
            std::mem::size_of_val(&nodelay) as libc::socklen_t,
        );
        
        // 2. SO_RCVBUF - 增大接收缓冲区到 256KB
        let rcvbuf: libc::c_int = 256 * 1024;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&rcvbuf) as libc::socklen_t,
        );
        
        // 3. SO_SNDBUF - 增大发送缓冲区到 256KB
        let sndbuf: libc::c_int = 256 * 1024;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sndbuf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&sndbuf) as libc::socklen_t,
        );
        
        // 4. TCP_QUICKACK - 快速 ACK（Linux）
        #[cfg(target_os = "linux")]
        {
            let quickack: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                &quickack as *const _ as *const libc::c_void,
                std::mem::size_of_val(&quickack) as libc::socklen_t,
            );
        }
    }
    
    Ok(())
}

/// 为 tokio TcpStream 优化
pub fn optimize_tokio_tcp(stream: &tokio::net::TcpStream) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    
    unsafe {
        let nodelay: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &nodelay as *const _ as *const libc::c_void,
            std::mem::size_of_val(&nodelay) as libc::socklen_t,
        );
        
        let rcvbuf: libc::c_int = 256 * 1024;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&rcvbuf) as libc::socklen_t,
        );
        
        let sndbuf: libc::c_int = 256 * 1024;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sndbuf as *const _ as *const libc::c_void,
            std::mem::size_of_val(&sndbuf) as libc::socklen_t,
        );
    }
    
    Ok(())
}
