use std::net::SocketAddr;
use tokio::net::UdpSocket;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

// 批量 UDP 数据包
pub struct UdpBatch {
    pub packets: Vec<UdpPacket>,
}

pub struct UdpPacket {
    pub data: Vec<u8>,
    pub source: SocketAddr,
    pub dest: SocketAddr,
}

// 批量处理器
pub struct BatchProcessor {
    batch_size: usize,
    timeout_ms: u64,
}

impl BatchProcessor {
    pub fn new(batch_size: usize, timeout_ms: u64) -> Self {
        Self { batch_size, timeout_ms }
    }
    
    pub async fn process_batch<F>(
        &self,
        mut rx: mpsc::Receiver<UdpPacket>,
        handler: F,
    ) where
        F: Fn(Vec<UdpPacket>) + Send + 'static,
    {
        let mut batch = Vec::with_capacity(self.batch_size);
        let timeout = tokio::time::Duration::from_millis(self.timeout_ms);
        
        loop {
            tokio::select! {
                Some(packet) = rx.recv() => {
                    batch.push(packet);
                    
                    if batch.len() >= self.batch_size {
                        handler(std::mem::take(&mut batch));
                        batch = Vec::with_capacity(self.batch_size);
                    }
                }
                _ = tokio::time::sleep(timeout), if !batch.is_empty() => {
                    handler(std::mem::take(&mut batch));
                    batch = Vec::with_capacity(self.batch_size);
                }
            }
        }
    }
}

// sendmmsg/recvmmsg 实现
#[cfg(target_os = "linux")]
pub mod mmsg {
    use super::*;
    use std::os::unix::io::AsRawFd;
    use std::mem;
    use std::ptr;
    
    // 批量接收
    pub async fn recvmmsg(
        socket: &UdpSocket,
        vlen: usize,
    ) -> Result<Vec<(Vec<u8>, SocketAddr)>> {
        use std::io::IoSliceMut;
        
        let fd = socket.as_raw_fd();
        let mut results = Vec::with_capacity(vlen);
        let mut buffers: Vec<Vec<u8>> = (0..vlen).map(|_| vec![0u8; 65536]).collect();
        let mut addrs: Vec<libc::sockaddr_storage> = vec![unsafe { mem::zeroed() }; vlen];
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(vlen);
        let mut msghdrs: Vec<libc::mmsghdr> = Vec::with_capacity(vlen);
        
        for i in 0..vlen {
            iovecs.push(libc::iovec {
                iov_base: buffers[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: buffers[i].len(),
            });
            
            msghdrs.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &mut addrs[i] as *mut _ as *mut libc::c_void,
                    msg_namelen: mem::size_of::<libc::sockaddr_storage>() as u32,
                    msg_iov: &mut iovecs[i],
                    msg_iovlen: 1,
                    msg_control: ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }
        
        let ret = unsafe {
            libc::recvmmsg(
                fd,
                msghdrs.as_mut_ptr(),
                vlen as u32,
                libc::MSG_DONTWAIT,
                ptr::null_mut(),
            )
        };
        
        if ret < 0 {
            return Err(anyhow::anyhow!("recvmmsg failed"));
        }
        
        for i in 0..(ret as usize) {
            let len = msghdrs[i].msg_len as usize;
            let data = buffers[i][..len].to_vec();
            let addr = unsafe { sockaddr_to_std(&addrs[i])? };
            results.push((data, addr));
        }
        
        Ok(results)
    }
    
    // 批量发送
    pub async fn sendmmsg(
        socket: &UdpSocket,
        packets: &[(Vec<u8>, SocketAddr)],
    ) -> Result<usize> {
        let fd = socket.as_raw_fd();
        let vlen = packets.len();
        
        let mut addrs: Vec<libc::sockaddr_storage> = Vec::with_capacity(vlen);
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(vlen);
        let mut msghdrs: Vec<libc::mmsghdr> = Vec::with_capacity(vlen);
        
        for (data, addr) in packets {
            let storage = std_to_sockaddr(addr);
            addrs.push(storage);
            
            iovecs.push(libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            });
        }
        
        for i in 0..vlen {
            msghdrs.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: &addrs[i] as *const _ as *mut libc::c_void,
                    msg_namelen: mem::size_of::<libc::sockaddr_storage>() as u32,
                    msg_iov: &iovecs[i] as *const _ as *mut libc::iovec,
                    msg_iovlen: 1,
                    msg_control: ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }
        
        let ret = unsafe {
            libc::sendmmsg(
                fd,
                msghdrs.as_mut_ptr(),
                vlen as u32,
                0,
            )
        };
        
        if ret < 0 {
            return Err(anyhow::anyhow!("sendmmsg failed"));
        }
        
        Ok(ret as usize)
    }
    
    unsafe fn sockaddr_to_std(addr: &libc::sockaddr_storage) -> Result<SocketAddr> {
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
            Err(anyhow::anyhow!("Unknown address family"))
        }
    }
    
    fn std_to_sockaddr(addr: &SocketAddr) -> libc::sockaddr_storage {
        unsafe {
            let mut storage: libc::sockaddr_storage = mem::zeroed();
            match addr {
                SocketAddr::V4(v4) => {
                    let sin = &mut storage as *mut _ as *mut libc::sockaddr_in;
                    (*sin).sin_family = libc::AF_INET as u16;
                    (*sin).sin_port = v4.port().to_be();
                    (*sin).sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                }
                SocketAddr::V6(v6) => {
                    let sin6 = &mut storage as *mut _ as *mut libc::sockaddr_in6;
                    (*sin6).sin6_family = libc::AF_INET6 as u16;
                    (*sin6).sin6_port = v6.port().to_be();
                    (*sin6).sin6_addr.s6_addr = v6.ip().octets();
                }
            }
            storage
        }
    }
}

// 零拷贝 UDP 发送（使用 sendmmsg）
#[cfg(target_os = "linux")]
pub async fn send_batch_zerocopy(
    socket: &UdpSocket,
    packets: &[(Vec<u8>, SocketAddr)],
) -> Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }
    
    mmsg::sendmmsg(socket, packets).await
}
