use bytes::{Bytes, BytesMut};
use std::sync::Arc;
use crossbeam::queue::ArrayQueue;

/// 零拷贝缓冲池 - 减少内存分配和拷贝
pub struct BufferPool {
    pool: Arc<ArrayQueue<BytesMut>>,
    size: usize,
    capacity: usize,
}

impl BufferPool {
    pub fn new(capacity: usize, size: usize) -> Self {
        let pool = Arc::new(ArrayQueue::new(capacity));
        
        // 预分配缓冲区
        for _ in 0..capacity {
            let buf = BytesMut::with_capacity(size);
            let _ = pool.push(buf);
        }
        
        Self { pool, size, capacity }
    }
    
    /// 获取缓冲区（优先从池中获取）
    pub fn get(&self) -> BytesMut {
        self.pool.pop()
            .unwrap_or_else(|| BytesMut::with_capacity(self.size))
    }
    
    /// 归还缓冲区到池中
    pub fn put(&self, mut buf: BytesMut) {
        if buf.capacity() >= self.size {
            buf.clear();
            let _ = self.pool.push(buf);
        }
    }
    
    /// 获取池的统计信息
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            capacity: self.capacity,
            available: self.pool.len(),
            buffer_size: self.size,
        }
    }
}

impl Clone for BufferPool {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            size: self.size,
            capacity: self.capacity,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub capacity: usize,
    pub available: usize,
    pub buffer_size: usize,
}

/// 零拷贝数据包 - 避免不必要的内存拷贝
pub struct ZeroCopyPacket {
    data: Bytes,
    offset: usize,
}

impl ZeroCopyPacket {
    pub fn new(data: Bytes) -> Self {
        Self { data, offset: 0 }
    }
    
    pub fn from_vec(vec: Vec<u8>) -> Self {
        Self::new(Bytes::from(vec))
    }
    
    pub fn slice(&self, range: std::ops::Range<usize>) -> Bytes {
        self.data.slice(range)
    }
    
    pub fn len(&self) -> usize {
        self.data.len() - self.offset
    }
    
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[self.offset..]
    }
    
    pub fn advance(&mut self, cnt: usize) {
        self.offset += cnt;
    }
}

/// 缓冲区守卫 - 自动归还缓冲区
pub struct BufferGuard {
    buf: Option<BytesMut>,
    pool: BufferPool,
}

impl BufferGuard {
    pub fn new(pool: BufferPool) -> Self {
        let buf = pool.get();
        Self {
            buf: Some(buf),
            pool,
        }
    }
    
    pub fn as_mut(&mut self) -> &mut BytesMut {
        self.buf.as_mut().unwrap()
    }
    
    pub fn freeze(mut self) -> Bytes {
        self.buf.take().unwrap().freeze()
    }
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.put(buf);
        }
    }
}

impl std::ops::Deref for BufferGuard {
    type Target = BytesMut;
    
    fn deref(&self) -> &Self::Target {
        self.buf.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for BufferGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf.as_mut().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(10, 4096);
        
        // 获取缓冲区
        let buf1 = pool.get();
        assert_eq!(buf1.capacity(), 4096);
        
        // 归还缓冲区
        pool.put(buf1);
        
        // 再次获取应该复用
        let buf2 = pool.get();
        assert_eq!(buf2.capacity(), 4096);
    }
    
    #[test]
    fn test_buffer_guard() {
        let pool = BufferPool::new(10, 4096);
        
        {
            let mut guard = BufferGuard::new(pool.clone());
            guard.extend_from_slice(b"hello");
            assert_eq!(&guard[..], b"hello");
        } // 自动归还
        
        let stats = pool.stats();
        assert_eq!(stats.available, 10);
    }
    
    #[test]
    fn test_zero_copy_packet() {
        let data = vec![1, 2, 3, 4, 5];
        let mut packet = ZeroCopyPacket::from_vec(data);
        
        assert_eq!(packet.len(), 5);
        assert_eq!(packet.as_bytes(), &[1, 2, 3, 4, 5]);
        
        packet.advance(2);
        assert_eq!(packet.len(), 3);
        assert_eq!(packet.as_bytes(), &[3, 4, 5]);
        
        let slice = packet.slice(0..2);
        assert_eq!(&slice[..], &[3, 4]);
    }
}
