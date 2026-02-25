use bytes::BytesMut;
use crossbeam::queue::ArrayQueue;

const SMALL_BUF_SIZE: usize = 4096;
const MEDIUM_BUF_SIZE: usize = 16384;
const LARGE_BUF_SIZE: usize = 65536;

pub struct BufferPool {
    small: ArrayQueue<BytesMut>,
    medium: ArrayQueue<BytesMut>,
    large: ArrayQueue<BytesMut>,
}

impl BufferPool {
    pub fn new(small_cap: usize, medium_cap: usize, large_cap: usize) -> Self {
        let pool = Self {
            small: ArrayQueue::new(small_cap),
            medium: ArrayQueue::new(medium_cap),
            large: ArrayQueue::new(large_cap),
        };
        
        // 预分配
        for _ in 0..small_cap {
            let _ = pool.small.push(BytesMut::with_capacity(SMALL_BUF_SIZE));
        }
        for _ in 0..medium_cap {
            let _ = pool.medium.push(BytesMut::with_capacity(MEDIUM_BUF_SIZE));
        }
        for _ in 0..large_cap {
            let _ = pool.large.push(BytesMut::with_capacity(LARGE_BUF_SIZE));
        }
        
        pool
    }
    
    pub fn get(&self, size: usize) -> BytesMut {
        let queue = match size {
            0..=4095 => &self.small,
            4096..=16383 => &self.medium,
            _ => &self.large,
        };
        
        queue.pop().unwrap_or_else(|| {
            let cap = match size {
                0..=4095 => SMALL_BUF_SIZE,
                4096..=16383 => MEDIUM_BUF_SIZE,
                _ => LARGE_BUF_SIZE,
            };
            BytesMut::with_capacity(cap)
        })
    }
    
    pub fn put(&self, mut buf: BytesMut) {
        buf.clear();
        let cap = buf.capacity();
        
        let queue = match cap {
            SMALL_BUF_SIZE => &self.small,
            MEDIUM_BUF_SIZE => &self.medium,
            LARGE_BUF_SIZE => &self.large,
            _ => return, // 非标准大小，直接丢弃
        };
        
        let _ = queue.push(buf);
    }
}

// 全局buffer池
static GLOBAL_POOL: once_cell::sync::Lazy<BufferPool> = 
    once_cell::sync::Lazy::new(|| BufferPool::new(64, 32, 16));

pub fn get_buffer(size: usize) -> BytesMut {
    GLOBAL_POOL.get(size)
}

pub fn put_buffer(buf: BytesMut) {
    GLOBAL_POOL.put(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(2, 2, 2);
        
        let buf1 = pool.get(1024);
        assert_eq!(buf1.capacity(), SMALL_BUF_SIZE);
        
        let buf2 = pool.get(8192);
        assert_eq!(buf2.capacity(), MEDIUM_BUF_SIZE);
        
        pool.put(buf1);
        pool.put(buf2);
        
        let buf3 = pool.get(1024);
        assert_eq!(buf3.capacity(), SMALL_BUF_SIZE);
    }
}
