use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::sync::Arc;

// UDP NAT 会话条目
#[derive(Clone)]
pub struct NatEntry {
    pub last_seen: Instant,
    pub packet_count: u64,
    pub byte_count: u64,
}

// 无锁 LRU NAT 表（使用 DashMap）
pub struct LruNatTable {
    entries: Arc<DashMap<(SocketAddr, SocketAddr), NatEntry>>,
    max_entries: usize,
    timeout: Duration,
}

impl LruNatTable {
    pub fn new(max_entries: usize, timeout: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::with_capacity(max_entries)),
            max_entries,
            timeout,
        }
    }
    
    pub async fn insert(&self, key: (SocketAddr, SocketAddr), data_len: usize) {
        // LRU 淘汰（无锁）
        if self.entries.len() >= self.max_entries {
            if let Some(oldest) = self.entries.iter()
                .min_by_key(|e| e.value().last_seen)
                .map(|e| *e.key()) {
                self.entries.remove(&oldest);
            }
        }
        
        self.entries.entry(key)
            .and_modify(|e| {
                e.last_seen = Instant::now();
                e.packet_count += 1;
                e.byte_count += data_len as u64;
            })
            .or_insert(NatEntry {
                last_seen: Instant::now(),
                packet_count: 1,
                byte_count: data_len as u64,
            });
    }
    
    pub async fn cleanup(&self) {
        let now = Instant::now();
        self.entries.retain(|_, v| now.duration_since(v.last_seen) < self.timeout);
    }
    
    pub async fn stats(&self) -> NatStats {
        let total_packets: u64 = self.entries.iter().map(|e| e.packet_count).sum();
        let total_bytes: u64 = self.entries.iter().map(|e| e.byte_count).sum();
        
        NatStats {
            active_sessions: self.entries.len(),
            total_packets,
            total_bytes,
        }
    }
    
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Clone)]
pub struct NatStats {
    pub active_sessions: usize,
    pub total_packets: u64,
    pub total_bytes: u64,
}
