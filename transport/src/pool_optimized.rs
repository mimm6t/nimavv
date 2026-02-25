use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use super::quic::{QuicClient, QuicConnection};
use x25519_dalek::PublicKey;
use std::hash::{Hash, Hasher};

const SHARD_COUNT: usize = 16; // 分片数量

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum LoadBalanceStrategy {
    RoundRobin,
    LeastLatency,
    LeastConnections,
    Random,
}

impl Default for LoadBalanceStrategy {
    fn default() -> Self {
        Self::LeastLatency
    }
}

#[derive(Clone)]
pub struct PoolConfig {
    pub max_idle: Duration,
    pub health_check_interval: Duration,
    pub connect_timeout: Duration,
    pub max_failures: u32,
    pub strategy: LoadBalanceStrategy,
    pub enable_ipv6: bool,
    pub persist_path: Option<String>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle: Duration::from_secs(60),
            health_check_interval: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(3),
            max_failures: 2,
            strategy: LoadBalanceStrategy::LeastLatency,
            enable_ipv6: true,
            persist_path: None,
        }
    }
}

// 分片连接池 - 减少锁竞争
pub struct ConnectionPool {
    client: Arc<QuicClient>,
    servers: Vec<SocketAddr>,
    shards: Vec<Arc<RwLock<HashMap<SocketAddr, PooledConnection>>>>,
    config: PoolConfig,
    metrics: Arc<PoolMetrics>,
    round_robin_index: Arc<AtomicU32>,
    server_keys: Arc<HashMap<SocketAddr, (PublicKey, [u8; 32])>>,
    worker_client: Option<Arc<gvbyh_worker_client::WorkerClient>>,
    uuid_map: Arc<HashMap<SocketAddr, String>>,
    health_check_interval: Arc<AtomicU64>, // 动态调整的检查间隔
}

#[derive(Default)]
pub struct PoolMetrics {
    pub total_requests: AtomicU64,
    pub active_connections: AtomicU32,
    pub failed_connections: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub avg_latency_us: AtomicU64, // 微秒
}

impl PoolMetrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            avg_latency_us: self.avg_latency_us.load(Ordering::Relaxed),
        }
    }
    
    pub fn record_latency(&self, latency: Duration) {
        let us = latency.as_micros() as u64;
        // 简单的移动平均
        let old = self.avg_latency_us.load(Ordering::Relaxed);
        let new = (old * 7 + us) / 8; // 7/8 旧值 + 1/8 新值
        self.avg_latency_us.store(new, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub total_requests: u64,
    pub active_connections: u32,
    pub failed_connections: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub avg_latency_us: u64,
}

impl MetricsSnapshot {
    pub fn cache_hit_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.cache_hits as f64 / self.total_requests as f64
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PooledConnection {
    #[serde(skip)]
    conn: Option<QuicConnection>,
    #[serde(skip, default = "Instant::now")]
    last_used: Instant,
    health: ConnectionHealth,
    addr: SocketAddr,
}

impl PooledConnection {
    fn is_valid(&self, max_idle: Duration, max_failures: u32) -> bool {
        self.conn.is_some() 
            && self.last_used.elapsed() < max_idle 
            && self.health.failures < max_failures
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct ConnectionHealth {
    failures: u32,
    #[serde(skip, default = "Instant::now")]
    last_check: Instant,
    latency_ms: u64,
    connection_count: u32,
}

impl ConnectionPool {
    pub fn new(client: QuicClient, servers: Vec<SocketAddr>) -> Self {
        Self::with_config(client, servers, PoolConfig::default())
    }
    
    pub fn with_config(client: QuicClient, servers: Vec<SocketAddr>, config: PoolConfig) -> Self {
        Self::with_config_and_keys(client, servers, config, HashMap::new())
    }
    
    pub fn with_config_and_keys(
        client: QuicClient, 
        servers: Vec<SocketAddr>, 
        config: PoolConfig,
        server_keys: HashMap<SocketAddr, (PublicKey, [u8; 32])>
    ) -> Self {
        Self::with_full_config(client, servers, config, server_keys, None, HashMap::new())
    }
    
    pub fn with_full_config(
        client: QuicClient, 
        servers: Vec<SocketAddr>, 
        config: PoolConfig,
        server_keys: HashMap<SocketAddr, (PublicKey, [u8; 32])>,
        worker_client: Option<Arc<gvbyh_worker_client::WorkerClient>>,
        uuid_map: HashMap<SocketAddr, String>,
    ) -> Self {
        // 初始化分片
        let shards: Vec<_> = (0..SHARD_COUNT)
            .map(|_| Arc::new(RwLock::new(HashMap::new())))
            .collect();
        
        let pool = Self {
            client: Arc::new(client),
            servers: servers.clone(),
            shards,
            config,
            metrics: Arc::new(PoolMetrics::default()),
            round_robin_index: Arc::new(AtomicU32::new(0)),
            server_keys: Arc::new(server_keys),
            worker_client,
            uuid_map: Arc::new(uuid_map),
            health_check_interval: Arc::new(AtomicU64::new(5000)), // 初始 5 秒
        };
        
        if let Some(ref path) = pool.config.persist_path {
            if let Err(e) = pool.load_state(path) {
                tracing::warn!("Failed to load pool state: {}", e);
            }
        }
        
        pool
    }
    
    // 计算分片索引
    fn shard_index(&self, addr: &SocketAddr) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        addr.hash(&mut hasher);
        (hasher.finish() as usize) % SHARD_COUNT
    }
    
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }
    
    // 优化的 get 方法：先读锁，必要时才写锁
    pub async fn get(&self) -> Result<QuicConnection> {
        let start = Instant::now();
        self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
        
        let addr = self.select_server().await?;
        let shard_idx = self.shard_index(&addr);
        let shard = &self.shards[shard_idx];
        
        // 第一步：尝试读锁获取现有连接
        {
            let conns = shard.read().await;
            if let Some(pooled) = conns.get(&addr) {
                if pooled.is_valid(self.config.max_idle, self.config.max_failures) {
                    self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                    self.metrics.record_latency(start.elapsed());
                    return Ok(pooled.conn.as_ref().unwrap().clone());
                }
            }
        }
        
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        
        // 第二步：需要创建新连接，获取写锁
        let mut conns = shard.write().await;
        
        // Double-check：可能其他线程已经创建了
        if let Some(pooled) = conns.get(&addr) {
            if pooled.is_valid(self.config.max_idle, self.config.max_failures) {
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                self.metrics.record_latency(start.elapsed());
                return Ok(pooled.conn.as_ref().unwrap().clone());
            }
        }
        
        // 获取服务器密钥信息
        let (server_public, root_key) = self.server_keys.get(&addr)
            .ok_or_else(|| anyhow::anyhow!("No keys for server {}", addr))?;
        
        // 创建新连接（带超时）
        let conn = match tokio::time::timeout(
            self.config.connect_timeout,
            self.client.connect_with_keys(addr, server_public, root_key)
        ).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                drop(conns); // 释放写锁
                self.mark_server_failed(addr).await;
                return Err(e);
            }
            Err(_) => {
                drop(conns); // 释放写锁
                self.mark_server_failed(addr).await;
                return Err(anyhow::anyhow!("Connection timeout"));
            }
        };
        
        self.metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        
        let pooled = PooledConnection {
            conn: Some(conn.clone()),
            last_used: Instant::now(),
            health: ConnectionHealth {
                failures: 0,
                last_check: Instant::now(),
                latency_ms: 100,
                connection_count: 1,
            },
            addr,
        };
        
        conns.insert(addr, pooled);
        self.metrics.record_latency(start.elapsed());
        Ok(conn)
    }
    
    async fn mark_server_failed(&self, addr: SocketAddr) {
        let shard_idx = self.shard_index(&addr);
        let shard = &self.shards[shard_idx];
        let mut conns = shard.write().await;
        
        let failures = if let Some(pooled) = conns.get_mut(&addr) {
            pooled.health.failures += 1;
            self.metrics.failed_connections.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("Server {} marked as failed ({}/{})", addr, pooled.health.failures, self.config.max_failures);
            pooled.health.failures
        } else {
            let pooled = PooledConnection {
                conn: None,
                last_used: Instant::now(),
                health: ConnectionHealth {
                    failures: 1,
                    last_check: Instant::now(),
                    latency_ms: 9999,
                    connection_count: 0,
                },
                addr,
            };
            conns.insert(addr, pooled);
            self.metrics.failed_connections.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("Server {} marked as failed (1/{})", addr, self.config.max_failures);
            1
        };
        
        if failures >= 3 {
            tracing::error!("Server {} failed 3 times, requesting Worker to delete it", addr);
            
            if let Some(uuid) = self.find_uuid_by_addr(addr).await {
                if let Some(worker_client) = &self.worker_client {
                    let worker_client = worker_client.clone();
                    tokio::spawn(async move {
                        match worker_client.delete_server(&uuid).await {
                            Ok(_) => tracing::info!("✓ Server {} removed from Worker", uuid),
                            Err(e) => tracing::error!("Failed to remove server {} from Worker: {}", uuid, e),
                        }
                    });
                }
            }
        }
    }
    
    async fn find_uuid_by_addr(&self, addr: SocketAddr) -> Option<String> {
        self.uuid_map.get(&addr).cloned()
    }
    
    async fn select_server(&self) -> Result<SocketAddr> {
        // 收集所有分片的健康服务器
        let mut healthy = Vec::new();
        
        for shard in &self.shards {
            let conns = shard.read().await;
            for &addr in &self.servers {
                if !self.config.enable_ipv6 && addr.is_ipv6() {
                    continue;
                }
                
                if let Some(pooled) = conns.get(&addr) {
                    if pooled.health.failures < self.config.max_failures {
                        healthy.push((addr, pooled.health.clone()));
                    }
                } else {
                    healthy.push((addr, ConnectionHealth {
                        failures: 0,
                        last_check: Instant::now(),
                        latency_ms: 100,
                        connection_count: 0,
                    }));
                }
            }
        }
        
        if healthy.is_empty() {
            anyhow::bail!("No healthy servers");
        }
        
        // 根据策略选择
        match self.config.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) as usize;
                Ok(healthy[idx % healthy.len()].0)
            }
            LoadBalanceStrategy::LeastLatency => {
                let best = healthy.iter()
                    .min_by_key(|(_, health)| health.latency_ms)
                    .map(|(addr, _)| *addr)
                    .unwrap();
                Ok(best)
            }
            LoadBalanceStrategy::LeastConnections => {
                let best = healthy.iter()
                    .min_by_key(|(_, health)| health.connection_count)
                    .map(|(addr, _)| *addr)
                    .unwrap();
                Ok(best)
            }
            LoadBalanceStrategy::Random => {
                use rand::Rng;
                let idx = rand::thread_rng().gen_range(0..healthy.len());
                Ok(healthy[idx].0)
            }
        }
    }
    
    // 异步健康检查 - 不阻塞主流程
    pub async fn health_check(&self) {
        let start = Instant::now();
        let mut total_checked = 0;
        let mut total_failed = 0;
        
        // 并发检查所有服务器
        let mut tasks = Vec::new();
        for &addr in &self.servers {
            let pool = self.clone();
            tasks.push(tokio::spawn(async move {
                pool.check_single_server(addr).await
            }));
        }
        
        // 收集结果
        for task in tasks {
            if let Ok(result) = task.await {
                total_checked += 1;
                if result.is_err() {
                    total_failed += 1;
                }
            }
        }
        
        let elapsed = start.elapsed();
        let failure_rate = if total_checked > 0 {
            total_failed as f64 / total_checked as f64
        } else {
            0.0
        };
        
        // 动态调整检查间隔
        let current_interval = self.health_check_interval.load(Ordering::Relaxed);
        let new_interval = if failure_rate > 0.3 {
            // 高失败率：增加检查频率
            (current_interval / 2).max(1000)
        } else if failure_rate < 0.05 {
            // 低失败率：降低检查频率
            (current_interval * 2).min(30000)
        } else {
            current_interval
        };
        self.health_check_interval.store(new_interval, Ordering::Relaxed);
        
        tracing::debug!(
            "Health check: checked={}, failed={}, rate={:.1}%, elapsed={:?}, next_interval={}ms",
            total_checked, total_failed, failure_rate * 100.0, elapsed, new_interval
        );
    }
    
    async fn check_single_server(&self, addr: SocketAddr) -> Result<Duration> {
        let shard_idx = self.shard_index(&addr);
        let shard = &self.shards[shard_idx];
        
        let conn = {
            let conns = shard.read().await;
            conns.get(&addr)
                .and_then(|p| p.conn.clone())
        };
        
        if let Some(conn) = conn {
            match conn.health_check().await {
                Ok(latency) => {
                    let mut conns = shard.write().await;
                    if let Some(pooled) = conns.get_mut(&addr) {
                        pooled.health.failures = 0;
                        pooled.health.latency_ms = latency.as_millis() as u64;
                        pooled.health.last_check = Instant::now();
                    }
                    Ok(latency)
                }
                Err(e) => {
                    let mut conns = shard.write().await;
                    if let Some(pooled) = conns.get_mut(&addr) {
                        pooled.health.failures += 1;
                        self.metrics.failed_connections.fetch_add(1, Ordering::Relaxed);
                        
                        if pooled.health.failures >= self.config.max_failures {
                            conns.remove(&addr);
                            self.metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                    Err(e)
                }
            }
        } else {
            Ok(Duration::from_millis(0))
        }
    }
    
    pub async fn cleanup(&self) {
        let mut total_removed = 0;
        
        for shard in &self.shards {
            let mut conns = shard.write().await;
            let before = conns.len();
            
            conns.retain(|addr, pooled| {
                let keep = pooled.is_valid(self.config.max_idle, self.config.max_failures);
                if !keep {
                    self.metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                    tracing::debug!("Removing connection to {}", addr);
                }
                keep
            });
            
            total_removed += before - conns.len();
        }
        
        if total_removed > 0 {
            tracing::info!("Cleaned up {} connections", total_removed);
        }
    }
    
    fn load_state(&self, path: &str) -> Result<()> {
        let data = std::fs::read_to_string(path)?;
        let state: Vec<PooledConnection> = serde_json::from_str(&data)?;
        
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                for mut pooled in state {
                    pooled.conn = None;
                    pooled.health.last_check = Instant::now();
                    
                    let shard_idx = self.shard_index(&pooled.addr);
                    let shard = &self.shards[shard_idx];
                    let mut conns = shard.write().await;
                    conns.insert(pooled.addr, pooled);
                }
            });
        });
        
        tracing::info!("Loaded pool state from {}", path);
        Ok(())
    }
    
    async fn save_state(&self) -> Result<()> {
        if let Some(ref path) = self.config.persist_path {
            let mut state = Vec::new();
            
            for shard in &self.shards {
                let conns = shard.read().await;
                state.extend(conns.values().cloned());
            }
            
            let data = serde_json::to_string_pretty(&state)?;
            std::fs::write(path, data)?;
            tracing::debug!("Saved pool state to {}", path);
        }
        Ok(())
    }
    
    pub async fn start_maintenance(&self) {
        let pool = self.clone();
        tokio::spawn(async move {
            loop {
                let interval_ms = pool.health_check_interval.load(Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
                
                pool.health_check().await;
                pool.cleanup().await;
                
                if let Err(e) = pool.save_state().await {
                    tracing::warn!("Failed to save pool state: {}", e);
                }
                
                let metrics = pool.metrics();
                tracing::info!(
                    "Pool: req={}, active={}, hit={:.1}%, fail={}, lat={}μs, strategy={:?}",
                    metrics.total_requests,
                    metrics.active_connections,
                    metrics.cache_hit_rate() * 100.0,
                    metrics.failed_connections,
                    metrics.avg_latency_us,
                    pool.config.strategy
                );
            }
        });
    }
}

impl Clone for ConnectionPool {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            servers: self.servers.clone(),
            shards: self.shards.clone(),
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            round_robin_index: self.round_robin_index.clone(),
            server_keys: self.server_keys.clone(),
            worker_client: self.worker_client.clone(),
            uuid_map: self.uuid_map.clone(),
            health_check_interval: self.health_check_interval.clone(),
        }
    }
}
