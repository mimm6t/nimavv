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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum LoadBalanceStrategy {
    RoundRobin,      // 轮询
    LeastLatency,    // 最低延迟
    LeastConnections,// 最少连接
    Random,          // 随机
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
            max_idle: Duration::from_secs(180),
            health_check_interval: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(3),
            max_failures: 10,  // 增加到10次，避免过早标记为不健康
            strategy: LoadBalanceStrategy::LeastLatency,
            enable_ipv6: true,
            persist_path: None,
        }
    }
}

pub struct ConnectionPool {
    client: Arc<QuicClient>,
    servers: Vec<SocketAddr>,
    connections: Arc<RwLock<HashMap<SocketAddr, PooledConnection>>>,
    config: PoolConfig,
    metrics: Arc<PoolMetrics>,
    round_robin_index: Arc<AtomicU32>,
    server_keys: Arc<HashMap<SocketAddr, (PublicKey, [u8; 32])>>,  // (server_public, root_key)
    worker_client: Option<Arc<gvbyh_worker_client::WorkerClient>>,
    uuid_map: Arc<HashMap<SocketAddr, String>>,  // addr -> uuid 映射
}

#[derive(Default)]
pub struct PoolMetrics {
    pub total_requests: AtomicU64,
    pub active_connections: AtomicU32,
    pub failed_connections: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
}

impl PoolMetrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub total_requests: u64,
    pub active_connections: u32,
    pub failed_connections: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
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
    
    // 快速检查连接是否仍然有效
    async fn is_connection_alive(conn: &QuicConnection) -> bool {
        // 使用短超时进行快速检查
        match tokio::time::timeout(Duration::from_millis(500), conn.health_check()).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
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
        let pool = Self {
            client: Arc::new(client),
            servers: servers.clone(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            config,
            metrics: Arc::new(PoolMetrics::default()),
            round_robin_index: Arc::new(AtomicU32::new(0)),
            server_keys: Arc::new(server_keys),
            worker_client,
            uuid_map: Arc::new(uuid_map),
        };
        
        if let Some(ref path) = pool.config.persist_path {
            if let Err(e) = pool.load_state(path) {
                tracing::warn!("Failed to load pool state: {}", e);
            }
        }
        
        pool
    }
    
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }
    
    pub async fn get(&self) -> Result<QuicConnection> {
        self.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
        
        let addr = self.select_server().await?;
        
        // 尝试复用连接 - 增加连接有效性检查
        {
            let mut conns = self.connections.write().await;
            if let Some(pooled) = conns.get_mut(&addr) {
                if pooled.last_used.elapsed() < self.config.max_idle {
                    if let Some(ref conn) = pooled.conn {
                        // 快速验证连接是否仍然有效
                        if Self::is_connection_alive(conn).await {
                            pooled.last_used = Instant::now();
                            pooled.health.connection_count += 1;
                            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!("Reusing connection to {}", addr);
                            return Ok(conn.clone());
                        } else {
                            tracing::warn!("Connection to {} is dead, removing from pool", addr);
                            conns.remove(&addr);
                        }
                    }
                } else {
                    tracing::debug!("Connection to {} expired, removing from pool", addr);
                    conns.remove(&addr);
                }
            }
        }
        
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        
        // 获取服务器密钥信息
        let (server_public, root_key) = self.server_keys.get(&addr)
            .ok_or_else(|| anyhow::anyhow!("No keys for server {}", addr))?;
        
        // 创建新连接
        let conn = match tokio::time::timeout(
            self.config.connect_timeout,
            self.client.connect_with_keys(addr, server_public, root_key)
        ).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                // 连接失败，标记服务器为不健康
                self.mark_server_failed(addr).await;
                return Err(e);
            }
            Err(_) => {
                // 超时，标记服务器为不健康
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
        
        self.connections.write().await.insert(addr, pooled);
        Ok(conn)
    }
    
    async fn mark_server_failed(&self, addr: SocketAddr) {
        let mut conns = self.connections.write().await;
        let failures = if let Some(pooled) = conns.get_mut(&addr) {
            pooled.health.failures = (pooled.health.failures + 1).min(self.config.max_failures);  // 限制最大值
            pooled.conn = None;
            self.metrics.failed_connections.fetch_add(1, Ordering::Relaxed);
            if pooled.health.connection_count > 0 {
                self.metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
            }
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
        
        // 如果失败次数达到阈值，从 Worker 删除
        if failures >= 3 {
            tracing::error!("Server {} failed 3 times, requesting Worker to delete it", addr);
            
            // 查找对应的 UUID
            if let Some(uuid) = self.find_uuid_by_addr(addr).await {
                // 异步删除，不阻塞当前流程
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
        let conns = self.connections.read().await;
        
        // 过滤健康的服务器
        let healthy: Vec<_> = self.servers.iter()
            .filter(|&&addr| {
                // IPv6 过滤
                if !self.config.enable_ipv6 && addr.is_ipv6() {
                    return false;
                }
                
                if let Some(pooled) = conns.get(&addr) {
                    pooled.health.failures < self.config.max_failures
                } else {
                    true
                }
            })
            .copied()
            .collect();
        
        if healthy.is_empty() {
            anyhow::bail!("No healthy servers");
        }
        
        // 根据策略选择
        match self.config.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let idx = self.round_robin_index.fetch_add(1, Ordering::Relaxed) as usize;
                Ok(healthy[idx % healthy.len()])
            }
            LoadBalanceStrategy::LeastLatency => {
                let mut best = healthy[0];
                let mut best_latency = u64::MAX;
                
                for &addr in &healthy {
                    if let Some(pooled) = conns.get(&addr) {
                        if pooled.health.latency_ms < best_latency {
                            best = addr;
                            best_latency = pooled.health.latency_ms;
                        }
                    } else {
                        return Ok(addr);
                    }
                }
                Ok(best)
            }
            LoadBalanceStrategy::LeastConnections => {
                let mut best = healthy[0];
                let mut best_count = u32::MAX;
                
                for &addr in &healthy {
                    if let Some(pooled) = conns.get(&addr) {
                        if pooled.health.connection_count < best_count {
                            best = addr;
                            best_count = pooled.health.connection_count;
                        }
                    } else {
                        return Ok(addr);
                    }
                }
                Ok(best)
            }
            LoadBalanceStrategy::Random => {
                use rand::Rng;
                let idx = rand::thread_rng().gen_range(0..healthy.len());
                Ok(healthy[idx])
            }
        }
    }
    
    pub async fn health_check(&self) {
        let mut conns = self.connections.write().await;
        let mut to_remove = Vec::new();
        
        for (&addr, pooled) in conns.iter_mut() {
            if pooled.health.last_check.elapsed() < self.config.health_check_interval {
                continue;
            }
            
            // 如果服务器已标记为不健康，尝试恢复
            if pooled.health.failures >= self.config.max_failures {
                pooled.health.failures = pooled.health.failures.saturating_sub(1);  // 逐步恢复
                pooled.health.last_check = Instant::now();
                tracing::debug!("Attempting to recover server {} (failures: {})", addr, pooled.health.failures);
                continue;
            }
            
            if let Some(ref conn) = pooled.conn {
                match tokio::time::timeout(
                    Duration::from_secs(3), 
                    conn.health_check()
                ).await {
                    Ok(Ok(latency)) => {
                        pooled.health.failures = 0;
                        pooled.health.latency_ms = latency.as_millis() as u64;
                        pooled.health.last_check = Instant::now();
                        tracing::debug!("Server {} healthy, latency: {}ms", addr, pooled.health.latency_ms);
                    }
                    Ok(Err(e)) => {
                        pooled.health.failures = (pooled.health.failures + 1).min(self.config.max_failures);
                        pooled.conn = None;
                        self.metrics.failed_connections.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!("Server {} health check failed ({}/{}): {}", 
                            addr, pooled.health.failures, self.config.max_failures, e);
                        
                        if pooled.health.failures >= self.config.max_failures {
                            to_remove.push(addr);
                        }
                    }
                    Err(_) => {
                        pooled.health.failures = (pooled.health.failures + 1).min(self.config.max_failures);
                        pooled.conn = None;
                        self.metrics.failed_connections.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!("Server {} health check timed out ({}/{})", 
                            addr, pooled.health.failures, self.config.max_failures);
                        
                        if pooled.health.failures >= self.config.max_failures {
                            to_remove.push(addr);
                        }
                    }
                }
            }
        }
        
        // 移除失败的连接
        for addr in to_remove {
            if let Some(pooled) = conns.remove(&addr) {
                tracing::info!("Removing failed connection to {}", addr);
                if pooled.conn.is_some() {
                    self.metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                }
            }
        }
    }
    
    pub async fn cleanup(&self) {
        let mut conns = self.connections.write().await;
        let before = conns.len();
        
        conns.retain(|addr, pooled| {
            let keep = pooled.last_used.elapsed() < self.config.max_idle 
                && pooled.health.failures < self.config.max_failures;
            if !keep {
                self.metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
                tracing::info!("Removing connection to {}", addr);
            }
            keep
        });
        
        let removed = before - conns.len();
        if removed > 0 {
            tracing::info!("Cleaned up {} connections", removed);
        }
    }
    
    fn load_state(&self, path: &str) -> Result<()> {
        let data = std::fs::read_to_string(path)?;
        let state: Vec<PooledConnection> = serde_json::from_str(&data)?;
        
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut conns = self.connections.write().await;
                for mut pooled in state {
                    pooled.conn = None; // 连接不持久化
                    pooled.health.last_check = Instant::now();
                    conns.insert(pooled.addr, pooled);
                }
            });
        });
        
        tracing::info!("Loaded pool state from {}", path);
        Ok(())
    }
    
    async fn save_state(&self) -> Result<()> {
        if let Some(ref path) = self.config.persist_path {
            let conns = self.connections.read().await;
            let state: Vec<_> = conns.values().cloned().collect();
            let data = serde_json::to_string_pretty(&state)?;
            std::fs::write(path, data)?;
            tracing::debug!("Saved pool state to {}", path);
        }
        Ok(())
    }
    
    pub async fn start_maintenance(&self) {
        let pool = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(pool.config.health_check_interval);
            loop {
                interval.tick().await;
                pool.health_check().await;
                pool.cleanup().await;
                
                if let Err(e) = pool.save_state().await {
                    tracing::warn!("Failed to save pool state: {}", e);
                }
                
                let metrics = pool.metrics();
                tracing::info!(
                    "Pool stats: requests={}, active={}, hit_rate={:.1}%, failures={}, strategy={:?}",
                    metrics.total_requests,
                    metrics.active_connections,
                    metrics.cache_hit_rate() * 100.0,
                    metrics.failed_connections,
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
            connections: self.connections.clone(),
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            round_robin_index: self.round_robin_index.clone(),
            server_keys: self.server_keys.clone(),
            worker_client: self.worker_client.clone(),
            uuid_map: self.uuid_map.clone(),
        }
    }
}
