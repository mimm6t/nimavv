use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber;

mod socks5;

use gvbyh_core::CryptoContext;
use gvbyh_transport::{QuicClient, DnsResolver, TProxyHandler, ConnectionPool, PoolConfig, LoadBalanceStrategy};
use gvbyh_router::GeoRouter;
use gvbyh_worker_client::WorkerClient;
use socks5::Socks5Server;

#[derive(Parser)]
#[command(name = "gvbyh-client")]
#[command(about = "高性能QUIC代理客户端 - OpenWrt优化版", long_about = None)]
struct Cli {
    #[arg(short, long)]
    config: Option<PathBuf>,
    
    #[arg(short, long, default_value = "info")]
    log_level: String,
    
    #[arg(short, long)]
    worker_url: Option<String>,
    
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    socks5: String,
}

#[derive(serde::Deserialize, Default)]
struct Config {
    #[serde(default)]
    server: ServerConfig,
    #[serde(default)]
    socks5: Socks5Config,
    #[serde(default)]
    tproxy: TProxyConfig,
    #[serde(default)]
    dns: DnsConfig,
    #[serde(default)]
    router: RouterConfig,
    #[serde(default)]
    pool: PoolConfigToml,
}

#[derive(serde::Deserialize)]
struct PoolConfigToml {
    #[serde(default = "default_max_idle_secs")]
    max_idle_secs: u64,
    #[serde(default = "default_health_check_secs")]
    health_check_interval_secs: u64,
    #[serde(default = "default_connect_timeout_secs")]
    connect_timeout_secs: u64,
    #[serde(default = "default_max_failures")]
    max_failures: u32,
    #[serde(default)]
    strategy: String,
    #[serde(default = "default_true")]
    enable_ipv6: bool,
    #[serde(default)]
    persist_path: Option<String>,
}

impl Default for PoolConfigToml {
    fn default() -> Self {
        Self {
            max_idle_secs: 600,
            health_check_interval_secs: 15,
            connect_timeout_secs: 5,
            max_failures: 5,
            strategy: "least_latency".to_string(),
            enable_ipv6: true,
            persist_path: None,
        }
    }
}

impl From<PoolConfigToml> for PoolConfig {
    fn from(c: PoolConfigToml) -> Self {
        let strategy = match c.strategy.as_str() {
            "round_robin" => LoadBalanceStrategy::RoundRobin,
            "least_latency" => LoadBalanceStrategy::LeastLatency,
            "least_connections" => LoadBalanceStrategy::LeastConnections,
            "random" => LoadBalanceStrategy::Random,
            _ => LoadBalanceStrategy::LeastLatency,
        };
        
        Self {
            max_idle: Duration::from_secs(c.max_idle_secs),
            health_check_interval: Duration::from_secs(c.health_check_interval_secs),
            connect_timeout: Duration::from_secs(c.connect_timeout_secs),
            max_failures: c.max_failures,
            strategy,
            enable_ipv6: c.enable_ipv6,
            persist_path: c.persist_path,
        }
    }
}

fn default_max_idle_secs() -> u64 { 600 }
fn default_health_check_secs() -> u64 { 15 }
fn default_connect_timeout_secs() -> u64 { 5 }
fn default_max_failures() -> u32 { 5 }

#[derive(serde::Deserialize, Default)]
struct ServerConfig {
    #[serde(default = "default_worker_url")]
    worker_url: String,
    #[serde(default = "default_api_key")]
    api_key: String,
}

fn default_worker_url() -> String { "http://mirrors.ustc.ip-ddns.com".to_string() }
fn default_api_key() -> String { "default-key".to_string() }

#[derive(serde::Deserialize, Default)]
struct Socks5Config {
    #[serde(default = "default_socks5_listen")]
    listen: String,
    #[serde(default = "default_true")]
    enable: bool,
}

#[derive(serde::Deserialize, Default)]
struct TProxyConfig {
    #[serde(default)]
    enable: bool,
    #[serde(default = "default_tproxy_port")]
    port: u16,
}

#[derive(serde::Deserialize, Default)]
struct DnsConfig {
    #[serde(default = "default_true")]
    enable: bool,
    #[serde(default = "default_dns_listen")]
    listen: String,
    #[serde(default = "default_cn_dns")]
    cn_upstream: String,
    #[serde(default = "default_foreign_dns")]
    foreign_upstream: String,
}

#[derive(serde::Deserialize, Default)]
struct RouterConfig {
    #[serde(default = "default_geoip_path")]
    geoip_db: String,
}

fn default_socks5_listen() -> String { "127.0.0.1:1080".to_string() }
fn default_tproxy_port() -> u16 { 12345 }
fn default_dns_listen() -> String { "0.0.0.0:53".to_string() }
fn default_cn_dns() -> String { "https://223.5.5.5/dns-query".to_string() }
fn default_foreign_dns() -> String { "tls://1.1.1.1".to_string() }
fn default_geoip_path() -> String { "/etc/gvbyh/GeoLite2-Country.mmdb".to_string() }
fn default_true() -> bool { true }

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    tracing_subscriber::fmt()
        .with_max_level(match cli.log_level.as_str() {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        })
        .with_target(false)
        .with_thread_ids(false)
        .init();
    
    tracing::info!("gvbyh-client v{} starting...", env!("CARGO_PKG_VERSION"));
    
    // 自动生成配置文件
    let config = if let Some(config_path) = &cli.config {
        let config_str = std::fs::read_to_string(config_path)?;
        toml::from_str(&config_str)?
    } else {
        let default_config_path = std::path::Path::new("config.toml");
        if !default_config_path.exists() {
            tracing::info!("Generating default config.toml...");
            let default_config = include_str!("../../../config.example.toml");
            std::fs::write(default_config_path, default_config)?;
            tracing::info!("✓ Created config.toml, please edit it if needed");
        }
        Config::default()
    };
    
    let worker_url = cli.worker_url
        .or_else(|| {
            if !config.server.worker_url.is_empty() {
                Some(config.server.worker_url.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "http://mirrors.ustc.ip-ddns.com".to_string());
    
    let crypto = CryptoContext::new();
    let worker_client = WorkerClient::new(worker_url.clone(), config.server.api_key.clone());
    
    tracing::info!("Fetching server list from Worker...");
    let servers = worker_client.list_servers().await?;
    tracing::info!("Found {} servers", servers.len());
    
    if servers.is_empty() {
        anyhow::bail!("No servers available");
    }
    
    // 解析服务器信息
    let mut server_addrs = Vec::new();
    let mut server_keys = std::collections::HashMap::new();
    let mut uuid_map = std::collections::HashMap::new();
    
    for server in servers {
        // 解密服务器地址（包含端口）
        let addr_str = decrypt_server_ip(&server.encrypted_ip)?;
        let addr: std::net::SocketAddr = addr_str.parse()?;
        
        // 解码服务端公钥
        use base64::Engine;
        let public_key_bytes = base64::engine::general_purpose::STANDARD.decode(&server.public_key)?;
        let server_public = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(public_key_bytes.as_slice())?);
        
        // 解码 root_key
        let root_key_bytes = base64::engine::general_purpose::STANDARD.decode(&server.root_key)?;
        let root_key: [u8; 32] = root_key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Invalid root_key length"))?;
        
        tracing::info!("Server: {} (port: {}) UUID: {}", addr.ip(), addr.port(), server.uuid);
        server_addrs.push(addr);
        server_keys.insert(addr, (server_public, root_key));
        uuid_map.insert(addr, server.uuid.clone());
    }
    
    // 创建连接池
    let quic_client = QuicClient::new(crypto)?;
    let pool_config: PoolConfig = config.pool.into();
    let pool = Arc::new(ConnectionPool::with_full_config(
        quic_client, 
        server_addrs, 
        pool_config, 
        server_keys,
        Some(Arc::new(worker_client)),
        uuid_map
    ));
    
    // 启动连接池维护任务
    pool.start_maintenance().await;
    
    // 预建立连接（后台异步）- 不阻塞启动
    tracing::info!("Pre-warming connection pool in background...");
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        for i in 0..100 {
            if let Ok(_conn) = pool_clone.get().await {
                // 连接成功，保持在池中（不关闭）
                if (i + 1) % 10 == 0 {
                    tracing::debug!("Pre-warmed {} connections", i + 1);
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
        tracing::info!("✓ Connection pool pre-warmed with 100 connections");
    });
    
    // 测试连接（尝试所有服务器）
    tracing::info!("Testing connection pool...");
    let mut last_error = None;
    for attempt in 1..=3 {
        match pool.get().await {
            Ok(_) => {
                let metrics = pool.metrics();
                tracing::info!("✓ Connection pool ready (active: {})", metrics.active_connections);
                break;
            }
            Err(e) => {
                tracing::warn!("Connection attempt {}/3 failed: {}", attempt, e);
                last_error = Some(e);
                if attempt < 3 {
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
    
    if let Some(e) = last_error {
        if pool.metrics().active_connections == 0 {
            anyhow::bail!("Failed to connect to any server: {}", e);
        }
    }
    
    // 初始化路由器
    let router = if std::path::Path::new(&config.router.geoip_db).exists() {
        tracing::info!("Loading GeoIP database from {}", config.router.geoip_db);
        Arc::new(GeoRouter::new(&config.router.geoip_db)?)
    } else {
        tracing::info!("Using embedded GeoIP database");
        Arc::new(GeoRouter::new_embedded()?)
    };
    
    // 启动DNS服务
    if config.dns.enable {
        let dns_resolver = Arc::new(
            DnsResolver::new(&config.dns.cn_upstream, &config.dns.foreign_upstream).await?
        );
        let dns_addr: std::net::SocketAddr = config.dns.listen.parse()?;
        
        tokio::spawn(async move {
            if let Err(e) = gvbyh_transport::start_dns_server(dns_resolver, dns_addr).await {
                tracing::error!("DNS server error: {}", e);
            }
        });
        
        tracing::info!("DNS server listening on {}", config.dns.listen);
    }
    
    // 启动SOCKS5服务
    let socks5_listen = cli.socks5.clone();
    let socks5_addr: std::net::SocketAddr = socks5_listen.parse()?;
    let socks5_server = Socks5Server::new(socks5_addr);
    let pool_clone = pool.clone();
    
    tokio::spawn(async move {
        if let Err(e) = socks5_server.run_with_pool(pool_clone).await {
            tracing::error!("SOCKS5 server error: {}", e);
        }
    });
    
    tracing::info!("SOCKS5 server listening on {}", socks5_listen);
    
    // 启动透明代理
    #[cfg(target_os = "linux")]
    if config.tproxy.enable {
        let tproxy_addr: std::net::SocketAddr = 
            format!("0.0.0.0:{}", config.tproxy.port).parse()?;
        let tproxy = TProxyHandler::new(tproxy_addr, router.clone(), pool.clone());
        
        tokio::spawn(async move {
            if let Err(e) = tproxy.run().await {
                tracing::error!("TProxy error: {}", e);
            }
        });
        
        tracing::info!("Transparent proxy listening on port {}", config.tproxy.port);
    }
    
    tracing::info!("All services started successfully");
    tracing::info!("Press Ctrl+C to stop");
    
    // 定期打印统计信息
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let m = pool_clone.metrics();
            tracing::info!(
                "📊 Stats: requests={}, active={}, cache_hit={:.1}%, failures={}",
                m.total_requests, m.active_connections, 
                m.cache_hit_rate() * 100.0, m.failed_connections
            );
        }
    });
    
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down...");
    
    // 打印最终统计
    let final_metrics = pool.metrics();
    tracing::info!("Final stats: {:#?}", final_metrics);
    
    Ok(())
}

fn decrypt_server_ip(encrypted: &str) -> Result<String> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(encrypted)?;
    Ok(String::from_utf8(decoded)?)
}
