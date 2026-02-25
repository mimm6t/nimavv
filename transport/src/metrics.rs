use prometheus::{
    Registry, IntCounter, IntGauge, Histogram, HistogramOpts, 
    IntCounterVec, Opts, register_int_counter_with_registry,
    register_int_gauge_with_registry, register_histogram_with_registry,
    register_int_counter_vec_with_registry,
};
use std::sync::Arc;
use anyhow::Result;

// Prometheus 指标
pub struct Metrics {
    registry: Registry,
    
    // 透明代理指标
    pub tproxy_tcp_connections: IntCounter,
    pub tproxy_udp_packets: IntCounter,
    pub tproxy_tcp_bytes: IntCounter,
    pub tproxy_udp_bytes: IntCounter,
    pub tproxy_errors: IntCounterVec,
    
    // NAT 表指标
    pub nat_active_sessions: IntGauge,
    pub nat_total_packets: IntCounter,
    pub nat_total_bytes: IntCounter,
    pub nat_evictions: IntCounter,
    
    // 连接池指标
    pub pool_active_connections: IntGauge,
    pub pool_total_requests: IntCounter,
    pub pool_cache_hits: IntCounter,
    pub pool_cache_misses: IntCounter,
    pub pool_failures: IntCounter,
    
    // 延迟指标
    pub udp_latency: Histogram,
    pub tcp_latency: Histogram,
    pub quic_latency: Histogram,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();
        
        // 透明代理指标
        let tproxy_tcp_connections = register_int_counter_with_registry!(
            "tproxy_tcp_connections_total",
            "Total TCP connections handled by TProxy",
            registry
        )?;
        
        let tproxy_udp_packets = register_int_counter_with_registry!(
            "tproxy_udp_packets_total",
            "Total UDP packets handled by TProxy",
            registry
        )?;
        
        let tproxy_tcp_bytes = register_int_counter_with_registry!(
            "tproxy_tcp_bytes_total",
            "Total TCP bytes transferred",
            registry
        )?;
        
        let tproxy_udp_bytes = register_int_counter_with_registry!(
            "tproxy_udp_bytes_total",
            "Total UDP bytes transferred",
            registry
        )?;
        
        let tproxy_errors = register_int_counter_vec_with_registry!(
            "tproxy_errors_total",
            "Total errors by type",
            &["type"],
            registry
        )?;
        
        // NAT 表指标
        let nat_active_sessions = register_int_gauge_with_registry!(
            "nat_active_sessions",
            "Current active NAT sessions",
            registry
        )?;
        
        let nat_total_packets = register_int_counter_with_registry!(
            "nat_packets_total",
            "Total packets tracked by NAT",
            registry
        )?;
        
        let nat_total_bytes = register_int_counter_with_registry!(
            "nat_bytes_total",
            "Total bytes tracked by NAT",
            registry
        )?;
        
        let nat_evictions = register_int_counter_with_registry!(
            "nat_evictions_total",
            "Total NAT table evictions",
            registry
        )?;
        
        // 连接池指标
        let pool_active_connections = register_int_gauge_with_registry!(
            "pool_active_connections",
            "Current active connections in pool",
            registry
        )?;
        
        let pool_total_requests = register_int_counter_with_registry!(
            "pool_requests_total",
            "Total connection pool requests",
            registry
        )?;
        
        let pool_cache_hits = register_int_counter_with_registry!(
            "pool_cache_hits_total",
            "Total connection pool cache hits",
            registry
        )?;
        
        let pool_cache_misses = register_int_counter_with_registry!(
            "pool_cache_misses_total",
            "Total connection pool cache misses",
            registry
        )?;
        
        let pool_failures = register_int_counter_with_registry!(
            "pool_failures_total",
            "Total connection pool failures",
            registry
        )?;
        
        // 延迟指标
        let udp_latency = register_histogram_with_registry!(
            "udp_latency_seconds",
            "UDP packet latency",
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
            registry
        )?;
        
        let tcp_latency = register_histogram_with_registry!(
            "tcp_latency_seconds",
            "TCP connection latency",
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
            registry
        )?;
        
        let quic_latency = register_histogram_with_registry!(
            "quic_latency_seconds",
            "QUIC connection latency",
            vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
            registry
        )?;
        
        Ok(Self {
            registry,
            tproxy_tcp_connections,
            tproxy_udp_packets,
            tproxy_tcp_bytes,
            tproxy_udp_bytes,
            tproxy_errors,
            nat_active_sessions,
            nat_total_packets,
            nat_total_bytes,
            nat_evictions,
            pool_active_connections,
            pool_total_requests,
            pool_cache_hits,
            pool_cache_misses,
            pool_failures,
            udp_latency,
            tcp_latency,
            quic_latency,
        })
    }
    
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

// HTTP 服务器导出指标
pub async fn serve_metrics(metrics: Arc<Metrics>, addr: &str) -> Result<()> {
    use warp::Filter;
    use prometheus::Encoder;
    
    let metrics_clone = metrics.clone();
    let metrics_route = warp::path("metrics")
        .map(move || {
            let encoder = prometheus::TextEncoder::new();
            let metric_families = metrics_clone.registry().gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            warp::reply::with_header(
                buffer,
                "Content-Type",
                "text/plain; version=0.0.4",
            )
        });
    
    let addr: std::net::SocketAddr = addr.parse()?;
    tracing::info!("Prometheus metrics server listening on {}", addr);
    warp::serve(metrics_route).run(addr).await;
    
    Ok(())
}
