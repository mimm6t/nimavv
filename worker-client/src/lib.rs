use serde::{Deserialize, Serialize};
use anyhow::Result;
use std::time::Duration;
use std::net::{IpAddr, SocketAddr};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("UUID already exists (conflict)")]
    UuidConflict,
    #[error("UUID not found (expired)")]
    UuidNotFound,
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Server error: {status} - {message}")]
    ServerError { status: u16, message: String },
}

#[derive(Clone)]
pub struct WorkerClient {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
}

// DoH DNS 解析器
#[derive(Clone)]
struct DohResolver;

impl Resolve for DohResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let domain = name.as_str();
            
            // 使用 DoH 解析
            match resolve_via_doh(domain).await {
                Ok(ip) => {
                    tracing::info!("✓ DoH resolved {} to {}", domain, ip);
                    let addr = SocketAddr::new(ip, 0);
                    let addrs: Addrs = Box::new(std::iter::once(addr));
                    return Ok(addrs);
                }
                Err(e) => {
                    tracing::warn!("DoH failed for {}: {}", domain, e);
                }
            }
            
            // DoH 失败，返回错误
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "DoH resolution failed"
            )) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

// 通过 DoH 解析域名
async fn resolve_via_doh(domain: &str) -> Result<IpAddr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    
    let doh_servers = [
        ("https://1.1.1.1/dns-query", "Cloudflare"),
        ("https://8.8.8.8/resolve", "Google"),
        ("https://223.5.5.5/resolve", "AliDNS"),
    ];
    
    for (server, name) in &doh_servers {
        let url = format!("{}?name={}&type=A", server, domain);
        
        match client
            .get(&url)
            .header("Accept", "application/dns-json")
            .timeout(Duration::from_secs(3))
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
                        for answer in answers {
                            if let Some(ip_str) = answer.get("data").and_then(|d| d.as_str()) {
                                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                    tracing::debug!("DoH {} resolved {} to {}", name, domain, ip);
                                    return Ok(ip);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::debug!("DoH {} failed: {}", name, e);
            }
        }
    }
    
    anyhow::bail!("All DoH servers failed to resolve {}", domain)
}

#[derive(Debug, Serialize)]
struct RegisterRequest {
    uuid: String,
    encrypted_ip: String,
    public_key: String,  // 服务端 DH 公钥
    timestamp: u64,
    nonce: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct UpdateRequest {
    uuid: String,
    encrypted_ip: String,
    timestamp: u64,
    nonce: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerInfo {
    pub uuid: String,
    pub encrypted_ip: String,
    pub public_key: String,  // 服务端 DH 公钥
    pub root_key: String,    // Worker 生成的 root_key
}

impl WorkerClient {
    pub fn new(base_url: String, api_key: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        
        Self {
            client,
            base_url,
            api_key,
        }
    }
    
    // 创建带 DoH 解析的 client
    async fn create_resolved_client(&self) -> reqwest::Client {
        let domain = self.base_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or("");
        
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30));
        
        // 尝试 DoH 解析
        if !domain.is_empty() && !domain.chars().next().unwrap().is_numeric() {
            if let Ok(ip) = resolve_via_doh(domain).await {
                tracing::info!("✓ Resolved {} to {}", domain, ip);
                let addr = format!("{}:80", ip).parse().unwrap();
                builder = builder.resolve(domain, addr);
            }
        }
        
        builder.build().unwrap()
    }
    
    fn build_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
    
    pub async fn register(
        &self,
        uuid: &str,
        encrypted_ip: &str,
        public_key: &str,
    ) -> Result<String, WorkerError> {
        let client = self.create_resolved_client().await;
        
        let timestamp = current_timestamp();
        let nonce = generate_nonce();
        let sign_data = format!("{}{}{}", uuid, encrypted_ip, timestamp);
        let signature = self.sign(&sign_data);
        
        if tracing::enabled!(tracing::Level::DEBUG) {
            tracing::debug!("=== Register Request ===");
            tracing::debug!("UUID: {}", uuid);
            tracing::debug!("Encrypted IP: {}", encrypted_ip);
            tracing::debug!("Public Key: {}...", &public_key[..16.min(public_key.len())]);
        }
        
        let req = RegisterRequest {
            uuid: uuid.to_string(),
            encrypted_ip: encrypted_ip.to_string(),
            public_key: public_key.to_string(),
            timestamp,
            nonce: base64_encode(&nonce),
            signature: base64_encode(signature.as_bytes()),
        };
        
        let url = self.build_url("/gmail/v1/users/me/messages/send");
        
        // 重试 3 次
        for attempt in 1..=3 {
            match self.try_register(&client, &url, &req).await {
                Ok(root_key) => return Ok(root_key),
                Err(WorkerError::UuidConflict) => return Err(WorkerError::UuidConflict),
                Err(e) if attempt == 3 => return Err(e),
                Err(e) => {
                    tracing::warn!("Register attempt {}/3 failed: {}", attempt, e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
            }
        }
        
        unreachable!()
    }
    
    /// 重新注册（忽略 UUID 冲突错误）
    pub async fn reregister(
        &self,
        uuid: &str,
        encrypted_ip: &str,
        public_key: &str,
    ) -> Result<()> {
        match self.register(uuid, encrypted_ip, public_key).await {
            Ok(_) => Ok(()),
            Err(WorkerError::UuidConflict) => {
                // UUID 冲突时尝试更新
                self.update(uuid, encrypted_ip).await
            }
            Err(e) => Err(e.into()),
        }
    }
    
    async fn try_register(
        &self,
        client: &reqwest::Client,
        url: &str,
        req: &RegisterRequest,
    ) -> Result<String, WorkerError> {
        let resp = client
            .post(url)
            .header("Host", "mirrors.ustc.ip-ddns.com")
            .header("Content-Type", "application/json")
            .header("User-Agent", "Mozilla/5.0")
            .json(req)
            .send()
            .await?;
        
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        
        if status == 409 || body.contains("1001") {
            return Err(WorkerError::UuidConflict);
        }
        
        if !status.is_success() {
            return Err(WorkerError::ServerError {
                status: status.as_u16(),
                message: body,
            });
        }
        
        let json: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| WorkerError::InvalidResponse(e.to_string()))?;
        
        let root_key = json.get("root_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkerError::InvalidResponse("No root_key in response".to_string()))?;
        
        Ok(root_key.to_string())
    }
    
    pub async fn update(&self, uuid: &str, encrypted_ip: &str) -> Result<()> {
        let client = self.create_resolved_client().await;
        
        let timestamp = current_timestamp();
        let nonce = generate_nonce();
        let sign_data = format!("{}{}", uuid, timestamp);
        let signature = self.sign(&sign_data);
        
        tracing::info!("=== Update Request ===");
        tracing::info!("UUID: {}", uuid);
        tracing::info!("Encrypted IP: {}", encrypted_ip);
        tracing::info!("Timestamp: {}", timestamp);
        tracing::info!("Sign Data: {}", sign_data);
        
        let req = UpdateRequest {
            uuid: uuid.to_string(),
            encrypted_ip: encrypted_ip.to_string(),
            timestamp,
            nonce: base64_encode(&nonce),
            signature: base64_encode(signature.as_bytes()),
        };
        
        let url = self.build_url("/gmail/v1/users/me/messages/modify");
        tracing::info!("Request URL: {}", url);
        
        let resp = client
            .post(&url)
            .header("Host", "mirrors.ustc.ip-ddns.com")
            .header("Content-Type", "application/json")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .json(&req)
            .send()
            .await?;
        
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        
        if status == 404 {
            return Err(WorkerError::UuidNotFound.into());
        }
        
        if !status.is_success() {
            tracing::error!("Update failed - Status: {}, Body: {}", status, body);
            anyhow::bail!("Update failed: {}", body);
        }
        
        tracing::info!("Update response: {}", body);
        Ok(())
    }
    
    pub async fn delete_server(&self, uuid: &str) -> Result<()> {
        let client = self.create_resolved_client().await;
        
        let url = self.build_url(&format!("/gmail/v1/users/me/messages/{}", uuid));
        tracing::info!("=== Delete Server Request ===");
        tracing::info!("UUID: {}", uuid);
        tracing::info!("Request URL: {}", url);
        
        let resp = client
            .delete(&url)
            .header("Host", "mirrors.ustc.ip-ddns.com")
            .header("Content-Type", "application/json")
            .header("User-Agent", "Mozilla/5.0")
            .send()
            .await?;
        
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        
        if !status.is_success() {
            tracing::error!("Delete server failed - Status: {}, Body: {}", status, body);
            anyhow::bail!("Delete server failed: {}", body);
        }
        
        tracing::info!("✓ Server {} deleted from Worker", uuid);
        Ok(())
    }
    
    pub async fn list_servers(&self) -> Result<Vec<ServerInfo>> {
        let client = self.create_resolved_client().await;
        
        let url = self.build_url("/gmail/v1/users/me/messages");
        tracing::info!("=== List Servers Request ===");
        tracing::info!("Request URL: {}", url);
        
        // 重试机制：最多尝试 3 次
        let mut last_error = None;
        for attempt in 1..=3 {
            tracing::info!("List servers attempt {}/3", attempt);
            
            match client
                .get(&url)
                .header("Host", "mirrors.ustc.ip-ddns.com")
                .header("Content-Type", "application/json")
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    
                    if !status.is_success() {
                        tracing::error!("List servers failed - Status: {}, Body: {}", status, body);
                        anyhow::bail!("List servers failed: {}", body);
                    }
                    
                    tracing::info!("List servers response: {}", body);
                    let servers: Vec<ServerInfo> = serde_json::from_str(&body)?;
                    tracing::info!("Found {} servers", servers.len());
                    return Ok(servers);
                }
                Err(e) => {
                    tracing::error!("List servers attempt {} failed: {}", attempt, e);
                    last_error = Some(e);
                    if attempt < 3 {
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    }
                }
            }
        }
        
        Err(last_error.unwrap().into())
    }
    
    fn sign(&self, data: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(self.api_key.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

fn generate_nonce() -> Vec<u8> {
    use std::time::SystemTime;
    let timestamp = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    timestamp.to_le_bytes().to_vec()
}

fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
