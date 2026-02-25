use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct DnsResolver {
    cn_upstream: String,
    foreign_upstream: String,
}

impl DnsResolver {
    pub async fn new(cn_upstream: &str, foreign_upstream: &str) -> Result<Self> {
        Ok(Self {
            cn_upstream: cn_upstream.to_string(),
            foreign_upstream: foreign_upstream.to_string(),
        })
    }
    
    pub async fn resolve(&self, domain: &str, is_cn: bool) -> Result<Vec<std::net::IpAddr>> {
        let upstream = if is_cn { &self.cn_upstream } else { &self.foreign_upstream };
        
        // 使用 DoH 解析
        let url = format!("{}?name={}&type=A", upstream, domain);
        let resp = reqwest::get(&url).await?;
        let json: serde_json::Value = resp.json().await?;
        
        let mut ips = Vec::new();
        if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
            for answer in answers {
                if let Some(ip_str) = answer.get("data").and_then(|d| d.as_str()) {
                    if let Ok(ip) = ip_str.parse() {
                        ips.push(ip);
                    }
                }
            }
        }
        
        Ok(ips)
    }
}

pub async fn start_dns_server(resolver: Arc<DnsResolver>, addr: SocketAddr) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    let mut buf = vec![0u8; 512];
    
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let query = buf[..len].to_vec();
        
        let resolver = resolver.clone();
        let socket = socket.clone();
        
        tokio::spawn(async move {
            if let Ok(response) = handle_dns_query(&query, &resolver).await {
                let _ = socket.send_to(&response, peer).await;
            }
        });
    }
}

async fn handle_dns_query(query: &[u8], resolver: &DnsResolver) -> Result<Vec<u8>> {
    use trust_dns_proto::op::{Message, MessageType, ResponseCode};
    use trust_dns_proto::rr::{RData, Record};
    
    // 解析 DNS 查询
    let request = match Message::from_vec(query) {
        Ok(msg) => msg,
        Err(_) => return Ok(query.to_vec()),
    };
    
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_recursion_desired(true);
    response.set_recursion_available(true);
    
    if let Some(query) = request.queries().first() {
        let domain = query.name().to_utf8();
        let is_cn = domain.ends_with(".cn") || domain.contains("baidu") || domain.contains("qq.com");
        
        response.add_query(query.clone());
        
        // 解析域名
        match resolver.resolve(&domain, is_cn).await {
            Ok(ips) => {
                response.set_response_code(ResponseCode::NoError);
                for ip in ips {
                    let mut record = Record::new();
                    record.set_name(query.name().clone());
                    record.set_ttl(300);
                    record.set_data(Some(match ip {
                        std::net::IpAddr::V4(ipv4) => RData::A(ipv4.into()),
                        std::net::IpAddr::V6(ipv6) => RData::AAAA(ipv6.into()),
                    }));
                    response.add_answer(record);
                }
            }
            Err(_) => {
                response.set_response_code(ResponseCode::ServFail);
            }
        }
    }
    
    Ok(response.to_vec()?)
}
