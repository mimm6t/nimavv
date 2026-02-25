use anyhow::Result;
use maxminddb::Reader;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use aho_corasick::AhoCorasick;

// 内置 GeoIP 数据库
const EMBEDDED_GEOIP: &[u8] = include_bytes!("../data/GeoLite2-Country.mmdb");

pub struct GeoRouter {
    reader: Reader<Vec<u8>>,
    cn_domains: Arc<HashSet<String>>,
    gfw_matcher: Arc<AhoCorasick>,
    direct_matcher: Arc<AhoCorasick>,
}

impl GeoRouter {
    /// 使用内置的 GeoIP 数据库创建路由器
    pub fn new_embedded() -> Result<Self> {
        let reader = Reader::from_source(EMBEDDED_GEOIP.to_vec())?;
        
        let cn_domains = Self::load_cn_domains();
        let gfw_patterns = Self::load_gfw_patterns();
        let gfw_matcher = AhoCorasick::new(gfw_patterns)?;
        let direct_patterns = Self::load_direct_patterns();
        let direct_matcher = AhoCorasick::new(direct_patterns)?;
        
        Ok(Self {
            reader,
            cn_domains: Arc::new(cn_domains),
            gfw_matcher: Arc::new(gfw_matcher),
            direct_matcher: Arc::new(direct_matcher),
        })
    }
    
    /// 从外部文件加载 GeoIP 数据库
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let reader = Reader::open_readfile(db_path)?;
        
        let cn_domains = Self::load_cn_domains();
        let gfw_patterns = Self::load_gfw_patterns();
        let gfw_matcher = AhoCorasick::new(gfw_patterns)?;
        let direct_patterns = Self::load_direct_patterns();
        let direct_matcher = AhoCorasick::new(direct_patterns)?;
        
        Ok(Self {
            reader,
            cn_domains: Arc::new(cn_domains),
            gfw_matcher: Arc::new(gfw_matcher),
            direct_matcher: Arc::new(direct_matcher),
        })
    }
    
    pub fn is_cn_ip(&self, ip: IpAddr) -> bool {
        match self.reader.lookup::<maxminddb::geoip2::Country>(ip) {
            Ok(country) => {
                if let Some(country) = country.country {
                    if let Some(iso_code) = country.iso_code {
                        return iso_code == "CN";
                    }
                }
                false
            }
            Err(_) => false,
        }
    }
    
    /// 检查是否为私有 IP（局域网）
    pub fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() ||        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                ipv4.is_loopback() ||       // 127.0.0.0/8
                ipv4.is_link_local() ||     // 169.254.0.0/16
                ipv4.is_broadcast() ||      // 255.255.255.255
                ipv4.octets()[0] == 0       // 0.0.0.0/8
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() ||       // ::1
                ipv6.is_unspecified() ||    // ::
                (ipv6.segments()[0] & 0xfe00) == 0xfc00 || // fc00::/7 (Unique Local)
                (ipv6.segments()[0] & 0xffc0) == 0xfe80    // fe80::/10 (Link Local)
            }
        }
    }
    
    pub fn should_proxy(&self, ip: IpAddr) -> bool {
        // 私有 IP 直连
        if Self::is_private_ip(ip) {
            return false;
        }
        // 国外 IP 走代理
        !self.is_cn_ip(ip)
    }
    
    pub fn is_cn_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        
        // 1. 检查直连列表（优先级最高）
        if self.direct_matcher.is_match(&domain_lower) {
            return true;
        }
        
        // 2. 检查 GFW 列表（需要代理）
        if self.gfw_matcher.is_match(&domain_lower) {
            return false;
        }
        
        // 3. 检查中国域名列表
        if self.cn_domains.contains(&domain_lower) {
            return true;
        }
        
        // 4. 检查域名后缀
        if domain_lower.ends_with(".cn") || domain_lower.ends_with(".中国") {
            return true;
        }
        
        // 5. 检查各级域名
        for part in domain_lower.split('.').rev() {
            if self.cn_domains.contains(part) {
                return true;
            }
        }
        
        // 默认：国外域名
        false
    }
    
    fn load_cn_domains() -> HashSet<String> {
        // 常见中国域名和服务
        let domains = vec![
            // 顶级域名
            "cn", "中国",
            // 搜索引擎
            "baidu.com", "so.com", "sogou.com", "soso.com",
            // 电商
            "taobao.com", "tmall.com", "jd.com", "pinduoduo.com", "suning.com",
            // 社交媒体
            "qq.com", "weixin.qq.com", "wechat.com", "weibo.com", "douban.com",
            "zhihu.com", "bilibili.com", "douyin.com",
            // 视频
            "youku.com", "iqiyi.com", "v.qq.com", "acfun.cn", "tudou.com",
            // 新闻门户
            "sina.com.cn", "163.com", "126.com", "sohu.com", "ifeng.com",
            "people.com.cn", "xinhuanet.com", "chinanews.com",
            // 政府
            "gov.cn", "edu.cn", "ac.cn", "mil.cn",
            // 银行
            "icbc.com.cn", "ccb.com", "boc.cn", "abchina.com", "bankcomm.com",
            // 科技公司
            "aliyun.com", "alicdn.com", "tencent.com", "huawei.com", "xiaomi.com",
            "oppo.com", "vivo.com", "lenovo.com", "zte.com.cn",
            // CDN
            "qcloud.com", "myqcloud.com", "aliyuncs.com", "cdn.bcebos.com",
            // 其他
            "10086.cn", "189.cn", "10010.com", "ctrip.com", "dianping.com",
            "meituan.com", "ele.me", "gaode.com", "amap.com",
        ];
        
        domains.into_iter().map(String::from).collect()
    }
    
    fn load_gfw_patterns() -> Vec<String> {
        // GFW 屏蔽的域名关键词（需要代理）
        vec![
            // 搜索引擎
            "google", "youtube", "gmail", "gstatic", "ggpht", "googleusercontent",
            "googlevideo", "googleapis", "googletagmanager", "googlesyndication",
            // 社交媒体
            "facebook", "fbcdn", "twitter", "twimg", "instagram", "whatsapp",
            "telegram", "t.me", "reddit", "tumblr", "pinterest",
            // 新闻媒体
            "nytimes", "bbc", "cnn", "wsj", "bloomberg", "reuters",
            // 技术网站
            "github", "stackoverflow", "medium", "quora", "wikipedia",
            "wikimedia", "cloudflare", "amazonaws",
            // 视频
            "vimeo", "dailymotion", "twitch",
            // VPN/代理
            "vpn", "shadowsocks", "v2ray", "trojan",
            // 其他
            "dropbox", "onedrive", "archive.org",
        ].into_iter().map(String::from).collect()
    }
    
    fn load_direct_patterns() -> Vec<String> {
        // 强制直连的域名关键词
        vec![
            // 中国服务
            "alipay", "taobao", "tmall", "jd.com", "qq.com", "wechat",
            "weixin", "baidu", "163.com", "sina", "sohu",
            // 本地服务
            "localhost", "local", "lan", "internal",
            // 中国 CDN
            "aliyuncs", "qcloud", "myqcloud", "cdn.bcebos",
        ].into_iter().map(String::from).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_domain_routing() {
        let router = GeoRouter::new("test.mmdb").ok();
        if let Some(router) = router {
            // 中国域名
            assert!(router.is_cn_domain("baidu.com"));
            assert!(router.is_cn_domain("qq.com"));
            assert!(router.is_cn_domain("example.cn"));
            
            // 国外域名
            assert!(!router.is_cn_domain("google.com"));
            assert!(!router.is_cn_domain("facebook.com"));
            assert!(!router.is_cn_domain("twitter.com"));
        }
        
        #[test]
        fn test_private_ip_detection() {
            use std::net::{Ipv4Addr, Ipv6Addr};
            
            // IPv4 私有地址
            assert!(GeoRouter::is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
            assert!(GeoRouter::is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
            assert!(GeoRouter::is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
            assert!(GeoRouter::is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
            assert!(GeoRouter::is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
            
            // IPv4 公网地址
            assert!(!GeoRouter::is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
            assert!(!GeoRouter::is_private_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
            
            // IPv6 私有地址
            assert!(GeoRouter::is_private_ip(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
            assert!(GeoRouter::is_private_ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
            assert!(GeoRouter::is_private_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
            
            // IPv6 公网地址
            assert!(!GeoRouter::is_private_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888))));
        }
    }
}
