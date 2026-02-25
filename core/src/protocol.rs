use bytes::{Bytes, BytesMut, Buf, BufMut};

// 使用真实的 Gmail SMTP 服务器地址进行伪装
const SMTP_EHLO: &[u8] = b"EHLO smtp.gmail.com\r\n";
const SMTP_MAIL_FROM: &[u8] = b"MAIL FROM:<noreply@gmail.com>\r\n";
const SMTP_RCPT_TO: &[u8] = b"RCPT TO:<user@gmail.com>\r\n";
const SMTP_DATA: &[u8] = b"DATA\r\n";
const SMTP_END: &[u8] = b"\r\n.\r\n";
const SMTP_RESPONSE: &[u8] = b"250 OK\r\n";

#[derive(Debug, Clone)]
pub struct SmtpPacket {
    pub payload: Bytes,
}

impl SmtpPacket {
    pub fn new(payload: Bytes) -> Self {
        Self { payload }
    }
    
    /// 编码为伪装的 SMTP 会话
    pub fn encode(&self) -> Bytes {
        // 添加随机填充防止流量特征识别
        let padding_len = (self.payload.len() % 16) as usize;
        
        let mut buf = BytesMut::with_capacity(
            SMTP_EHLO.len() + 
            SMTP_MAIL_FROM.len() + 
            SMTP_RCPT_TO.len() + 
            SMTP_DATA.len() + 
            4 + // 长度字段
            self.payload.len() + 
            padding_len +
            SMTP_END.len()
        );
        
        // 完整的 SMTP 会话伪装
        buf.put_slice(SMTP_EHLO);
        buf.put_slice(SMTP_MAIL_FROM);
        buf.put_slice(SMTP_RCPT_TO);
        buf.put_slice(SMTP_DATA);
        
        // 实际数据
        buf.put_u32(self.payload.len() as u32);
        buf.put_slice(&self.payload);
        
        // 随机填充
        if padding_len > 0 {
            buf.put_slice(&vec![0u8; padding_len]);
        }
        
        buf.put_slice(SMTP_END);
        
        buf.freeze()
    }
    
    /// 解码 SMTP 伪装包，返回包和消费的字节数
    pub fn decode(mut data: Bytes) -> Result<(Self, usize), ProtocolError> {
        let original_len = data.len();
        let header_len = SMTP_EHLO.len() + SMTP_MAIL_FROM.len() + SMTP_RCPT_TO.len() + SMTP_DATA.len();
        
        if data.len() < header_len + 4 + SMTP_END.len() {
            return Err(ProtocolError::InvalidPacket);
        }
        
        // 验证 SMTP 头部
        if &data[..SMTP_EHLO.len()] != SMTP_EHLO {
            return Err(ProtocolError::InvalidMagic);
        }
        data.advance(SMTP_EHLO.len());
        
        if &data[..SMTP_MAIL_FROM.len()] != SMTP_MAIL_FROM {
            return Err(ProtocolError::InvalidMagic);
        }
        data.advance(SMTP_MAIL_FROM.len());
        
        if &data[..SMTP_RCPT_TO.len()] != SMTP_RCPT_TO {
            return Err(ProtocolError::InvalidMagic);
        }
        data.advance(SMTP_RCPT_TO.len());
        
        if &data[..SMTP_DATA.len()] != SMTP_DATA {
            return Err(ProtocolError::InvalidMagic);
        }
        data.advance(SMTP_DATA.len());
        
        // 读取长度
        let len = data.get_u32() as usize;
        
        if data.len() < len + SMTP_END.len() {
            return Err(ProtocolError::InvalidLength);
        }
        
        // 提取 payload
        let payload = data.slice(..len);
        data.advance(len);
        
        // 跳过填充，验证结束标记
        let remaining = data.len();
        if remaining < SMTP_END.len() {
            return Err(ProtocolError::InvalidEnd);
        }
        
        // 查找结束标记
        let end_pos = remaining - SMTP_END.len();
        if &data[end_pos..] != SMTP_END {
            return Err(ProtocolError::InvalidEnd);
        }
        
        // 计算消费的字节数：header + len字段 + payload + padding + end
        let padding_len = (len % 16) as usize;
        let consumed = header_len + 4 + len + padding_len + SMTP_END.len();
        
        Ok((Self { payload }, consumed))
    }
    
    /// 生成 SMTP 响应包装
    pub fn wrap_response(payload: Bytes) -> Bytes {
        let mut buf = BytesMut::with_capacity(
            SMTP_RESPONSE.len() + 4 + payload.len() + SMTP_END.len()
        );
        
        buf.put_slice(SMTP_RESPONSE);
        buf.put_u32(payload.len() as u32);
        buf.put_slice(&payload);
        buf.put_slice(SMTP_END);
        
        buf.freeze()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Invalid packet")]
    InvalidPacket,
    #[error("Invalid magic")]
    InvalidMagic,
    #[error("Invalid length")]
    InvalidLength,
    #[error("Invalid end marker")]
    InvalidEnd,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_smtp_roundtrip() {
        let payload = Bytes::from_static(b"test data");
        let packet = SmtpPacket::new(payload.clone());
        
        let encoded = packet.encode();
        
        // 验证包含完整的 SMTP 会话伪装
        assert!(encoded.starts_with(b"EHLO smtp.gmail.com"));
        assert!(encoded.windows(b"MAIL FROM:<noreply@gmail.com>".len())
            .any(|w| w == b"MAIL FROM:<noreply@gmail.com>"));
        
        let decoded = SmtpPacket::decode(encoded).unwrap();
        assert_eq!(payload, decoded.payload);
    }
    
    #[test]
    fn test_smtp_response() {
        let payload = Bytes::from_static(b"response data");
        let wrapped = SmtpPacket::wrap_response(payload);
        
        // 验证响应包含 SMTP 格式
        assert!(wrapped.starts_with(b"250 OK"));
    }
}
