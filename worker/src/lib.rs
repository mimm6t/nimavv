use worker::*;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct RegisterRequest {
    uuid: String,
    encrypted_ip: String,
    public_key: String,  // 服务端 DH 公钥
    timestamp: u64,
    nonce: String,
    signature: String,
}

#[derive(Deserialize)]
struct UpdateRequest {
    uuid: String,
    encrypted_ip: String,
    timestamp: u64,
    nonce: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct ServerInfo {
    uuid: String,
    encrypted_ip: String,
    public_key: String,  // 服务端 DH 公钥
    root_key: String,    // Worker 生成的 root_key
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();
    
    router
        .post_async("/gmail/v1/users/me/messages/send", |mut req, ctx| async move {
            match ctx.kv("SERVERS") {
                Ok(kv) => {
                    let body: RegisterRequest = req.json().await?;
                    
                    // 验证时间戳（放宽到 7 天）
                    let now = Date::now().as_millis() / 1000;
                    if now.abs_diff(body.timestamp) > 604800 {
                        return Response::error("Timestamp expired", 401);
                    }
                    
                    // 检查 UUID 是否已存在
                    if let Some(existing) = kv.get(&body.uuid).text().await? {
                        // UUID 已存在，返回冲突错误
                        return Response::error("UUID already exists", 409);
                    }
                    
                    // Worker 生成 root_key (32 字节随机数)
                    let root_key = generate_root_key();
                    
                    // 存储服务器信息
                    let server = ServerInfo {
                        uuid: body.uuid.clone(),
                        encrypted_ip: body.encrypted_ip,
                        public_key: body.public_key,
                        root_key: root_key.clone(),
                    };
                    
                    kv.put(&body.uuid, serde_json::to_string(&server)?)?
                        .expiration_ttl(1800)  // 30 分钟
                        .execute()
                        .await?;
                    
                    // 返回 root_key 给服务端
                    Response::from_json(&serde_json::json!({
                        "id": body.uuid,
                        "threadId": body.uuid,
                        "labelIds": ["SENT"],
                        "root_key": root_key
                    }))
                }
                Err(_) => {
                    Response::from_json(&serde_json::json!({
                        "id": "mock",
                        "threadId": "mock",
                        "labelIds": ["SENT"],
                        "root_key": generate_root_key()
                    }))
                }
            }
        })
        .post_async("/gmail/v1/users/me/messages/modify", |mut req, ctx| async move {
            match ctx.kv("SERVERS") {
                Ok(kv) => {
                    let body: UpdateRequest = req.json().await?;
                    
                    let now = Date::now().as_millis() / 1000;
                    if now.abs_diff(body.timestamp) > 604800 {
                        return Response::error("Timestamp expired", 401);
                    }
                    
                    if let Some(value) = kv.get(&body.uuid).text().await? {
                        if let Ok(mut server) = serde_json::from_str::<ServerInfo>(&value) {
                            if !body.encrypted_ip.is_empty() {
                                server.encrypted_ip = body.encrypted_ip;
                            }
                            
                            kv.put(&body.uuid, serde_json::to_string(&server)?)?
                                .expiration_ttl(1800)  // 30 分钟
                                .execute()
                                .await?;
                            
                            Response::from_json(&serde_json::json!({
                                "id": body.uuid,
                                "labelIds": ["INBOX", "UNREAD"]
                            }))
                        } else {
                            kv.put(&body.uuid, value)?
                                .expiration_ttl(1800)  // 30 分钟
                                .execute()
                                .await?;
                            
                            Response::from_json(&serde_json::json!({
                                "id": body.uuid,
                                "labelIds": ["INBOX", "UNREAD"]
                            }))
                        }
                    } else {
                        // UUID 不存在（已过期），返回 404
                        Response::error("UUID not found (expired)", 404)
                    }
                }
                Err(_) => {
                    Response::from_json(&serde_json::json!({
                        "id": "mock",
                        "labelIds": ["INBOX"]
                    }))
                }
            }
        })
        .get_async("/gmail/v1/users/me/messages", |_req, ctx| async move {
            match ctx.kv("SERVERS") {
                Ok(kv) => {
                    let list = kv.list().execute().await?;
                    let mut servers = Vec::new();
                    
                    for key in list.keys {
                        if let Some(value) = kv.get(&key.name).text().await? {
                            if let Ok(server) = serde_json::from_str::<ServerInfo>(&value) {
                                servers.push(server);
                            }
                        }
                    }
                    
                    Response::from_json(&servers)
                }
                Err(_) => {
                    Response::from_json(&Vec::<ServerInfo>::new())
                }
            }
        })
        .delete_async("/gmail/v1/users/me/messages/:uuid", |_req, ctx| async move {
            match ctx.kv("SERVERS") {
                Ok(kv) => {
                    if let Some(uuid) = ctx.param("uuid") {
                        kv.delete(uuid).await?;
                        Response::from_json(&serde_json::json!({
                            "id": uuid,
                            "deleted": true
                        }))
                    } else {
                        Response::error("UUID required", 400)
                    }
                }
                Err(_) => {
                    Response::error("KV not available", 500)
                }
            }
        })
        .run(req, env)
        .await
}

// 生成 32 字节随机 root_key
fn generate_root_key() -> String {
    use getrandom::getrandom;
    let mut key = [0u8; 32];
    let _ = getrandom(&mut key);
    base64_encode(&key)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}
