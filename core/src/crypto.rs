use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use x25519_dalek::{PublicKey, StaticSecret};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use bytes::{Bytes, BytesMut, BufMut};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;

type HmacSha256 = Hmac<Sha256>;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KEY_B_COUNT: usize = 10;

#[derive(Clone)]
pub struct KeyB {
    pub key: [u8; 32],
    pub expires_at: u64,
}

#[derive(Clone)]
pub struct KeySet {
    pub key_a: [u8; KEY_SIZE],
    pub key_b_pool: Vec<[u8; KEY_SIZE]>,
    pub hmac_key: [u8; KEY_SIZE],
}

pub struct CryptoContext {
    dh_secret_bytes: Option<[u8; 32]>,  // Store as bytes so it can be cloned
    dh_public: PublicKey,
    keys: Option<KeySet>,
    pub key_b_pool: Vec<KeyB>,
    pub root_key: [u8; 32],
}

impl Clone for CryptoContext {
    fn clone(&self) -> Self {
        Self {
            dh_secret_bytes: self.dh_secret_bytes,  // Now we can clone it!
            dh_public: self.dh_public,
            keys: self.keys.clone(),
            key_b_pool: self.key_b_pool.clone(),
            root_key: self.root_key,
        }
    }
}

impl CryptoContext {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut dh_secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut dh_secret_bytes);
        let dh_secret = StaticSecret::from(dh_secret_bytes);
        let dh_public = PublicKey::from(&dh_secret);
        
        let mut root_key = [0u8; 32];
        rng.fill_bytes(&mut root_key);
        
        let mut key_b_pool = Vec::new();
        let now = current_timestamp();
        for _ in 0..KEY_B_COUNT {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            key_b_pool.push(KeyB {
                key,
                expires_at: now + 365 * 24 * 3600,
            });
        }
        
        Self {
            dh_secret_bytes: Some(dh_secret_bytes),
            dh_public,
            keys: None,
            key_b_pool,
            root_key,
        }
    }
    
    /// Create context from persisted DH secret
    pub fn from_secret(dh_secret_bytes: [u8; 32]) -> Self {
        let dh_secret = StaticSecret::from(dh_secret_bytes);
        let dh_public = PublicKey::from(&dh_secret);
        
        Self {
            dh_secret_bytes: Some(dh_secret_bytes),
            dh_public,
            keys: None,
            key_b_pool: Vec::new(),
            root_key: [0u8; 32],
        }
    }
    
    pub fn with_keys(keys: KeySet, root_key: [u8; 32]) -> Self {
        Self {
            dh_secret_bytes: None,
            dh_public: PublicKey::from([0u8; 32]),
            keys: Some(keys),
            key_b_pool: Vec::new(),
            root_key,
        }
    }
    
    pub fn public_key(&self) -> &PublicKey {
        &self.dh_public
    }
    
    pub fn dh_secret_bytes(&self) -> Option<[u8; 32]> {
        self.dh_secret_bytes
    }
    
    /// Derive session keys from peer's public key and root key
    /// This is the ONLY place where key derivation happens
    pub fn derive_keys(&mut self, peer_public: &PublicKey, root_key: &[u8]) -> Result<KeySet, CryptoError> {
        let dh_secret_bytes = self.dh_secret_bytes
            .ok_or(CryptoError::KeysNotDerived)?;
        
        let keys = Self::derive_keys_static(&dh_secret_bytes, peer_public, root_key)?;
        self.keys = Some(keys.clone());
        Ok(keys)
    }
    
    /// Static method for deriving keys - used by both client and server
    pub fn derive_keys_static(
        dh_secret_bytes: &[u8; 32],
        peer_public: &PublicKey,
        root_key: &[u8],
    ) -> Result<KeySet, CryptoError> {
        let dh_secret = StaticSecret::from(*dh_secret_bytes);
        let shared = dh_secret.diffie_hellman(peer_public);
        
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), shared.as_bytes());
        
        let mut key_a = [0u8; KEY_SIZE];
        hkdf.expand(b"key_a", &mut key_a)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        
        let mut key_b_pool = Vec::with_capacity(10);
        for i in 0..10 {
            let mut key_b = [0u8; KEY_SIZE];
            let info = format!("key_b_{}", i);
            hkdf.expand(info.as_bytes(), &mut key_b)
                .map_err(|_| CryptoError::KeyDerivationFailed)?;
            key_b_pool.push(key_b);
        }
        
        let mut hmac_key = [0u8; KEY_SIZE];
        hkdf.expand(b"hmac_key", &mut hmac_key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        
        Ok(KeySet { key_a, key_b_pool, hmac_key })
    }
    
    pub fn encrypt(&self, data: &[u8]) -> Result<Bytes, CryptoError> {
        let keys = self.keys.as_ref().ok_or(CryptoError::KeysNotDerived)?;
        
        let hash = sha2::Sha256::digest(data);
        let idx = (hash[0] as usize) % keys.key_b_pool.len();
        let key_b = &keys.key_b_pool[idx];
        
        let nonce = generate_nonce();
        
        let cipher = Aes256Gcm::new(key_b.into());
        let ciphertext = cipher.encrypt(&nonce, data)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&keys.hmac_key).unwrap();
        mac.update(&ciphertext);
        let signature = mac.finalize().into_bytes();
        
        let mut result = BytesMut::with_capacity(1 + 8 + NONCE_SIZE + ciphertext.len() + 32);
        result.put_u8(idx as u8);
        result.put_u64(current_timestamp());
        result.put_slice(nonce.as_slice());
        result.put_slice(&ciphertext);
        result.put_slice(&signature);
        
        Ok(result.freeze())
    }
    
    pub fn decrypt(&self, data: &[u8]) -> Result<Bytes, CryptoError> {
        if data.len() < 1 + 8 + NONCE_SIZE + TAG_SIZE + 32 {
            return Err(CryptoError::InvalidPacket);
        }
        
        let keys = self.keys.as_ref().ok_or(CryptoError::KeysNotDerived)?;
        
        let idx = data[0] as usize;
        let timestamp = u64::from_be_bytes(data[1..9].try_into().unwrap());
        let nonce = &data[9..21];
        let ciphertext_end = data.len() - 32;
        let ciphertext = &data[21..ciphertext_end];
        let signature = &data[ciphertext_end..];
        
        let now = current_timestamp();
        let diff = now.abs_diff(timestamp);
        if diff > 604800 {  // 7 天
            return Err(CryptoError::TimestampExpired(diff));
        }
        
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&keys.hmac_key).unwrap();
        mac.update(ciphertext);
        mac.verify_slice(signature).map_err(|_| CryptoError::SignatureInvalid)?;
        
        if idx >= keys.key_b_pool.len() {
            return Err(CryptoError::InvalidKeyIndex(idx));
        }
        let key_b = &keys.key_b_pool[idx];
        let cipher = Aes256Gcm::new(key_b.into());
        let nonce = Nonce::from_slice(nonce);
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        
        Ok(Bytes::from(plaintext))
    }
}

fn generate_nonce() -> Nonce<typenum::U12> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    *Nonce::from_slice(&nonce)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Keys not derived")]
    KeysNotDerived,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid packet")]
    InvalidPacket,
    #[error("Timestamp expired (diff: {0}s)")]
    TimestampExpired(u64),
    #[error("Signature invalid")]
    SignatureInvalid,
    #[error("Invalid key index: {0}")]
    InvalidKeyIndex(usize),
    #[error("Key derivation failed")]
    KeyDerivationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_crypto_roundtrip() {
        let mut alice = CryptoContext::new();
        let mut bob = CryptoContext::new();
        
        let alice_pub = *alice.public_key();
        let bob_pub = *bob.public_key();
        
        let root_key = b"test_root_key_32_bytes_long_____";
        alice.derive_keys(&bob_pub, root_key).unwrap();
        bob.derive_keys(&alice_pub, root_key).unwrap();
        
        let plaintext = b"Hello, World!";
        let ciphertext = alice.encrypt(plaintext).unwrap();
        let decrypted = bob.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
    
    #[test]
    fn test_clone_preserves_secret() {
        let mut ctx1 = CryptoContext::new();
        let ctx2 = ctx1.clone();
        
        // Both should have the same DH secret
        assert_eq!(ctx1.dh_secret_bytes(), ctx2.dh_secret_bytes());
        assert_eq!(ctx1.public_key().as_bytes(), ctx2.public_key().as_bytes());
        
        // Both should derive the same keys
        let peer = CryptoContext::new();
        let peer_pub = *peer.public_key();
        let root_key = b"test_root_key_32_bytes_long_____";
        
        let keys1 = ctx1.derive_keys(&peer_pub, root_key).unwrap();
        let mut ctx2_mut = ctx2;
        let keys2 = ctx2_mut.derive_keys(&peer_pub, root_key).unwrap();
        
        assert_eq!(keys1.hmac_key, keys2.hmac_key);
    }
    
    #[test]
    fn test_signature_validation() {
        let mut alice = CryptoContext::new();
        let mut bob = CryptoContext::new();
        
        let alice_pub = *alice.public_key();
        let bob_pub = *bob.public_key();
        
        let root_key = b"test_root_key_32_bytes_long_____";
        alice.derive_keys(&bob_pub, root_key).unwrap();
        bob.derive_keys(&alice_pub, root_key).unwrap();
        
        let plaintext = b"Test message";
        let mut ciphertext = alice.encrypt(plaintext).unwrap().to_vec();
        
        // Tamper with ciphertext
        ciphertext[50] ^= 0xFF;
        
        // Should fail signature verification
        let result = bob.decrypt(&ciphertext);
        assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
    }
}
