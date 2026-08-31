//! 密码加密模块
//!
//! 使用 AES-256-GCM 进行认证加密，密钥存储在 OS keychain 中。
//!
//! # 安全特性
//! - **AES-256-GCM**: 提供加密和认证（防篡改）
//! - **OS Keychain**: 密钥安全存储在系统密钥链中
//! - **随机 Nonce**: 每次加密使用新的 12 字节随机 nonce
//! - **Zeroize**: 敏感数据在使用后立即从内存中清除
//!
//! # 使用示例
//! ```ignore
//! use crate::crypto::{encrypt, decrypt};
//!
//! // 加密明文密码
//! let encrypted = encrypt("my_secret_password")?;
//!
//! // 解密密文
//! let decrypted = decrypt(&encrypted)?;
//! assert_eq!(decrypted, "my_secret_password");
//! ```
//!
//! 本文件是 `flow-engine-crypto/src/encryption.rs` 的独立副本（sidecar 边界：
//! 插件只依赖 `mpe-plugin-sdk`，不得链接宿主 crate）。密钥服务名/用户名与宿主
//! 一致（`multi-protocol-flow-executor` / `db-encryption-key`），因此宿主加密的
//! 密码/token 密文可被插件解密。
//!
//! 注：宿主源文件的单元测试依赖 OS keychain（Linux 需 Secret Service），
//! 离线 `cargo test` 环境（headless）无法保证可用，故未随副本移植。

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use keyring::Entry;
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroize;

/// Keychain 服务名称
const KEYRING_SERVICE: &str = "multi-protocol-flow-executor";

/// Keychain 用户名（用于存储加密密钥）
const KEYRING_USERNAME: &str = "db-encryption-key";

/// Nonce 长度（AES-GCM 要求 12 字节）
const NONCE_SIZE: usize = 12;

/// AES-256 密钥长度
const KEY_SIZE: usize = 32;

/// 加密Error类型
#[derive(Error, Debug)]
pub enum EncryptionError {
    /// 加密操作Failed
    #[allow(dead_code)] // host GUI encrypts; the plugin only decrypts
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// 解密操作Failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Keychain 操作Failed
    #[error("Keychain operation failed: {0}")]
    KeyringError(String),

    /// Base64 编解码Failed
    #[error("Base64 encoding/decoding failed: {0}")]
    Base64Error(String),

    /// 密钥生成Failed
    #[allow(dead_code)] // host GUI encrypts; the plugin only decrypts
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// UTF-8 编解码Failed
    #[error("UTF-8 encoding/decoding failed: {0}")]
    Utf8Error(String),

    /// 密文格式无效
    #[error("Invalid ciphertext format: {0}")]
    InvalidFormat(String),
}

/// 使用 AES-256-GCM 加密明文密码
///
/// 保留为完整副本（宿主 GUI 在保存时加密；插件侧仅需要解密路径）。
///
/// # 加密流程
/// 1. 从 OS keychain 获取或创建加密密钥
/// 2. 生成 12 字节随机 nonce
/// 3. 使用 AES-256-GCM 加密
/// 4. 返回格式：`base64(nonce):base64(ciphertext)`
///
/// # 安全特性
/// - 每次加密使用不同的随机 nonce
/// - GCM 模式提供认证（防篡改）
/// - 密钥从不在内存中持久化存储
///
/// # 参数
/// - `plaintext`: 要加密的明文密码
///
/// # 返回
/// - `Ok(String)`: 格式为 `base64(nonce):base64(ciphertext)` 的密文
/// - `Err(EncryptionError)`: 加密Failed
#[allow(dead_code)]
pub fn encrypt(plaintext: &str) -> Result<String, EncryptionError> {
    // 获取或创建密钥
    let key = get_or_create_key()?;

    // 创建密码器
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    // 生成随机 nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 加密
    let mut ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

    // 编码结果：base64(nonce):base64(ciphertext)
    let result = format!(
        "{}:{}",
        BASE64.encode(nonce_bytes),
        BASE64.encode(&ciphertext)
    );

    // 清理内存中的敏感数据
    ciphertext.zeroize();
    nonce_bytes.zeroize();

    Ok(result)
}

/// 使用 AES-256-GCM 解密密文
///
/// # 解密流程
/// 1. 从 OS keychain 获取加密密钥
/// 2. 解析密文格式 `base64(nonce):base64(ciphertext)`
/// 3. 使用 AES-256-GCM 解密
/// 4. 验证认证标签（防篡改）
///
/// # 安全特性
/// - GCM 模式自动验证完整性
/// - 任何篡改都会导致解密Failed
///
/// # 参数
/// - `ciphertext`: 格式为 `base64(nonce):base64(ciphertext)` 的密文
///
/// # 返回
/// - `Ok(String)`: 解密后的明文
/// - `Err(EncryptionError)`: 解密Failed（密钥Error、密文篡改等）
pub fn decrypt(ciphertext: &str) -> Result<String, EncryptionError> {
    // 解析密文格式
    let parts: Vec<&str> = ciphertext.split(':').collect();
    if parts.len() != 2 {
        return Err(EncryptionError::InvalidFormat(
            "密文格式应为 base64(nonce):base64(ciphertext)".to_string(),
        ));
    }

    // 解码 nonce
    let mut nonce_bytes = BASE64
        .decode(parts[0])
        .map_err(|e| EncryptionError::Base64Error(e.to_string()))?;

    if nonce_bytes.len() != NONCE_SIZE {
        nonce_bytes.zeroize();
        return Err(EncryptionError::InvalidFormat(format!(
            "Nonce 长度应为 {} 字节，实际为 {} 字节",
            NONCE_SIZE,
            nonce_bytes.len()
        )));
    }

    let nonce = Nonce::from_slice(&nonce_bytes);

    // 解码密文
    let mut ciphertext_bytes = BASE64
        .decode(parts[1])
        .map_err(|e| EncryptionError::Base64Error(e.to_string()))?;

    // 获取密钥
    let key = get_or_create_key()?;

    // 创建密码器
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

    // 解密
    let mut plaintext = cipher
        .decrypt(nonce, ciphertext_bytes.as_slice())
        .map_err(|_| {
            EncryptionError::DecryptionFailed("解密Failed：密钥Error或密文已被篡改".to_string())
        })?;

    // 转换为字符串
    let result = String::from_utf8(plaintext.clone()).map_err(|e| {
        plaintext.zeroize();
        EncryptionError::Utf8Error(e.to_string())
    })?;

    // 清理内存中的敏感数据
    plaintext.zeroize();
    ciphertext_bytes.zeroize();
    nonce_bytes.zeroize();

    Ok(result)
}

/// 从 OS keychain 获取或创建加密密钥
///
/// # 流程
/// 1. 尝试从 keychain 获取现有密钥
/// 2. 如果不存在，生成新的 32 字节随机密钥
/// 3. 将新密钥存储到 keychain
///
/// # 安全特性
/// - 密钥存储在系统密钥链中（Windows Credential Manager / macOS Keychain / Linux Secret Service）
/// - 密钥从不写入磁盘文件
/// - 临时密钥变量在使用后立即 zeroize
///
/// # 返回
/// - `Ok([u8; 32])`: 32 字节 AES-256 密钥
/// - `Err(EncryptionError)`: keychain 操作Failed
fn get_or_create_key() -> Result<[u8; KEY_SIZE], EncryptionError> {
    // 创建 keychain entry
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)
        .map_err(|e| EncryptionError::KeyringError(e.to_string()))?;

    // 尝试获取现有密钥
    match entry.get_password() {
        Ok(key_b64) => {
            log::debug!("Retrieved existing key from keychain");

            // 解码现有密钥
            let mut key_bytes = BASE64
                .decode(&key_b64)
                .map_err(|e| EncryptionError::Base64Error(e.to_string()))?;

            if key_bytes.len() != KEY_SIZE {
                key_bytes.zeroize();
                return Err(EncryptionError::KeyringError(format!(
                    "Key length should be {} bytes, actual: {} bytes",
                    KEY_SIZE,
                    key_bytes.len()
                )));
            }

            // 转换为数组
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&key_bytes);

            // 清理临时变量
            key_bytes.zeroize();

            Ok(key)
        }
        Err(e) => {
            log::debug!("Key not found, generating new key: {}", e);

            // 密钥不存在，生成新密钥
            let mut key = [0u8; KEY_SIZE];
            rand::thread_rng().fill_bytes(&mut key);

            // 编码并存储到 keychain
            let key_b64 = BASE64.encode(key);

            entry
                .set_password(&key_b64)
                .map_err(|e| EncryptionError::KeyringError(e.to_string()))?;

            log::debug!("New key stored in keychain");

            Ok(key)
        }
    }
}

/// 删除 keychain 中的加密密钥
///
/// # 用途
/// 用于测试清理或密钥轮换
///
/// # 返回
/// - `Ok(())`: 删除Success
/// - `Err(EncryptionError)`: 删除Failed或密钥不存在
#[allow(dead_code)]
pub fn delete_key() -> Result<(), EncryptionError> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_USERNAME)
        .map_err(|e| EncryptionError::KeyringError(e.to_string()))?;

    entry
        .delete_credential()
        .map_err(|e| EncryptionError::KeyringError(e.to_string()))?;

    Ok(())
}
