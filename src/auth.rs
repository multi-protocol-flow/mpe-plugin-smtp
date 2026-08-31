//! SMTP/IMAP 认证解析与 SASL 字符串构建（插件侧）。
//!
//! 兼容两种 wire 形态（均可能出现在存量 `.mpf` 流程中）：
//!
//! 1. 当前前端形态：`{ "auth_type": "plain"|"login"|"xoauth2", "username",
//!    "password"?, "oauth2_tokens"?: { "access_token", ... } }` —— 密码为明文。
//! 2. 旧宿主形态（`flow-engine-core::email_types::EmailAuthConfig`）：
//!    `{ "type": "plain"|"login", "username", "encrypted_password" }` 或
//!    `{ "type": "oauth2", ..., "encrypted_tokens" }` —— 密码/token 用
//!    AES-256-GCM 加密（见 [`crate::crypto`]），连接时解密。
//!
//! SASL 字符串构建（`xoauth2_string` / `plain_string` / `login_strings`）
//! 移植自宿主 `flow-engine-core/src/email_auth.rs`。

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

/// 解析后的认证凭证，供 lettre transport 构建使用。
#[derive(Debug, Clone, PartialEq)]
pub enum AuthCredentials {
    /// PLAIN：用户名 + 明文密码。
    Plain { username: String, password: String },
    /// LOGIN：用户名 + 明文密码。
    Login { username: String, password: String },
    /// XOAUTH2：用户 + access token（SASL 字符串在 transport 构建时生成）。
    XOAuth2 { user: String, access_token: String },
}

/// 从节点配置的 `auth` JSON 块解析认证凭证。
///
/// 同时接受当前前端形态（`auth_type` + 明文）与旧宿主形态
/// （`type` + `encrypted_password` / `encrypted_tokens`，需解密）。
/// `null` / 缺失 → `Ok(None)`（无认证）。未知形态 → 可读错误。
pub fn resolve_auth(auth: &serde_json::Value) -> Result<Option<AuthCredentials>, String> {
    if auth.is_null() {
        return Ok(None);
    }
    let parsed_holder;
    let obj = match auth {
        serde_json::Value::Object(map) => map,
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed == "{}" {
                return Ok(None);
            }
            parsed_holder = serde_json::from_str::<serde_json::Value>(trimmed).map_err(|err| {
                format!(
                    "{}: {err}",
                    crate::i18n::t("认证配置不是合法的 JSON 对象", "Auth config is not a valid JSON object")
                )
            })?;
            match &parsed_holder {
                serde_json::Value::Object(map) => map,
                serde_json::Value::Null => return Ok(None),
                _ => {
                    return Err(
                        crate::i18n::t("认证配置格式无效", "Invalid auth config format").to_string(),
                    )
                }
            }
        }
        _ => {
            return Err(crate::i18n::t("认证配置格式无效", "Invalid auth config format").to_string());
        }
    };

    // 当前前端形态：auth_type
    if let Some(auth_type) = obj.get("auth_type").and_then(serde_json::Value::as_str) {
        let username = obj
            .get("username")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        return match auth_type {
            "plain" => {
                let password = obj
                    .get("password")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string();
                Ok(Some(AuthCredentials::Plain { username, password }))
            }
            "login" => {
                let password = obj
                    .get("password")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string();
                Ok(Some(AuthCredentials::Login { username, password }))
            }
            "xoauth2" => {
                let access_token = obj
                    .get("oauth2_tokens")
                    .and_then(|t| t.get("access_token"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if access_token.is_empty() {
                    return Err(crate::i18n::t(
                        "XOAUTH2 缺少 access_token",
                        "XOAUTH2 is missing access_token",
                    )
                    .to_string());
                }
                Ok(Some(AuthCredentials::XOAuth2 { user: username, access_token }))
            }
            other => Err(crate::i18n::t("未知认证类型", "Unknown auth type").to_string()
                + &format!(" `{other}`")),
        };
    }

    // 旧宿主形态：type（EmailAuthConfig 的 serde tag）
    if let Some(auth_type) = obj.get("type").and_then(serde_json::Value::as_str) {
        let username = obj
            .get("username")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        return match auth_type {
            "plain" => {
                let encrypted = obj
                    .get("encrypted_password")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let password = crate::crypto::decrypt(encrypted).map_err(|e| {
                    format!("{}: {e}", crate::i18n::t("解密密码Failed", "Password decryption failed"))
                })?;
                Ok(Some(AuthCredentials::Plain { username, password }))
            }
            "login" => {
                let encrypted = obj
                    .get("encrypted_password")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let password = crate::crypto::decrypt(encrypted).map_err(|e| {
                    format!("{}: {e}", crate::i18n::t("解密密码Failed", "Password decryption failed"))
                })?;
                Ok(Some(AuthCredentials::Login { username, password }))
            }
            "oauth2" => {
                let encrypted_tokens = obj
                    .get("encrypted_tokens")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        crate::i18n::t(
                            "OAuth2 配置缺少 encrypted_tokens",
                            "OAuth2 config is missing encrypted_tokens",
                        )
                        .to_string()
                    })?;
                let tokens_json = crate::crypto::decrypt(encrypted_tokens).map_err(|e| {
                    format!("{}: {e}", crate::i18n::t("解密 OAuth2 token Failed", "OAuth2 token decryption failed"))
                })?;
                let tokens: serde_json::Value = serde_json::from_str(&tokens_json).map_err(|e| {
                    format!("{}: {e}", crate::i18n::t("解析 OAuth2 token JSON Failed", "Failed to parse OAuth2 token JSON"))
                })?;
                let access_token = tokens
                    .get("access_token")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if access_token.is_empty() {
                    return Err(crate::i18n::t(
                        "OAuth2 token 缺少 access_token",
                        "OAuth2 token is missing access_token",
                    )
                    .to_string());
                }
                Ok(Some(AuthCredentials::XOAuth2 { user: username, access_token }))
            }
            other => Err(crate::i18n::t("未知认证类型", "Unknown auth type").to_string()
                + &format!(" `{other}`")),
        };
    }

    Err(crate::i18n::t(
        "认证配置缺少 auth_type/type 字段",
        "Auth config is missing the auth_type/type field",
    )
    .to_string())
}

/// 生成 XOAUTH2 SASL 字符串
///
/// 格式: `base64("user={email}\x01auth=Bearer {token}\x01\x01")`
pub fn xoauth2_string(user: &str, token: &str) -> String {
    // XOAUTH2 格式: user={user}\x01auth=Bearer {token}\x01\x01
    let raw = format!("user={}\x01auth=Bearer {}\x01\x01", user, token);
    BASE64.encode(raw.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_null_is_none() {
        assert_eq!(resolve_auth(&serde_json::Value::Null).expect("null is valid"), None);
    }

    #[test]
    fn resolve_current_plain_shape() {
        let auth = serde_json::json!({
            "auth_type": "plain",
            "username": "user@example.com",
            "password": "s3cret",
        });
        assert_eq!(
            resolve_auth(&auth).expect("current shape parses"),
            Some(AuthCredentials::Plain {
                username: "user@example.com".to_string(),
                password: "s3cret".to_string(),
            })
        );
    }

    #[test]
    fn resolve_current_login_missing_password() {
        let auth = serde_json::json!({ "auth_type": "login", "username": "u" });
        assert_eq!(
            resolve_auth(&auth).expect("login without password parses"),
            Some(AuthCredentials::Login {
                username: "u".to_string(),
                password: String::new(),
            })
        );
    }

    #[test]
    fn resolve_current_xoauth2_shape() {
        let auth = serde_json::json!({
            "auth_type": "xoauth2",
            "username": "user@gmail.com",
            "oauth2_tokens": { "access_token": "ya29.token" },
        });
        assert_eq!(
            resolve_auth(&auth).expect("xoauth2 parses"),
            Some(AuthCredentials::XOAuth2 {
                user: "user@gmail.com".to_string(),
                access_token: "ya29.token".to_string(),
            })
        );
    }

    #[test]
    fn resolve_xoauth2_missing_token_fails() {
        let auth = serde_json::json!({ "auth_type": "xoauth2", "username": "u" });
        assert!(resolve_auth(&auth).is_err());
    }

    #[test]
    fn resolve_unknown_auth_type_fails() {
        let auth = serde_json::json!({ "auth_type": "cram-md5", "username": "u" });
        let err = resolve_auth(&auth).expect_err("unknown type fails");
        assert!(err.contains("cram-md5"), "unknown type named: {err}");
    }

    #[test]
    fn resolve_legacy_plain_shape_requires_keyring() {
        // Legacy shape decryption needs the OS keychain; on a headless
        // machine this errors with a keychain message rather than panicking
        // — asserting that the shape is *recognized* (falls into the decrypt
        // path) is enough offline.
        let auth = serde_json::json!({
            "type": "plain",
            "username": "u",
            "encrypted_password": "bm9uY2U6Y2lwaGVy",
        });
        let result = resolve_auth(&auth);
        // Either the keychain works (Ok) or it fails with a keychain error;
        // both prove the legacy path was taken (never "missing type").
        match result {
            Ok(Some(AuthCredentials::Plain { username, .. })) => {
                assert_eq!(username, "u");
            }
            Ok(other) => panic!("expected UsernamePassword, got {other:?}"),
            Err(e) => assert!(
                e.contains("解密") || e.contains("keychain") || e.contains("Keychain") || e.contains("failed"),
                "legacy plain path reports a decryption/keychain error: {e}"
            ),
        }
    }

    #[test]
    fn resolve_missing_shape_fields_fails() {
        assert!(resolve_auth(&serde_json::json!({ "username": "u" })).is_err());
    }

    #[test]
    fn xoauth2_sasl_string_roundtrip() {
        let sasl = xoauth2_string("user@gmail.com", "ya29.token");
        let decoded = BASE64.decode(&sasl).expect("valid base64");
        let decoded_str = String::from_utf8_lossy(&decoded);
        assert!(decoded_str.starts_with("user=user@gmail.com"));
        assert!(decoded_str.contains("auth=Bearer ya29.token"));
        assert_eq!(&decoded[decoded.len() - 2..], &[0x01, 0x01]);
    }
}
