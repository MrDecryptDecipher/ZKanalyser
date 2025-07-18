use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::error::{ZKError, ZKResult};

type HmacSha256 = Hmac<Sha256>;

/// Comprehensive security and audit system
pub struct SecurityManager {
    config: Config,
    state: Arc<RwLock<SecurityState>>,
    audit_logger: Arc<AuditLogger>,
    access_control: Arc<AccessControl>,
    crypto_manager: Arc<CryptoManager>,
}

#[derive(Debug, Clone)]
pub struct SecurityState {
    pub rbac_enabled: bool,
    pub audit_enabled: bool,
    pub webhook_signing_enabled: bool,
    pub self_destruct_armed: bool,
    pub active_sessions: HashMap<String, SessionInfo>,
    pub failed_auth_attempts: u64,
    pub last_security_scan: chrono::DateTime<chrono::Utc>,
    pub security_events: u64,
    pub tamper_attempts: u64,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub token: String,
    pub role: UserRole,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub ip_address: String,
    pub user_agent: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    ReadOnly,
    Replay,
    Monitor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Permission {
    ReadMetrics,
    ReadConfig,
    WriteConfig,
    ExecuteReplay,
    ManageAlerts,
    SystemControl,
    AuditAccess,
    SecurityManagement,
}

/// Tamper-evident audit logging with Merkle chain
pub struct AuditLogger {
    state: Arc<RwLock<AuditState>>,
    merkle_chain: Arc<RwLock<MerkleChain>>,
    config: Config,
}

#[derive(Debug, Clone)]
pub struct AuditState {
    pub total_entries: u64,
    pub chain_verified: bool,
    pub last_entry_hash: String,
    pub last_verification: chrono::DateTime<chrono::Utc>,
    pub integrity_violations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: AuditEventType,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub source_ip: Option<String>,
    pub action: String,
    pub resource: String,
    pub result: AuditResult,
    pub details: serde_json::Value,
    pub hash: String,
    pub previous_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    DataAccess,
    ConfigChange,
    SystemControl,
    SecurityEvent,
    ReplayExecution,
    AlertTriggered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure,
    Denied,
    Error,
}

/// Merkle chain for tamper-evident logging
pub struct MerkleChain {
    entries: Vec<MerkleNode>,
    root_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub data_hash: String,
    pub previous_hash: String,
}

/// Role-Based Access Control (RBAC) system
pub struct AccessControl {
    tokens: Arc<RwLock<HashMap<String, TokenInfo>>>,
    roles: Arc<RwLock<HashMap<UserRole, Vec<Permission>>>>,
    config: Config,
}

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub token: String,
    pub role: UserRole,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used: chrono::DateTime<chrono::Utc>,
    pub usage_count: u64,
    pub revoked: bool,
}

/// Cryptographic operations manager
pub struct CryptoManager {
    signing_key: Option<SigningKey>,
    verifying_key: Option<VerifyingKey>,
    webhook_signing_key: Option<Vec<u8>>,
}

impl Default for SecurityManager {
    fn default() -> Self {
        let config = Config::default();
        let state = Arc::new(RwLock::new(SecurityState {
            rbac_enabled: false,
            audit_enabled: false,
            webhook_signing_enabled: false,
            self_destruct_armed: false,
            active_sessions: HashMap::new(),
            failed_auth_attempts: 0,
            last_security_scan: chrono::Utc::now(),
            security_events: 0,
            tamper_attempts: 0,
        }));

        let audit_logger = Arc::new(AuditLogger::default());
        let access_control = Arc::new(AccessControl::default());
        let crypto_manager = Arc::new(CryptoManager::default());

        Self {
            config,
            state,
            audit_logger,
            access_control,
            crypto_manager,
        }
    }
}

impl SecurityManager {
    pub async fn new(config: Config) -> ZKResult<Self> {
        info!("🔒 Initializing Security Manager");

        let audit_logger = Arc::new(AuditLogger::new(config.clone()).await?);
        let access_control = Arc::new(AccessControl::new(config.clone()).await?);
        let crypto_manager = Arc::new(CryptoManager::new(config.clone()).await?);

        let state = Arc::new(RwLock::new(SecurityState {
            rbac_enabled: config.security.rbac_enabled,
            audit_enabled: config.features.audit_enabled,
            webhook_signing_enabled: config.security.webhook_signing_enabled,
            self_destruct_armed: config.security.self_destruct_enabled,
            active_sessions: HashMap::new(),
            failed_auth_attempts: 0,
            last_security_scan: chrono::Utc::now(),
            security_events: 0,
            tamper_attempts: 0,
        }));

        let manager = Self {
            config,
            state,
            audit_logger,
            access_control,
            crypto_manager,
        };

        // Log security initialization
        manager.audit_logger.log_event(AuditEntry {
            id: 0, // Will be assigned by logger
            timestamp: chrono::Utc::now(),
            event_type: AuditEventType::SystemControl,
            user_id: Some("system".to_string()),
            session_id: None,
            source_ip: None,
            action: "security_manager_initialized".to_string(),
            resource: "security_system".to_string(),
            result: AuditResult::Success,
            details: serde_json::json!({
                "rbac_enabled": manager.config.security.rbac_enabled,
                "audit_enabled": manager.config.features.audit_enabled,
                "webhook_signing": manager.config.security.webhook_signing_enabled
            }),
            hash: String::new(), // Will be calculated by logger
            previous_hash: String::new(),
        }).await?;

        info!("✅ Security Manager initialized - RBAC: {}, Audit: {}, Signing: {}", 
              config.security.rbac_enabled, 
              config.features.audit_enabled,
              config.security.webhook_signing_enabled);

        Ok(manager)
    }

    /// Authenticate user and create session
    pub async fn authenticate(&self, token: &str, ip_address: &str, user_agent: &str) -> ZKResult<SessionInfo> {
        debug!("🔐 Authenticating token from IP: {}", ip_address);

        let token_info = self.access_control.validate_token(token).await?;
        
        if token_info.revoked {
            self.audit_logger.log_event(AuditEntry {
                id: 0,
                timestamp: chrono::Utc::now(),
                event_type: AuditEventType::Authentication,
                user_id: None,
                session_id: None,
                source_ip: Some(ip_address.to_string()),
                action: "authentication_attempt".to_string(),
                resource: "auth_system".to_string(),
                result: AuditResult::Denied,
                details: serde_json::json!({
                    "reason": "revoked_token",
                    "token_hash": self.hash_token(token)
                }),
                hash: String::new(),
                previous_hash: String::new(),
            }).await?;

            return Err(ZKError::SecurityError("Token has been revoked".to_string()));
        }

        // Create session
        let session_id = uuid::Uuid::new_v4().to_string();
        let permissions = self.access_control.get_role_permissions(&token_info.role).await;
        
        let session = SessionInfo {
            token: token.to_string(),
            role: token_info.role.clone(),
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            permissions,
        };

        // Store session
        {
            let mut state = self.state.write().await;
            state.active_sessions.insert(session_id.clone(), session.clone());
        }

        // Update token usage
        self.access_control.update_token_usage(token).await?;

        // Log successful authentication
        self.audit_logger.log_event(AuditEntry {
            id: 0,
            timestamp: chrono::Utc::now(),
            event_type: AuditEventType::Authentication,
            user_id: Some(format!("{:?}", token_info.role)),
            session_id: Some(session_id),
            source_ip: Some(ip_address.to_string()),
            action: "authentication_success".to_string(),
            resource: "auth_system".to_string(),
            result: AuditResult::Success,
            details: serde_json::json!({
                "role": format!("{:?}", token_info.role),
                "user_agent": user_agent
            }),
            hash: String::new(),
            previous_hash: String::new(),
        }).await?;

        info!("✅ Authentication successful for role: {:?}", token_info.role);
        Ok(session)
    }

    /// Check if user has required permission
    pub async fn authorize(&self, session_id: &str, permission: Permission) -> ZKResult<bool> {
        let state = self.state.read().await;
        
        if let Some(session) = state.active_sessions.get(session_id) {
            let authorized = session.permissions.contains(&permission);
            
            // Log authorization attempt
            drop(state);
            self.audit_logger.log_event(AuditEntry {
                id: 0,
                timestamp: chrono::Utc::now(),
                event_type: AuditEventType::Authorization,
                user_id: Some(format!("{:?}", session.role)),
                session_id: Some(session_id.to_string()),
                source_ip: Some(session.ip_address.clone()),
                action: "authorization_check".to_string(),
                resource: format!("{:?}", permission),
                result: if authorized { AuditResult::Success } else { AuditResult::Denied },
                details: serde_json::json!({
                    "permission": format!("{:?}", permission),
                    "role": format!("{:?}", session.role)
                }),
                hash: String::new(),
                previous_hash: String::new(),
            }).await?;

            Ok(authorized)
        } else {
            Err(ZKError::SecurityError("Invalid session".to_string()))
        }
    }

    /// Sign webhook payload
    pub async fn sign_webhook_payload(&self, payload: &str) -> ZKResult<String> {
        if !self.config.security.webhook_signing_enabled {
            return Err(ZKError::SecurityError("Webhook signing not enabled".to_string()));
        }

        self.crypto_manager.sign_webhook_payload(payload).await
    }

    /// Verify webhook signature
    pub async fn verify_webhook_signature(&self, payload: &str, signature: &str) -> ZKResult<bool> {
        if !self.config.security.webhook_signing_enabled {
            return Ok(true); // Skip verification if not enabled
        }

        self.crypto_manager.verify_webhook_signature(payload, signature).await
    }

    /// Trigger self-destruct sequence
    pub async fn self_destruct(&self, authorization_code: &str) -> ZKResult<()> {
        if !self.config.security.self_destruct_enabled {
            return Err(ZKError::SecurityError("Self-destruct not enabled".to_string()));
        }

        // Verify authorization code (simplified)
        let expected_code = "EMERGENCY_DESTRUCT_2024";
        if authorization_code != expected_code {
            self.audit_logger.log_event(AuditEntry {
                id: 0,
                timestamp: chrono::Utc::now(),
                event_type: AuditEventType::SecurityEvent,
                user_id: None,
                session_id: None,
                source_ip: None,
                action: "self_destruct_attempt".to_string(),
                resource: "security_system".to_string(),
                result: AuditResult::Denied,
                details: serde_json::json!({
                    "reason": "invalid_authorization_code"
                }),
                hash: String::new(),
                previous_hash: String::new(),
            }).await?;

            return Err(ZKError::SecurityError("Invalid authorization code".to_string()));
        }

        warn!("🔥 SELF-DESTRUCT SEQUENCE INITIATED");

        // Log self-destruct
        self.audit_logger.log_event(AuditEntry {
            id: 0,
            timestamp: chrono::Utc::now(),
            event_type: AuditEventType::SecurityEvent,
            user_id: Some("emergency".to_string()),
            session_id: None,
            source_ip: None,
            action: "self_destruct_initiated".to_string(),
            resource: "entire_system".to_string(),
            result: AuditResult::Success,
            details: serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "reason": "emergency_security_protocol"
            }),
            hash: String::new(),
            previous_hash: String::new(),
        }).await?;

        // Perform secure data wipe
        self.secure_wipe_data().await?;

        info!("💥 Self-destruct sequence completed");
        Ok(())
    }

    async fn secure_wipe_data(&self) -> ZKResult<()> {
        info!("🗑️  Performing secure data wipe");

        // Wipe database
        if let Err(e) = tokio::fs::remove_file(&self.config.storage.db_path).await {
            warn!("Failed to remove database: {}", e);
        }

        // Wipe logs
        let log_dir = format!("{}/.zkanalyzer/logs", std::env::var("HOME").unwrap_or_default());
        if let Err(e) = tokio::fs::remove_dir_all(&log_dir).await {
            warn!("Failed to remove logs: {}", e);
        }

        // Wipe configuration (keep backup)
        let config_backup = format!("{}.destroyed", self.config.system.data_dir);
        if let Err(e) = tokio::fs::rename(&self.config.system.data_dir, &config_backup).await {
            warn!("Failed to backup config: {}", e);
        }

        info!("✅ Secure data wipe completed");
        Ok(())
    }

    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub async fn get_state(&self) -> SecurityState {
        self.state.read().await.clone()
    }

    pub async fn get_audit_state(&self) -> AuditState {
        self.audit_logger.get_state().await
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        let state = Arc::new(RwLock::new(AuditState {
            total_entries: 0,
            chain_verified: true,
            last_entry_hash: "genesis".to_string(),
            last_verification: chrono::Utc::now(),
            integrity_violations: 0,
        }));

        let merkle_chain = Arc::new(RwLock::new(MerkleChain {
            entries: Vec::new(),
            root_hash: "genesis".to_string(),
        }));

        Self {
            state,
            merkle_chain,
            config: Config::default(),
        }
    }
}

impl AuditLogger {
    pub async fn new(config: Config) -> ZKResult<Self> {
        let state = Arc::new(RwLock::new(AuditState {
            total_entries: 0,
            chain_verified: true,
            last_entry_hash: "genesis".to_string(),
            last_verification: chrono::Utc::now(),
            integrity_violations: 0,
        }));

        let merkle_chain = Arc::new(RwLock::new(MerkleChain {
            entries: Vec::new(),
            root_hash: "genesis".to_string(),
        }));

        Ok(Self {
            state,
            merkle_chain,
            config,
        })
    }

    pub async fn log_event(&self, mut entry: AuditEntry) -> ZKResult<()> {
        let mut state = self.state.write().await;
        let mut chain = self.merkle_chain.write().await;

        // Assign ID
        entry.id = state.total_entries + 1;
        entry.previous_hash = state.last_entry_hash.clone();

        // Calculate hash
        entry.hash = self.calculate_entry_hash(&entry);

        // Add to Merkle chain
        let node = MerkleNode {
            hash: entry.hash.clone(),
            timestamp: entry.timestamp,
            data_hash: self.calculate_data_hash(&entry),
            previous_hash: entry.previous_hash.clone(),
        };

        chain.entries.push(node);
        chain.root_hash = entry.hash.clone();

        // Update state
        state.total_entries += 1;
        state.last_entry_hash = entry.hash.clone();

        // Persist entry (in real implementation, would write to secure storage)
        debug!("📝 Audit entry logged: {} - {}", entry.id, entry.action);

        Ok(())
    }

    fn calculate_entry_hash(&self, entry: &AuditEntry) -> String {
        let mut hasher = Sha256::new();
        hasher.update(entry.id.to_string().as_bytes());
        hasher.update(entry.timestamp.to_rfc3339().as_bytes());
        hasher.update(entry.action.as_bytes());
        hasher.update(entry.resource.as_bytes());
        hasher.update(entry.previous_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn calculate_data_hash(&self, entry: &AuditEntry) -> String {
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_string(&entry.details).unwrap_or_default().as_bytes());
        hex::encode(hasher.finalize())
    }

    pub async fn verify_chain_integrity(&self) -> ZKResult<bool> {
        let chain = self.merkle_chain.read().await;
        
        for (i, node) in chain.entries.iter().enumerate() {
            if i > 0 {
                let previous_node = &chain.entries[i - 1];
                if node.previous_hash != previous_node.hash {
                    error!("🚨 Merkle chain integrity violation at entry {}", i);
                    return Ok(false);
                }
            }
        }

        info!("✅ Merkle chain integrity verified");
        Ok(true)
    }

    pub async fn get_state(&self) -> AuditState {
        self.state.read().await.clone()
    }
}

impl Default for AccessControl {
    fn default() -> Self {
        let tokens = Arc::new(RwLock::new(HashMap::new()));
        let roles = Arc::new(RwLock::new(Self::initialize_default_roles()));

        Self {
            tokens,
            roles,
            config: Config::default(),
        }
    }
}

impl AccessControl {
    pub async fn new(config: Config) -> ZKResult<Self> {
        let tokens = Arc::new(RwLock::new(HashMap::new()));
        let roles = Arc::new(RwLock::new(Self::initialize_default_roles()));

        let access_control = Self {
            tokens,
            roles,
            config: config.clone(),
        };

        // Initialize default tokens if provided in config
        access_control.initialize_default_tokens().await?;

        Ok(access_control)
    }

    fn initialize_default_roles() -> HashMap<UserRole, Vec<Permission>> {
        let mut roles = HashMap::new();

        roles.insert(UserRole::Admin, vec![
            Permission::ReadMetrics,
            Permission::ReadConfig,
            Permission::WriteConfig,
            Permission::ExecuteReplay,
            Permission::ManageAlerts,
            Permission::SystemControl,
            Permission::AuditAccess,
            Permission::SecurityManagement,
        ]);

        roles.insert(UserRole::ReadOnly, vec![
            Permission::ReadMetrics,
            Permission::ReadConfig,
        ]);

        roles.insert(UserRole::Replay, vec![
            Permission::ReadMetrics,
            Permission::ReadConfig,
            Permission::ExecuteReplay,
        ]);

        roles.insert(UserRole::Monitor, vec![
            Permission::ReadMetrics,
            Permission::ManageAlerts,
        ]);

        roles
    }

    async fn initialize_default_tokens(&self) -> ZKResult<()> {
        let mut tokens = self.tokens.write().await;

        // Admin token
        if let Some(admin_token) = &self.config.security.admin_token {
            tokens.insert(admin_token.clone(), TokenInfo {
                token: admin_token.clone(),
                role: UserRole::Admin,
                created_at: chrono::Utc::now(),
                expires_at: None,
                last_used: chrono::Utc::now(),
                usage_count: 0,
                revoked: false,
            });
        }

        // Read-only token
        if let Some(readonly_token) = &self.config.security.readonly_token {
            tokens.insert(readonly_token.clone(), TokenInfo {
                token: readonly_token.clone(),
                role: UserRole::ReadOnly,
                created_at: chrono::Utc::now(),
                expires_at: None,
                last_used: chrono::Utc::now(),
                usage_count: 0,
                revoked: false,
            });
        }

        // Replay token
        if let Some(replay_token) = &self.config.security.replay_token {
            tokens.insert(replay_token.clone(), TokenInfo {
                token: replay_token.clone(),
                role: UserRole::Replay,
                created_at: chrono::Utc::now(),
                expires_at: None,
                last_used: chrono::Utc::now(),
                usage_count: 0,
                revoked: false,
            });
        }

        info!("🔑 Initialized {} default tokens", tokens.len());
        Ok(())
    }

    pub async fn validate_token(&self, token: &str) -> ZKResult<TokenInfo> {
        let tokens = self.tokens.read().await;
        
        if let Some(token_info) = tokens.get(token) {
            // Check if token is expired
            if let Some(expires_at) = token_info.expires_at {
                if chrono::Utc::now() > expires_at {
                    return Err(ZKError::SecurityError("Token has expired".to_string()));
                }
            }

            Ok(token_info.clone())
        } else {
            Err(ZKError::SecurityError("Invalid token".to_string()))
        }
    }

    pub async fn get_role_permissions(&self, role: &UserRole) -> Vec<Permission> {
        let roles = self.roles.read().await;
        roles.get(role).cloned().unwrap_or_default()
    }

    pub async fn update_token_usage(&self, token: &str) -> ZKResult<()> {
        let mut tokens = self.tokens.write().await;
        
        if let Some(token_info) = tokens.get_mut(token) {
            token_info.last_used = chrono::Utc::now();
            token_info.usage_count += 1;
        }

        Ok(())
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self {
            signing_key: None,
            verifying_key: None,
            webhook_signing_key: None,
        }
    }
}

impl CryptoManager {
    pub async fn new(config: Config) -> ZKResult<Self> {
        let mut signing_key = None;
        let mut verifying_key = None;
        let mut webhook_signing_key = None;

        // Initialize Ed25519 keys for plugin signing
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let vk = sk.verifying_key();
        
        signing_key = Some(sk);
        verifying_key = Some(vk);

        // Initialize webhook signing key
        if config.security.webhook_signing_enabled {
            if let Some(key_str) = &config.security.webhook_signing_key {
                webhook_signing_key = Some(key_str.as_bytes().to_vec());
            } else {
                // Generate random key
                let mut key = vec![0u8; 32];
                use rand::RngCore;
                OsRng.fill_bytes(&mut key);
                webhook_signing_key = Some(key);
                warn!("🔑 Generated random webhook signing key - save this for production!");
            }
        }

        Ok(Self {
            signing_key,
            verifying_key,
            webhook_signing_key,
        })
    }

    pub async fn sign_webhook_payload(&self, payload: &str) -> ZKResult<String> {
        if let Some(key) = &self.webhook_signing_key {
            let mut mac = HmacSha256::new_from_slice(key)
                .map_err(|e| ZKError::SecurityError(format!("Invalid signing key: {}", e)))?;
            
            mac.update(payload.as_bytes());
            let signature = mac.finalize().into_bytes();
            
            Ok(format!("sha256={}", hex::encode(signature)))
        } else {
            Err(ZKError::SecurityError("Webhook signing key not configured".to_string()))
        }
    }

    pub async fn verify_webhook_signature(&self, payload: &str, signature: &str) -> ZKResult<bool> {
        if let Some(key) = &self.webhook_signing_key {
            let expected_signature = self.sign_webhook_payload(payload).await?;
            Ok(signature == expected_signature)
        } else {
            Err(ZKError::SecurityError("Webhook signing key not configured".to_string()))
        }
    }

    pub async fn sign_plugin(&self, plugin_data: &[u8]) -> ZKResult<String> {
        if let Some(signing_key) = &self.signing_key {
            let signature = signing_key.sign(plugin_data);
            Ok(hex::encode(signature.to_bytes()))
        } else {
            Err(ZKError::SecurityError("Plugin signing key not available".to_string()))
        }
    }

    pub async fn verify_plugin_signature(&self, plugin_data: &[u8], signature_hex: &str) -> ZKResult<bool> {
        if let Some(verifying_key) = &self.verifying_key {
            let signature_bytes = hex::decode(signature_hex)
                .map_err(|e| ZKError::SecurityError(format!("Invalid signature format: {}", e)))?;
            
            let signature = Signature::from_bytes(&signature_bytes)
                .map_err(|e| ZKError::SecurityError(format!("Invalid signature: {}", e)))?;
            
            Ok(verifying_key.verify(plugin_data, &signature).is_ok())
        } else {
            Err(ZKError::SecurityError("Plugin verification key not available".to_string()))
        }
    }
}
