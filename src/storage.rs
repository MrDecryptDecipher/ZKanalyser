use anyhow::Result;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Pool, Row, Sqlite,
};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use zstd::stream::{encode_all, decode_all};

use crate::config::Config;
use crate::error::{ZKError, ZKResult};
use crate::risk_engine::TransactionRiskAssessment;

/// Advanced SQLite storage system with WAL mode, encryption, and compression
pub struct StorageEngine {
    pool: Pool<Sqlite>,
    config: Config,
    encryption_key: Option<Aes256Gcm>,
    state: Arc<RwLock<StorageState>>,
    compression_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct StorageState {
    pub database_size_mb: f64,
    pub total_records: u64,
    pub transactions_stored: u64,
    pub slots_stored: u64,
    pub risk_assessments_stored: u64,
    pub alerts_stored: u64,
    pub last_vacuum: chrono::DateTime<chrono::Utc>,
    pub last_rotation: chrono::DateTime<chrono::Utc>,
    pub encryption_enabled: bool,
    pub compression_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTransaction {
    pub id: i64,
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub compute_units_consumed: Option<u64>,
    pub fee: u64,
    pub status: String,
    pub accounts: String, // JSON array
    pub log_messages: String, // JSON array
    pub risk_score: Option<f64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub data_compressed: bool,
    pub data_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSlot {
    pub id: i64,
    pub slot: u64,
    pub parent_slot: Option<u64>,
    pub block_hash: String,
    pub previous_block_hash: String,
    pub transaction_count: u32,
    pub successful_transactions: u32,
    pub failed_transactions: u32,
    pub total_compute_units: u64,
    pub block_time: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRiskAssessment {
    pub id: i64,
    pub transaction_signature: String,
    pub slot: u64,
    pub overall_risk_score: f64,
    pub risk_factors: String, // JSON
    pub cpi_analysis: String, // JSON
    pub anchor_analysis: String, // JSON
    pub compute_analysis: String, // JSON
    pub signer_analysis: String, // JSON
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub data_compressed: bool,
    pub data_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAlert {
    pub id: i64,
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub data: String, // JSON
    pub delivered: bool,
    pub delivery_attempts: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub delivered_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl StorageEngine {
    pub async fn new(config: Config) -> ZKResult<Self> {
        info!("💾 Initializing SQLite storage engine with WAL mode");

        // Ensure database directory exists
        if let Some(parent) = Path::new(&config.storage.db_path).parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| ZKError::StorageError(format!("Failed to create database directory: {}", e)))?;
        }

        // Configure SQLite with WAL mode and performance optimizations
        let connect_options = SqliteConnectOptions::new()
            .filename(&config.storage.db_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal) // WAL mode for better concurrency
            .synchronous(SqliteSynchronous::Normal) // Balance between safety and performance
            .pragma("cache_size", "-64000") // 64MB cache
            .pragma("temp_store", "memory") // Store temp tables in memory
            .pragma("mmap_size", "268435456") // 256MB memory-mapped I/O
            .pragma("optimize", "0x10002"); // Enable query planner optimizations

        // Create connection pool
        let pool = SqlitePoolOptions::new()
            .max_connections(10) // Limit connections for resource management
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect_with(connect_options)
            .await
            .map_err(|e| ZKError::StorageError(format!("Failed to create database pool: {}", e)))?;

        // Initialize encryption if enabled
        let encryption_key = if config.storage.encryption_enabled {
            if let Some(key_str) = &config.storage.encryption_key {
                let key_bytes = base64::decode(key_str)
                    .map_err(|e| ZKError::EncryptionError(format!("Invalid encryption key: {}", e)))?;
                
                if key_bytes.len() != 32 {
                    return Err(ZKError::EncryptionError("Encryption key must be 32 bytes".to_string()));
                }
                
                let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
                Some(Aes256Gcm::new(key))
            } else {
                // Generate new key
                let mut key_bytes = [0u8; 32];
                OsRng.fill_bytes(&mut key_bytes);
                let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
                let cipher = Aes256Gcm::new(key);
                
                let key_b64 = base64::encode(&key_bytes);
                warn!("🔑 Generated new encryption key: {}", key_b64);
                warn!("⚠️  Save this key securely! Data will be unrecoverable without it.");
                
                Some(cipher)
            }
        } else {
            None
        };

        let state = Arc::new(RwLock::new(StorageState {
            database_size_mb: 0.0,
            total_records: 0,
            transactions_stored: 0,
            slots_stored: 0,
            risk_assessments_stored: 0,
            alerts_stored: 0,
            last_vacuum: chrono::Utc::now(),
            last_rotation: chrono::Utc::now(),
            encryption_enabled: config.storage.encryption_enabled,
            compression_ratio: 1.0,
        }));

        let storage = Self {
            pool,
            config: config.clone(),
            encryption_key,
            state,
            compression_enabled: config.storage.compression_enabled,
        };

        // Initialize database schema
        storage.initialize_schema().await?;
        
        // Update initial state
        storage.update_storage_stats().await?;

        info!("✅ SQLite storage engine initialized - Encryption: {}, Compression: {}", 
              storage.encryption_key.is_some(), storage.compression_enabled);

        Ok(storage)
    }

    async fn initialize_schema(&self) -> ZKResult<()> {
        info!("🗄️  Initializing database schema");

        // Create transactions table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature TEXT UNIQUE NOT NULL,
                slot INTEGER NOT NULL,
                block_time INTEGER,
                compute_units_consumed INTEGER,
                fee INTEGER NOT NULL,
                status TEXT NOT NULL,
                accounts TEXT NOT NULL,
                log_messages TEXT NOT NULL,
                risk_score REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                data_compressed BOOLEAN DEFAULT FALSE,
                data_encrypted BOOLEAN DEFAULT FALSE
            )
        "#).execute(&self.pool).await
            .map_err(|e| ZKError::DatabaseError(format!("Failed to create transactions table: {}", e)))?;

        // Create slots table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS slots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slot INTEGER UNIQUE NOT NULL,
                parent_slot INTEGER,
                block_hash TEXT NOT NULL,
                previous_block_hash TEXT NOT NULL,
                transaction_count INTEGER NOT NULL,
                successful_transactions INTEGER NOT NULL,
                failed_transactions INTEGER NOT NULL,
                total_compute_units INTEGER NOT NULL,
                block_time INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        "#).execute(&self.pool).await
            .map_err(|e| ZKError::DatabaseError(format!("Failed to create slots table: {}", e)))?;

        // Create risk_assessments table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS risk_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_signature TEXT NOT NULL,
                slot INTEGER NOT NULL,
                overall_risk_score REAL NOT NULL,
                risk_factors TEXT NOT NULL,
                cpi_analysis TEXT NOT NULL,
                anchor_analysis TEXT NOT NULL,
                compute_analysis TEXT NOT NULL,
                signer_analysis TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                data_compressed BOOLEAN DEFAULT FALSE,
                data_encrypted BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (transaction_signature) REFERENCES transactions(signature)
            )
        "#).execute(&self.pool).await
            .map_err(|e| ZKError::DatabaseError(format!("Failed to create risk_assessments table: {}", e)))?;

        // Create alerts table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                data TEXT NOT NULL,
                delivered BOOLEAN DEFAULT FALSE,
                delivery_attempts INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                delivered_at DATETIME
            )
        "#).execute(&self.pool).await
            .map_err(|e| ZKError::DatabaseError(format!("Failed to create alerts table: {}", e)))?;

        // Create indexes for performance
        let indexes = vec![
            "CREATE INDEX IF NOT EXISTS idx_transactions_slot ON transactions(slot)",
            "CREATE INDEX IF NOT EXISTS idx_transactions_signature ON transactions(signature)",
            "CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_slots_slot ON slots(slot)",
            "CREATE INDEX IF NOT EXISTS idx_slots_created_at ON slots(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_risk_assessments_signature ON risk_assessments(transaction_signature)",
            "CREATE INDEX IF NOT EXISTS idx_risk_assessments_slot ON risk_assessments(slot)",
            "CREATE INDEX IF NOT EXISTS idx_risk_assessments_score ON risk_assessments(overall_risk_score)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_delivered ON alerts(delivered)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)",
        ];

        for index_sql in indexes {
            sqlx::query(index_sql).execute(&self.pool).await
                .map_err(|e| ZKError::DatabaseError(format!("Failed to create index: {}", e)))?;
        }

        info!("✅ Database schema initialized with indexes");
        Ok(())
    }

    /// Store transaction with compression and encryption
    pub async fn store_transaction(&self, transaction: &crate::solana_client::TransactionInfo) -> ZKResult<i64> {
        let accounts_json = serde_json::to_string(&transaction.accounts)
            .map_err(|e| ZKError::SerializationError(format!("Failed to serialize accounts: {}", e)))?;
        
        let log_messages_json = serde_json::to_string(&transaction.log_messages)
            .map_err(|e| ZKError::SerializationError(format!("Failed to serialize log messages: {}", e)))?;

        // Compress data if enabled
        let (accounts_data, log_messages_data, compressed) = if self.compression_enabled {
            let compressed_accounts = encode_all(accounts_json.as_bytes(), 3)
                .map_err(|e| ZKError::CompressionError(format!("Failed to compress accounts: {}", e)))?;
            let compressed_logs = encode_all(log_messages_json.as_bytes(), 3)
                .map_err(|e| ZKError::CompressionError(format!("Failed to compress logs: {}", e)))?;
            (compressed_accounts, compressed_logs, true)
        } else {
            (accounts_json.into_bytes(), log_messages_json.into_bytes(), false)
        };

        // Encrypt data if enabled
        let (final_accounts, final_logs, encrypted) = if let Some(cipher) = &self.encryption_key {
            let accounts_encrypted = self.encrypt_data(cipher, &accounts_data)?;
            let logs_encrypted = self.encrypt_data(cipher, &log_messages_data)?;
            (accounts_encrypted, logs_encrypted, true)
        } else {
            (accounts_data, log_messages_data, false)
        };

        let status_str = match &transaction.status {
            crate::geyser_client::TransactionStatus::Success => "success",
            crate::geyser_client::TransactionStatus::Failed(_) => "failed",
        };

        let result = sqlx::query(r#"
            INSERT INTO transactions (
                signature, slot, compute_units_consumed, fee, status, 
                accounts, log_messages, data_compressed, data_encrypted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(&transaction.signature)
        .bind(0i64) // slot would come from context
        .bind(transaction.compute_units_consumed.map(|c| c as i64))
        .bind(transaction.fee as i64)
        .bind(status_str)
        .bind(base64::encode(&final_accounts))
        .bind(base64::encode(&final_logs))
        .bind(compressed)
        .bind(encrypted)
        .execute(&self.pool)
        .await
        .map_err(|e| ZKError::DatabaseError(format!("Failed to store transaction: {}", e)))?;

        // Update state
        {
            let mut state = self.state.write().await;
            state.transactions_stored += 1;
            state.total_records += 1;
        }

        debug!("💾 Stored transaction: {} (compressed: {}, encrypted: {})", 
               transaction.signature, compressed, encrypted);

        Ok(result.last_insert_rowid())
    }

    /// Store risk assessment with compression and encryption
    pub async fn store_risk_assessment(&self, assessment: &TransactionRiskAssessment) -> ZKResult<i64> {
        let risk_factors_json = serde_json::to_string(&assessment.risk_factors)
            .map_err(|e| ZKError::SerializationError(format!("Failed to serialize risk factors: {}", e)))?;
        
        let cpi_analysis_json = serde_json::to_string(&assessment.cpi_analysis)
            .map_err(|e| ZKError::SerializationError(format!("Failed to serialize CPI analysis: {}", e)))?;
        
        let anchor_analysis_json = serde_json::to_string(&assessment.anchor_analysis)
            .map_err(|e| ZKError::SerializationError(format!("Failed to serialize Anchor analysis: {}", e)))?;
        
        let compute_analysis_json = serde_json::to_string(&assessment.compute_analysis)
            .map_err(|e| ZKError::SerializationError(format!("Failed to serialize compute analysis: {}", e)))?;
        
        let signer_analysis_json = serde_json::to_string(&assessment.signer_analysis)
            .map_err(|e| ZKError::SerializationError(format!("Failed to serialize signer analysis: {}", e)))?;

        // Compress and encrypt if enabled
        let (risk_factors_data, compressed) = self.process_data_for_storage(&risk_factors_json)?;
        let (cpi_analysis_data, _) = self.process_data_for_storage(&cpi_analysis_json)?;
        let (anchor_analysis_data, _) = self.process_data_for_storage(&anchor_analysis_json)?;
        let (compute_analysis_data, _) = self.process_data_for_storage(&compute_analysis_json)?;
        let (signer_analysis_data, _) = self.process_data_for_storage(&signer_analysis_json)?;

        let encrypted = self.encryption_key.is_some();

        let result = sqlx::query(r#"
            INSERT INTO risk_assessments (
                transaction_signature, slot, overall_risk_score,
                risk_factors, cpi_analysis, anchor_analysis, 
                compute_analysis, signer_analysis,
                data_compressed, data_encrypted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(&assessment.signature)
        .bind(assessment.slot as i64)
        .bind(assessment.overall_risk_score)
        .bind(base64::encode(&risk_factors_data))
        .bind(base64::encode(&cpi_analysis_data))
        .bind(base64::encode(&anchor_analysis_data))
        .bind(base64::encode(&compute_analysis_data))
        .bind(base64::encode(&signer_analysis_data))
        .bind(compressed)
        .bind(encrypted)
        .execute(&self.pool)
        .await
        .map_err(|e| ZKError::DatabaseError(format!("Failed to store risk assessment: {}", e)))?;

        // Update state
        {
            let mut state = self.state.write().await;
            state.risk_assessments_stored += 1;
            state.total_records += 1;
        }

        debug!("🛡️  Stored risk assessment for transaction: {} (score: {:.2})", 
               assessment.signature, assessment.overall_risk_score);

        Ok(result.last_insert_rowid())
    }

    fn process_data_for_storage(&self, data: &str) -> ZKResult<(Vec<u8>, bool)> {
        let mut processed_data = data.as_bytes().to_vec();
        let mut compressed = false;

        // Compress if enabled
        if self.compression_enabled {
            processed_data = encode_all(&processed_data, 3)
                .map_err(|e| ZKError::CompressionError(format!("Failed to compress data: {}", e)))?;
            compressed = true;
        }

        // Encrypt if enabled
        if let Some(cipher) = &self.encryption_key {
            processed_data = self.encrypt_data(cipher, &processed_data)?;
        }

        Ok((processed_data, compressed))
    }

    fn encrypt_data(&self, cipher: &Aes256Gcm, data: &[u8]) -> ZKResult<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| ZKError::EncryptionError(format!("Failed to encrypt data: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt_data(&self, cipher: &Aes256Gcm, data: &[u8]) -> ZKResult<Vec<u8>> {
        if data.len() < 12 {
            return Err(ZKError::EncryptionError("Invalid encrypted data length".to_string()));
        }

        let nonce = Nonce::from_slice(&data[0..12]);
        let ciphertext = &data[12..];

        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| ZKError::EncryptionError(format!("Failed to decrypt data: {}", e)))
    }

    /// Perform database maintenance (vacuum, rotation)
    pub async fn perform_maintenance(&self) -> ZKResult<()> {
        info!("🧹 Performing database maintenance");

        // Check if vacuum is needed
        let should_vacuum = {
            let state = self.state.read().await;
            let hours_since_vacuum = chrono::Utc::now()
                .signed_duration_since(state.last_vacuum)
                .num_hours();
            hours_since_vacuum >= self.config.storage.vacuum_interval_hours as i64
        };

        if should_vacuum {
            self.vacuum_database().await?;
        }

        // Check database size and rotate if needed
        self.check_and_rotate_if_needed().await?;

        // Update storage statistics
        self.update_storage_stats().await?;

        info!("✅ Database maintenance completed");
        Ok(())
    }

    async fn vacuum_database(&self) -> ZKResult<()> {
        info!("🗜️  Running database VACUUM");

        sqlx::query("VACUUM").execute(&self.pool).await
            .map_err(|e| ZKError::DatabaseError(format!("Failed to vacuum database: {}", e)))?;

        // Update last vacuum time
        {
            let mut state = self.state.write().await;
            state.last_vacuum = chrono::Utc::now();
        }

        info!("✅ Database VACUUM completed");
        Ok(())
    }

    async fn check_and_rotate_if_needed(&self) -> ZKResult<()> {
        let current_size_mb = self.get_database_size_mb().await?;
        let max_size_mb = self.config.storage.max_db_size_mb as f64;

        if current_size_mb > max_size_mb {
            warn!("⚠️  Database size ({:.1}MB) exceeds limit ({:.1}MB), starting rotation", 
                  current_size_mb, max_size_mb);
            self.rotate_old_data().await?;
        }

        Ok(())
    }

    async fn rotate_old_data(&self) -> ZKResult<()> {
        info!("🔄 Rotating old data to maintain size limits");

        // Delete oldest 25% of records to free up space
        let delete_queries = vec![
            "DELETE FROM transactions WHERE id IN (SELECT id FROM transactions ORDER BY created_at LIMIT (SELECT COUNT(*) / 4 FROM transactions))",
            "DELETE FROM risk_assessments WHERE id IN (SELECT id FROM risk_assessments ORDER BY created_at LIMIT (SELECT COUNT(*) / 4 FROM risk_assessments))",
            "DELETE FROM alerts WHERE delivered = 1 AND id IN (SELECT id FROM alerts WHERE delivered = 1 ORDER BY created_at LIMIT (SELECT COUNT(*) / 4 FROM alerts WHERE delivered = 1))",
        ];

        for query in delete_queries {
            let result = sqlx::query(query).execute(&self.pool).await
                .map_err(|e| ZKError::DatabaseError(format!("Failed to rotate data: {}", e)))?;
            debug!("🗑️  Deleted {} old records", result.rows_affected());
        }

        // Update rotation time
        {
            let mut state = self.state.write().await;
            state.last_rotation = chrono::Utc::now();
        }

        info!("✅ Data rotation completed");
        Ok(())
    }

    async fn update_storage_stats(&self) -> ZKResult<()> {
        let size_mb = self.get_database_size_mb().await?;
        
        let counts: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT 
                (SELECT COUNT(*) FROM transactions) as tx_count,
                (SELECT COUNT(*) FROM slots) as slot_count,
                (SELECT COUNT(*) FROM risk_assessments) as risk_count,
                (SELECT COUNT(*) FROM alerts) as alert_count"
        ).fetch_one(&self.pool).await
            .map_err(|e| ZKError::DatabaseError(format!("Failed to get record counts: {}", e)))?;

        let mut state = self.state.write().await;
        state.database_size_mb = size_mb;
        state.transactions_stored = counts.0 as u64;
        state.slots_stored = counts.1 as u64;
        state.risk_assessments_stored = counts.2 as u64;
        state.alerts_stored = counts.3 as u64;
        state.total_records = state.transactions_stored + state.slots_stored + state.risk_assessments_stored + state.alerts_stored;

        Ok(())
    }

    async fn get_database_size_mb(&self) -> ZKResult<f64> {
        let metadata = tokio::fs::metadata(&self.config.storage.db_path).await
            .map_err(|e| ZKError::StorageError(format!("Failed to get database file size: {}", e)))?;
        
        Ok(metadata.len() as f64 / (1024.0 * 1024.0))
    }

    pub async fn get_state(&self) -> StorageState {
        self.state.read().await.clone()
    }

    /// Get recent high-risk transactions
    pub async fn get_high_risk_transactions(&self, limit: i32) -> ZKResult<Vec<StoredRiskAssessment>> {
        let rows = sqlx::query_as::<_, (i64, String, i64, f64, String, String, String, String, String, chrono::DateTime<chrono::Utc>, bool, bool)>(
            "SELECT id, transaction_signature, slot, overall_risk_score, 
                    risk_factors, cpi_analysis, anchor_analysis, compute_analysis, signer_analysis,
                    created_at, data_compressed, data_encrypted
             FROM risk_assessments 
             WHERE overall_risk_score > 0.7 
             ORDER BY created_at DESC 
             LIMIT ?"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ZKError::DatabaseError(format!("Failed to fetch high-risk transactions: {}", e)))?;

        let mut assessments = Vec::new();
        for row in rows {
            assessments.push(StoredRiskAssessment {
                id: row.0,
                transaction_signature: row.1,
                slot: row.2 as u64,
                overall_risk_score: row.3,
                risk_factors: row.4,
                cpi_analysis: row.5,
                anchor_analysis: row.6,
                compute_analysis: row.7,
                signer_analysis: row.8,
                created_at: row.9,
                data_compressed: row.10,
                data_encrypted: row.11,
            });
        }

        Ok(assessments)
    }
}
