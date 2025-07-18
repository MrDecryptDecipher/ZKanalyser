use anyhow::Result;
use solana_client::{
    nonblocking::rpc_client::RpcClient,
    rpc_config::{RpcTransactionConfig, RpcBlockConfig, RpcAccountInfoConfig},
    rpc_request::RpcRequest,
    rpc_response::{Response, RpcConfirmedTransactionStatusWithSignature},
};
use solana_sdk::{
    clock::Slot,
    commitment_config::{CommitmentConfig, CommitmentLevel},
    pubkey::Pubkey,
    signature::Signature,
};
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, TransactionDetails, UiTransactionEncoding,
};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::error::{ZKError, ZKResult};
use crate::metrics::MetricsCollector;
use crate::risk_engine::{RiskDetectionEngine, TransactionRiskAssessment};

/// Enhanced Solana RPC client for real-time data fetching and analysis
pub struct SolanaClient {
    rpc_client: RpcClient,
    config: Config,
    metrics: Arc<MetricsCollector>,
    risk_engine: Arc<RiskDetectionEngine>,
    state: Arc<RwLock<SolanaClientState>>,
    commitment: CommitmentConfig,
}

#[derive(Debug, Clone)]
pub struct SolanaClientState {
    pub connected: bool,
    pub current_slot: Slot,
    pub latest_blockhash: String,
    pub epoch_info: Option<EpochInfo>,
    pub validator_info: Option<ValidatorInfo>,
    pub performance_stats: PerformanceStats,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EpochInfo {
    pub epoch: u64,
    pub slot_index: u64,
    pub slots_in_epoch: u64,
    pub absolute_slot: Slot,
    pub block_height: u64,
    pub transaction_count: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    pub identity: String,
    pub vote_account: String,
    pub commission: u8,
    pub last_vote: Slot,
    pub root_slot: Slot,
    pub credits: u64,
    pub activated_stake: u64,
}

#[derive(Debug, Clone)]
pub struct PerformanceStats {
    pub avg_slot_time_ms: f64,
    pub tps: f64,
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub compute_units_per_second: f64,
}

#[derive(Debug, Clone)]
pub struct SlotInfo {
    pub slot: Slot,
    pub parent: Option<Slot>,
    pub root: Slot,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub transaction_count: u32,
    pub successful_transactions: u32,
    pub failed_transactions: u32,
    pub total_compute_units: u64,
    pub block_hash: String,
    pub previous_block_hash: String,
}

#[derive(Debug, Clone)]
pub struct TransactionBatch {
    pub slot: Slot,
    pub transactions: Vec<EncodedConfirmedTransactionWithStatusMeta>,
    pub risk_assessments: Vec<TransactionRiskAssessment>,
    pub batch_stats: BatchStats,
}

#[derive(Debug, Clone)]
pub struct BatchStats {
    pub total_transactions: u32,
    pub successful_transactions: u32,
    pub failed_transactions: u32,
    pub vote_transactions: u32,
    pub high_risk_transactions: u32,
    pub total_compute_units: u64,
    pub total_fees: u64,
    pub processing_time_ms: u64,
}

impl SolanaClient {
    pub async fn new(
        config: Config,
        metrics: Arc<MetricsCollector>,
        risk_engine: Arc<RiskDetectionEngine>,
    ) -> ZKResult<Self> {
        info!("🔗 Initializing Solana RPC client for: {}", config.solana.rpc_url);

        let rpc_client = RpcClient::new(config.solana.rpc_url.clone());
        
        let commitment = match config.solana.commitment.as_str() {
            "finalized" => CommitmentConfig::finalized(),
            "confirmed" => CommitmentConfig::confirmed(),
            "processed" => CommitmentConfig::processed(),
            _ => CommitmentConfig::confirmed(),
        };

        let state = Arc::new(RwLock::new(SolanaClientState {
            connected: false,
            current_slot: 0,
            latest_blockhash: String::new(),
            epoch_info: None,
            validator_info: None,
            performance_stats: PerformanceStats {
                avg_slot_time_ms: 0.0,
                tps: 0.0,
                total_transactions: 0,
                successful_transactions: 0,
                failed_transactions: 0,
                compute_units_per_second: 0.0,
            },
            last_error: None,
        }));

        Ok(Self {
            rpc_client,
            config,
            metrics,
            risk_engine,
            state,
            commitment,
        })
    }

    /// Establish connection and validate RPC endpoint
    pub async fn connect(&self) -> ZKResult<()> {
        info!("🔌 Connecting to Solana RPC endpoint");

        if self.config.system.dry_run {
            info!("🧪 Dry-run mode: Simulating Solana connection");
            let mut state = self.state.write().await;
            state.connected = true;
            state.current_slot = 100_000_000;
            state.latest_blockhash = "DryRunBlockhash1111111111111111111111111111".to_string();
            return Ok(());
        }

        // Test connection with health check
        match self.rpc_client.get_health().await {
            Ok(_) => {
                info!("✅ Solana RPC health check passed");
            }
            Err(e) => {
                error!("❌ Solana RPC health check failed: {}", e);
                return Err(ZKError::SolanaError(format!("Health check failed: {}", e)));
            }
        }

        // Get current slot
        let current_slot = self.rpc_client.get_slot_with_commitment(self.commitment).await
            .map_err(|e| ZKError::SolanaError(format!("Failed to get current slot: {}", e)))?;

        // Get latest blockhash
        let latest_blockhash = self.rpc_client.get_latest_blockhash_with_commitment(self.commitment).await
            .map_err(|e| ZKError::SolanaError(format!("Failed to get latest blockhash: {}", e)))?;

        // Get epoch info
        let epoch_info = self.rpc_client.get_epoch_info_with_commitment(self.commitment).await
            .map_err(|e| ZKError::SolanaError(format!("Failed to get epoch info: {}", e)))?;

        // Update state
        {
            let mut state = self.state.write().await;
            state.connected = true;
            state.current_slot = current_slot;
            state.latest_blockhash = latest_blockhash.value.blockhash.to_string();
            state.epoch_info = Some(EpochInfo {
                epoch: epoch_info.epoch,
                slot_index: epoch_info.slot_index,
                slots_in_epoch: epoch_info.slots_in_epoch,
                absolute_slot: epoch_info.absolute_slot,
                block_height: epoch_info.block_height,
                transaction_count: epoch_info.transaction_count,
            });
        }

        info!("✅ Connected to Solana network - Slot: {}, Epoch: {}", 
              current_slot, epoch_info.epoch);

        Ok(())
    }

    /// Fetch and analyze a specific slot with all transactions
    pub async fn analyze_slot(&self, slot: Slot) -> ZKResult<SlotInfo> {
        let start_time = std::time::Instant::now();
        debug!("🔍 Analyzing slot: {}", slot);

        // Get block with full transaction details
        let block = self.rpc_client.get_block_with_config(
            slot,
            RpcBlockConfig {
                encoding: Some(UiTransactionEncoding::JsonParsed),
                transaction_details: Some(TransactionDetails::Full),
                rewards: Some(true),
                commitment: Some(self.commitment),
                max_supported_transaction_version: Some(0),
            },
        ).await.map_err(|e| ZKError::SolanaError(format!("Failed to get block {}: {}", slot, e)))?;

        let mut successful_transactions = 0u32;
        let mut failed_transactions = 0u32;
        let mut total_compute_units = 0u64;

        // Analyze each transaction in the block
        if let Some(transactions) = &block.transactions {
            for transaction in transactions {
                if let Some(meta) = &transaction.meta {
                    if meta.err.is_none() {
                        successful_transactions += 1;
                    } else {
                        failed_transactions += 1;
                    }

                    if let Some(compute_units) = meta.compute_units_consumed {
                        total_compute_units += compute_units;
                    }

                    // Perform risk analysis on non-vote transactions
                    if let Some(encoded_tx) = transaction.transaction.as_ref() {
                        // Skip vote transactions for performance
                        let is_vote = self.is_vote_transaction(encoded_tx);
                        if !is_vote {
                            // Convert to the format expected by risk engine
                            let confirmed_tx = EncodedConfirmedTransactionWithStatusMeta {
                                slot,
                                transaction: transaction.clone(),
                                block_time: block.block_time,
                            };

                            match self.risk_engine.analyze_transaction(&confirmed_tx, slot).await {
                                Ok(assessment) => {
                                    // Update metrics based on risk assessment
                                    self.metrics.tx_risk_score.set(assessment.overall_risk_score);
                                    
                                    if assessment.overall_risk_score > 0.7 {
                                        warn!("🚨 High-risk transaction detected: {} (score: {:.2})", 
                                              assessment.signature, assessment.overall_risk_score);
                                    }
                                }
                                Err(e) => {
                                    debug!("Failed to analyze transaction risk: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        let slot_info = SlotInfo {
            slot,
            parent: block.parent_slot,
            root: 0, // Would need to fetch separately
            timestamp: chrono::Utc::now(),
            transaction_count: (successful_transactions + failed_transactions),
            successful_transactions,
            failed_transactions,
            total_compute_units,
            block_hash: block.blockhash,
            previous_block_hash: block.previous_blockhash,
        };

        let processing_time = start_time.elapsed();
        debug!("✅ Slot {} analyzed in {:?} - {} transactions, {} CU", 
               slot, processing_time, slot_info.transaction_count, total_compute_units);

        // Update performance metrics
        self.update_performance_stats(&slot_info, processing_time).await;

        Ok(slot_info)
    }

    /// Stream real-time slot updates
    pub async fn stream_slots(&self, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) -> ZKResult<()> {
        info!("📡 Starting real-time slot streaming");

        let mut current_slot = {
            let state = self.state.read().await;
            state.current_slot
        };

        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(400)); // ~400ms slot time

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.process_next_slot(&mut current_slot).await {
                        Ok(_) => {
                            // Update state
                            let mut state = self.state.write().await;
                            state.current_slot = current_slot;
                        }
                        Err(e) => {
                            error!("Failed to process slot {}: {}", current_slot, e);
                            
                            // Update error state
                            let mut state = self.state.write().await;
                            state.last_error = Some(e.to_string());
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("🔄 Stopping slot streaming");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn process_next_slot(&self, current_slot: &mut Slot) -> ZKResult<()> {
        // Get the latest slot from the network
        let latest_slot = if self.config.system.dry_run {
            *current_slot + 1
        } else {
            self.rpc_client.get_slot_with_commitment(self.commitment).await
                .map_err(|e| ZKError::SolanaError(format!("Failed to get latest slot: {}", e)))?
        };

        // Process any missed slots
        while *current_slot < latest_slot {
            *current_slot += 1;
            
            // Analyze the slot (skip in dry-run for performance)
            if !self.config.system.dry_run {
                match self.analyze_slot(*current_slot).await {
                    Ok(slot_info) => {
                        debug!("📊 Processed slot {}: {} transactions", 
                               slot_info.slot, slot_info.transaction_count);
                        
                        // Update metrics
                        self.metrics.slot_gap_total.inc_by(0); // No gap
                    }
                    Err(e) => {
                        // Slot might not be available yet, this is normal
                        debug!("Slot {} not yet available: {}", *current_slot, e);
                        break;
                    }
                }
            } else {
                // Simulate slot processing in dry-run mode
                debug!("🎭 Simulated processing of slot {}", *current_slot);
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        }

        Ok(())
    }

    fn is_vote_transaction(&self, _transaction: &solana_transaction_status::EncodedTransaction) -> bool {
        // Simple heuristic - in a real implementation, this would check the program IDs
        // Vote transactions typically have specific patterns
        false // For now, analyze all transactions
    }

    async fn update_performance_stats(&self, slot_info: &SlotInfo, processing_time: std::time::Duration) {
        let mut state = self.state.write().await;
        
        // Update performance statistics
        state.performance_stats.total_transactions += slot_info.transaction_count as u64;
        state.performance_stats.successful_transactions += slot_info.successful_transactions as u64;
        state.performance_stats.failed_transactions += slot_info.failed_transactions as u64;
        
        // Calculate TPS (transactions per second)
        let slot_time_ms = processing_time.as_millis() as f64;
        if slot_time_ms > 0.0 {
            state.performance_stats.avg_slot_time_ms = 
                (state.performance_stats.avg_slot_time_ms * 0.9) + (slot_time_ms * 0.1);
            
            state.performance_stats.tps = 
                slot_info.transaction_count as f64 / (slot_time_ms / 1000.0);
        }
        
        // Calculate compute units per second
        state.performance_stats.compute_units_per_second = 
            slot_info.total_compute_units as f64 / (slot_time_ms / 1000.0);
    }

    /// Get specific transaction with full details
    pub async fn get_transaction(&self, signature: &str) -> ZKResult<EncodedConfirmedTransactionWithStatusMeta> {
        let sig = Signature::from_str(signature)
            .map_err(|e| ZKError::ValidationError(format!("Invalid signature: {}", e)))?;

        let transaction = self.rpc_client.get_transaction_with_config(
            &sig,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::JsonParsed),
                commitment: Some(self.commitment),
                max_supported_transaction_version: Some(0),
            },
        ).await.map_err(|e| ZKError::SolanaError(format!("Failed to get transaction: {}", e)))?;

        Ok(transaction)
    }

    /// Batch analyze multiple transactions for efficiency
    pub async fn analyze_transaction_batch(&self, signatures: Vec<String>) -> ZKResult<Vec<TransactionRiskAssessment>> {
        let mut assessments = Vec::new();
        
        for signature in signatures {
            match self.get_transaction(&signature).await {
                Ok(transaction) => {
                    match self.risk_engine.analyze_transaction(&transaction, transaction.slot).await {
                        Ok(assessment) => assessments.push(assessment),
                        Err(e) => {
                            warn!("Failed to analyze transaction {}: {}", signature, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch transaction {}: {}", signature, e);
                }
            }
        }
        
        Ok(assessments)
    }

    pub async fn get_state(&self) -> SolanaClientState {
        self.state.read().await.clone()
    }

    pub async fn is_connected(&self) -> bool {
        self.state.read().await.connected
    }

    pub async fn get_current_slot(&self) -> Slot {
        self.state.read().await.current_slot
    }
}
