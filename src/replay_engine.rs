use anyhow::Result;
use serde::{Deserialize, Serialize};
use solana_sdk::{clock::Slot, signature::Signature};
use solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::error::{ZKError, ZKResult};
use crate::solana_client::SolanaClient;
use crate::storage::StorageEngine;
use crate::risk_engine::{RiskDetectionEngine, TransactionRiskAssessment};

/// Advanced replay engine for slot-by-slot audit and debugging
pub struct ReplayEngine {
    config: Config,
    solana_client: Arc<SolanaClient>,
    storage_engine: Arc<StorageEngine>,
    risk_engine: Arc<RiskDetectionEngine>,
    state: Arc<RwLock<ReplayState>>,
}

#[derive(Debug, Clone)]
pub struct ReplayState {
    pub active_replays: HashMap<String, ReplaySession>,
    pub completed_replays: u64,
    pub failed_replays: u64,
    pub total_slots_replayed: u64,
    pub total_transactions_replayed: u64,
    pub export_count: u64,
    pub last_replay_timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct ReplaySession {
    pub id: String,
    pub replay_type: ReplayType,
    pub status: ReplayStatus,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub progress: ReplayProgress,
    pub results: Option<ReplayResults>,
}

#[derive(Debug, Clone)]
pub enum ReplayType {
    Slot { slot: Slot },
    Transaction { signature: String },
    SlotRange { start_slot: Slot, end_slot: Slot },
    TimeRange { start_time: chrono::DateTime<chrono::Utc>, end_time: chrono::DateTime<chrono::Utc> },
}

#[derive(Debug, Clone)]
pub enum ReplayStatus {
    Initializing,
    InProgress,
    Completed,
    Failed(String),
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct ReplayProgress {
    pub current_item: u64,
    pub total_items: u64,
    pub percentage: f64,
    pub estimated_completion: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResults {
    pub replay_id: String,
    pub replay_type: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub duration_ms: u64,
    pub slots_processed: u64,
    pub transactions_processed: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub risk_assessments: Vec<TransactionRiskAssessment>,
    pub slot_details: Vec<SlotReplayDetail>,
    pub summary_stats: ReplaySummaryStats,
    pub export_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotReplayDetail {
    pub slot: Slot,
    pub parent_slot: Option<Slot>,
    pub block_hash: String,
    pub transaction_count: u32,
    pub successful_transactions: u32,
    pub failed_transactions: u32,
    pub total_compute_units: u64,
    pub total_fees: u64,
    pub block_time: Option<i64>,
    pub replay_timestamp: chrono::DateTime<chrono::Utc>,
    pub processing_time_ms: u64,
    pub risk_score: f64,
    pub anomalies_detected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReplayDetail {
    pub signature: String,
    pub slot: Slot,
    pub success: bool,
    pub compute_units_consumed: Option<u64>,
    pub fee: u64,
    pub log_messages: Vec<String>,
    pub account_changes: Vec<AccountChange>,
    pub instruction_trace: Vec<InstructionTrace>,
    pub risk_assessment: Option<TransactionRiskAssessment>,
    pub replay_timestamp: chrono::DateTime<chrono::Utc>,
    pub processing_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountChange {
    pub pubkey: String,
    pub before_lamports: u64,
    pub after_lamports: u64,
    pub before_data_hash: String,
    pub after_data_hash: String,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionTrace {
    pub program_id: String,
    pub instruction_index: u32,
    pub data: String,
    pub accounts: Vec<String>,
    pub inner_instructions: Vec<InnerInstructionTrace>,
    pub logs: Vec<String>,
    pub compute_units_consumed: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InnerInstructionTrace {
    pub program_id: String,
    pub data: String,
    pub accounts: Vec<String>,
    pub stack_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySummaryStats {
    pub total_compute_units: u64,
    pub total_fees: u64,
    pub average_risk_score: f64,
    pub high_risk_transactions: u64,
    pub anchor_errors: u64,
    pub cpi_violations: u64,
    pub unique_programs: u64,
    pub vote_transactions: u64,
    pub performance_metrics: PerformanceMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub transactions_per_second: f64,
    pub slots_per_second: f64,
    pub average_slot_time_ms: f64,
    pub peak_memory_usage_mb: f64,
    pub total_processing_time_ms: u64,
}

impl ReplayEngine {
    pub async fn new(
        config: Config,
        solana_client: Arc<SolanaClient>,
        storage_engine: Arc<StorageEngine>,
        risk_engine: Arc<RiskDetectionEngine>,
    ) -> ZKResult<Self> {
        info!("🔄 Initializing Replay Engine");

        let state = Arc::new(RwLock::new(ReplayState {
            active_replays: HashMap::new(),
            completed_replays: 0,
            failed_replays: 0,
            total_slots_replayed: 0,
            total_transactions_replayed: 0,
            export_count: 0,
            last_replay_timestamp: chrono::Utc::now(),
        }));

        // Ensure export directory exists
        let export_dir = format!("{}/.zkanalyzer/reports", std::env::var("HOME").unwrap_or_default());
        tokio::fs::create_dir_all(&export_dir).await
            .map_err(|e| ZKError::ReplayError(format!("Failed to create export directory: {}", e)))?;

        info!("✅ Replay Engine initialized with export directory: {}", export_dir);

        Ok(Self {
            config,
            solana_client,
            storage_engine,
            risk_engine,
            state,
        })
    }

    /// Replay a specific slot with comprehensive analysis
    pub async fn replay_slot(&self, slot: Slot) -> ZKResult<ReplayResults> {
        let session_id = format!("slot_{}", slot);
        info!("🔄 Starting slot replay: {}", slot);

        let start_time = chrono::Utc::now();
        let processing_start = std::time::Instant::now();

        // Create replay session
        let session = ReplaySession {
            id: session_id.clone(),
            replay_type: ReplayType::Slot { slot },
            status: ReplayStatus::Initializing,
            start_time,
            progress: ReplayProgress {
                current_item: 0,
                total_items: 1,
                percentage: 0.0,
                estimated_completion: None,
            },
            results: None,
        };

        // Register session
        {
            let mut state = self.state.write().await;
            state.active_replays.insert(session_id.clone(), session);
        }

        // Update status to in progress
        self.update_session_status(&session_id, ReplayStatus::InProgress).await;

        // Perform slot analysis
        let slot_info = match self.solana_client.analyze_slot(slot).await {
            Ok(info) => info,
            Err(e) => {
                self.update_session_status(&session_id, ReplayStatus::Failed(e.to_string())).await;
                return Err(e);
            }
        };

        // Get block with full transaction details
        let block = match self.get_block_with_transactions(slot).await {
            Ok(block) => block,
            Err(e) => {
                warn!("Failed to get block details for slot {}: {}", slot, e);
                // Continue with available slot info
                None
            }
        };

        let mut risk_assessments = Vec::new();
        let mut transaction_details = Vec::new();

        // Analyze transactions if block data is available
        if let Some(block_data) = block {
            for (idx, transaction) in block_data.transactions.iter().enumerate() {
                self.update_progress(&session_id, idx as u64 + 1, block_data.transactions.len() as u64).await;

                // Perform risk analysis
                if let Ok(assessment) = self.risk_engine.analyze_transaction(transaction, slot).await {
                    risk_assessments.push(assessment);
                }

                // Extract transaction details
                if let Some(signature) = transaction.transaction.signatures.first() {
                    let detail = self.extract_transaction_detail(transaction, slot).await;
                    transaction_details.push(detail);
                }
            }
        }

        let processing_time = processing_start.elapsed();
        let end_time = chrono::Utc::now();

        // Calculate summary statistics
        let summary_stats = self.calculate_summary_stats(&risk_assessments, &transaction_details, processing_time);

        // Create slot detail
        let slot_detail = SlotReplayDetail {
            slot,
            parent_slot: slot_info.parent,
            block_hash: slot_info.block_hash.clone(),
            transaction_count: slot_info.transaction_count,
            successful_transactions: slot_info.successful_transactions,
            failed_transactions: slot_info.failed_transactions,
            total_compute_units: slot_info.total_compute_units,
            total_fees: summary_stats.total_fees,
            block_time: None, // Would be extracted from block data
            replay_timestamp: chrono::Utc::now(),
            processing_time_ms: processing_time.as_millis() as u64,
            risk_score: summary_stats.average_risk_score,
            anomalies_detected: self.detect_slot_anomalies(&slot_info, &risk_assessments),
        };

        // Create results
        let results = ReplayResults {
            replay_id: session_id.clone(),
            replay_type: "slot".to_string(),
            start_time,
            end_time,
            duration_ms: processing_time.as_millis() as u64,
            slots_processed: 1,
            transactions_processed: slot_info.transaction_count as u64,
            successful_transactions: slot_info.successful_transactions as u64,
            failed_transactions: slot_info.failed_transactions as u64,
            risk_assessments,
            slot_details: vec![slot_detail],
            summary_stats,
            export_paths: Vec::new(), // Will be populated during export
        };

        // Update session with results
        self.complete_session(&session_id, results.clone()).await;

        // Update global state
        {
            let mut state = self.state.write().await;
            state.completed_replays += 1;
            state.total_slots_replayed += 1;
            state.total_transactions_replayed += slot_info.transaction_count as u64;
            state.last_replay_timestamp = chrono::Utc::now();
        }

        info!("✅ Slot replay completed: {} ({} transactions, {:.2}ms)", 
              slot, slot_info.transaction_count, processing_time.as_millis());

        Ok(results)
    }

    /// Replay a specific transaction with detailed analysis
    pub async fn replay_transaction(&self, signature: &str) -> ZKResult<TransactionReplayDetail> {
        info!("🔄 Starting transaction replay: {}", signature);

        let start_time = std::time::Instant::now();

        // Get transaction from Solana
        let transaction = self.solana_client.get_transaction(signature).await?;

        // Perform risk analysis
        let risk_assessment = self.risk_engine.analyze_transaction(&transaction, transaction.slot).await.ok();

        // Extract detailed information
        let detail = TransactionReplayDetail {
            signature: signature.to_string(),
            slot: transaction.slot,
            success: transaction.meta.as_ref().map(|m| m.err.is_none()).unwrap_or(false),
            compute_units_consumed: transaction.meta.as_ref().and_then(|m| m.compute_units_consumed),
            fee: transaction.meta.as_ref().map(|m| m.fee).unwrap_or(0),
            log_messages: transaction.meta.as_ref()
                .and_then(|m| m.log_messages.as_ref())
                .cloned()
                .unwrap_or_default(),
            account_changes: self.extract_account_changes(&transaction),
            instruction_trace: self.extract_instruction_trace(&transaction),
            risk_assessment,
            replay_timestamp: chrono::Utc::now(),
            processing_time_ms: start_time.elapsed().as_millis() as u64,
        };

        info!("✅ Transaction replay completed: {} ({:.2}ms)", 
              signature, start_time.elapsed().as_millis());

        Ok(detail)
    }

    /// Export replay results in multiple formats
    pub async fn export_results(&self, results: &ReplayResults, formats: Vec<ExportFormat>) -> ZKResult<Vec<String>> {
        info!("📦 Exporting replay results in {} formats", formats.len());

        let mut export_paths = Vec::new();
        let base_path = format!("{}/.zkanalyzer/reports", std::env::var("HOME").unwrap_or_default());

        for format in formats {
            let export_path = match format {
                ExportFormat::Json => {
                    let path = format!("{}/replay_{}.json", base_path, results.replay_id);
                    self.export_json(results, &path).await?;
                    path
                }
                ExportFormat::Markdown => {
                    let path = format!("{}/replay_{}.md", base_path, results.replay_id);
                    self.export_markdown(results, &path).await?;
                    path
                }
                ExportFormat::Protobuf => {
                    let path = format!("{}/replay_{}.pb", base_path, results.replay_id);
                    self.export_protobuf(results, &path).await?;
                    path
                }
                ExportFormat::Csv => {
                    let path = format!("{}/replay_{}.csv", base_path, results.replay_id);
                    self.export_csv(results, &path).await?;
                    path
                }
            };
            export_paths.push(export_path);
        }

        // Update export count
        {
            let mut state = self.state.write().await;
            state.export_count += export_paths.len() as u64;
        }

        info!("✅ Export completed: {} files generated", export_paths.len());
        Ok(export_paths)
    }

    async fn get_block_with_transactions(&self, slot: Slot) -> ZKResult<Option<BlockWithTransactions>> {
        // This would fetch the full block data with transactions
        // For now, return None to indicate block data not available
        Ok(None)
    }

    async fn extract_transaction_detail(&self, transaction: &EncodedConfirmedTransactionWithStatusMeta, slot: Slot) -> TransactionReplayDetail {
        let signature = transaction.transaction.signatures.first().cloned().unwrap_or_default();
        
        TransactionReplayDetail {
            signature,
            slot,
            success: transaction.meta.as_ref().map(|m| m.err.is_none()).unwrap_or(false),
            compute_units_consumed: transaction.meta.as_ref().and_then(|m| m.compute_units_consumed),
            fee: transaction.meta.as_ref().map(|m| m.fee).unwrap_or(0),
            log_messages: transaction.meta.as_ref()
                .and_then(|m| m.log_messages.as_ref())
                .cloned()
                .unwrap_or_default(),
            account_changes: self.extract_account_changes(transaction),
            instruction_trace: self.extract_instruction_trace(transaction),
            risk_assessment: None, // Would be populated separately
            replay_timestamp: chrono::Utc::now(),
            processing_time_ms: 0,
        }
    }

    fn extract_account_changes(&self, transaction: &EncodedConfirmedTransactionWithStatusMeta) -> Vec<AccountChange> {
        // Extract account balance changes from transaction meta
        Vec::new() // Placeholder implementation
    }

    fn extract_instruction_trace(&self, transaction: &EncodedConfirmedTransactionWithStatusMeta) -> Vec<InstructionTrace> {
        // Extract instruction execution trace
        Vec::new() // Placeholder implementation
    }

    fn calculate_summary_stats(&self, risk_assessments: &[TransactionRiskAssessment], transaction_details: &[TransactionReplayDetail], processing_time: std::time::Duration) -> ReplaySummaryStats {
        let total_compute_units = transaction_details.iter()
            .filter_map(|t| t.compute_units_consumed)
            .sum();

        let total_fees = transaction_details.iter()
            .map(|t| t.fee)
            .sum();

        let average_risk_score = if risk_assessments.is_empty() {
            0.0
        } else {
            risk_assessments.iter().map(|r| r.overall_risk_score).sum::<f64>() / risk_assessments.len() as f64
        };

        let high_risk_transactions = risk_assessments.iter()
            .filter(|r| r.overall_risk_score > 0.7)
            .count() as u64;

        ReplaySummaryStats {
            total_compute_units,
            total_fees,
            average_risk_score,
            high_risk_transactions,
            anchor_errors: 0, // Would be calculated from risk assessments
            cpi_violations: 0, // Would be calculated from risk assessments
            unique_programs: 0, // Would be calculated from transaction analysis
            vote_transactions: 0, // Would be calculated from transaction analysis
            performance_metrics: PerformanceMetrics {
                transactions_per_second: transaction_details.len() as f64 / processing_time.as_secs_f64(),
                slots_per_second: 1.0 / processing_time.as_secs_f64(),
                average_slot_time_ms: processing_time.as_millis() as f64,
                peak_memory_usage_mb: 0.0, // Would be monitored during replay
                total_processing_time_ms: processing_time.as_millis() as u64,
            },
        }
    }

    fn detect_slot_anomalies(&self, slot_info: &crate::solana_client::SlotInfo, risk_assessments: &[TransactionRiskAssessment]) -> Vec<String> {
        let mut anomalies = Vec::new();

        // Check for high transaction failure rate
        if slot_info.transaction_count > 0 {
            let failure_rate = slot_info.failed_transactions as f64 / slot_info.transaction_count as f64;
            if failure_rate > 0.1 {
                anomalies.push(format!("High failure rate: {:.1}%", failure_rate * 100.0));
            }
        }

        // Check for high risk transactions
        let high_risk_count = risk_assessments.iter().filter(|r| r.overall_risk_score > 0.7).count();
        if high_risk_count > 0 {
            anomalies.push(format!("High risk transactions: {}", high_risk_count));
        }

        // Check for excessive compute units
        if slot_info.total_compute_units > 10_000_000 {
            anomalies.push(format!("High compute usage: {} CU", slot_info.total_compute_units));
        }

        anomalies
    }

    async fn export_json(&self, results: &ReplayResults, path: &str) -> ZKResult<()> {
        let json = serde_json::to_string_pretty(results)
            .map_err(|e| ZKError::SerializationError(format!("Failed to serialize to JSON: {}", e)))?;
        
        tokio::fs::write(path, json).await
            .map_err(|e| ZKError::ReplayError(format!("Failed to write JSON export: {}", e)))?;
        
        Ok(())
    }

    async fn export_markdown(&self, results: &ReplayResults, path: &str) -> ZKResult<()> {
        let markdown = self.generate_markdown_report(results);
        
        tokio::fs::write(path, markdown).await
            .map_err(|e| ZKError::ReplayError(format!("Failed to write Markdown export: {}", e)))?;
        
        Ok(())
    }

    async fn export_protobuf(&self, results: &ReplayResults, path: &str) -> ZKResult<()> {
        // For now, export as compressed JSON (would be actual protobuf in production)
        let json = serde_json::to_vec(results)
            .map_err(|e| ZKError::SerializationError(format!("Failed to serialize for protobuf: {}", e)))?;
        
        let compressed = zstd::encode_all(&json[..], 3)
            .map_err(|e| ZKError::CompressionError(format!("Failed to compress protobuf: {}", e)))?;
        
        tokio::fs::write(path, compressed).await
            .map_err(|e| ZKError::ReplayError(format!("Failed to write protobuf export: {}", e)))?;
        
        Ok(())
    }

    async fn export_csv(&self, results: &ReplayResults, path: &str) -> ZKResult<()> {
        let csv = self.generate_csv_report(results);
        
        tokio::fs::write(path, csv).await
            .map_err(|e| ZKError::ReplayError(format!("Failed to write CSV export: {}", e)))?;
        
        Ok(())
    }

    fn generate_markdown_report(&self, results: &ReplayResults) -> String {
        format!(r#"# 🔄 ZKAnalyzer Replay Report

## 📊 Summary
- **Replay ID**: {}
- **Type**: {}
- **Duration**: {}ms
- **Slots Processed**: {}
- **Transactions Processed**: {}
- **Success Rate**: {:.1}%

## 📈 Performance Metrics
- **TPS**: {:.2}
- **Average Risk Score**: {:.3}
- **High Risk Transactions**: {}
- **Total Compute Units**: {}
- **Total Fees**: {} lamports

## 🛡️ Risk Analysis
{}

## 📋 Slot Details
{}

---
*Generated by ZKAnalyzer v3.5 at {}*
"#,
            results.replay_id,
            results.replay_type,
            results.duration_ms,
            results.slots_processed,
            results.transactions_processed,
            if results.transactions_processed > 0 {
                (results.successful_transactions as f64 / results.transactions_processed as f64) * 100.0
            } else { 0.0 },
            results.summary_stats.performance_metrics.transactions_per_second,
            results.summary_stats.average_risk_score,
            results.summary_stats.high_risk_transactions,
            results.summary_stats.total_compute_units,
            results.summary_stats.total_fees,
            self.format_risk_assessments(&results.risk_assessments),
            self.format_slot_details(&results.slot_details),
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        )
    }

    fn generate_csv_report(&self, results: &ReplayResults) -> String {
        let mut csv = String::from("slot,transaction_count,successful_transactions,failed_transactions,total_compute_units,risk_score,processing_time_ms\n");
        
        for slot_detail in &results.slot_details {
            csv.push_str(&format!("{},{},{},{},{},{:.3},{}\n",
                slot_detail.slot,
                slot_detail.transaction_count,
                slot_detail.successful_transactions,
                slot_detail.failed_transactions,
                slot_detail.total_compute_units,
                slot_detail.risk_score,
                slot_detail.processing_time_ms
            ));
        }
        
        csv
    }

    fn format_risk_assessments(&self, assessments: &[TransactionRiskAssessment]) -> String {
        if assessments.is_empty() {
            return "No risk assessments available.".to_string();
        }

        let mut output = String::new();
        for assessment in assessments.iter().take(5) { // Show top 5
            output.push_str(&format!("- **{}**: Risk Score {:.3}\n", 
                assessment.signature, assessment.overall_risk_score));
        }
        
        if assessments.len() > 5 {
            output.push_str(&format!("... and {} more transactions\n", assessments.len() - 5));
        }
        
        output
    }

    fn format_slot_details(&self, slot_details: &[SlotReplayDetail]) -> String {
        let mut output = String::new();
        for detail in slot_details {
            output.push_str(&format!("### Slot {}\n- Transactions: {}\n- Compute Units: {}\n- Risk Score: {:.3}\n\n",
                detail.slot, detail.transaction_count, detail.total_compute_units, detail.risk_score));
        }
        output
    }

    async fn update_session_status(&self, session_id: &str, status: ReplayStatus) {
        let mut state = self.state.write().await;
        if let Some(session) = state.active_replays.get_mut(session_id) {
            session.status = status;
        }
    }

    async fn update_progress(&self, session_id: &str, current: u64, total: u64) {
        let mut state = self.state.write().await;
        if let Some(session) = state.active_replays.get_mut(session_id) {
            session.progress.current_item = current;
            session.progress.total_items = total;
            session.progress.percentage = if total > 0 { (current as f64 / total as f64) * 100.0 } else { 0.0 };
        }
    }

    async fn complete_session(&self, session_id: &str, results: ReplayResults) {
        let mut state = self.state.write().await;
        if let Some(session) = state.active_replays.get_mut(session_id) {
            session.status = ReplayStatus::Completed;
            session.results = Some(results);
        }
    }

    pub async fn get_state(&self) -> ReplayState {
        self.state.read().await.clone()
    }

    pub async fn get_active_replays(&self) -> Vec<ReplaySession> {
        let state = self.state.read().await;
        state.active_replays.values().cloned().collect()
    }
}

#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    Markdown,
    Protobuf,
    Csv,
}

#[derive(Debug, Clone)]
struct BlockWithTransactions {
    transactions: Vec<EncodedConfirmedTransactionWithStatusMeta>,
}
