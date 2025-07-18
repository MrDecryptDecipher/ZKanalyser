use anyhow::Result;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::CompiledInstruction,
    message::{Message, VersionedMessage},
    pubkey::Pubkey,
    signature::Signature,
    transaction::{Transaction, VersionedTransaction},
};
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, TransactionStatusMeta, UiInstruction,
    UiTransactionStatusMeta,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::error::{ZKError, ZKResult};
use crate::metrics::MetricsCollector;

/// Real-time risk detection engine for Solana transactions
/// Implements CPI depth analysis, Anchor panic detection, compute unit monitoring
pub struct RiskDetectionEngine {
    config: Config,
    metrics: Arc<MetricsCollector>,
    state: Arc<RwLock<RiskEngineState>>,
    anchor_program_cache: Arc<RwLock<HashSet<Pubkey>>>,
    risk_thresholds: RiskThresholds,
}

#[derive(Debug, Clone)]
pub struct RiskEngineState {
    pub total_transactions_analyzed: u64,
    pub high_risk_transactions: u64,
    pub anchor_errors_detected: u64,
    pub cpi_depth_violations: u64,
    pub compute_unit_violations: u64,
    pub signer_anomalies: u64,
    pub current_risk_score: f64,
    pub last_analysis_timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    pub max_cpi_depth: u8,
    pub max_compute_units: u64,
    pub max_signers: u8,
    pub max_instructions: u16,
    pub anchor_error_weight: f64,
    pub cpi_depth_weight: f64,
    pub compute_unit_weight: f64,
    pub signer_anomaly_weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRiskAssessment {
    pub signature: String,
    pub slot: u64,
    pub overall_risk_score: f64,
    pub risk_factors: Vec<RiskFactor>,
    pub cpi_analysis: CpiAnalysis,
    pub anchor_analysis: AnchorAnalysis,
    pub compute_analysis: ComputeAnalysis,
    pub signer_analysis: SignerAnalysis,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub category: RiskCategory,
    pub severity: RiskSeverity,
    pub score: f64,
    pub description: String,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskCategory {
    CpiDepth,
    AnchorError,
    ComputeUnits,
    SignerAnomaly,
    InstructionComplexity,
    AccountAccess,
    ProgramInvocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpiAnalysis {
    pub max_depth: u8,
    pub total_cpi_calls: u16,
    pub unique_programs_invoked: u16,
    pub cross_program_calls: Vec<CrossProgramCall>,
    pub depth_violation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProgramCall {
    pub caller_program: String,
    pub callee_program: String,
    pub instruction_index: u16,
    pub depth_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorAnalysis {
    pub anchor_programs_detected: u16,
    pub anchor_errors: Vec<AnchorError>,
    pub panic_detected: bool,
    pub error_codes: Vec<u32>,
    pub discriminator_analysis: Vec<DiscriminatorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorError {
    pub program_id: String,
    pub error_code: u32,
    pub error_message: String,
    pub instruction_index: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscriminatorInfo {
    pub program_id: String,
    pub discriminator: [u8; 8],
    pub method_name: Option<String>,
    pub is_known_anchor_method: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeAnalysis {
    pub units_consumed: u64,
    pub units_requested: u64,
    pub efficiency_ratio: f64,
    pub compute_budget_instructions: u16,
    pub unit_price: Option<u64>,
    pub exceeds_threshold: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerAnalysis {
    pub total_signers: u8,
    pub unique_signers: u8,
    pub fee_payer: String,
    pub signer_patterns: Vec<SignerPattern>,
    pub anomaly_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerPattern {
    pub signer: String,
    pub instruction_count: u16,
    pub is_fee_payer: bool,
    pub is_program_derived: bool,
    pub risk_indicators: Vec<String>,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            max_cpi_depth: 4,           // PRD: Monitor CPI depth
            max_compute_units: 900_000, // PRD: CU spike detection
            max_signers: 10,            // Signer anomaly threshold
            max_instructions: 50,       // Instruction complexity limit
            anchor_error_weight: 0.8,   // High weight for Anchor errors
            cpi_depth_weight: 0.6,      // Medium-high weight for CPI depth
            compute_unit_weight: 0.7,   // High weight for compute units
            signer_anomaly_weight: 0.5, // Medium weight for signer anomalies
        }
    }
}

impl RiskDetectionEngine {
    pub async fn new(config: Config, metrics: Arc<MetricsCollector>) -> ZKResult<Self> {
        info!("🛡️  Initializing Risk Detection Engine");

        let state = Arc::new(RwLock::new(RiskEngineState {
            total_transactions_analyzed: 0,
            high_risk_transactions: 0,
            anchor_errors_detected: 0,
            cpi_depth_violations: 0,
            compute_unit_violations: 0,
            signer_anomalies: 0,
            current_risk_score: 0.0,
            last_analysis_timestamp: chrono::Utc::now(),
        }));

        let anchor_program_cache = Arc::new(RwLock::new(HashSet::new()));
        let risk_thresholds = RiskThresholds::default();

        // Initialize known Anchor programs
        Self::initialize_anchor_program_cache(&anchor_program_cache).await?;

        info!("✅ Risk Detection Engine initialized with thresholds: CPI depth ≤ {}, CU ≤ {}", 
              risk_thresholds.max_cpi_depth, risk_thresholds.max_compute_units);

        Ok(Self {
            config,
            metrics,
            state,
            anchor_program_cache,
            risk_thresholds,
        })
    }

    /// Analyze a Solana transaction for risk factors
    pub async fn analyze_transaction(
        &self,
        transaction: &EncodedConfirmedTransactionWithStatusMeta,
        slot: u64,
    ) -> ZKResult<TransactionRiskAssessment> {
        let start_time = std::time::Instant::now();
        
        let signature = transaction.transaction.signatures.first()
            .ok_or_else(|| ZKError::ValidationError("Transaction has no signatures".to_string()))?
            .clone();

        debug!("🔍 Analyzing transaction {} in slot {}", signature, slot);

        // Extract transaction data
        let meta = transaction.meta.as_ref()
            .ok_or_else(|| ZKError::ValidationError("Transaction meta is missing".to_string()))?;

        // Perform comprehensive risk analysis
        let cpi_analysis = self.analyze_cpi_depth(transaction).await?;
        let anchor_analysis = self.analyze_anchor_programs(transaction).await?;
        let compute_analysis = self.analyze_compute_usage(meta).await?;
        let signer_analysis = self.analyze_signers(transaction).await?;

        // Calculate risk factors
        let mut risk_factors = Vec::new();
        
        // CPI Depth Risk
        if cpi_analysis.depth_violation {
            risk_factors.push(RiskFactor {
                category: RiskCategory::CpiDepth,
                severity: RiskSeverity::High,
                score: self.risk_thresholds.cpi_depth_weight,
                description: format!("CPI depth {} exceeds threshold {}", 
                                   cpi_analysis.max_depth, self.risk_thresholds.max_cpi_depth),
                evidence: serde_json::to_value(&cpi_analysis)?,
            });
        }

        // Anchor Error Risk
        if anchor_analysis.panic_detected || !anchor_analysis.anchor_errors.is_empty() {
            let severity = if anchor_analysis.panic_detected { 
                RiskSeverity::Critical 
            } else { 
                RiskSeverity::High 
            };
            
            risk_factors.push(RiskFactor {
                category: RiskCategory::AnchorError,
                severity,
                score: self.risk_thresholds.anchor_error_weight,
                description: format!("Anchor errors detected: {} errors, panic: {}", 
                                   anchor_analysis.anchor_errors.len(), anchor_analysis.panic_detected),
                evidence: serde_json::to_value(&anchor_analysis)?,
            });
        }

        // Compute Unit Risk
        if compute_analysis.exceeds_threshold {
            risk_factors.push(RiskFactor {
                category: RiskCategory::ComputeUnits,
                severity: RiskSeverity::Medium,
                score: self.risk_thresholds.compute_unit_weight,
                description: format!("Compute units {} exceed threshold {}", 
                                   compute_analysis.units_consumed, self.risk_thresholds.max_compute_units),
                evidence: serde_json::to_value(&compute_analysis)?,
            });
        }

        // Signer Anomaly Risk
        if signer_analysis.anomaly_detected {
            risk_factors.push(RiskFactor {
                category: RiskCategory::SignerAnomaly,
                severity: RiskSeverity::Medium,
                score: self.risk_thresholds.signer_anomaly_weight,
                description: format!("Signer anomaly detected: {} signers", signer_analysis.total_signers),
                evidence: serde_json::to_value(&signer_analysis)?,
            });
        }

        // Calculate overall risk score
        let overall_risk_score = self.calculate_overall_risk_score(&risk_factors);

        // Update metrics
        self.update_metrics(&risk_factors, overall_risk_score).await;

        // Update state
        self.update_state(overall_risk_score, &risk_factors).await;

        let analysis_time = start_time.elapsed();
        debug!("✅ Transaction analysis completed in {:?}", analysis_time);

        Ok(TransactionRiskAssessment {
            signature,
            slot,
            overall_risk_score,
            risk_factors,
            cpi_analysis,
            anchor_analysis,
            compute_analysis,
            signer_analysis,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Analyze CPI (Cross-Program Invocation) depth and complexity
    async fn analyze_cpi_depth(
        &self,
        transaction: &EncodedConfirmedTransactionWithStatusMeta,
    ) -> ZKResult<CpiAnalysis> {
        // Extract instructions from transaction
        let instructions = match &transaction.transaction.message {
            solana_transaction_status::UiMessage::Parsed(parsed) => {
                &parsed.instructions
            }
            solana_transaction_status::UiMessage::Raw(_) => {
                return Err(ZKError::ValidationError("Raw message format not supported for CPI analysis".to_string()));
            }
        };

        let mut max_depth = 0u8;
        let mut total_cpi_calls = 0u16;
        let mut unique_programs = HashSet::new();
        let mut cross_program_calls = Vec::new();
        let mut current_depth = 0u8;

        // Analyze each instruction for CPI patterns
        for (idx, instruction) in instructions.iter().enumerate() {
            if let UiInstruction::Parsed(parsed_instruction) = instruction {
                let program_id = &parsed_instruction.program_id;
                unique_programs.insert(program_id.clone());

                // Detect CPI patterns based on instruction structure
                if let Some(info) = parsed_instruction.parsed.as_object() {
                    if info.contains_key("innerInstructions") || 
                       info.get("type").and_then(|t| t.as_str()) == Some("createAccount") ||
                       program_id.contains("11111111111111111111111111111111") { // System Program
                        current_depth += 1;
                        total_cpi_calls += 1;
                        max_depth = max_depth.max(current_depth);

                        cross_program_calls.push(CrossProgramCall {
                            caller_program: "unknown".to_string(), // Would need more context
                            callee_program: program_id.clone(),
                            instruction_index: idx as u16,
                            depth_level: current_depth,
                        });
                    }
                }
            }
        }

        let depth_violation = max_depth > self.risk_thresholds.max_cpi_depth;

        Ok(CpiAnalysis {
            max_depth,
            total_cpi_calls,
            unique_programs_invoked: unique_programs.len() as u16,
            cross_program_calls,
            depth_violation,
        })
    }

    /// Analyze Anchor program interactions and detect errors/panics
    async fn analyze_anchor_programs(
        &self,
        transaction: &EncodedConfirmedTransactionWithStatusMeta,
    ) -> ZKResult<AnchorAnalysis> {
        let mut anchor_programs_detected = 0u16;
        let mut anchor_errors = Vec::new();
        let mut panic_detected = false;
        let mut error_codes = Vec::new();
        let mut discriminator_analysis = Vec::new();

        // Check transaction logs for Anchor-specific patterns
        if let Some(meta) = &transaction.meta {
            if let Some(log_messages) = &meta.log_messages {
                for (idx, log) in log_messages.iter().enumerate() {
                    // Detect Anchor panics
                    if log.contains("panicked") || log.contains("anchor") {
                        panic_detected = true;
                        
                        // Extract error codes from Anchor error messages
                        if let Some(error_code) = self.extract_anchor_error_code(log) {
                            error_codes.push(error_code);
                            anchor_errors.push(AnchorError {
                                program_id: "unknown".to_string(), // Would extract from context
                                error_code,
                                error_message: log.clone(),
                                instruction_index: idx as u16,
                            });
                        }
                    }

                    // Detect Anchor program invocations
                    if log.contains("Program") && log.contains("invoke") {
                        anchor_programs_detected += 1;
                    }
                }
            }
        }

        // Analyze instruction discriminators for Anchor methods
        if let solana_transaction_status::UiMessage::Parsed(parsed) = &transaction.transaction.message {
            for instruction in &parsed.instructions {
                if let UiInstruction::Parsed(parsed_instruction) = instruction {
                    // Check if this looks like an Anchor program
                    let program_cache = self.anchor_program_cache.read().await;
                    if let Ok(pubkey) = parsed_instruction.program_id.parse::<Pubkey>() {
                        if program_cache.contains(&pubkey) {
                            // Analyze discriminator if available
                            if let Some(data) = parsed_instruction.parsed.get("data") {
                                if let Some(data_str) = data.as_str() {
                                    if let Ok(decoded) = base64::decode(data_str) {
                                        if decoded.len() >= 8 {
                                            let mut discriminator = [0u8; 8];
                                            discriminator.copy_from_slice(&decoded[0..8]);
                                            
                                            discriminator_analysis.push(DiscriminatorInfo {
                                                program_id: parsed_instruction.program_id.clone(),
                                                discriminator,
                                                method_name: self.resolve_anchor_method(&discriminator),
                                                is_known_anchor_method: true,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(AnchorAnalysis {
            anchor_programs_detected,
            anchor_errors,
            panic_detected,
            error_codes,
            discriminator_analysis,
        })
    }

    /// Analyze compute unit usage and efficiency
    async fn analyze_compute_usage(
        &self,
        meta: &UiTransactionStatusMeta,
    ) -> ZKResult<ComputeAnalysis> {
        let units_consumed = meta.compute_units_consumed.unwrap_or(0);
        let units_requested = 200_000u64; // Default if not specified
        
        // Calculate efficiency ratio
        let efficiency_ratio = if units_requested > 0 {
            units_consumed as f64 / units_requested as f64
        } else {
            0.0
        };

        let exceeds_threshold = units_consumed > self.risk_thresholds.max_compute_units;

        Ok(ComputeAnalysis {
            units_consumed,
            units_requested,
            efficiency_ratio,
            compute_budget_instructions: 0, // Would count from instructions
            unit_price: None, // Would extract from compute budget instructions
            exceeds_threshold,
        })
    }

    /// Analyze transaction signers for anomalies
    async fn analyze_signers(
        &self,
        transaction: &EncodedConfirmedTransactionWithStatusMeta,
    ) -> ZKResult<SignerAnalysis> {
        let signatures = &transaction.transaction.signatures;
        let total_signers = signatures.len() as u8;
        let unique_signers = signatures.iter().collect::<HashSet<_>>().len() as u8;
        
        let fee_payer = signatures.first()
            .map(|s| s.clone())
            .unwrap_or_default();

        let mut signer_patterns = Vec::new();
        let anomaly_detected = total_signers > self.risk_thresholds.max_signers;

        // Analyze each signer
        for (idx, signature) in signatures.iter().enumerate() {
            let mut risk_indicators = Vec::new();
            
            if idx == 0 {
                risk_indicators.push("fee_payer".to_string());
            }
            
            if total_signers > 5 {
                risk_indicators.push("high_signer_count".to_string());
            }

            signer_patterns.push(SignerPattern {
                signer: signature.clone(),
                instruction_count: 1, // Would count actual instruction usage
                is_fee_payer: idx == 0,
                is_program_derived: false, // Would check if PDA
                risk_indicators,
            });
        }

        Ok(SignerAnalysis {
            total_signers,
            unique_signers,
            fee_payer,
            signer_patterns,
            anomaly_detected,
        })
    }

    fn calculate_overall_risk_score(&self, risk_factors: &[RiskFactor]) -> f64 {
        if risk_factors.is_empty() {
            return 0.0;
        }

        let weighted_sum: f64 = risk_factors.iter()
            .map(|factor| {
                let severity_multiplier = match factor.severity {
                    RiskSeverity::Low => 0.25,
                    RiskSeverity::Medium => 0.5,
                    RiskSeverity::High => 0.75,
                    RiskSeverity::Critical => 1.0,
                };
                factor.score * severity_multiplier
            })
            .sum();

        (weighted_sum / risk_factors.len() as f64).min(1.0)
    }

    async fn update_metrics(&self, risk_factors: &[RiskFactor], overall_score: f64) {
        // Update Prometheus metrics
        self.metrics.tx_risk_score.set(overall_score);

        for factor in risk_factors {
            match factor.category {
                RiskCategory::AnchorError => {
                    self.metrics.anchor_error_count.inc();
                }
                _ => {}
            }
        }
    }

    async fn update_state(&self, risk_score: f64, risk_factors: &[RiskFactor]) {
        let mut state = self.state.write().await;
        state.total_transactions_analyzed += 1;
        state.current_risk_score = risk_score;
        state.last_analysis_timestamp = chrono::Utc::now();

        if risk_score > 0.7 {
            state.high_risk_transactions += 1;
        }

        for factor in risk_factors {
            match factor.category {
                RiskCategory::CpiDepth => state.cpi_depth_violations += 1,
                RiskCategory::AnchorError => state.anchor_errors_detected += 1,
                RiskCategory::ComputeUnits => state.compute_unit_violations += 1,
                RiskCategory::SignerAnomaly => state.signer_anomalies += 1,
                _ => {}
            }
        }
    }

    async fn initialize_anchor_program_cache(cache: &Arc<RwLock<HashSet<Pubkey>>>) -> ZKResult<()> {
        let mut cache_write = cache.write().await;
        
        // Add known Anchor program IDs (this would be populated from a registry)
        // For now, adding some common ones
        if let Ok(pubkey) = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".parse::<Pubkey>() {
            cache_write.insert(pubkey);
        }
        
        info!("📋 Initialized Anchor program cache with {} programs", cache_write.len());
        Ok(())
    }

    fn extract_anchor_error_code(&self, log_message: &str) -> Option<u32> {
        // Extract error codes from Anchor error messages
        // Pattern: "Error Code: 6000" or similar
        if let Some(start) = log_message.find("Error Code:") {
            let code_part = &log_message[start + 11..];
            if let Some(end) = code_part.find(' ') {
                code_part[..end].trim().parse().ok()
            } else {
                code_part.trim().parse().ok()
            }
        } else {
            None
        }
    }

    fn resolve_anchor_method(&self, discriminator: &[u8; 8]) -> Option<String> {
        // This would contain a mapping of discriminators to method names
        // For now, returning None as this requires a comprehensive database
        None
    }

    pub async fn get_current_risk_score(&self) -> f64 {
        self.state.read().await.current_risk_score
    }

    pub async fn get_state(&self) -> RiskEngineState {
        self.state.read().await.clone()
    }
}
