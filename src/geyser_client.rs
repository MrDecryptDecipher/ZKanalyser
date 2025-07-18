use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use solana_account_decoder::UiAccount;
use solana_sdk::{clock::Slot, pubkey::Pubkey, signature::Signature};
use solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::error::{ZKError, ZKResult};
use crate::metrics::MetricsCollector;
use crate::risk_engine::{RiskDetectionEngine, TransactionRiskAssessment};

/// Real-time Geyser plugin client for Solana data streaming
/// Implements buffered ingest for slots, accounts, and transactions
pub struct GeyserClient {
    config: Config,
    metrics: Arc<MetricsCollector>,
    risk_engine: Arc<RiskDetectionEngine>,
    state: Arc<RwLock<GeyserState>>,
    event_sender: broadcast::Sender<GeyserEvent>,
    shutdown_receiver: broadcast::Receiver<()>,
}

#[derive(Debug, Clone)]
pub struct GeyserState {
    pub connected: bool,
    pub last_slot: Slot,
    pub events_processed: u64,
    pub transactions_analyzed: u64,
    pub accounts_tracked: u64,
    pub connection_uptime: std::time::Instant,
    pub last_error: Option<String>,
    pub buffer_size: usize,
    pub buffer_utilization: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GeyserEvent {
    SlotUpdate {
        slot: Slot,
        parent: Option<Slot>,
        status: SlotStatus,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    AccountUpdate {
        pubkey: String,
        account: AccountInfo,
        slot: Slot,
        is_startup: bool,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    TransactionUpdate {
        signature: String,
        transaction: TransactionInfo,
        slot: Slot,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    BlockUpdate {
        slot: Slot,
        blockhash: String,
        rewards: Vec<RewardInfo>,
        block_time: Option<i64>,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlotStatus {
    Processed,
    Confirmed,
    Finalized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub lamports: u64,
    pub data: Vec<u8>,
    pub owner: String,
    pub executable: bool,
    pub rent_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    pub signature: String,
    pub is_vote: bool,
    pub compute_units_consumed: Option<u64>,
    pub fee: u64,
    pub accounts: Vec<String>,
    pub log_messages: Vec<String>,
    pub status: TransactionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    Success,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardInfo {
    pub pubkey: String,
    pub lamports: i64,
    pub post_balance: u64,
    pub reward_type: Option<String>,
    pub commission: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GeyserSubscribeRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct GeyserResponse {
    jsonrpc: String,
    id: Option<u64>,
    result: Option<serde_json::Value>,
    error: Option<GeyserError>,
    method: Option<String>,
    params: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GeyserError {
    code: i32,
    message: String,
}

impl GeyserClient {
    pub async fn new(
        config: Config,
        metrics: Arc<MetricsCollector>,
        risk_engine: Arc<RiskDetectionEngine>,
        shutdown_receiver: broadcast::Receiver<()>,
    ) -> ZKResult<Self> {
        info!("🌊 Initializing Geyser client for endpoint: {}", config.solana.geyser.endpoint);

        let (event_sender, _) = broadcast::channel(config.solana.geyser.buffer_size);
        
        let state = Arc::new(RwLock::new(GeyserState {
            connected: false,
            last_slot: 0,
            events_processed: 0,
            transactions_analyzed: 0,
            accounts_tracked: 0,
            connection_uptime: std::time::Instant::now(),
            last_error: None,
            buffer_size: config.solana.geyser.buffer_size,
            buffer_utilization: 0.0,
        }));

        Ok(Self {
            config,
            metrics,
            risk_engine,
            state,
            event_sender,
            shutdown_receiver,
        })
    }

    /// Start the Geyser client and begin streaming data
    pub async fn start(&self) -> ZKResult<()> {
        info!("🚀 Starting Geyser client");

        if self.config.system.dry_run {
            info!("🧪 Running in dry-run mode - simulating Geyser connection");
            return self.run_dry_mode().await;
        }

        // Connect to Geyser endpoint
        let ws_url = &self.config.solana.geyser.endpoint;
        let (ws_stream, _) = connect_async(ws_url).await
            .map_err(|e| ZKError::GeyserError(format!("Failed to connect to Geyser: {}", e)))?;

        info!("✅ Connected to Geyser endpoint: {}", ws_url);

        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        // Update connection state
        {
            let mut state = self.state.write().await;
            state.connected = true;
            state.connection_uptime = std::time::Instant::now();
        }

        // Subscribe to all event types
        self.subscribe_to_events(&mut ws_sender).await?;

        // Start event processing loop
        let state = Arc::clone(&self.state);
        let metrics = Arc::clone(&self.metrics);
        let risk_engine = Arc::clone(&self.risk_engine);
        let event_sender = self.event_sender.clone();
        let mut shutdown_rx = self.shutdown_receiver.resubscribe();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    message = ws_receiver.next() => {
                        match message {
                            Some(Ok(msg)) => {
                                if let Err(e) = Self::process_geyser_message(
                                    msg, 
                                    &state, 
                                    &metrics, 
                                    &risk_engine, 
                                    &event_sender
                                ).await {
                                    error!("Failed to process Geyser message: {}", e);
                                }
                            }
                            Some(Err(e)) => {
                                error!("WebSocket error: {}", e);
                                break;
                            }
                            None => {
                                warn!("Geyser connection closed");
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("🔄 Shutting down Geyser client");
                        break;
                    }
                }
            }

            // Update disconnection state
            let mut state_write = state.write().await;
            state_write.connected = false;
        });

        info!("✅ Geyser client started successfully");
        Ok(())
    }

    async fn subscribe_to_events(
        &self,
        ws_sender: &mut futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
            Message,
        >,
    ) -> ZKResult<()> {
        info!("📡 Subscribing to Geyser events");

        // Subscribe to slot updates
        let slot_subscription = GeyserSubscribeRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "slotSubscribe".to_string(),
            params: serde_json::json!({}),
        };

        ws_sender.send(Message::Text(serde_json::to_string(&slot_subscription)?)).await
            .map_err(|e| ZKError::GeyserError(format!("Failed to subscribe to slots: {}", e)))?;

        // Subscribe to transaction updates
        let transaction_subscription = GeyserSubscribeRequest {
            jsonrpc: "2.0".to_string(),
            id: 2,
            method: "transactionSubscribe".to_string(),
            params: serde_json::json!({
                "vote": false,
                "failed": true,
                "signature": null,
                "accountInclude": [],
                "accountExclude": [],
                "accountRequired": []
            }),
        };

        ws_sender.send(Message::Text(serde_json::to_string(&transaction_subscription)?)).await
            .map_err(|e| ZKError::GeyserError(format!("Failed to subscribe to transactions: {}", e)))?;

        // Subscribe to account updates for specific programs
        let account_subscription = GeyserSubscribeRequest {
            jsonrpc: "2.0".to_string(),
            id: 3,
            method: "accountSubscribe".to_string(),
            params: serde_json::json!({
                "account": [],
                "owner": ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"], // SPL Token program
                "filters": []
            }),
        };

        ws_sender.send(Message::Text(serde_json::to_string(&account_subscription)?)).await
            .map_err(|e| ZKError::GeyserError(format!("Failed to subscribe to accounts: {}", e)))?;

        // Subscribe to block updates
        let block_subscription = GeyserSubscribeRequest {
            jsonrpc: "2.0".to_string(),
            id: 4,
            method: "blockSubscribe".to_string(),
            params: serde_json::json!({
                "mentionsAccountOrProgram": null,
                "showRewards": true,
                "transactionDetails": "signatures"
            }),
        };

        ws_sender.send(Message::Text(serde_json::to_string(&block_subscription)?)).await
            .map_err(|e| ZKError::GeyserError(format!("Failed to subscribe to blocks: {}", e)))?;

        info!("✅ Subscribed to all Geyser event types");
        Ok(())
    }

    async fn process_geyser_message(
        message: Message,
        state: &Arc<RwLock<GeyserState>>,
        metrics: &Arc<MetricsCollector>,
        risk_engine: &Arc<RiskDetectionEngine>,
        event_sender: &broadcast::Sender<GeyserEvent>,
    ) -> ZKResult<()> {
        let text = match message {
            Message::Text(text) => text,
            Message::Binary(_) => return Ok(()), // Skip binary messages
            Message::Close(_) => {
                warn!("Received close message from Geyser");
                return Ok(());
            }
            _ => return Ok(()),
        };

        let response: GeyserResponse = serde_json::from_str(&text)
            .map_err(|e| ZKError::GeyserError(format!("Failed to parse Geyser response: {}", e)))?;

        if let Some(error) = response.error {
            error!("Geyser error: {} - {}", error.code, error.message);
            return Err(ZKError::GeyserError(format!("Geyser error: {}", error.message)));
        }

        // Process different event types
        if let Some(method) = response.method {
            match method.as_str() {
                "slotNotification" => {
                    Self::process_slot_update(&response, state, event_sender).await?;
                }
                "transactionNotification" => {
                    Self::process_transaction_update(&response, state, metrics, risk_engine, event_sender).await?;
                }
                "accountNotification" => {
                    Self::process_account_update(&response, state, event_sender).await?;
                }
                "blockNotification" => {
                    Self::process_block_update(&response, state, event_sender).await?;
                }
                _ => {
                    debug!("Unknown Geyser method: {}", method);
                }
            }
        }

        // Update metrics
        metrics.geyser_events_processed.inc();

        // Update state
        {
            let mut state_write = state.write().await;
            state_write.events_processed += 1;
            
            // Calculate buffer utilization
            let current_buffer_size = event_sender.len();
            state_write.buffer_utilization = current_buffer_size as f64 / state_write.buffer_size as f64;
        }

        Ok(())
    }

    async fn process_slot_update(
        response: &GeyserResponse,
        state: &Arc<RwLock<GeyserState>>,
        event_sender: &broadcast::Sender<GeyserEvent>,
    ) -> ZKResult<()> {
        if let Some(params) = &response.params {
            if let Some(slot_info) = params.get("result") {
                let slot = slot_info.get("slot")
                    .and_then(|s| s.as_u64())
                    .ok_or_else(|| ZKError::GeyserError("Invalid slot in notification".to_string()))?;

                let parent = slot_info.get("parent").and_then(|p| p.as_u64());
                
                let status = match slot_info.get("status").and_then(|s| s.as_str()) {
                    Some("processed") => SlotStatus::Processed,
                    Some("confirmed") => SlotStatus::Confirmed,
                    Some("finalized") => SlotStatus::Finalized,
                    _ => SlotStatus::Processed,
                };

                let event = GeyserEvent::SlotUpdate {
                    slot,
                    parent,
                    status,
                    timestamp: chrono::Utc::now(),
                };

                // Update state
                {
                    let mut state_write = state.write().await;
                    state_write.last_slot = slot;
                }

                // Send event
                if let Err(e) = event_sender.send(event) {
                    debug!("No receivers for slot event: {}", e);
                }

                debug!("📊 Processed slot update: {}", slot);
            }
        }

        Ok(())
    }

    async fn process_transaction_update(
        response: &GeyserResponse,
        state: &Arc<RwLock<GeyserState>>,
        metrics: &Arc<MetricsCollector>,
        risk_engine: &Arc<RiskDetectionEngine>,
        event_sender: &broadcast::Sender<GeyserEvent>,
    ) -> ZKResult<()> {
        if let Some(params) = &response.params {
            if let Some(tx_info) = params.get("result") {
                let signature = tx_info.get("signature")
                    .and_then(|s| s.as_str())
                    .ok_or_else(|| ZKError::GeyserError("Invalid signature in transaction".to_string()))?
                    .to_string();

                let slot = tx_info.get("slot")
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0);

                // Extract transaction details
                let transaction_info = TransactionInfo {
                    signature: signature.clone(),
                    is_vote: tx_info.get("is_vote").and_then(|v| v.as_bool()).unwrap_or(false),
                    compute_units_consumed: tx_info.get("compute_units_consumed").and_then(|c| c.as_u64()),
                    fee: tx_info.get("fee").and_then(|f| f.as_u64()).unwrap_or(0),
                    accounts: tx_info.get("accounts")
                        .and_then(|a| a.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                    log_messages: tx_info.get("log_messages")
                        .and_then(|l| l.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                    status: if tx_info.get("err").is_some() {
                        TransactionStatus::Failed("Transaction failed".to_string())
                    } else {
                        TransactionStatus::Success
                    },
                };

                // Skip vote transactions for risk analysis
                if !transaction_info.is_vote {
                    // Perform risk analysis (this would need the full transaction data)
                    // For now, we'll increment the counter
                    {
                        let mut state_write = state.write().await;
                        state_write.transactions_analyzed += 1;
                    }
                }

                let event = GeyserEvent::TransactionUpdate {
                    signature,
                    transaction: transaction_info,
                    slot,
                    timestamp: chrono::Utc::now(),
                };

                // Send event
                if let Err(e) = event_sender.send(event) {
                    debug!("No receivers for transaction event: {}", e);
                }

                debug!("💳 Processed transaction update");
            }
        }

        Ok(())
    }

    async fn process_account_update(
        response: &GeyserResponse,
        state: &Arc<RwLock<GeyserState>>,
        event_sender: &broadcast::Sender<GeyserEvent>,
    ) -> ZKResult<()> {
        if let Some(params) = &response.params {
            if let Some(account_info) = params.get("result") {
                let pubkey = account_info.get("pubkey")
                    .and_then(|p| p.as_str())
                    .ok_or_else(|| ZKError::GeyserError("Invalid pubkey in account".to_string()))?
                    .to_string();

                let slot = account_info.get("slot")
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0);

                let is_startup = account_info.get("is_startup")
                    .and_then(|s| s.as_bool())
                    .unwrap_or(false);

                // Extract account data
                let account = if let Some(account_data) = account_info.get("account") {
                    AccountInfo {
                        lamports: account_data.get("lamports").and_then(|l| l.as_u64()).unwrap_or(0),
                        data: account_data.get("data")
                            .and_then(|d| d.as_str())
                            .and_then(|s| base64::decode(s).ok())
                            .unwrap_or_default(),
                        owner: account_data.get("owner").and_then(|o| o.as_str()).unwrap_or("").to_string(),
                        executable: account_data.get("executable").and_then(|e| e.as_bool()).unwrap_or(false),
                        rent_epoch: account_data.get("rent_epoch").and_then(|r| r.as_u64()).unwrap_or(0),
                    }
                } else {
                    return Err(ZKError::GeyserError("Missing account data".to_string()));
                };

                let event = GeyserEvent::AccountUpdate {
                    pubkey,
                    account,
                    slot,
                    is_startup,
                    timestamp: chrono::Utc::now(),
                };

                // Update state
                {
                    let mut state_write = state.write().await;
                    state_write.accounts_tracked += 1;
                }

                // Send event
                if let Err(e) = event_sender.send(event) {
                    debug!("No receivers for account event: {}", e);
                }

                debug!("👤 Processed account update");
            }
        }

        Ok(())
    }

    async fn process_block_update(
        response: &GeyserResponse,
        state: &Arc<RwLock<GeyserState>>,
        event_sender: &broadcast::Sender<GeyserEvent>,
    ) -> ZKResult<()> {
        if let Some(params) = &response.params {
            if let Some(block_info) = params.get("result") {
                let slot = block_info.get("slot")
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0);

                let blockhash = block_info.get("blockhash")
                    .and_then(|b| b.as_str())
                    .unwrap_or("")
                    .to_string();

                let block_time = block_info.get("block_time")
                    .and_then(|t| t.as_i64());

                let rewards = block_info.get("rewards")
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter().filter_map(|reward| {
                            Some(RewardInfo {
                                pubkey: reward.get("pubkey")?.as_str()?.to_string(),
                                lamports: reward.get("lamports")?.as_i64()?,
                                post_balance: reward.get("post_balance")?.as_u64()?,
                                reward_type: reward.get("reward_type").and_then(|t| t.as_str()).map(|s| s.to_string()),
                                commission: reward.get("commission").and_then(|c| c.as_u64()).map(|c| c as u8),
                            })
                        }).collect()
                    })
                    .unwrap_or_default();

                let event = GeyserEvent::BlockUpdate {
                    slot,
                    blockhash,
                    rewards,
                    block_time,
                    timestamp: chrono::Utc::now(),
                };

                // Send event
                if let Err(e) = event_sender.send(event) {
                    debug!("No receivers for block event: {}", e);
                }

                debug!("🧱 Processed block update: {}", slot);
            }
        }

        Ok(())
    }

    async fn run_dry_mode(&self) -> ZKResult<()> {
        info!("🧪 Running Geyser client in dry-run mode");
        
        // Simulate connection
        {
            let mut state = self.state.write().await;
            state.connected = true;
            state.connection_uptime = std::time::Instant::now();
        }

        // Simulate periodic events
        let mut shutdown_rx = self.shutdown_receiver.resubscribe();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        let mut slot_counter = 100_000_000u64;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Simulate slot update
                    let event = GeyserEvent::SlotUpdate {
                        slot: slot_counter,
                        parent: Some(slot_counter - 1),
                        status: SlotStatus::Confirmed,
                        timestamp: chrono::Utc::now(),
                    };

                    if let Err(e) = self.event_sender.send(event) {
                        debug!("No receivers for simulated event: {}", e);
                    }

                    slot_counter += 1;

                    // Update state
                    {
                        let mut state = self.state.write().await;
                        state.last_slot = slot_counter;
                        state.events_processed += 1;
                    }

                    debug!("🎭 Simulated slot update: {}", slot_counter);
                }
                _ = shutdown_rx.recv() => {
                    info!("🔄 Shutting down dry-run Geyser client");
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn subscribe_to_events(&self) -> broadcast::Receiver<GeyserEvent> {
        self.event_sender.subscribe()
    }

    pub async fn get_state(&self) -> GeyserState {
        self.state.read().await.clone()
    }
}
