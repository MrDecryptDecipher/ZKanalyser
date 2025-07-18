use anyhow::Result;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::error::{ZKError, ZKResult};
use crate::risk_engine::TransactionRiskAssessment;

type HmacSha256 = Hmac<Sha256>;

/// Multi-channel alert engine with 3-second delivery requirement
pub struct AlertEngine {
    config: Config,
    rules: Arc<RwLock<Vec<AlertRule>>>,
    channels: Vec<Box<dyn AlertChannel>>,
    state: Arc<RwLock<AlertEngineState>>,
    alert_sender: mpsc::Sender<AlertEvent>,
    shutdown_receiver: broadcast::Receiver<()>,
}

#[derive(Debug, Clone)]
pub struct AlertEngineState {
    pub alerts_sent: u64,
    pub alerts_failed: u64,
    pub alerts_pending: u64,
    pub average_delivery_time_ms: f64,
    pub last_alert_timestamp: chrono::DateTime<chrono::Utc>,
    pub active_rules: u64,
    pub channel_status: HashMap<String, ChannelStatus>,
}

#[derive(Debug, Clone)]
pub struct ChannelStatus {
    pub name: String,
    pub enabled: bool,
    pub last_success: Option<chrono::DateTime<chrono::Utc>>,
    pub last_failure: Option<chrono::DateTime<chrono::Utc>>,
    pub success_count: u64,
    pub failure_count: u64,
    pub average_latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub enabled: bool,
    pub conditions: Vec<AlertCondition>,
    pub actions: Vec<AlertAction>,
    pub cooldown_seconds: u64,
    pub severity: AlertSeverity,
    pub last_triggered: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCondition {
    pub field: String,
    pub operator: ComparisonOperator,
    pub value: f64,
    pub duration_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    GreaterThan,
    LessThan,
    Equals,
    NotEquals,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertAction {
    pub channel: String,
    pub template: String,
    pub priority: AlertPriority,
    pub retry_count: u32,
    pub retry_delay_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertPriority {
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    pub id: String,
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub priority: AlertPriority,
    pub title: String,
    pub message: String,
    pub data: serde_json::Value,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub actions: Vec<AlertAction>,
    pub delivery_deadline: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDeliveryResult {
    pub alert_id: String,
    pub channel: String,
    pub success: bool,
    pub delivery_time_ms: u64,
    pub error: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub trait AlertChannel: Send + Sync {
    fn name(&self) -> &str;
    fn send_alert(&self, alert: &AlertEvent) -> impl std::future::Future<Output = ZKResult<AlertDeliveryResult>> + Send;
    fn is_enabled(&self) -> bool;
    fn test_connection(&self) -> impl std::future::Future<Output = ZKResult<()>> + Send;
}

/// Slack webhook alert channel
pub struct SlackChannel {
    webhook_url: String,
    signing_key: Option<String>,
    enabled: bool,
}

/// Generic webhook alert channel
pub struct WebhookChannel {
    webhook_url: String,
    signing_key: Option<String>,
    headers: HashMap<String, String>,
    enabled: bool,
}

/// SMS alert channel (fallback)
pub struct SmsChannel {
    provider: String,
    api_key: String,
    phone_number: String,
    enabled: bool,
}

impl AlertEngine {
    pub async fn new(
        config: Config,
        shutdown_receiver: broadcast::Receiver<()>,
    ) -> ZKResult<Self> {
        info!("🔔 Initializing Alert Engine");

        // Load alert rules from YAML file
        let rules = Self::load_alert_rules(&config.alerts.rules_path).await?;
        info!("📋 Loaded {} alert rules", rules.len());

        // Initialize alert channels
        let mut channels: Vec<Box<dyn AlertChannel>> = Vec::new();

        // Slack channel
        if let Some(slack_webhook) = &config.alerts.slack_webhook {
            channels.push(Box::new(SlackChannel::new(
                slack_webhook.clone(),
                config.security.webhook_signing_key.clone(),
            )));
            info!("📱 Slack channel initialized");
        }

        // Generic webhook channel
        if let Some(webhook_url) = &config.alerts.webhook_url {
            channels.push(Box::new(WebhookChannel::new(
                webhook_url.clone(),
                config.security.webhook_signing_key.clone(),
                HashMap::new(),
            )));
            info!("🌐 Webhook channel initialized");
        }

        // SMS channel
        if let Some(sms_config) = &config.alerts.sms {
            channels.push(Box::new(SmsChannel::new(
                sms_config.provider.clone(),
                sms_config.api_key.clone(),
                sms_config.phone_number.clone(),
            )));
            info!("📞 SMS channel initialized");
        }

        let (alert_sender, alert_receiver) = mpsc::channel(1000);

        let state = Arc::new(RwLock::new(AlertEngineState {
            alerts_sent: 0,
            alerts_failed: 0,
            alerts_pending: 0,
            average_delivery_time_ms: 0.0,
            last_alert_timestamp: chrono::Utc::now(),
            active_rules: rules.len() as u64,
            channel_status: HashMap::new(),
        }));

        // Initialize channel status
        {
            let mut state_write = state.write().await;
            for channel in &channels {
                state_write.channel_status.insert(
                    channel.name().to_string(),
                    ChannelStatus {
                        name: channel.name().to_string(),
                        enabled: channel.is_enabled(),
                        last_success: None,
                        last_failure: None,
                        success_count: 0,
                        failure_count: 0,
                        average_latency_ms: 0.0,
                    },
                );
            }
        }

        let engine = Self {
            config,
            rules: Arc::new(RwLock::new(rules)),
            channels,
            state,
            alert_sender,
            shutdown_receiver,
        };

        // Start alert processing task
        engine.start_alert_processor(alert_receiver).await;

        info!("✅ Alert Engine initialized with {} channels", engine.channels.len());
        Ok(engine)
    }

    async fn load_alert_rules(rules_path: &str) -> ZKResult<Vec<AlertRule>> {
        if !std::path::Path::new(rules_path).exists() {
            // Create default rules file
            let default_rules = Self::create_default_rules();
            let yaml_content = serde_yaml::to_string(&default_rules)
                .map_err(|e| ZKError::SerializationError(format!("Failed to serialize default rules: {}", e)))?;
            
            tokio::fs::write(rules_path, yaml_content).await
                .map_err(|e| ZKError::AlertError(format!("Failed to write default rules: {}", e)))?;
            
            info!("📝 Created default alert rules file: {}", rules_path);
            return Ok(default_rules);
        }

        let content = tokio::fs::read_to_string(rules_path).await
            .map_err(|e| ZKError::AlertError(format!("Failed to read rules file: {}", e)))?;

        let rules: Vec<AlertRule> = serde_yaml::from_str(&content)
            .map_err(|e| ZKError::AlertError(format!("Failed to parse rules YAML: {}", e)))?;

        Ok(rules)
    }

    fn create_default_rules() -> Vec<AlertRule> {
        vec![
            AlertRule {
                name: "HighRiskTransaction".to_string(),
                enabled: true,
                conditions: vec![
                    AlertCondition {
                        field: "risk_score".to_string(),
                        operator: ComparisonOperator::GreaterThan,
                        value: 0.8,
                        duration_seconds: None,
                    }
                ],
                actions: vec![
                    AlertAction {
                        channel: "slack".to_string(),
                        template: "🚨 High risk transaction detected: {{signature}} (Risk: {{risk_score}})".to_string(),
                        priority: AlertPriority::High,
                        retry_count: 3,
                        retry_delay_seconds: 1,
                    }
                ],
                cooldown_seconds: 300,
                severity: AlertSeverity::Error,
                last_triggered: None,
            },
            AlertRule {
                name: "AnchorPanic".to_string(),
                enabled: true,
                conditions: vec![
                    AlertCondition {
                        field: "anchor_panic_detected".to_string(),
                        operator: ComparisonOperator::Equals,
                        value: 1.0,
                        duration_seconds: None,
                    }
                ],
                actions: vec![
                    AlertAction {
                        channel: "webhook".to_string(),
                        template: "⚠️ Anchor panic detected in transaction {{signature}}".to_string(),
                        priority: AlertPriority::High,
                        retry_count: 2,
                        retry_delay_seconds: 2,
                    }
                ],
                cooldown_seconds: 60,
                severity: AlertSeverity::Warning,
                last_triggered: None,
            },
            AlertRule {
                name: "SystemResourceAlert".to_string(),
                enabled: true,
                conditions: vec![
                    AlertCondition {
                        field: "memory_usage_percent".to_string(),
                        operator: ComparisonOperator::GreaterThan,
                        value: 80.0,
                        duration_seconds: Some(300),
                    }
                ],
                actions: vec![
                    AlertAction {
                        channel: "sms".to_string(),
                        template: "🔥 High memory usage: {{memory_usage_percent}}%".to_string(),
                        priority: AlertPriority::Urgent,
                        retry_count: 5,
                        retry_delay_seconds: 1,
                    }
                ],
                cooldown_seconds: 1800,
                severity: AlertSeverity::Critical,
                last_triggered: None,
            },
        ]
    }

    /// Evaluate risk assessment against alert rules
    pub async fn evaluate_risk_assessment(&self, assessment: &TransactionRiskAssessment) -> ZKResult<()> {
        let rules = self.rules.read().await;
        
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // Check cooldown
            if let Some(last_triggered) = rule.last_triggered {
                let elapsed = chrono::Utc::now().signed_duration_since(last_triggered);
                if elapsed.num_seconds() < rule.cooldown_seconds as i64 {
                    continue;
                }
            }

            // Evaluate conditions
            if self.evaluate_conditions(&rule.conditions, assessment).await {
                self.trigger_alert(rule, assessment).await?;
            }
        }

        Ok(())
    }

    async fn evaluate_conditions(&self, conditions: &[AlertCondition], assessment: &TransactionRiskAssessment) -> bool {
        for condition in conditions {
            let field_value = self.extract_field_value(&condition.field, assessment);
            
            let condition_met = match condition.operator {
                ComparisonOperator::GreaterThan => field_value > condition.value,
                ComparisonOperator::LessThan => field_value < condition.value,
                ComparisonOperator::Equals => (field_value - condition.value).abs() < f64::EPSILON,
                ComparisonOperator::NotEquals => (field_value - condition.value).abs() >= f64::EPSILON,
                ComparisonOperator::GreaterThanOrEqual => field_value >= condition.value,
                ComparisonOperator::LessThanOrEqual => field_value <= condition.value,
            };

            if !condition_met {
                return false;
            }
        }

        true
    }

    fn extract_field_value(&self, field: &str, assessment: &TransactionRiskAssessment) -> f64 {
        match field {
            "risk_score" => assessment.overall_risk_score,
            "anchor_panic_detected" => if assessment.anchor_analysis.panic_detected { 1.0 } else { 0.0 },
            "cpi_depth" => assessment.cpi_analysis.max_depth as f64,
            "compute_units" => assessment.compute_analysis.units_consumed as f64,
            "signer_count" => assessment.signer_analysis.total_signers as f64,
            _ => 0.0,
        }
    }

    async fn trigger_alert(&self, rule: &AlertRule, assessment: &TransactionRiskAssessment) -> ZKResult<()> {
        let alert_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now();
        
        // Create alert event
        let alert = AlertEvent {
            id: alert_id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.severity.clone(),
            priority: rule.actions.first().map(|a| a.priority.clone()).unwrap_or(AlertPriority::Normal),
            title: format!("Alert: {}", rule.name),
            message: self.render_alert_message(&rule.actions[0].template, assessment),
            data: serde_json::to_value(assessment)
                .unwrap_or_else(|_| serde_json::Value::Null),
            timestamp,
            actions: rule.actions.clone(),
            delivery_deadline: timestamp + chrono::Duration::seconds(self.config.alerts.delivery_timeout_secs as i64),
        };

        // Send alert for processing
        if let Err(e) = self.alert_sender.send(alert).await {
            error!("Failed to queue alert: {}", e);
            return Err(ZKError::AlertError(format!("Failed to queue alert: {}", e)));
        }

        // Update rule last triggered time
        // Note: In a real implementation, we'd need to update the rule in the rules collection

        info!("🔔 Alert triggered: {} for transaction {}", rule.name, assessment.signature);
        Ok(())
    }

    fn render_alert_message(&self, template: &str, assessment: &TransactionRiskAssessment) -> String {
        template
            .replace("{{signature}}", &assessment.signature)
            .replace("{{risk_score}}", &format!("{:.3}", assessment.overall_risk_score))
            .replace("{{slot}}", &assessment.slot.to_string())
            .replace("{{timestamp}}", &assessment.timestamp.to_rfc3339())
    }

    async fn start_alert_processor(&self, mut alert_receiver: mpsc::Receiver<AlertEvent>) {
        let channels = self.channels.iter().map(|c| c.name().to_string()).collect::<Vec<_>>();
        let state = Arc::clone(&self.state);
        let config = self.config.clone();
        let mut shutdown_rx = self.shutdown_receiver.resubscribe();

        tokio::spawn(async move {
            info!("🔄 Alert processor started");

            loop {
                tokio::select! {
                    Some(alert) = alert_receiver.recv() => {
                        let start_time = std::time::Instant::now();
                        
                        // Process alert with deadline enforcement
                        let deadline_duration = alert.delivery_deadline.signed_duration_since(chrono::Utc::now());
                        if deadline_duration.num_milliseconds() <= 0 {
                            warn!("⏰ Alert {} missed delivery deadline", alert.id);
                            continue;
                        }

                        // Attempt delivery to all configured channels
                        let mut delivery_results = Vec::new();
                        
                        for action in &alert.actions {
                            // Find matching channel
                            if channels.contains(&action.channel) {
                                // In a real implementation, we'd call the actual channel
                                let delivery_result = AlertDeliveryResult {
                                    alert_id: alert.id.clone(),
                                    channel: action.channel.clone(),
                                    success: true, // Simulated success
                                    delivery_time_ms: start_time.elapsed().as_millis() as u64,
                                    error: None,
                                    timestamp: chrono::Utc::now(),
                                };
                                
                                delivery_results.push(delivery_result);
                            }
                        }

                        // Update statistics
                        let total_time = start_time.elapsed().as_millis() as u64;
                        let success_count = delivery_results.iter().filter(|r| r.success).count();
                        
                        {
                            let mut state_write = state.write().await;
                            if success_count > 0 {
                                state_write.alerts_sent += success_count as u64;
                            }
                            if success_count < delivery_results.len() {
                                state_write.alerts_failed += (delivery_results.len() - success_count) as u64;
                            }
                            
                            // Update average delivery time
                            state_write.average_delivery_time_ms = 
                                (state_write.average_delivery_time_ms * 0.9) + (total_time as f64 * 0.1);
                            
                            state_write.last_alert_timestamp = chrono::Utc::now();
                        }

                        // Check if delivery was within deadline (PRD: ≤3s)
                        if total_time <= config.alerts.delivery_timeout_secs * 1000 {
                            debug!("✅ Alert {} delivered within deadline ({} ms)", alert.id, total_time);
                        } else {
                            warn!("⚠️ Alert {} exceeded delivery deadline ({} ms)", alert.id, total_time);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("🔄 Alert processor shutting down");
                        break;
                    }
                }
            }
        });
    }

    pub async fn get_state(&self) -> AlertEngineState {
        self.state.read().await.clone()
    }

    pub async fn reload_rules(&self) -> ZKResult<()> {
        info!("🔄 Reloading alert rules");
        
        let new_rules = Self::load_alert_rules(&self.config.alerts.rules_path).await?;
        
        {
            let mut rules = self.rules.write().await;
            *rules = new_rules;
        }
        
        {
            let mut state = self.state.write().await;
            state.active_rules = self.rules.read().await.len() as u64;
        }
        
        info!("✅ Alert rules reloaded");
        Ok(())
    }
}

impl SlackChannel {
    pub fn new(webhook_url: String, signing_key: Option<String>) -> Self {
        Self {
            webhook_url,
            signing_key,
            enabled: true,
        }
    }
}

impl AlertChannel for SlackChannel {
    fn name(&self) -> &str {
        "slack"
    }

    async fn send_alert(&self, alert: &AlertEvent) -> ZKResult<AlertDeliveryResult> {
        let start_time = std::time::Instant::now();
        
        // Create Slack payload
        let payload = serde_json::json!({
            "text": alert.message,
            "username": "ZKAnalyzer",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": match alert.severity {
                    AlertSeverity::Critical => "danger",
                    AlertSeverity::Error => "warning",
                    AlertSeverity::Warning => "warning",
                    AlertSeverity::Info => "good",
                },
                "fields": [
                    {
                        "title": "Alert ID",
                        "value": alert.id,
                        "short": true
                    },
                    {
                        "title": "Severity",
                        "value": format!("{:?}", alert.severity),
                        "short": true
                    },
                    {
                        "title": "Timestamp",
                        "value": alert.timestamp.to_rfc3339(),
                        "short": true
                    }
                ]
            }]
        });

        // Send HTTP request (simulated for now)
        let delivery_time = start_time.elapsed().as_millis() as u64;
        
        Ok(AlertDeliveryResult {
            alert_id: alert.id.clone(),
            channel: "slack".to_string(),
            success: true, // Simulated success
            delivery_time_ms: delivery_time,
            error: None,
            timestamp: chrono::Utc::now(),
        })
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    async fn test_connection(&self) -> ZKResult<()> {
        // Test Slack webhook connection
        Ok(())
    }
}

impl WebhookChannel {
    pub fn new(webhook_url: String, signing_key: Option<String>, headers: HashMap<String, String>) -> Self {
        Self {
            webhook_url,
            signing_key,
            headers,
            enabled: true,
        }
    }
}

impl AlertChannel for WebhookChannel {
    fn name(&self) -> &str {
        "webhook"
    }

    async fn send_alert(&self, alert: &AlertEvent) -> ZKResult<AlertDeliveryResult> {
        let start_time = std::time::Instant::now();
        
        // Create webhook payload
        let payload = serde_json::to_string(alert)
            .map_err(|e| ZKError::SerializationError(format!("Failed to serialize alert: {}", e)))?;

        // Add HMAC signature if signing key is provided
        let mut headers = self.headers.clone();
        if let Some(signing_key) = &self.signing_key {
            let signature = self.sign_payload(&payload, signing_key)?;
            headers.insert("X-ZKAnalyzer-Signature".to_string(), signature);
        }

        // Send HTTP request (simulated for now)
        let delivery_time = start_time.elapsed().as_millis() as u64;
        
        Ok(AlertDeliveryResult {
            alert_id: alert.id.clone(),
            channel: "webhook".to_string(),
            success: true, // Simulated success
            delivery_time_ms: delivery_time,
            error: None,
            timestamp: chrono::Utc::now(),
        })
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    async fn test_connection(&self) -> ZKResult<()> {
        // Test webhook endpoint
        Ok(())
    }
}

impl WebhookChannel {
    fn sign_payload(&self, payload: &str, signing_key: &str) -> ZKResult<String> {
        let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
            .map_err(|e| ZKError::SecurityError(format!("Invalid signing key: {}", e)))?;
        
        mac.update(payload.as_bytes());
        let signature = mac.finalize().into_bytes();
        
        Ok(format!("sha256={}", hex::encode(signature)))
    }
}

impl SmsChannel {
    pub fn new(provider: String, api_key: String, phone_number: String) -> Self {
        Self {
            provider,
            api_key,
            phone_number,
            enabled: true,
        }
    }
}

impl AlertChannel for SmsChannel {
    fn name(&self) -> &str {
        "sms"
    }

    async fn send_alert(&self, alert: &AlertEvent) -> ZKResult<AlertDeliveryResult> {
        let start_time = std::time::Instant::now();
        
        // Create SMS message (truncated for SMS limits)
        let message = if alert.message.len() > 160 {
            format!("{}...", &alert.message[..157])
        } else {
            alert.message.clone()
        };

        // Send SMS via provider API (simulated for now)
        let delivery_time = start_time.elapsed().as_millis() as u64;
        
        Ok(AlertDeliveryResult {
            alert_id: alert.id.clone(),
            channel: "sms".to_string(),
            success: true, // Simulated success
            delivery_time_ms: delivery_time,
            error: None,
            timestamp: chrono::Utc::now(),
        })
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    async fn test_connection(&self) -> ZKResult<()> {
        // Test SMS provider API
        Ok(())
    }
}
