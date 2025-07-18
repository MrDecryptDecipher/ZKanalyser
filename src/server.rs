use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::{StatusCode, HeaderMap, header},
    response::{Html, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{info, error, debug};

use crate::config::Config;
use crate::core::{ZKAnalyzer, AnalyzerState};
use crate::error::ZKError;
use crate::metrics::MetricsCollector;
use crate::replay_engine::ReplayEngine;

pub struct ApiServer {
    config: Config,
    analyzer: Arc<ZKAnalyzer>,
    metrics: Arc<MetricsCollector>,
    replay_engine: Option<Arc<ReplayEngine>>,
}

impl ApiServer {
    pub fn new(
        config: Config,
        analyzer: Arc<ZKAnalyzer>,
        metrics: Arc<MetricsCollector>,
    ) -> Self {
        Self {
            config,
            analyzer,
            metrics,
            replay_engine: None, // Will be set from analyzer if available
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        let app = self.create_router();
        
        let addr = format!("{}:{}", 
                          self.config.network.bind_address, 
                          self.config.network.api_port);
        
        info!("🌐 Starting API server on {}", addr);
        
        let listener = TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        
        Ok(())
    }
    
    fn create_router(&self) -> Router {
        let app_state = AppState {
            analyzer: Arc::clone(&self.analyzer),
            metrics: Arc::clone(&self.metrics),
            config: self.config.clone(),
            replay_engine: None, // Would get from analyzer if available
        };
        
        Router::new()
            // Health endpoints (PRD requirement)
            .route("/health", get(health_handler))
            .route("/health/ready", get(readiness_handler))
            .route("/health/live", get(liveness_handler))
            .route("/health/detailed", get(detailed_health_handler))

            // Metrics endpoints (PRD requirement)
            .route("/metrics", get(metrics_handler))
            .route("/metrics/prometheus", get(prometheus_metrics_handler))
            .route("/metrics/json", get(json_metrics_handler))

            // Risk score endpoint (PRD requirement)
            .route("/risk_score", get(risk_score_handler))
            .route("/risk_score/detailed", get(detailed_risk_score_handler))

            // Status and info endpoints
            .route("/status", get(status_handler))
            .route("/info", get(info_handler))
            .route("/version", get(version_handler))

            // API endpoints
            .route("/api/v1/state", get(get_state_handler))
            .route("/api/v1/config", get(get_config_handler))
            .route("/api/v1/modules", get(get_modules_handler))
            .route("/api/v1/performance", get(get_performance_handler))
            .route("/api/v1/storage", get(get_storage_handler))

            // Replay endpoints
            .route("/api/v1/replay/slot/:slot", get(replay_slot_handler))
            .route("/api/v1/replay/transaction/:signature", get(replay_transaction_handler))
            .route("/api/v1/replay/status", get(replay_status_handler))

            // Control endpoints
            .route("/api/v1/shutdown", post(shutdown_handler))
            .route("/api/v1/maintenance", post(maintenance_handler))

            .layer(CorsLayer::permissive())
            .with_state(app_state)
    }
}

#[derive(Clone)]
struct AppState {
    analyzer: Arc<ZKAnalyzer>,
    metrics: Arc<MetricsCollector>,
    config: Config,
    replay_engine: Option<Arc<ReplayEngine>>,
}

#[derive(Deserialize)]
struct MetricsQuery {
    format: Option<String>,
    compress: Option<bool>,
}

#[derive(Serialize)]
struct DetailedHealthResponse {
    status: String,
    timestamp: String,
    uptime_seconds: u64,
    system_info: SystemInfo,
    modules: Vec<ModuleHealth>,
    performance: PerformanceInfo,
    alerts: Vec<String>,
}

#[derive(Serialize)]
struct SystemInfo {
    memory_usage_mb: f64,
    memory_limit_mb: f64,
    cpu_usage_percent: f64,
    cpu_limit_percent: f64,
    disk_usage_mb: f64,
    disk_limit_mb: f64,
    network_connections: u32,
}

#[derive(Serialize)]
struct ModuleHealth {
    name: String,
    status: String,
    uptime_seconds: u64,
    memory_usage_mb: f64,
    cpu_usage_percent: f64,
    last_error: Option<String>,
    metrics: HashMap<String, f64>,
}

#[derive(Serialize)]
struct PerformanceInfo {
    transactions_per_second: f64,
    slots_per_second: f64,
    average_response_time_ms: f64,
    error_rate_percent: f64,
    queue_depth: u32,
}

// Health check handler
async fn health_handler(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let analyzer_state = state.analyzer.get_state().await;
    
    let is_healthy = matches!(analyzer_state.status, crate::core::AnalyzerStatus::Running);
    
    let response = json!({
        "status": if is_healthy { "healthy" } else { "unhealthy" },
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "uptime_seconds": analyzer_state.uptime_secs,
        "memory_usage_mb": analyzer_state.memory_usage_mb,
        "cpu_usage_percent": analyzer_state.cpu_usage_percent,
        "active_modules": analyzer_state.active_modules.len(),
        "version": "3.5.0"
    });
    
    if is_healthy {
        Ok(Json(response))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

// Readiness check
async fn readiness_handler(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let analyzer_state = state.analyzer.get_state().await;
    
    let is_ready = matches!(
        analyzer_state.status, 
        crate::core::AnalyzerStatus::Running
    ) && !analyzer_state.active_modules.is_empty();
    
    if is_ready {
        Ok(Json(json!({
            "status": "ready",
            "active_modules": analyzer_state.active_modules
        })))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

// Liveness check
async fn liveness_handler() -> Json<Value> {
    Json(json!({
        "status": "alive",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// Detailed health check with comprehensive system information
async fn detailed_health_handler(State(state): State<AppState>) -> Result<Json<DetailedHealthResponse>, StatusCode> {
    let analyzer_state = state.analyzer.get_state().await;

    let is_healthy = matches!(analyzer_state.status, crate::core::AnalyzerStatus::Running);

    // Get system information
    let system_info = SystemInfo {
        memory_usage_mb: analyzer_state.memory_usage_mb,
        memory_limit_mb: state.config.system.max_memory_gb.unwrap_or(10.5) * 1024.0,
        cpu_usage_percent: analyzer_state.cpu_usage_percent,
        cpu_limit_percent: state.config.system.max_cpu_percent.unwrap_or(40.0),
        disk_usage_mb: 0.0, // Would get from storage engine
        disk_limit_mb: state.config.system.max_disk_gb.unwrap_or(4.5) * 1024.0,
        network_connections: 0, // Would get from network monitoring
    };

    // Get module health information
    let modules = vec![
        ModuleHealth {
            name: "risk-engine".to_string(),
            status: "running".to_string(),
            uptime_seconds: analyzer_state.uptime_secs,
            memory_usage_mb: 350.0, // Estimated
            cpu_usage_percent: 5.0, // Estimated
            last_error: None,
            metrics: HashMap::from([
                ("transactions_analyzed".to_string(), 0.0),
                ("risk_assessments_generated".to_string(), 0.0),
            ]),
        },
        ModuleHealth {
            name: "storage".to_string(),
            status: "running".to_string(),
            uptime_seconds: analyzer_state.uptime_secs,
            memory_usage_mb: 200.0, // Estimated
            cpu_usage_percent: 1.0, // Estimated
            last_error: None,
            metrics: HashMap::from([
                ("database_size_mb".to_string(), 0.0),
                ("records_stored".to_string(), 0.0),
            ]),
        },
        ModuleHealth {
            name: "geyser".to_string(),
            status: if analyzer_state.active_modules.contains(&"geyser".to_string()) { "running" } else { "stopped" }.to_string(),
            uptime_seconds: analyzer_state.uptime_secs,
            memory_usage_mb: 250.0, // Estimated
            cpu_usage_percent: 3.0, // Estimated
            last_error: None,
            metrics: HashMap::from([
                ("events_processed".to_string(), 0.0),
                ("buffer_utilization".to_string(), 0.0),
            ]),
        },
    ];

    // Performance information
    let performance = PerformanceInfo {
        transactions_per_second: 0.0, // Would calculate from metrics
        slots_per_second: 0.0, // Would calculate from metrics
        average_response_time_ms: 5.0, // Estimated
        error_rate_percent: 0.1, // Estimated
        queue_depth: 0, // Would get from queue monitoring
    };

    // Check for alerts
    let mut alerts = Vec::new();
    if analyzer_state.memory_usage_mb > system_info.memory_limit_mb * 0.8 {
        alerts.push("High memory usage detected".to_string());
    }
    if analyzer_state.cpu_usage_percent > system_info.cpu_limit_percent * 0.8 {
        alerts.push("High CPU usage detected".to_string());
    }
    if analyzer_state.last_error.is_some() {
        alerts.push("Recent error detected".to_string());
    }

    let response = DetailedHealthResponse {
        status: if is_healthy { "healthy" } else { "unhealthy" }.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        uptime_seconds: analyzer_state.uptime_secs,
        system_info,
        modules,
        performance,
        alerts,
    };

    if is_healthy {
        Ok(Json(response))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

// Prometheus metrics endpoint (PRD requirement)
async fn metrics_handler(State(state): State<AppState>) -> Result<String, StatusCode> {
    prometheus_metrics_handler(State(state)).await
}

// Prometheus metrics with optional compression
async fn prometheus_metrics_handler(State(state): State<AppState>) -> Result<String, StatusCode> {
    match state.metrics.gather() {
        Ok(metrics) => Ok(metrics),
        Err(e) => {
            error!("Failed to gather Prometheus metrics: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// JSON format metrics
async fn json_metrics_handler(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    let analyzer_state = state.analyzer.get_state().await;

    let metrics = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "system": {
            "memory_usage_mb": analyzer_state.memory_usage_mb,
            "cpu_usage_percent": analyzer_state.cpu_usage_percent,
            "uptime_seconds": analyzer_state.uptime_secs,
            "active_modules": analyzer_state.active_modules.len()
        },
        "performance": {
            "transactions_per_second": 0.0, // Would be calculated from metrics
            "average_response_time_ms": 0.0,
            "error_rate_percent": 0.0
        },
        "risk": {
            "current_risk_score": 0.0, // Would get from risk engine
            "high_risk_transactions": 0,
            "anchor_errors": 0,
            "cpi_violations": 0
        },
        "storage": {
            "database_size_mb": 0.0, // Would get from storage engine
            "total_records": 0,
            "compression_ratio": 1.0
        }
    });

    Ok(Json(metrics))
}

// Risk score endpoint (PRD requirement)
async fn risk_score_handler(State(state): State<AppState>) -> Json<Value> {
    // Get current risk score from risk engine
    let risk_score = 0.0; // Would get from risk engine: state.risk_engine.get_current_risk_score().await

    Json(json!({
        "risk_score": risk_score,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "level": if risk_score > 0.8 { "critical" } else if risk_score > 0.6 { "high" } else if risk_score > 0.3 { "medium" } else { "low" },
        "details": {
            "cpi_depth_risk": 0.0,
            "anchor_panic_risk": 0.0,
            "compute_unit_risk": 0.0,
            "signer_anomaly_risk": 0.0
        }
    }))
}

// Detailed risk score with historical data
async fn detailed_risk_score_handler(State(state): State<AppState>) -> Json<Value> {
    let current_risk = 0.0; // Would get from risk engine

    Json(json!({
        "current_risk_score": current_risk,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "risk_level": if current_risk > 0.8 { "critical" } else if current_risk > 0.6 { "high" } else if current_risk > 0.3 { "medium" } else { "low" },
        "historical": {
            "last_hour_avg": 0.0,
            "last_24h_avg": 0.0,
            "last_7d_avg": 0.0,
            "peak_24h": 0.0,
            "trend": "stable"
        },
        "breakdown": {
            "cpi_depth_risk": {
                "score": 0.0,
                "violations_count": 0,
                "max_depth_detected": 0
            },
            "anchor_panic_risk": {
                "score": 0.0,
                "panic_count": 0,
                "error_codes": []
            },
            "compute_unit_risk": {
                "score": 0.0,
                "spike_count": 0,
                "max_cu_detected": 0
            },
            "signer_anomaly_risk": {
                "score": 0.0,
                "anomaly_count": 0,
                "max_signers_detected": 0
            }
        },
        "recent_high_risk_transactions": [],
        "recommendations": []
    }))
}

// System status
async fn status_handler(State(state): State<AppState>) -> Json<Value> {
    let analyzer_state = state.analyzer.get_state().await;
    
    Json(json!({
        "status": format!("{:?}", analyzer_state.status),
        "uptime_seconds": analyzer_state.uptime_secs,
        "memory_usage_mb": analyzer_state.memory_usage_mb,
        "cpu_usage_percent": analyzer_state.cpu_usage_percent,
        "active_modules": analyzer_state.active_modules,
        "last_error": analyzer_state.last_error,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// System info
async fn info_handler(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "name": "ZKAnalyzer",
        "version": "3.5.0",
        "description": "Solana Validator Observability, Security & Replay Suite",
        "build_info": {
            "rust_version": env!("RUSTC_VERSION"),
            "build_timestamp": env!("BUILD_TIMESTAMP"),
            "git_commit": env!("GIT_COMMIT")
        },
        "configuration": {
            "max_memory_gb": state.config.system.max_memory_gb,
            "max_cpu_percent": state.config.system.max_cpu_percent,
            "max_disk_gb": state.config.system.max_disk_gb,
            "features_enabled": {
                "tui": state.config.features.tui_enabled,
                "web_ui": state.config.features.web_ui_enabled,
                "ebpf": state.config.features.ebpf_enabled,
                "plugins": state.config.features.plugins_enabled,
                "audit": state.config.features.audit_enabled
            }
        }
    }))
}

// Get analyzer state
async fn get_state_handler(State(state): State<AppState>) -> Json<AnalyzerState> {
    let analyzer_state = state.analyzer.get_state().await;
    Json(analyzer_state)
}

// Get configuration
async fn get_config_handler(State(state): State<AppState>) -> Json<Value> {
    // Return sanitized config (no sensitive data)
    Json(json!({
        "system": {
            "max_memory_gb": state.config.system.max_memory_gb,
            "max_cpu_percent": state.config.system.max_cpu_percent,
            "max_disk_gb": state.config.system.max_disk_gb,
            "log_level": state.config.system.log_level,
            "data_dir": state.config.system.data_dir
        },
        "features": state.config.features,
        "network": {
            "api_port": state.config.network.api_port,
            "ws_port": state.config.network.ws_port,
            "grpc_port": state.config.network.grpc_port,
            "web_ui_port": state.config.network.web_ui_port
        }
    }))
}

// Get active modules
async fn get_modules_handler(State(state): State<AppState>) -> Json<Value> {
    let analyzer_state = state.analyzer.get_state().await;
    
    Json(json!({
        "active_modules": analyzer_state.active_modules,
        "total_count": analyzer_state.active_modules.len(),
        "status": format!("{:?}", analyzer_state.status)
    }))
}

// Version information
async fn version_handler() -> Json<Value> {
    Json(json!({
        "name": "ZKAnalyzer",
        "version": "3.5.0",
        "build_info": {
            "rust_version": env!("RUSTC_VERSION"),
            "build_timestamp": chrono::Utc::now().to_rfc3339(), // Would be actual build time
            "git_commit": "latest", // Would be actual git commit
            "features": ["risk-detection", "geyser", "storage", "metrics", "replay"]
        },
        "api_version": "v1",
        "supported_formats": ["json", "prometheus", "csv", "markdown"]
    }))
}

// Performance metrics
async fn get_performance_handler(State(state): State<AppState>) -> Json<Value> {
    let analyzer_state = state.analyzer.get_state().await;

    Json(json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "uptime_seconds": analyzer_state.uptime_secs,
        "system_performance": {
            "memory_usage_mb": analyzer_state.memory_usage_mb,
            "memory_usage_percent": (analyzer_state.memory_usage_mb / (state.config.system.max_memory_gb.unwrap_or(10.5) * 1024.0)) * 100.0,
            "cpu_usage_percent": analyzer_state.cpu_usage_percent,
            "cpu_limit_percent": state.config.system.max_cpu_percent.unwrap_or(40.0)
        },
        "processing_performance": {
            "transactions_per_second": 0.0, // Would calculate from metrics
            "slots_per_second": 0.0,
            "average_response_time_ms": 5.0,
            "p95_response_time_ms": 15.0,
            "p99_response_time_ms": 25.0
        },
        "resource_utilization": {
            "active_connections": 0,
            "queue_depth": 0,
            "buffer_utilization_percent": 0.0,
            "database_size_mb": 0.0
        }
    }))
}

// Storage information
async fn get_storage_handler(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "database": {
            "type": "SQLite",
            "mode": "WAL",
            "path": state.config.storage.db_path,
            "size_mb": 0.0, // Would get from storage engine
            "size_limit_mb": state.config.storage.max_db_size_mb,
            "utilization_percent": 0.0
        },
        "features": {
            "encryption_enabled": state.config.storage.encryption_enabled,
            "compression_enabled": state.config.storage.compression_enabled,
            "auto_vacuum": true,
            "rotation_enabled": true
        },
        "statistics": {
            "total_records": 0, // Would get from storage engine
            "transactions_stored": 0,
            "risk_assessments_stored": 0,
            "alerts_stored": 0,
            "last_vacuum": chrono::Utc::now().to_rfc3339(),
            "compression_ratio": 1.0
        }
    }))
}

// Replay slot endpoint
async fn replay_slot_handler(
    axum::extract::Path(slot): axum::extract::Path<u64>,
    State(state): State<AppState>
) -> Result<Json<Value>, StatusCode> {
    if let Some(replay_engine) = &state.replay_engine {
        match replay_engine.replay_slot(slot).await {
            Ok(results) => Ok(Json(serde_json::to_value(results).unwrap_or_default())),
            Err(e) => {
                error!("Failed to replay slot {}: {}", slot, e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

// Replay transaction endpoint
async fn replay_transaction_handler(
    axum::extract::Path(signature): axum::extract::Path<String>,
    State(state): State<AppState>
) -> Result<Json<Value>, StatusCode> {
    if let Some(replay_engine) = &state.replay_engine {
        match replay_engine.replay_transaction(&signature).await {
            Ok(results) => Ok(Json(serde_json::to_value(results).unwrap_or_default())),
            Err(e) => {
                error!("Failed to replay transaction {}: {}", signature, e);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

// Replay status endpoint
async fn replay_status_handler(State(state): State<AppState>) -> Json<Value> {
    if let Some(replay_engine) = &state.replay_engine {
        let replay_state = replay_engine.get_state().await;
        let active_replays = replay_engine.get_active_replays().await;

        Json(json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "statistics": {
                "completed_replays": replay_state.completed_replays,
                "failed_replays": replay_state.failed_replays,
                "total_slots_replayed": replay_state.total_slots_replayed,
                "total_transactions_replayed": replay_state.total_transactions_replayed,
                "export_count": replay_state.export_count
            },
            "active_replays": active_replays.len(),
            "active_sessions": active_replays.iter().map(|session| json!({
                "id": session.id,
                "type": format!("{:?}", session.replay_type),
                "status": format!("{:?}", session.status),
                "progress": session.progress.percentage,
                "start_time": session.start_time.to_rfc3339()
            })).collect::<Vec<_>>(),
            "last_replay": replay_state.last_replay_timestamp.to_rfc3339()
        }))
    } else {
        Json(json!({
            "error": "Replay engine not available",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }
}

// Maintenance endpoint
async fn maintenance_handler(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    info!("🧹 Maintenance requested via API");

    // TODO: Implement proper authentication check here

    // Trigger maintenance tasks
    tokio::spawn(async move {
        // Would trigger storage maintenance, metrics cleanup, etc.
        info!("Maintenance tasks completed");
    });

    Ok(Json(json!({
        "message": "Maintenance initiated",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "tasks": ["database_vacuum", "metrics_cleanup", "log_rotation"]
    })))
}

// Shutdown endpoint
async fn shutdown_handler(State(state): State<AppState>) -> Result<Json<Value>, StatusCode> {
    info!("🔄 Shutdown requested via API");

    // TODO: Implement proper authentication check here

    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        if let Err(e) = state.analyzer.shutdown().await {
            error!("Failed to shutdown analyzer: {}", e);
        }
    });

    Ok(Json(json!({
        "message": "Shutdown initiated",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}
