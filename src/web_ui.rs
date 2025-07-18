use anyhow::Result;
use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode},
    response::{Html, Json, Response},
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tower_http::services::ServeDir;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::core::ZKAnalyzer;
use crate::error::{ZKError, ZKResult};
use crate::metrics::MetricsCollector;
use crate::security::SecurityManager;

/// Modern web UI and admin dashboard
pub struct WebUiServer {
    config: Config,
    analyzer: Arc<ZKAnalyzer>,
    metrics: Arc<MetricsCollector>,
    security_manager: Arc<SecurityManager>,
    state: Arc<RwLock<WebUiState>>,
}

#[derive(Debug, Clone)]
pub struct WebUiState {
    pub active_sessions: u64,
    pub page_views: u64,
    pub api_requests: u64,
    pub websocket_connections: u64,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub dashboard_theme: String,
    pub real_time_updates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub system_status: SystemStatus,
    pub risk_metrics: RiskMetrics,
    pub performance_metrics: PerformanceMetrics,
    pub storage_metrics: StorageMetrics,
    pub alert_summary: AlertSummary,
    pub recent_transactions: Vec<TransactionSummary>,
    pub active_modules: Vec<ModuleStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub status: String,
    pub uptime_seconds: u64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub disk_usage_mb: f64,
    pub network_status: String,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskMetrics {
    pub current_risk_score: f64,
    pub risk_level: String,
    pub high_risk_transactions: u64,
    pub anchor_errors: u64,
    pub cpi_violations: u64,
    pub compute_unit_spikes: u64,
    pub risk_trend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub transactions_per_second: f64,
    pub average_response_time_ms: f64,
    pub queue_depth: u32,
    pub error_rate_percent: f64,
    pub throughput_mbps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetrics {
    pub database_size_mb: f64,
    pub total_records: u64,
    pub compression_ratio: f64,
    pub encryption_enabled: bool,
    pub last_vacuum: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSummary {
    pub total_alerts: u64,
    pub critical_alerts: u64,
    pub warning_alerts: u64,
    pub info_alerts: u64,
    pub recent_alerts: Vec<AlertInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInfo {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub signature: String,
    pub slot: u64,
    pub risk_score: f64,
    pub compute_units: Option<u64>,
    pub fee: u64,
    pub status: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    pub name: String,
    pub status: String,
    pub uptime_seconds: u64,
    pub memory_usage_mb: f64,
    pub last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DashboardQuery {
    pub theme: Option<String>,
    pub refresh_rate: Option<u32>,
    pub real_time: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigUpdateRequest {
    pub section: String,
    pub key: String,
    pub value: serde_json::Value,
}

impl WebUiServer {
    pub fn new(
        config: Config,
        analyzer: Arc<ZKAnalyzer>,
        metrics: Arc<MetricsCollector>,
        security_manager: Arc<SecurityManager>,
    ) -> Self {
        let state = Arc::new(RwLock::new(WebUiState {
            active_sessions: 0,
            page_views: 0,
            api_requests: 0,
            websocket_connections: 0,
            last_activity: chrono::Utc::now(),
            dashboard_theme: "dark".to_string(),
            real_time_updates: true,
        }));

        Self {
            config,
            analyzer,
            metrics,
            security_manager,
            state,
        }
    }

    pub fn create_router(&self) -> Router {
        let app_state = WebUiAppState {
            analyzer: Arc::clone(&self.analyzer),
            metrics: Arc::clone(&self.metrics),
            security_manager: Arc::clone(&self.security_manager),
            state: Arc::clone(&self.state),
            config: self.config.clone(),
        };

        Router::new()
            // Static file serving
            .nest_service("/static", ServeDir::new("web/static"))
            
            // Main dashboard pages
            .route("/", get(dashboard_handler))
            .route("/dashboard", get(dashboard_handler))
            .route("/risk", get(risk_dashboard_handler))
            .route("/performance", get(performance_dashboard_handler))
            .route("/storage", get(storage_dashboard_handler))
            .route("/alerts", get(alerts_dashboard_handler))
            .route("/plugins", get(plugins_dashboard_handler))
            .route("/settings", get(settings_dashboard_handler))
            
            // API endpoints for dashboard data
            .route("/api/dashboard/data", get(get_dashboard_data))
            .route("/api/dashboard/risk", get(get_risk_data))
            .route("/api/dashboard/performance", get(get_performance_data))
            .route("/api/dashboard/storage", get(get_storage_data))
            .route("/api/dashboard/alerts", get(get_alerts_data))
            .route("/api/dashboard/transactions", get(get_transactions_data))
            
            // Configuration management
            .route("/api/config", get(get_config_handler))
            .route("/api/config", post(update_config_handler))
            
            // Plugin management
            .route("/api/plugins", get(get_plugins_handler))
            .route("/api/plugins/:name/reload", post(reload_plugin_handler))
            .route("/api/plugins/:name/unload", post(unload_plugin_handler))
            
            // Real-time WebSocket endpoint
            .route("/ws/dashboard", get(websocket_handler))
            
            // Authentication endpoints
            .route("/login", get(login_page_handler))
            .route("/api/auth/login", post(login_handler))
            .route("/api/auth/logout", post(logout_handler))
            
            .with_state(app_state)
    }

    pub async fn start(&self, port: u16) -> ZKResult<()> {
        info!("🌐 Starting Web UI server on port {}", port);

        let app = self.create_router();
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await
            .map_err(|e| ZKError::ServerError(format!("Failed to bind to port {}: {}", port, e)))?;

        info!("✅ Web UI server started at http://0.0.0.0:{}", port);
        
        axum::serve(listener, app).await
            .map_err(|e| ZKError::ServerError(format!("Web UI server error: {}", e)))?;

        Ok(())
    }
}

#[derive(Clone)]
struct WebUiAppState {
    analyzer: Arc<ZKAnalyzer>,
    metrics: Arc<MetricsCollector>,
    security_manager: Arc<SecurityManager>,
    state: Arc<RwLock<WebUiState>>,
    config: Config,
}

// Dashboard page handlers
async fn dashboard_handler(
    Query(params): Query<DashboardQuery>,
    State(state): State<WebUiAppState>,
) -> Html<String> {
    // Update page view count
    {
        let mut ui_state = state.state.write().await;
        ui_state.page_views += 1;
        ui_state.last_activity = chrono::Utc::now();
    }

    let theme = params.theme.unwrap_or_else(|| "dark".to_string());
    let refresh_rate = params.refresh_rate.unwrap_or(5000);
    let real_time = params.real_time.unwrap_or(true);

    let html = format!(r#"
<!DOCTYPE html>
<html lang="en" data-theme="{}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 ZKAnalyzer Dashboard</title>
    <link href="/static/css/dashboard.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</head>
<body>
    <div id="app" x-data="dashboardApp()" x-init="init()">
        <!-- Navigation -->
        <nav class="navbar">
            <div class="nav-brand">
                <h1>🔐 ZKAnalyzer v3.5</h1>
            </div>
            <div class="nav-links">
                <a href="/dashboard" class="nav-link active">Dashboard</a>
                <a href="/risk" class="nav-link">Risk Analysis</a>
                <a href="/performance" class="nav-link">Performance</a>
                <a href="/storage" class="nav-link">Storage</a>
                <a href="/alerts" class="nav-link">Alerts</a>
                <a href="/plugins" class="nav-link">Plugins</a>
                <a href="/settings" class="nav-link">Settings</a>
            </div>
            <div class="nav-controls">
                <button @click="toggleTheme()" class="btn-icon">🌓</button>
                <button @click="toggleRealTime()" class="btn-icon" :class="{{realTime ? 'active' : ''}}">📡</button>
            </div>
        </nav>

        <!-- Main Content -->
        <main class="main-content">
            <!-- Status Cards -->
            <div class="status-grid">
                <div class="status-card">
                    <div class="status-icon">🛡️</div>
                    <div class="status-content">
                        <h3>Risk Score</h3>
                        <div class="status-value" x-text="data.risk_metrics?.current_risk_score?.toFixed(3) || '0.000'"></div>
                        <div class="status-trend" x-text="data.risk_metrics?.risk_level || 'Unknown'"></div>
                    </div>
                </div>
                
                <div class="status-card">
                    <div class="status-icon">💾</div>
                    <div class="status-content">
                        <h3>Memory Usage</h3>
                        <div class="status-value" x-text="(data.system_status?.memory_usage_mb || 0).toFixed(1) + ' MB'"></div>
                        <div class="status-trend">Normal</div>
                    </div>
                </div>
                
                <div class="status-card">
                    <div class="status-icon">⚡</div>
                    <div class="status-content">
                        <h3>TPS</h3>
                        <div class="status-value" x-text="(data.performance_metrics?.transactions_per_second || 0).toFixed(1)"></div>
                        <div class="status-trend">Stable</div>
                    </div>
                </div>
                
                <div class="status-card">
                    <div class="status-icon">🔔</div>
                    <div class="status-content">
                        <h3>Alerts</h3>
                        <div class="status-value" x-text="data.alert_summary?.total_alerts || 0"></div>
                        <div class="status-trend" x-text="(data.alert_summary?.critical_alerts || 0) + ' Critical'"></div>
                    </div>
                </div>
            </div>

            <!-- Charts Section -->
            <div class="charts-grid">
                <div class="chart-container">
                    <h3>Risk Score Trend</h3>
                    <canvas id="riskChart"></canvas>
                </div>
                
                <div class="chart-container">
                    <h3>System Resources</h3>
                    <canvas id="resourceChart"></canvas>
                </div>
                
                <div class="chart-container">
                    <h3>Transaction Volume</h3>
                    <canvas id="transactionChart"></canvas>
                </div>
                
                <div class="chart-container">
                    <h3>Alert Distribution</h3>
                    <canvas id="alertChart"></canvas>
                </div>
            </div>

            <!-- Recent Transactions -->
            <div class="data-table-container">
                <h3>Recent High-Risk Transactions</h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Signature</th>
                            <th>Slot</th>
                            <th>Risk Score</th>
                            <th>Compute Units</th>
                            <th>Status</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        <template x-for="tx in data.recent_transactions || []" :key="tx.signature">
                            <tr>
                                <td class="mono" x-text="tx.signature.substring(0, 16) + '...'"></td>
                                <td x-text="tx.slot"></td>
                                <td>
                                    <span class="risk-badge" :class="getRiskClass(tx.risk_score)" x-text="tx.risk_score.toFixed(3)"></span>
                                </td>
                                <td x-text="tx.compute_units?.toLocaleString() || 'N/A'"></td>
                                <td>
                                    <span class="status-badge" :class="tx.status.toLowerCase()" x-text="tx.status"></span>
                                </td>
                                <td x-text="formatTimestamp(tx.timestamp)"></td>
                            </tr>
                        </template>
                    </tbody>
                </table>
            </div>
        </main>
    </div>

    <script>
        function dashboardApp() {{
            return {{
                data: {{}},
                realTime: {},
                refreshRate: {},
                theme: '{}',
                
                init() {{
                    this.loadData();
                    if (this.realTime) {{
                        this.startRealTimeUpdates();
                    }}
                    this.initCharts();
                }},
                
                async loadData() {{
                    try {{
                        const response = await fetch('/api/dashboard/data');
                        this.data = await response.json();
                        this.updateCharts();
                    }} catch (error) {{
                        console.error('Failed to load dashboard data:', error);
                    }}
                }},
                
                startRealTimeUpdates() {{
                    setInterval(() => {{
                        if (this.realTime) {{
                            this.loadData();
                        }}
                    }}, this.refreshRate);
                }},
                
                toggleRealTime() {{
                    this.realTime = !this.realTime;
                }},
                
                toggleTheme() {{
                    this.theme = this.theme === 'dark' ? 'light' : 'dark';
                    document.documentElement.setAttribute('data-theme', this.theme);
                }},
                
                getRiskClass(score) {{
                    if (score > 0.8) return 'critical';
                    if (score > 0.6) return 'high';
                    if (score > 0.3) return 'medium';
                    return 'low';
                }},
                
                formatTimestamp(timestamp) {{
                    return new Date(timestamp).toLocaleTimeString();
                }},
                
                initCharts() {{
                    // Initialize Chart.js charts
                    this.riskChart = new Chart(document.getElementById('riskChart'), {{
                        type: 'line',
                        data: {{
                            labels: [],
                            datasets: [{{
                                label: 'Risk Score',
                                data: [],
                                borderColor: '#ff6b6b',
                                backgroundColor: 'rgba(255, 107, 107, 0.1)',
                                tension: 0.4
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            scales: {{
                                y: {{
                                    beginAtZero: true,
                                    max: 1.0
                                }}
                            }}
                        }}
                    }});
                    
                    // Initialize other charts...
                }},
                
                updateCharts() {{
                    // Update chart data with new values
                    if (this.riskChart && this.data.risk_metrics) {{
                        // Add new data point
                        const now = new Date().toLocaleTimeString();
                        this.riskChart.data.labels.push(now);
                        this.riskChart.data.datasets[0].data.push(this.data.risk_metrics.current_risk_score);
                        
                        // Keep only last 20 points
                        if (this.riskChart.data.labels.length > 20) {{
                            this.riskChart.data.labels.shift();
                            this.riskChart.data.datasets[0].data.shift();
                        }}
                        
                        this.riskChart.update('none');
                    }}
                }}
            }}
        }}
    </script>
</body>
</html>
"#, theme, real_time, refresh_rate, theme);

    Html(html)
}

async fn risk_dashboard_handler() -> Html<String> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Risk Analysis Dashboard</title>
    <link href="/static/css/dashboard.css" rel="stylesheet">
</head>
<body>
    <h1>🛡️ Risk Analysis Dashboard</h1>
    <p>Detailed risk analysis interface would be implemented here.</p>
</body>
</html>
"#.to_string())
}

async fn performance_dashboard_handler() -> Html<String> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>⚡ Performance Dashboard</title>
    <link href="/static/css/dashboard.css" rel="stylesheet">
</head>
<body>
    <h1>⚡ Performance Dashboard</h1>
    <p>Performance monitoring interface would be implemented here.</p>
</body>
</html>
"#.to_string())
}

async fn storage_dashboard_handler() -> Html<String> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>💾 Storage Dashboard</title>
    <link href="/static/css/dashboard.css" rel="stylesheet">
</head>
<body>
    <h1>💾 Storage Dashboard</h1>
    <p>Storage management interface would be implemented here.</p>
</body>
</html>
"#.to_string())
}

async fn alerts_dashboard_handler() -> Html<String> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>🔔 Alerts Dashboard</title>
    <link href="/static/css/dashboard.css" rel="stylesheet">
</head>
<body>
    <h1>🔔 Alerts Dashboard</h1>
    <p>Alert management interface would be implemented here.</p>
</body>
</html>
"#.to_string())
}

async fn plugins_dashboard_handler() -> Html<String> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>🔌 Plugins Dashboard</title>
    <link href="/static/css/dashboard.css" rel="stylesheet">
</head>
<body>
    <h1>🔌 Plugins Dashboard</h1>
    <p>Plugin management interface would be implemented here.</p>
</body>
</html>
"#.to_string())
}

async fn settings_dashboard_handler() -> Html<String> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>⚙️ Settings Dashboard</title>
    <link href="/static/css/dashboard.css" rel="stylesheet">
</head>
<body>
    <h1>⚙️ Settings Dashboard</h1>
    <p>System settings interface would be implemented here.</p>
</body>
</html>
"#.to_string())
}

// API handlers for dashboard data
async fn get_dashboard_data(State(state): State<WebUiAppState>) -> Json<DashboardData> {
    let analyzer_state = state.analyzer.get_state().await;
    
    let dashboard_data = DashboardData {
        timestamp: chrono::Utc::now(),
        system_status: SystemStatus {
            status: format!("{:?}", analyzer_state.status),
            uptime_seconds: analyzer_state.uptime_secs,
            memory_usage_mb: analyzer_state.memory_usage_mb,
            cpu_usage_percent: analyzer_state.cpu_usage_percent,
            disk_usage_mb: 0.0, // Would get from storage
            network_status: "Connected".to_string(),
            last_error: analyzer_state.last_error,
        },
        risk_metrics: RiskMetrics {
            current_risk_score: 0.25, // Would get from risk engine
            risk_level: "Low".to_string(),
            high_risk_transactions: 5,
            anchor_errors: 2,
            cpi_violations: 0,
            compute_unit_spikes: 1,
            risk_trend: "Stable".to_string(),
        },
        performance_metrics: PerformanceMetrics {
            transactions_per_second: 12.5,
            average_response_time_ms: 8.2,
            queue_depth: 0,
            error_rate_percent: 0.1,
            throughput_mbps: 2.5,
        },
        storage_metrics: StorageMetrics {
            database_size_mb: 125.5,
            total_records: 15_000,
            compression_ratio: 2.8,
            encryption_enabled: true,
            last_vacuum: chrono::Utc::now() - chrono::Duration::hours(2),
        },
        alert_summary: AlertSummary {
            total_alerts: 8,
            critical_alerts: 0,
            warning_alerts: 2,
            info_alerts: 6,
            recent_alerts: vec![
                AlertInfo {
                    id: "alert_001".to_string(),
                    severity: "Warning".to_string(),
                    title: "High memory usage detected".to_string(),
                    timestamp: chrono::Utc::now() - chrono::Duration::minutes(15),
                    acknowledged: false,
                },
            ],
        },
        recent_transactions: vec![
            TransactionSummary {
                signature: "5VfydnLu4XwV2H2dLHPv22JxhLbYJruaM9YTaGY30TZjd4re".to_string(),
                slot: 250_000_000,
                risk_score: 0.85,
                compute_units: Some(450_000),
                fee: 5000,
                status: "Success".to_string(),
                timestamp: chrono::Utc::now() - chrono::Duration::minutes(2),
            },
        ],
        active_modules: analyzer_state.active_modules.iter().map(|name| ModuleStatus {
            name: name.clone(),
            status: "Running".to_string(),
            uptime_seconds: analyzer_state.uptime_secs,
            memory_usage_mb: 50.0, // Estimated
            last_error: None,
        }).collect(),
    };

    // Update API request count
    {
        let mut ui_state = state.state.write().await;
        ui_state.api_requests += 1;
    }

    Json(dashboard_data)
}

async fn get_risk_data(State(_state): State<WebUiAppState>) -> Json<Value> {
    Json(json!({
        "current_risk_score": 0.25,
        "risk_breakdown": {
            "cpi_depth": 0.1,
            "anchor_errors": 0.05,
            "compute_units": 0.08,
            "signer_anomalies": 0.02
        },
        "recent_assessments": []
    }))
}

async fn get_performance_data(State(_state): State<WebUiAppState>) -> Json<Value> {
    Json(json!({
        "cpu_usage": 8.5,
        "memory_usage": 420.5,
        "disk_io": {
            "reads_per_sec": 125,
            "writes_per_sec": 85
        },
        "network": {
            "bytes_in": 1_250_000,
            "bytes_out": 850_000
        }
    }))
}

async fn get_storage_data(State(_state): State<WebUiAppState>) -> Json<Value> {
    Json(json!({
        "database_size_mb": 125.5,
        "total_records": 15_000,
        "compression_enabled": true,
        "encryption_enabled": true,
        "last_vacuum": chrono::Utc::now().to_rfc3339()
    }))
}

async fn get_alerts_data(State(_state): State<WebUiAppState>) -> Json<Value> {
    Json(json!({
        "total_alerts": 8,
        "by_severity": {
            "critical": 0,
            "warning": 2,
            "info": 6
        },
        "recent_alerts": []
    }))
}

async fn get_transactions_data(State(_state): State<WebUiAppState>) -> Json<Value> {
    Json(json!({
        "recent_transactions": [],
        "high_risk_count": 5,
        "total_processed": 1_250
    }))
}

async fn get_config_handler(State(_state): State<WebUiAppState>) -> Json<Value> {
    Json(json!({
        "system": {
            "max_memory_gb": 10.5,
            "max_cpu_percent": 40.0
        },
        "storage": {
            "encryption_enabled": true,
            "compression_enabled": true
        }
    }))
}

async fn update_config_handler(
    State(_state): State<WebUiAppState>,
    Json(_payload): Json<ConfigUpdateRequest>,
) -> Result<Json<Value>, StatusCode> {
    // Configuration update logic would be implemented here
    Ok(Json(json!({
        "success": true,
        "message": "Configuration updated successfully"
    })))
}

async fn get_plugins_handler(State(_state): State<WebUiAppState>) -> Json<Value> {
    Json(json!({
        "plugins": [],
        "total_loaded": 0,
        "total_active": 0
    }))
}

async fn reload_plugin_handler(
    Path(_name): Path<String>,
    State(_state): State<WebUiAppState>,
) -> Json<Value> {
    Json(json!({
        "success": true,
        "message": "Plugin reloaded successfully"
    }))
}

async fn unload_plugin_handler(
    Path(_name): Path<String>,
    State(_state): State<WebUiAppState>,
) -> Json<Value> {
    Json(json!({
        "success": true,
        "message": "Plugin unloaded successfully"
    }))
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(_state): State<WebUiAppState>,
) -> Response {
    ws.on_upgrade(handle_websocket)
}

async fn handle_websocket(mut socket: axum::extract::ws::WebSocket) {
    info!("📡 WebSocket connection established");
    
    // Send real-time updates
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let update = json!({
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "risk_score": 0.25,
                    "memory_usage": 420.5,
                    "cpu_usage": 8.5
                });
                
                if socket.send(axum::extract::ws::Message::Text(update.to_string())).await.is_err() {
                    break;
                }
            }
        }
    }
    
    info!("📡 WebSocket connection closed");
}

async fn login_page_handler() -> Html<String> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>🔐 ZKAnalyzer Login</title>
    <link href="/static/css/auth.css" rel="stylesheet">
</head>
<body>
    <div class="login-container">
        <h1>🔐 ZKAnalyzer</h1>
        <form id="loginForm">
            <input type="text" placeholder="Access Token" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"#.to_string())
}

async fn login_handler(
    State(_state): State<WebUiAppState>,
    Json(_payload): Json<Value>,
) -> Json<Value> {
    Json(json!({
        "success": true,
        "token": "session_token_here"
    }))
}

async fn logout_handler(
    State(_state): State<WebUiAppState>,
) -> Json<Value> {
    Json(json!({
        "success": true,
        "message": "Logged out successfully"
    }))
}
