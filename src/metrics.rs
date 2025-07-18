use anyhow::Result;
use prometheus::{
    Counter, Gauge, Histogram, IntCounter, IntGauge, Registry, 
    Encoder, TextEncoder, opts, register_counter, register_gauge, 
    register_histogram, register_int_counter, register_int_gauge
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};

use crate::config::Config;
use crate::error::ZKError;

/// Prometheus metrics collector for ZKAnalyzer
pub struct MetricsCollector {
    registry: Registry,
    
    // Core metrics as per PRD specification
    pub tx_risk_score: Gauge,
    pub slot_gap_total: IntCounter,
    pub anchor_error_count: IntCounter,
    pub plugin_crash_count: IntCounter,
    pub sys_disk_latency_ms: Histogram,
    pub syscalls_per_sec: Gauge,
    pub fork_spike_avg: Gauge,
    pub config_drift_detected: IntGauge,
    
    // System resource metrics
    pub memory_usage_mb: Gauge,
    pub cpu_usage_percent: Gauge,
    pub disk_usage_mb: Gauge,
    pub uptime_seconds: IntCounter,
    
    // Performance metrics
    pub geyser_events_processed: IntCounter,
    pub database_operations: IntCounter,
    pub alert_delivery_time_ms: Histogram,
    pub api_request_duration: Histogram,
    
    // Health metrics
    pub health_status: IntGauge,
    pub active_modules: IntGauge,
    pub last_error_timestamp: IntGauge,
}

impl MetricsCollector {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();
        
        // Core PRD metrics
        let tx_risk_score = Gauge::with_opts(opts!(
            "zk_tx_risk_score",
            "Current transaction risk score (0.0-1.0)"
        ))?;
        
        let slot_gap_total = IntCounter::with_opts(opts!(
            "zk_slot_gap_total",
            "Total number of slot gaps detected"
        ))?;
        
        let anchor_error_count = IntCounter::with_opts(opts!(
            "zk_anchor_error_count",
            "Total number of Anchor program errors"
        ))?;
        
        let plugin_crash_count = IntCounter::with_opts(opts!(
            "zk_plugin_crash_count",
            "Total number of plugin crashes"
        ))?;
        
        let sys_disk_latency_ms = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "zk_sys_disk_latency_ms",
                "System disk latency in milliseconds"
            ).buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0])
        )?;
        
        let syscalls_per_sec = Gauge::with_opts(opts!(
            "zk_syscalls_per_sec",
            "System calls per second"
        ))?;
        
        let fork_spike_avg = Gauge::with_opts(opts!(
            "zk_fork_spike_avg",
            "Average fork spike detection value"
        ))?;
        
        let config_drift_detected = IntGauge::with_opts(opts!(
            "zk_config_drift_detected",
            "Configuration drift detection flag (0/1)"
        ))?;
        
        // System resource metrics
        let memory_usage_mb = Gauge::with_opts(opts!(
            "zk_memory_usage_mb",
            "Current memory usage in megabytes"
        ))?;
        
        let cpu_usage_percent = Gauge::with_opts(opts!(
            "zk_cpu_usage_percent",
            "Current CPU usage percentage"
        ))?;
        
        let disk_usage_mb = Gauge::with_opts(opts!(
            "zk_disk_usage_mb",
            "Current disk usage in megabytes"
        ))?;
        
        let uptime_seconds = IntCounter::with_opts(opts!(
            "zk_uptime_seconds",
            "Total uptime in seconds"
        ))?;
        
        // Performance metrics
        let geyser_events_processed = IntCounter::with_opts(opts!(
            "zk_geyser_events_processed_total",
            "Total number of Geyser events processed"
        ))?;
        
        let database_operations = IntCounter::with_opts(opts!(
            "zk_database_operations_total",
            "Total number of database operations"
        ))?;
        
        let alert_delivery_time_ms = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "zk_alert_delivery_time_ms",
                "Alert delivery time in milliseconds"
            ).buckets(vec![100.0, 500.0, 1000.0, 2000.0, 3000.0, 5000.0])
        )?;
        
        let api_request_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "zk_api_request_duration_ms",
                "API request duration in milliseconds"
            ).buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0])
        )?;
        
        // Health metrics
        let health_status = IntGauge::with_opts(opts!(
            "zk_health_status",
            "Overall health status (0=unhealthy, 1=healthy)"
        ))?;
        
        let active_modules = IntGauge::with_opts(opts!(
            "zk_active_modules",
            "Number of active modules"
        ))?;
        
        let last_error_timestamp = IntGauge::with_opts(opts!(
            "zk_last_error_timestamp",
            "Timestamp of last error (Unix timestamp)"
        ))?;
        
        // Register all metrics
        registry.register(Box::new(tx_risk_score.clone()))?;
        registry.register(Box::new(slot_gap_total.clone()))?;
        registry.register(Box::new(anchor_error_count.clone()))?;
        registry.register(Box::new(plugin_crash_count.clone()))?;
        registry.register(Box::new(sys_disk_latency_ms.clone()))?;
        registry.register(Box::new(syscalls_per_sec.clone()))?;
        registry.register(Box::new(fork_spike_avg.clone()))?;
        registry.register(Box::new(config_drift_detected.clone()))?;
        registry.register(Box::new(memory_usage_mb.clone()))?;
        registry.register(Box::new(cpu_usage_percent.clone()))?;
        registry.register(Box::new(disk_usage_mb.clone()))?;
        registry.register(Box::new(uptime_seconds.clone()))?;
        registry.register(Box::new(geyser_events_processed.clone()))?;
        registry.register(Box::new(database_operations.clone()))?;
        registry.register(Box::new(alert_delivery_time_ms.clone()))?;
        registry.register(Box::new(api_request_duration.clone()))?;
        registry.register(Box::new(health_status.clone()))?;
        registry.register(Box::new(active_modules.clone()))?;
        registry.register(Box::new(last_error_timestamp.clone()))?;
        
        Ok(Self {
            registry,
            tx_risk_score,
            slot_gap_total,
            anchor_error_count,
            plugin_crash_count,
            sys_disk_latency_ms,
            syscalls_per_sec,
            fork_spike_avg,
            config_drift_detected,
            memory_usage_mb,
            cpu_usage_percent,
            disk_usage_mb,
            uptime_seconds,
            geyser_events_processed,
            database_operations,
            alert_delivery_time_ms,
            api_request_duration,
            health_status,
            active_modules,
            last_error_timestamp,
        })
    }
    
    pub fn gather(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
    
    pub fn update_system_metrics(&self, memory_mb: f64, cpu_percent: f64, disk_mb: f64) {
        self.memory_usage_mb.set(memory_mb);
        self.cpu_usage_percent.set(cpu_percent);
        self.disk_usage_mb.set(disk_mb);
    }
    
    pub fn update_health_status(&self, is_healthy: bool, active_module_count: i64) {
        self.health_status.set(if is_healthy { 1 } else { 0 });
        self.active_modules.set(active_module_count);
    }
    
    pub fn record_error(&self) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.last_error_timestamp.set(timestamp);
    }
    
    pub fn increment_uptime(&self) {
        self.uptime_seconds.inc();
    }
}
