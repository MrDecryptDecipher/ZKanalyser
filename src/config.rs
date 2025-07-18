use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub system: SystemConfig,
    pub solana: SolanaConfig,
    pub features: FeatureConfig,
    pub storage: StorageConfig,
    pub metrics: MetricsConfig,
    pub alerts: AlertConfig,
    pub security: SecurityConfig,
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    /// Maximum RAM usage in GB (PRD: ≤10.5GB)
    pub max_memory_gb: Option<f64>,
    /// Maximum CPU usage percentage (PRD: ≤40%)
    pub max_cpu_percent: Option<f64>,
    /// Maximum disk usage in GB (PRD: ≤4.5GB)
    pub max_disk_gb: Option<f64>,
    /// Dry run mode (no actual connections)
    pub dry_run: bool,
    /// Log level
    pub log_level: String,
    /// Data directory
    pub data_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaConfig {
    /// Solana RPC endpoint
    pub rpc_url: String,
    /// WebSocket endpoint for real-time data
    pub ws_url: String,
    /// Geyser plugin configuration
    pub geyser: GeyserConfig,
    /// Commitment level for transactions
    pub commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeyserConfig {
    /// Enable Geyser plugin
    pub enabled: bool,
    /// Geyser endpoint
    pub endpoint: String,
    /// Buffer size for events
    pub buffer_size: usize,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureConfig {
    /// Enable TUI dashboard
    pub tui_enabled: bool,
    /// Enable web UI
    pub web_ui_enabled: bool,
    /// Enable eBPF profiler
    pub ebpf_enabled: bool,
    /// Enable chaos testing
    pub chaos_enabled: bool,
    /// Enable plugin system
    pub plugins_enabled: bool,
    /// Enable audit logging
    pub audit_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// SQLite database path
    pub db_path: String,
    /// Enable encryption
    pub encryption_enabled: bool,
    /// Encryption key (base64 encoded)
    pub encryption_key: Option<String>,
    /// Enable compression
    pub compression_enabled: bool,
    /// Maximum database size in MB
    pub max_db_size_mb: u64,
    /// Vacuum interval in hours
    pub vacuum_interval_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Prometheus metrics port
    pub port: u16,
    /// Enable TLS for metrics endpoint
    pub tls_enabled: bool,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS key path
    pub tls_key_path: Option<String>,
    /// Metrics collection interval in seconds
    pub collection_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable alert system
    pub enabled: bool,
    /// Alert rules file path
    pub rules_path: String,
    /// Slack webhook URL
    pub slack_webhook: Option<String>,
    /// Generic webhook URL
    pub webhook_url: Option<String>,
    /// SMS configuration
    pub sms: Option<SmsConfig>,
    /// Alert delivery timeout in seconds (PRD: ≤3s)
    pub delivery_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    /// SMS provider (e.g., "twilio")
    pub provider: String,
    /// Provider API key
    pub api_key: String,
    /// Phone number to send alerts to
    pub phone_number: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable RBAC
    pub rbac_enabled: bool,
    /// Admin token
    pub admin_token: Option<String>,
    /// Readonly token
    pub readonly_token: Option<String>,
    /// Replay token
    pub replay_token: Option<String>,
    /// Enable webhook signing
    pub webhook_signing_enabled: bool,
    /// Webhook signing key
    pub webhook_signing_key: Option<String>,
    /// Enable self-destruct hook
    pub self_destruct_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// API server port
    pub api_port: u16,
    /// WebSocket port
    pub ws_port: u16,
    /// gRPC port
    pub grpc_port: u16,
    /// Web UI port
    pub web_ui_port: u16,
    /// Bind address
    pub bind_address: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            system: SystemConfig {
                max_memory_gb: Some(10.5),
                max_cpu_percent: Some(40.0),
                max_disk_gb: Some(4.5),
                dry_run: false,
                log_level: "info".to_string(),
                data_dir: "/home/ubuntu/.zkanalyzer".to_string(),
            },
            solana: SolanaConfig {
                rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
                ws_url: "wss://api.mainnet-beta.solana.com".to_string(),
                geyser: GeyserConfig {
                    enabled: true,
                    endpoint: "http://localhost:10000".to_string(),
                    buffer_size: 10000,
                    timeout_secs: 30,
                },
                commitment: "confirmed".to_string(),
            },
            features: FeatureConfig {
                tui_enabled: false,
                web_ui_enabled: false,
                ebpf_enabled: false,
                chaos_enabled: false,
                plugins_enabled: false,
                audit_enabled: true,
            },
            storage: StorageConfig {
                db_path: "/home/ubuntu/.zkanalyzer/zkanalyzer.db".to_string(),
                encryption_enabled: false,
                encryption_key: None,
                compression_enabled: true,
                max_db_size_mb: 2500, // PRD: ≤2.5GB
                vacuum_interval_hours: 24,
            },
            metrics: MetricsConfig {
                port: 9102,
                tls_enabled: false,
                tls_cert_path: None,
                tls_key_path: None,
                collection_interval_secs: 10,
            },
            alerts: AlertConfig {
                enabled: true,
                rules_path: "/home/ubuntu/.zkanalyzer/rules.yaml".to_string(),
                slack_webhook: None,
                webhook_url: None,
                sms: None,
                delivery_timeout_secs: 3, // PRD requirement
            },
            security: SecurityConfig {
                rbac_enabled: true,
                admin_token: None,
                readonly_token: None,
                replay_token: None,
                webhook_signing_enabled: true,
                webhook_signing_key: None,
                self_destruct_enabled: false,
            },
            network: NetworkConfig {
                api_port: 9102,
                ws_port: 9103,
                grpc_port: 9104,
                web_ui_port: 9101,
                bind_address: "0.0.0.0".to_string(),
            },
        }
    }
}

impl Config {
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        
        if !path.exists() {
            // Create default config file
            let default_config = Self::default();
            default_config.save(path).await?;
            return Ok(default_config);
        }
        
        let content = fs::read_to_string(path).await?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
    
    pub async fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_yaml::to_string(self)?;
        
        // Ensure parent directory exists
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).await?;
        }
        
        fs::write(path, content).await?;
        Ok(())
    }
    
    pub fn validate(&self) -> Result<()> {
        // Validate port ranges (9101-9109 as per requirements)
        let ports = [
            self.network.web_ui_port,
            self.network.api_port,
            self.network.ws_port,
            self.network.grpc_port,
            self.metrics.port,
        ];
        
        for port in ports {
            if port < 9101 || port > 9109 {
                anyhow::bail!("Port {} is outside allowed range 9101-9109", port);
            }
        }
        
        // Validate resource constraints
        if let Some(memory) = self.system.max_memory_gb {
            if memory > 10.5 {
                anyhow::bail!("Max memory {:.1}GB exceeds PRD limit of 10.5GB", memory);
            }
        }
        
        if let Some(cpu) = self.system.max_cpu_percent {
            if cpu > 40.0 {
                anyhow::bail!("Max CPU {:.1}% exceeds PRD limit of 40%", cpu);
            }
        }
        
        if let Some(disk) = self.system.max_disk_gb {
            if disk > 4.5 {
                anyhow::bail!("Max disk {:.1}GB exceeds PRD limit of 4.5GB", disk);
            }
        }
        
        // Validate alert delivery timeout
        if self.alerts.delivery_timeout_secs > 3 {
            anyhow::bail!("Alert delivery timeout {}s exceeds PRD limit of 3s", 
                         self.alerts.delivery_timeout_secs);
        }
        
        Ok(())
    }
}
