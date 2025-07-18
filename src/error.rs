use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZKError {
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Solana client error: {0}")]
    SolanaError(String),
    
    #[error("Geyser plugin error: {0}")]
    GeyserError(String),
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Metrics error: {0}")]
    MetricsError(String),
    
    #[error("Alert error: {0}")]
    AlertError(String),
    
    #[error("Security error: {0}")]
    SecurityError(String),
    
    #[error("eBPF error: {0}")]
    EbpfError(String),
    
    #[error("Plugin error: {0}")]
    PluginError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("System error: {0}")]
    SystemError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Shutdown error")]
    ShutdownError,
    
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitError(String),
    
    #[error("Risk detection error: {0}")]
    RiskDetectionError(String),
    
    #[error("Replay error: {0}")]
    ReplayError(String),
    
    #[error("Audit error: {0}")]
    AuditError(String),
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    
    #[error("Compression error: {0}")]
    CompressionError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),
    
    #[error("SQL error: {0}")]
    SqlError(#[from] sqlx::Error),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    
    #[error("Join error: {0}")]
    JoinError(#[from] tokio::task::JoinError),
    
    #[error("Channel error: {0}")]
    ChannelError(String),
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl ZKError {
    pub fn is_recoverable(&self) -> bool {
        match self {
            ZKError::NetworkError(_) => true,
            ZKError::TimeoutError(_) => true,
            ZKError::ChannelError(_) => true,
            ZKError::HttpError(_) => true,
            ZKError::SolanaError(_) => true,
            ZKError::GeyserError(_) => true,
            _ => false,
        }
    }
    
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            ZKError::ConfigError(_) => ErrorSeverity::Critical,
            ZKError::SecurityError(_) => ErrorSeverity::Critical,
            ZKError::ResourceLimitError(_) => ErrorSeverity::Critical,
            ZKError::ShutdownError => ErrorSeverity::Critical,
            ZKError::DatabaseError(_) => ErrorSeverity::High,
            ZKError::StorageError(_) => ErrorSeverity::High,
            ZKError::EncryptionError(_) => ErrorSeverity::High,
            ZKError::AuditError(_) => ErrorSeverity::High,
            ZKError::NetworkError(_) => ErrorSeverity::Medium,
            ZKError::TimeoutError(_) => ErrorSeverity::Medium,
            ZKError::SolanaError(_) => ErrorSeverity::Medium,
            ZKError::GeyserError(_) => ErrorSeverity::Medium,
            ZKError::MetricsError(_) => ErrorSeverity::Low,
            ZKError::AlertError(_) => ErrorSeverity::Low,
            _ => ErrorSeverity::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ErrorSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl ErrorSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorSeverity::Critical => "CRITICAL",
            ErrorSeverity::High => "HIGH",
            ErrorSeverity::Medium => "MEDIUM",
            ErrorSeverity::Low => "LOW",
        }
    }
}

pub type ZKResult<T> = Result<T, ZKError>;
