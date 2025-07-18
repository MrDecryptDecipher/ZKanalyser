//! # ZKAnalyzer v3.5 - Advanced Solana Transaction Risk Analysis System
//!
//! A comprehensive Solana transaction risk analysis system designed for production environments.
//! Provides real-time monitoring, advanced risk detection, and extensive security features.

pub mod config;
pub mod core;
pub mod error;
pub mod metrics;
pub mod server;
pub mod risk_engine;
pub mod geyser_client;
pub mod solana_client;
pub mod storage;

// Advanced modules (feature-gated)
#[cfg(feature = "replay")]
pub mod replay_engine;

#[cfg(feature = "alerts")]
pub mod alert_engine;

#[cfg(feature = "tui")]
pub mod tui_dashboard;

#[cfg(feature = "ebpf")]
pub mod ebpf_profiler;

#[cfg(feature = "security")]
pub mod security;

#[cfg(feature = "plugins")]
pub mod plugin_manager;

#[cfg(feature = "web-ui")]
pub mod web_ui;

// Re-exports for convenience
pub use config::Config;
pub use core::ZKAnalyzer;
pub use error::{ZKError, ZKResult};
pub use metrics::MetricsCollector;

/// ZKAnalyzer version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ZKAnalyzer build information
pub const BUILD_INFO: &str = concat!(
    "ZKAnalyzer v",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("CARGO_PKG_REPOSITORY"),
    ")"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
        assert!(VERSION.starts_with("3.5"));
    }

    #[test]
    fn test_build_info() {
        assert!(BUILD_INFO.contains("ZKAnalyzer"));
        assert!(BUILD_INFO.contains("3.5"));
    }
}
