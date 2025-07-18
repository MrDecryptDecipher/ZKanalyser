use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, error};

mod config;
mod core;
mod error;
mod metrics;
mod server;
mod risk_engine;
mod geyser_client;
mod solana_client;
mod storage;
mod replay_engine;
mod alert_engine;
mod tui_dashboard;
mod ebpf_profiler;
mod security;
mod plugin_manager;
mod web_ui;

#[cfg(test)]
mod integration_test;

use config::Config;
use core::ZKAnalyzer;

#[derive(Parser)]
#[command(name = "zkanalyzer")]
#[command(about = "Solana Validator Observability, Security & Replay Suite")]
#[command(version = "3.5.0")]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
    
    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
    
    /// Enable TUI dashboard
    #[arg(long)]
    tui: bool,
    
    /// Enable web UI
    #[arg(long)]
    web_ui: bool,
    
    /// Enable eBPF profiler
    #[arg(long)]
    ebpf: bool,
    
    /// Dry run mode (no actual connections)
    #[arg(long)]
    dry_run: bool,

    /// Run integration tests
    #[arg(long)]
    test: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    init_logging(cli.debug)?;
    
    info!("🔐 ZKAnalyzer v3.5 - Solana Validator Observability Suite");
    info!("Starting with config: {}", cli.config);
    
    // Load configuration
    let config = Config::load(&cli.config).await?;
    info!("✅ Configuration loaded successfully");

    // Override config with CLI flags
    let mut config = config;
    config.features.tui_enabled = cli.tui || config.features.tui_enabled;
    config.features.web_ui_enabled = cli.web_ui || config.features.web_ui_enabled;
    config.features.ebpf_enabled = cli.ebpf || config.features.ebpf_enabled;
    config.system.dry_run = cli.dry_run || config.system.dry_run;

    // Run integration tests if requested
    if cli.test {
        info!("🧪 Running integration tests");
        #[cfg(test)]
        {
            let test_runner = integration_test::IntegrationTest::new();
            let results = test_runner.run_all_tests().await?;

            if results.all_passed() {
                info!("✅ All integration tests passed!");
                return Ok(());
            } else {
                error!("❌ Some integration tests failed: {}", results.summary());
                std::process::exit(1);
            }
        }
        #[cfg(not(test))]
        {
            error!("❌ Integration tests not available in release build");
            std::process::exit(1);
        }
    }
    
    // Validate resource constraints
    validate_system_requirements(&config)?;
    
    // Initialize the main analyzer
    let analyzer = Arc::new(ZKAnalyzer::new(config).await?);
    info!("✅ ZKAnalyzer core initialized");
    
    // Start all services
    analyzer.start().await?;
    info!("🚀 ZKAnalyzer v3.5 fully operational with all advanced features");
    
    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("📡 Received shutdown signal");
        }
        result = analyzer.wait_for_completion() => {
            match result {
                Ok(_) => info!("✅ ZKAnalyzer completed successfully"),
                Err(e) => error!("❌ ZKAnalyzer error: {}", e),
            }
        }
    }
    
    // Graceful shutdown
    info!("🔄 Initiating graceful shutdown...");
    analyzer.shutdown().await?;
    info!("✅ ZKAnalyzer shutdown complete");
    
    Ok(())
}

fn init_logging(debug: bool) -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    
    let filter = if debug {
        EnvFilter::new("zkanalyzer=debug,info")
    } else {
        EnvFilter::new("zkanalyzer=info,warn,error")
    };
    
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
        )
        .init();
    
    Ok(())
}

fn validate_system_requirements(config: &Config) -> Result<()> {
    use sysinfo::{System, SystemExt};
    
    let mut sys = System::new_all();
    sys.refresh_all();
    
    // Check available RAM (should be at least 16GB for Lightsail)
    let total_memory = sys.total_memory();
    let available_memory = sys.available_memory();
    
    info!("💾 System Memory: {} GB total, {} GB available", 
          total_memory / (1024 * 1024 * 1024),
          available_memory / (1024 * 1024 * 1024));
    
    // Validate against PRD constraints
    let max_memory_gb = config.system.max_memory_gb.unwrap_or(10.5);
    if available_memory < (max_memory_gb * 1024.0 * 1024.0 * 1024.0) as u64 {
        anyhow::bail!("Insufficient memory: need at least {:.1}GB, have {:.1}GB", 
                     max_memory_gb, 
                     available_memory as f64 / (1024.0 * 1024.0 * 1024.0));
    }
    
    // Check CPU count
    let cpu_count = sys.cpus().len();
    info!("🖥️  CPU Cores: {}", cpu_count);
    
    if cpu_count < 1 {
        anyhow::bail!("Insufficient CPU cores: need at least 1 vCPU");
    }
    
    // Check disk space
    let disk_usage_gb = config.system.max_disk_gb.unwrap_or(4.5);
    info!("💿 Max disk usage configured: {:.1}GB", disk_usage_gb);
    
    info!("✅ System requirements validation passed");
    Ok(())
}
