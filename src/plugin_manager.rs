use anyhow::Result;
use libloading::{Library, Symbol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::error::{ZKError, ZKResult};
use crate::security::SecurityManager;

/// Hot-reloadable plugin system with Ed25519 signature verification
pub struct PluginManager {
    config: Config,
    plugins: Arc<RwLock<HashMap<String, LoadedPlugin>>>,
    security_manager: Arc<SecurityManager>,
    state: Arc<RwLock<PluginManagerState>>,
    shutdown_receiver: broadcast::Receiver<()>,
}

#[derive(Debug, Clone)]
pub struct PluginManagerState {
    pub plugins_loaded: u64,
    pub plugins_active: u64,
    pub plugins_failed: u64,
    pub hot_reloads: u64,
    pub last_reload: chrono::DateTime<chrono::Utc>,
    pub plugin_directory: String,
    pub signature_verification_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub api_version: String,
    pub capabilities: Vec<PluginCapability>,
    pub dependencies: Vec<String>,
    pub signature: Option<String>,
    pub loaded: bool,
    pub active: bool,
    pub last_error: Option<String>,
    pub load_time: Option<chrono::DateTime<chrono::Utc>>,
    pub memory_usage_kb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginCapability {
    RiskAnalysis,
    DataProcessing,
    AlertHandling,
    MetricsCollection,
    StorageExtension,
    NetworkMonitoring,
    CustomVisualization,
}

#[derive(Debug)]
pub struct LoadedPlugin {
    pub info: PluginInfo,
    pub library: Library,
    pub api: PluginApi,
    pub state: PluginState,
}

#[derive(Debug, Clone)]
pub struct PluginState {
    pub initialized: bool,
    pub active: bool,
    pub error_count: u64,
    pub last_error: Option<String>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub memory_usage_kb: u64,
    pub cpu_time_ms: u64,
}

/// Plugin API interface
#[derive(Debug)]
pub struct PluginApi {
    pub init: unsafe extern "C" fn() -> c_int,
    pub shutdown: unsafe extern "C" fn() -> c_int,
    pub get_info: unsafe extern "C" fn() -> *const c_char,
    pub process_data: Option<unsafe extern "C" fn(*const c_char) -> *const c_char>,
    pub handle_event: Option<unsafe extern "C" fn(*const c_char) -> c_int>,
    pub get_metrics: Option<unsafe extern "C" fn() -> *const c_char>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub api_version: String,
    pub entry_point: String,
    pub capabilities: Vec<PluginCapability>,
    pub dependencies: Vec<String>,
    pub config_schema: Option<serde_json::Value>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEvent {
    pub plugin_name: String,
    pub event_type: PluginEventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginEventType {
    Loaded,
    Unloaded,
    Reloaded,
    Error,
    DataProcessed,
    MetricsUpdated,
}

impl PluginManager {
    pub async fn new(
        config: Config,
        security_manager: Arc<SecurityManager>,
        shutdown_receiver: broadcast::Receiver<()>,
    ) -> ZKResult<Self> {
        info!("🔌 Initializing Plugin Manager");

        let plugin_dir = format!("{}/.zkanalyzer/plugins", std::env::var("HOME").unwrap_or_default());
        tokio::fs::create_dir_all(&plugin_dir).await
            .map_err(|e| ZKError::PluginError(format!("Failed to create plugin directory: {}", e)))?;

        let state = Arc::new(RwLock::new(PluginManagerState {
            plugins_loaded: 0,
            plugins_active: 0,
            plugins_failed: 0,
            hot_reloads: 0,
            last_reload: chrono::Utc::now(),
            plugin_directory: plugin_dir,
            signature_verification_enabled: config.security.plugin_signature_verification,
        }));

        let manager = Self {
            config,
            plugins: Arc::new(RwLock::new(HashMap::new())),
            security_manager,
            state,
            shutdown_receiver,
        };

        // Start plugin monitoring task
        manager.start_monitoring_task().await;

        info!("✅ Plugin Manager initialized");
        Ok(manager)
    }

    /// Load a plugin from file with signature verification
    pub async fn load_plugin(&self, plugin_path: &str) -> ZKResult<()> {
        info!("🔌 Loading plugin: {}", plugin_path);

        let path = Path::new(plugin_path);
        if !path.exists() {
            return Err(ZKError::PluginError(format!("Plugin file not found: {}", plugin_path)));
        }

        // Load and verify manifest
        let manifest = self.load_plugin_manifest(plugin_path).await?;
        
        // Verify plugin signature if enabled
        if self.config.security.plugin_signature_verification {
            self.verify_plugin_signature(plugin_path, &manifest).await?;
        }

        // Check if plugin is already loaded
        {
            let plugins = self.plugins.read().await;
            if plugins.contains_key(&manifest.name) {
                return Err(ZKError::PluginError(format!("Plugin {} is already loaded", manifest.name)));
            }
        }

        // Load the dynamic library
        let library = unsafe {
            Library::new(plugin_path)
                .map_err(|e| ZKError::PluginError(format!("Failed to load library: {}", e)))?
        };

        // Load plugin API functions
        let api = self.load_plugin_api(&library, &manifest).await?;

        // Initialize plugin
        let init_result = unsafe { (api.init)() };
        if init_result != 0 {
            return Err(ZKError::PluginError(format!("Plugin initialization failed with code: {}", init_result)));
        }

        // Get plugin info from the plugin itself
        let plugin_info_json = unsafe {
            let info_ptr = (api.get_info)();
            if info_ptr.is_null() {
                return Err(ZKError::PluginError("Plugin get_info returned null".to_string()));
            }
            CStr::from_ptr(info_ptr).to_string_lossy().to_string()
        };

        let mut plugin_info: PluginInfo = serde_json::from_str(&plugin_info_json)
            .map_err(|e| ZKError::PluginError(format!("Failed to parse plugin info: {}", e)))?;

        plugin_info.loaded = true;
        plugin_info.active = true;
        plugin_info.load_time = Some(chrono::Utc::now());

        // Create loaded plugin
        let loaded_plugin = LoadedPlugin {
            info: plugin_info.clone(),
            library,
            api,
            state: PluginState {
                initialized: true,
                active: true,
                error_count: 0,
                last_error: None,
                last_activity: chrono::Utc::now(),
                memory_usage_kb: 0, // Would be measured in real implementation
                cpu_time_ms: 0,
            },
        };

        // Store plugin
        {
            let mut plugins = self.plugins.write().await;
            plugins.insert(manifest.name.clone(), loaded_plugin);
        }

        // Update state
        {
            let mut state = self.state.write().await;
            state.plugins_loaded += 1;
            state.plugins_active += 1;
        }

        // Emit plugin loaded event
        self.emit_plugin_event(PluginEvent {
            plugin_name: manifest.name.clone(),
            event_type: PluginEventType::Loaded,
            timestamp: chrono::Utc::now(),
            data: serde_json::to_value(&plugin_info).unwrap_or_default(),
        }).await;

        info!("✅ Plugin loaded successfully: {} v{}", manifest.name, manifest.version);
        Ok(())
    }

    /// Unload a plugin
    pub async fn unload_plugin(&self, plugin_name: &str) -> ZKResult<()> {
        info!("🔌 Unloading plugin: {}", plugin_name);

        let plugin = {
            let mut plugins = self.plugins.write().await;
            plugins.remove(plugin_name)
                .ok_or_else(|| ZKError::PluginError(format!("Plugin not found: {}", plugin_name)))?
        };

        // Shutdown plugin
        let shutdown_result = unsafe { (plugin.api.shutdown)() };
        if shutdown_result != 0 {
            warn!("Plugin shutdown returned non-zero code: {}", shutdown_result);
        }

        // Update state
        {
            let mut state = self.state.write().await;
            state.plugins_active = state.plugins_active.saturating_sub(1);
        }

        // Emit plugin unloaded event
        self.emit_plugin_event(PluginEvent {
            plugin_name: plugin_name.to_string(),
            event_type: PluginEventType::Unloaded,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({ "reason": "manual_unload" }),
        }).await;

        info!("✅ Plugin unloaded: {}", plugin_name);
        Ok(())
    }

    /// Hot-reload a plugin
    pub async fn reload_plugin(&self, plugin_name: &str) -> ZKResult<()> {
        info!("🔄 Hot-reloading plugin: {}", plugin_name);

        // Get plugin path
        let plugin_path = {
            let plugins = self.plugins.read().await;
            let plugin = plugins.get(plugin_name)
                .ok_or_else(|| ZKError::PluginError(format!("Plugin not found: {}", plugin_name)))?;
            
            // In a real implementation, we'd store the original path
            format!("{}/{}.so", self.state.read().await.plugin_directory, plugin_name)
        };

        // Unload current plugin
        self.unload_plugin(plugin_name).await?;

        // Small delay to ensure cleanup
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Load new version
        self.load_plugin(&plugin_path).await?;

        // Update reload count
        {
            let mut state = self.state.write().await;
            state.hot_reloads += 1;
            state.last_reload = chrono::Utc::now();
        }

        // Emit plugin reloaded event
        self.emit_plugin_event(PluginEvent {
            plugin_name: plugin_name.to_string(),
            event_type: PluginEventType::Reloaded,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({ "reload_count": self.state.read().await.hot_reloads }),
        }).await;

        info!("✅ Plugin hot-reloaded: {}", plugin_name);
        Ok(())
    }

    /// Process data through a plugin
    pub async fn process_data(&self, plugin_name: &str, data: &str) -> ZKResult<String> {
        let plugins = self.plugins.read().await;
        let plugin = plugins.get(plugin_name)
            .ok_or_else(|| ZKError::PluginError(format!("Plugin not found: {}", plugin_name)))?;

        if let Some(process_data_fn) = plugin.api.process_data {
            let input_cstr = CString::new(data)
                .map_err(|e| ZKError::PluginError(format!("Failed to create C string: {}", e)))?;

            let result_ptr = unsafe { process_data_fn(input_cstr.as_ptr()) };
            
            if result_ptr.is_null() {
                return Err(ZKError::PluginError("Plugin returned null result".to_string()));
            }

            let result = unsafe {
                CStr::from_ptr(result_ptr).to_string_lossy().to_string()
            };

            // Emit data processed event
            drop(plugins);
            self.emit_plugin_event(PluginEvent {
                plugin_name: plugin_name.to_string(),
                event_type: PluginEventType::DataProcessed,
                timestamp: chrono::Utc::now(),
                data: serde_json::json!({
                    "input_size": data.len(),
                    "output_size": result.len()
                }),
            }).await;

            Ok(result)
        } else {
            Err(ZKError::PluginError("Plugin does not support data processing".to_string()))
        }
    }

    /// Get plugin metrics
    pub async fn get_plugin_metrics(&self, plugin_name: &str) -> ZKResult<serde_json::Value> {
        let plugins = self.plugins.read().await;
        let plugin = plugins.get(plugin_name)
            .ok_or_else(|| ZKError::PluginError(format!("Plugin not found: {}", plugin_name)))?;

        if let Some(get_metrics_fn) = plugin.api.get_metrics {
            let metrics_ptr = unsafe { get_metrics_fn() };
            
            if metrics_ptr.is_null() {
                return Ok(serde_json::json!({}));
            }

            let metrics_json = unsafe {
                CStr::from_ptr(metrics_ptr).to_string_lossy().to_string()
            };

            let metrics: serde_json::Value = serde_json::from_str(&metrics_json)
                .map_err(|e| ZKError::PluginError(format!("Failed to parse plugin metrics: {}", e)))?;

            Ok(metrics)
        } else {
            Ok(serde_json::json!({}))
        }
    }

    /// List all loaded plugins
    pub async fn list_plugins(&self) -> Vec<PluginInfo> {
        let plugins = self.plugins.read().await;
        plugins.values().map(|p| p.info.clone()).collect()
    }

    /// Install plugin from GitHub release
    pub async fn install_plugin_from_github(&self, repo: &str, tag: &str) -> ZKResult<()> {
        info!("📦 Installing plugin from GitHub: {}/{}", repo, tag);

        // Download plugin from GitHub releases
        let download_url = format!("https://github.com/{}/releases/download/{}/plugin.so", repo, tag);
        let plugin_path = format!("{}/{}.so", self.state.read().await.plugin_directory, repo.replace('/', "_"));

        // Download file (simplified implementation)
        let response = reqwest::get(&download_url).await
            .map_err(|e| ZKError::PluginError(format!("Failed to download plugin: {}", e)))?;

        if !response.status().is_success() {
            return Err(ZKError::PluginError(format!("Failed to download plugin: HTTP {}", response.status())));
        }

        let plugin_data = response.bytes().await
            .map_err(|e| ZKError::PluginError(format!("Failed to read plugin data: {}", e)))?;

        // Write plugin file
        tokio::fs::write(&plugin_path, &plugin_data).await
            .map_err(|e| ZKError::PluginError(format!("Failed to write plugin file: {}", e)))?;

        // Load the plugin
        self.load_plugin(&plugin_path).await?;

        info!("✅ Plugin installed from GitHub: {}", repo);
        Ok(())
    }

    async fn load_plugin_manifest(&self, plugin_path: &str) -> ZKResult<PluginManifest> {
        // Look for manifest file alongside the plugin
        let manifest_path = format!("{}.manifest.json", plugin_path.trim_end_matches(".so"));
        
        if Path::new(&manifest_path).exists() {
            let manifest_content = tokio::fs::read_to_string(&manifest_path).await
                .map_err(|e| ZKError::PluginError(format!("Failed to read manifest: {}", e)))?;
            
            let manifest: PluginManifest = serde_json::from_str(&manifest_content)
                .map_err(|e| ZKError::PluginError(format!("Failed to parse manifest: {}", e)))?;
            
            Ok(manifest)
        } else {
            // Create default manifest
            let plugin_name = Path::new(plugin_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            Ok(PluginManifest {
                name: plugin_name,
                version: "1.0.0".to_string(),
                description: "Plugin loaded without manifest".to_string(),
                author: "Unknown".to_string(),
                api_version: "1.0".to_string(),
                entry_point: "plugin_main".to_string(),
                capabilities: vec![PluginCapability::DataProcessing],
                dependencies: vec![],
                config_schema: None,
                signature: None,
            })
        }
    }

    async fn verify_plugin_signature(&self, plugin_path: &str, manifest: &PluginManifest) -> ZKResult<()> {
        if let Some(signature) = &manifest.signature {
            let plugin_data = tokio::fs::read(plugin_path).await
                .map_err(|e| ZKError::PluginError(format!("Failed to read plugin for verification: {}", e)))?;

            let is_valid = self.security_manager.crypto_manager.verify_plugin_signature(&plugin_data, signature).await?;
            
            if !is_valid {
                return Err(ZKError::SecurityError("Plugin signature verification failed".to_string()));
            }

            info!("✅ Plugin signature verified: {}", manifest.name);
        } else if self.config.security.require_plugin_signatures {
            return Err(ZKError::SecurityError("Plugin signature required but not provided".to_string()));
        }

        Ok(())
    }

    async fn load_plugin_api(&self, library: &Library, manifest: &PluginManifest) -> ZKResult<PluginApi> {
        unsafe {
            // Load required functions
            let init: Symbol<unsafe extern "C" fn() -> c_int> = library
                .get(b"plugin_init")
                .map_err(|e| ZKError::PluginError(format!("Failed to load plugin_init: {}", e)))?;

            let shutdown: Symbol<unsafe extern "C" fn() -> c_int> = library
                .get(b"plugin_shutdown")
                .map_err(|e| ZKError::PluginError(format!("Failed to load plugin_shutdown: {}", e)))?;

            let get_info: Symbol<unsafe extern "C" fn() -> *const c_char> = library
                .get(b"plugin_get_info")
                .map_err(|e| ZKError::PluginError(format!("Failed to load plugin_get_info: {}", e)))?;

            // Load optional functions
            let process_data = library.get(b"plugin_process_data").ok()
                .map(|f: Symbol<unsafe extern "C" fn(*const c_char) -> *const c_char>| *f);

            let handle_event = library.get(b"plugin_handle_event").ok()
                .map(|f: Symbol<unsafe extern "C" fn(*const c_char) -> c_int>| *f);

            let get_metrics = library.get(b"plugin_get_metrics").ok()
                .map(|f: Symbol<unsafe extern "C" fn() -> *const c_char>| *f);

            Ok(PluginApi {
                init: *init,
                shutdown: *shutdown,
                get_info: *get_info,
                process_data,
                handle_event,
                get_metrics,
            })
        }
    }

    async fn start_monitoring_task(&self) {
        let plugins = Arc::clone(&self.plugins);
        let state = Arc::clone(&self.state);
        let mut shutdown_rx = self.shutdown_receiver.resubscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Monitor plugin health
                        let plugins_read = plugins.read().await;
                        let mut active_count = 0;

                        for (name, plugin) in plugins_read.iter() {
                            if plugin.state.active {
                                active_count += 1;
                            }

                            // Check for plugin errors or crashes
                            if plugin.state.error_count > 10 {
                                warn!("Plugin {} has high error count: {}", name, plugin.state.error_count);
                            }
                        }

                        // Update state
                        {
                            let mut state_write = state.write().await;
                            state_write.plugins_active = active_count;
                        }

                        debug!("Plugin monitoring: {} active plugins", active_count);
                    }
                    _ = shutdown_rx.recv() => {
                        info!("🔄 Plugin monitoring task shutting down");
                        break;
                    }
                }
            }
        });
    }

    async fn emit_plugin_event(&self, event: PluginEvent) {
        debug!("📡 Plugin event: {:?} - {}", event.event_type, event.plugin_name);
        // In a real implementation, this would emit to an event bus
    }

    pub async fn get_state(&self) -> PluginManagerState {
        self.state.read().await.clone()
    }

    /// Shutdown all plugins
    pub async fn shutdown_all_plugins(&self) -> ZKResult<()> {
        info!("🔄 Shutting down all plugins");

        let plugin_names: Vec<String> = {
            let plugins = self.plugins.read().await;
            plugins.keys().cloned().collect()
        };

        for plugin_name in plugin_names {
            if let Err(e) = self.unload_plugin(&plugin_name).await {
                error!("Failed to unload plugin {}: {}", plugin_name, e);
            }
        }

        info!("✅ All plugins shut down");
        Ok(())
    }
}

// Example plugin interface for reference
#[no_mangle]
pub extern "C" fn plugin_init() -> c_int {
    // Plugin initialization code
    0 // Success
}

#[no_mangle]
pub extern "C" fn plugin_shutdown() -> c_int {
    // Plugin cleanup code
    0 // Success
}

#[no_mangle]
pub extern "C" fn plugin_get_info() -> *const c_char {
    let info = r#"{
        "name": "example_plugin",
        "version": "1.0.0",
        "description": "Example ZKAnalyzer plugin",
        "author": "ZKAnalyzer Team",
        "api_version": "1.0",
        "capabilities": ["DataProcessing"],
        "dependencies": []
    }"#;
    
    info.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn plugin_process_data(input: *const c_char) -> *const c_char {
    // Process input data and return result
    input // Echo for example
}

#[no_mangle]
pub extern "C" fn plugin_get_metrics() -> *const c_char {
    let metrics = r#"{
        "processed_items": 100,
        "processing_time_ms": 1500,
        "memory_usage_kb": 256
    }"#;
    
    metrics.as_ptr() as *const c_char
}
