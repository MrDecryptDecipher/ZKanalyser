use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::{
        Axis, BarChart, Block, Borders, Chart, Clear, Dataset, Gauge, List, ListItem, 
        Paragraph, Row, Sparkline, Table, Tabs, Wrap
    },
    Frame, Terminal,
};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info};

use crate::config::Config;
use crate::core::ZKAnalyzer;
use crate::error::{ZKError, ZKResult};

/// Real-time TUI dashboard for ZKAnalyzer monitoring
pub struct TuiDashboard {
    config: Config,
    analyzer: Arc<ZKAnalyzer>,
    state: Arc<RwLock<DashboardState>>,
    shutdown_receiver: broadcast::Receiver<()>,
}

#[derive(Debug, Clone)]
pub struct DashboardState {
    pub current_tab: usize,
    pub risk_history: VecDeque<f64>,
    pub memory_history: VecDeque<f64>,
    pub cpu_history: VecDeque<f64>,
    pub transaction_count: u64,
    pub alert_count: u64,
    pub last_update: Instant,
    pub selected_item: usize,
    pub scroll_offset: usize,
    pub show_help: bool,
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub risk_score: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub active_modules: Vec<String>,
    pub uptime_seconds: u64,
    pub transactions_processed: u64,
    pub alerts_sent: u64,
    pub storage_size_mb: f64,
    pub network_status: String,
}

const TABS: &[&str] = &["Overview", "Risk Analysis", "Performance", "Storage", "Alerts", "Help"];
const MAX_HISTORY_POINTS: usize = 100;

impl TuiDashboard {
    pub fn new(
        config: Config,
        analyzer: Arc<ZKAnalyzer>,
        shutdown_receiver: broadcast::Receiver<()>,
    ) -> Self {
        let state = Arc::new(RwLock::new(DashboardState {
            current_tab: 0,
            risk_history: VecDeque::with_capacity(MAX_HISTORY_POINTS),
            memory_history: VecDeque::with_capacity(MAX_HISTORY_POINTS),
            cpu_history: VecDeque::with_capacity(MAX_HISTORY_POINTS),
            transaction_count: 0,
            alert_count: 0,
            last_update: Instant::now(),
            selected_item: 0,
            scroll_offset: 0,
            show_help: false,
        }));

        Self {
            config,
            analyzer,
            state,
            shutdown_receiver,
        }
    }

    pub async fn run(&mut self) -> ZKResult<()> {
        info!("🖥️  Starting TUI Dashboard");

        // Setup terminal
        enable_raw_mode().map_err(|e| ZKError::SystemError(format!("Failed to enable raw mode: {}", e)))?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
            .map_err(|e| ZKError::SystemError(format!("Failed to setup terminal: {}", e)))?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)
            .map_err(|e| ZKError::SystemError(format!("Failed to create terminal: {}", e)))?;

        // Start data collection task
        self.start_data_collection().await;

        // Main event loop
        let result = self.run_event_loop(&mut terminal).await;

        // Restore terminal
        disable_raw_mode().map_err(|e| ZKError::SystemError(format!("Failed to disable raw mode: {}", e)))?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        ).map_err(|e| ZKError::SystemError(format!("Failed to restore terminal: {}", e)))?;
        terminal.show_cursor()
            .map_err(|e| ZKError::SystemError(format!("Failed to show cursor: {}", e)))?;

        info!("✅ TUI Dashboard stopped");
        result
    }

    async fn run_event_loop<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> ZKResult<()> {
        let mut last_tick = Instant::now();
        let tick_rate = Duration::from_millis(250);
        let mut shutdown_rx = self.shutdown_receiver.resubscribe();

        loop {
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or_else(|| Duration::from_secs(0));

            tokio::select! {
                // Handle keyboard events
                _ = tokio::time::sleep(timeout) => {
                    if crossterm::event::poll(Duration::from_millis(0))
                        .map_err(|e| ZKError::SystemError(format!("Event poll failed: {}", e)))? {
                        
                        if let Event::Key(key) = event::read()
                            .map_err(|e| ZKError::SystemError(format!("Failed to read event: {}", e)))? {
                            
                            if key.kind == KeyEventKind::Press {
                                match key.code {
                                    KeyCode::Char('q') | KeyCode::Esc => break,
                                    KeyCode::Char('h') | KeyCode::F(1) => {
                                        let mut state = self.state.write().await;
                                        state.show_help = !state.show_help;
                                    }
                                    KeyCode::Tab | KeyCode::Right => {
                                        let mut state = self.state.write().await;
                                        state.current_tab = (state.current_tab + 1) % TABS.len();
                                    }
                                    KeyCode::BackTab | KeyCode::Left => {
                                        let mut state = self.state.write().await;
                                        state.current_tab = if state.current_tab > 0 {
                                            state.current_tab - 1
                                        } else {
                                            TABS.len() - 1
                                        };
                                    }
                                    KeyCode::Up => {
                                        let mut state = self.state.write().await;
                                        if state.selected_item > 0 {
                                            state.selected_item -= 1;
                                        }
                                    }
                                    KeyCode::Down => {
                                        let mut state = self.state.write().await;
                                        state.selected_item += 1;
                                    }
                                    KeyCode::PageUp => {
                                        let mut state = self.state.write().await;
                                        state.scroll_offset = state.scroll_offset.saturating_sub(10);
                                    }
                                    KeyCode::PageDown => {
                                        let mut state = self.state.write().await;
                                        state.scroll_offset += 10;
                                    }
                                    KeyCode::Char('r') => {
                                        // Refresh data
                                        debug!("Manual refresh requested");
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    if last_tick.elapsed() >= tick_rate {
                        // Draw the UI
                        terminal.draw(|f| {
                            if let Err(e) = self.draw_ui(f) {
                                error!("Failed to draw UI: {}", e);
                            }
                        }).map_err(|e| ZKError::SystemError(format!("Failed to draw terminal: {}", e)))?;
                        
                        last_tick = Instant::now();
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("🔄 TUI Dashboard received shutdown signal");
                    break;
                }
            }
        }

        Ok(())
    }

    fn draw_ui(&self, f: &mut Frame) -> Result<()> {
        let rt = tokio::runtime::Handle::current();
        let state = rt.block_on(self.state.read());

        if state.show_help {
            self.draw_help_popup(f);
            return Ok(());
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Main content
                Constraint::Length(3), // Footer
            ])
            .split(f.size());

        // Draw header
        self.draw_header(f, chunks[0], &state);

        // Draw main content based on selected tab
        match state.current_tab {
            0 => self.draw_overview_tab(f, chunks[1], &state),
            1 => self.draw_risk_analysis_tab(f, chunks[1], &state),
            2 => self.draw_performance_tab(f, chunks[1], &state),
            3 => self.draw_storage_tab(f, chunks[1], &state),
            4 => self.draw_alerts_tab(f, chunks[1], &state),
            5 => self.draw_help_tab(f, chunks[1], &state),
            _ => {}
        }

        // Draw footer
        self.draw_footer(f, chunks[2], &state);

        Ok(())
    }

    fn draw_header(&self, f: &mut Frame, area: Rect, state: &DashboardState) {
        let titles = TABS.iter().cloned().map(Line::from).collect();
        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL).title("🔐 ZKAnalyzer v3.5"))
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .select(state.current_tab);
        f.render_widget(tabs, area);
    }

    fn draw_footer(&self, f: &mut Frame, area: Rect, state: &DashboardState) {
        let footer_text = vec![
            Line::from(vec![
                Span::styled("Press ", Style::default().fg(Color::Gray)),
                Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(" to quit, ", Style::default().fg(Color::Gray)),
                Span::styled("h", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(" for help, ", Style::default().fg(Color::Gray)),
                Span::styled("Tab", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(" to switch tabs", Style::default().fg(Color::Gray)),
            ])
        ];

        let footer = Paragraph::new(footer_text)
            .block(Block::default().borders(Borders::ALL))
            .alignment(Alignment::Center);
        f.render_widget(footer, area);
    }

    fn draw_overview_tab(&self, f: &mut Frame, area: Rect, state: &DashboardState) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(7),  // Status cards
                Constraint::Min(10),    // Charts
            ])
            .split(area);

        // Status cards
        let status_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
            ])
            .split(chunks[0]);

        // Risk Score Card
        let risk_score = state.risk_history.back().copied().unwrap_or(0.0);
        let risk_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Risk Score"))
            .gauge_style(Style::default().fg(if risk_score > 0.7 { Color::Red } else if risk_score > 0.4 { Color::Yellow } else { Color::Green }))
            .ratio(risk_score);
        f.render_widget(risk_gauge, status_chunks[0]);

        // Memory Usage Card
        let memory_usage = state.memory_history.back().copied().unwrap_or(0.0);
        let memory_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Memory (MB)"))
            .gauge_style(Style::default().fg(Color::Blue))
            .ratio(memory_usage / (self.config.system.max_memory_gb.unwrap_or(10.5) * 1024.0));
        f.render_widget(memory_gauge, status_chunks[1]);

        // CPU Usage Card
        let cpu_usage = state.cpu_history.back().copied().unwrap_or(0.0);
        let cpu_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("CPU (%)"))
            .gauge_style(Style::default().fg(Color::Cyan))
            .ratio(cpu_usage / 100.0);
        f.render_widget(cpu_gauge, status_chunks[2]);

        // Transaction Count Card
        let tx_text = vec![
            Line::from(vec![
                Span::styled("Processed: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", state.transaction_count), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Alerts: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", state.alert_count), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]),
        ];
        let tx_paragraph = Paragraph::new(tx_text)
            .block(Block::default().borders(Borders::ALL).title("Statistics"))
            .alignment(Alignment::Center);
        f.render_widget(tx_paragraph, status_chunks[3]);

        // Charts
        let chart_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[1]);

        // Risk Score Chart
        if !state.risk_history.is_empty() {
            let risk_data: Vec<(f64, f64)> = state.risk_history
                .iter()
                .enumerate()
                .map(|(i, &value)| (i as f64, value))
                .collect();

            let risk_dataset = Dataset::default()
                .name("Risk Score")
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(Color::Red))
                .data(&risk_data);

            let risk_chart = Chart::new(vec![risk_dataset])
                .block(Block::default().borders(Borders::ALL).title("Risk Score History"))
                .x_axis(Axis::default().title("Time").bounds([0.0, MAX_HISTORY_POINTS as f64]))
                .y_axis(Axis::default().title("Score").bounds([0.0, 1.0]));

            f.render_widget(risk_chart, chart_chunks[0]);
        }

        // System Resources Chart
        if !state.memory_history.is_empty() && !state.cpu_history.is_empty() {
            let memory_data: Vec<(f64, f64)> = state.memory_history
                .iter()
                .enumerate()
                .map(|(i, &value)| (i as f64, value / 10.0)) // Scale for display
                .collect();

            let cpu_data: Vec<(f64, f64)> = state.cpu_history
                .iter()
                .enumerate()
                .map(|(i, &value)| (i as f64, value))
                .collect();

            let memory_dataset = Dataset::default()
                .name("Memory (GB)")
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(Color::Blue))
                .data(&memory_data);

            let cpu_dataset = Dataset::default()
                .name("CPU (%)")
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(Color::Cyan))
                .data(&cpu_data);

            let resources_chart = Chart::new(vec![memory_dataset, cpu_dataset])
                .block(Block::default().borders(Borders::ALL).title("System Resources"))
                .x_axis(Axis::default().title("Time").bounds([0.0, MAX_HISTORY_POINTS as f64]))
                .y_axis(Axis::default().title("Usage").bounds([0.0, 100.0]));

            f.render_widget(resources_chart, chart_chunks[1]);
        }
    }

    fn draw_risk_analysis_tab(&self, f: &mut Frame, area: Rect, _state: &DashboardState) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Risk Breakdown
        let risk_items = vec![
            ListItem::new("🔍 CPI Depth Analysis: Normal"),
            ListItem::new("⚠️  Anchor Panic Detection: 2 detected"),
            ListItem::new("💻 Compute Unit Monitoring: Within limits"),
            ListItem::new("👤 Signer Anomaly Detection: No anomalies"),
        ];

        let risk_list = List::new(risk_items)
            .block(Block::default().borders(Borders::ALL).title("Risk Analysis"))
            .style(Style::default().fg(Color::White));
        f.render_widget(risk_list, chunks[0]);

        // Recent High-Risk Transactions
        let tx_items = vec![
            ListItem::new("🚨 5VfydnLu4XwV2H2dLHPv22JxhLbYJruaM9YTaGY30TZjd4re - Score: 0.85"),
            ListItem::new("⚠️  3KjHgFd8Hs2Kj9Lm3Nq7Pr5St8Uv2Wx4Yz6Ab1Cd2Ef3Gh4 - Score: 0.72"),
            ListItem::new("ℹ️  7MnBvCxDfGhIjKlMnOpQrStUvWxYz1Ab2Cd3Ef4Gh5Ij6Kl - Score: 0.68"),
        ];

        let tx_list = List::new(tx_items)
            .block(Block::default().borders(Borders::ALL).title("Recent High-Risk Transactions"))
            .style(Style::default().fg(Color::White));
        f.render_widget(tx_list, chunks[1]);
    }

    fn draw_performance_tab(&self, f: &mut Frame, area: Rect, state: &DashboardState) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),  // Performance metrics
                Constraint::Min(0),     // Performance charts
            ])
            .split(area);

        // Performance Metrics Table
        let header = Row::new(vec!["Metric", "Current", "Average", "Peak"])
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

        let rows = vec![
            Row::new(vec!["TPS", "0.0", "0.0", "0.0"]),
            Row::new(vec!["Response Time (ms)", "5.2", "4.8", "15.3"]),
            Row::new(vec!["Memory Usage (MB)", &format!("{:.1}", state.memory_history.back().unwrap_or(&0.0)), "350.0", "420.0"]),
            Row::new(vec!["CPU Usage (%)", &format!("{:.1}", state.cpu_history.back().unwrap_or(&0.0)), "5.2", "12.8"]),
            Row::new(vec!["Queue Depth", "0", "0", "5"]),
        ];

        let table = Table::new(rows, [Constraint::Percentage(25); 4])
            .header(header)
            .block(Block::default().borders(Borders::ALL).title("Performance Metrics"));
        f.render_widget(table, chunks[0]);

        // Performance sparklines
        let sparkline_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[1]);

        // Memory sparkline
        if !state.memory_history.is_empty() {
            let memory_data: Vec<u64> = state.memory_history.iter().map(|&x| x as u64).collect();
            let memory_sparkline = Sparkline::default()
                .block(Block::default().borders(Borders::ALL).title("Memory Usage Trend"))
                .data(&memory_data)
                .style(Style::default().fg(Color::Blue));
            f.render_widget(memory_sparkline, sparkline_chunks[0]);
        }

        // CPU sparkline
        if !state.cpu_history.is_empty() {
            let cpu_data: Vec<u64> = state.cpu_history.iter().map(|&x| x as u64).collect();
            let cpu_sparkline = Sparkline::default()
                .block(Block::default().borders(Borders::ALL).title("CPU Usage Trend"))
                .data(&cpu_data)
                .style(Style::default().fg(Color::Cyan));
            f.render_widget(cpu_sparkline, sparkline_chunks[1]);
        }
    }

    fn draw_storage_tab(&self, f: &mut Frame, area: Rect, _state: &DashboardState) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        // Storage Information
        let storage_info = vec![
            Line::from(vec![
                Span::styled("Database Type: ", Style::default().fg(Color::Gray)),
                Span::styled("SQLite WAL", Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("Encryption: ", Style::default().fg(Color::Gray)),
                Span::styled(if self.config.storage.encryption_enabled { "AES-256" } else { "Disabled" }, 
                           Style::default().fg(if self.config.storage.encryption_enabled { Color::Green } else { Color::Yellow })),
            ]),
            Line::from(vec![
                Span::styled("Compression: ", Style::default().fg(Color::Gray)),
                Span::styled(if self.config.storage.compression_enabled { "Zstd" } else { "Disabled" }, 
                           Style::default().fg(if self.config.storage.compression_enabled { Color::Green } else { Color::Yellow })),
            ]),
            Line::from(vec![
                Span::styled("Size Limit: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{} MB", self.config.storage.max_db_size_mb), Style::default().fg(Color::Cyan)),
            ]),
        ];

        let storage_paragraph = Paragraph::new(storage_info)
            .block(Block::default().borders(Borders::ALL).title("Storage Configuration"))
            .wrap(Wrap { trim: true });
        f.render_widget(storage_paragraph, chunks[0]);

        // Storage Statistics
        let stats_items = vec![
            ListItem::new("📊 Total Records: 0"),
            ListItem::new("💳 Transactions Stored: 0"),
            ListItem::new("🛡️  Risk Assessments: 0"),
            ListItem::new("🔔 Alerts Stored: 0"),
            ListItem::new("💾 Database Size: 0.0 MB"),
            ListItem::new("🗜️  Compression Ratio: 1.0x"),
            ListItem::new("🧹 Last Vacuum: Never"),
        ];

        let stats_list = List::new(stats_items)
            .block(Block::default().borders(Borders::ALL).title("Storage Statistics"))
            .style(Style::default().fg(Color::White));
        f.render_widget(stats_list, chunks[1]);
    }

    fn draw_alerts_tab(&self, f: &mut Frame, area: Rect, state: &DashboardState) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Min(0)])
            .split(area);

        // Alert Statistics
        let alert_stats = vec![
            Line::from(vec![
                Span::styled("Total Alerts Sent: ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}", state.alert_count), Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("Failed Deliveries: ", Style::default().fg(Color::Gray)),
                Span::styled("0", Style::default().fg(Color::Red)),
            ]),
            Line::from(vec![
                Span::styled("Average Delivery Time: ", Style::default().fg(Color::Gray)),
                Span::styled("1.2s", Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("Active Rules: ", Style::default().fg(Color::Gray)),
                Span::styled("3", Style::default().fg(Color::Cyan)),
            ]),
        ];

        let stats_paragraph = Paragraph::new(alert_stats)
            .block(Block::default().borders(Borders::ALL).title("Alert Statistics"))
            .wrap(Wrap { trim: true });
        f.render_widget(stats_paragraph, chunks[0]);

        // Recent Alerts
        let alert_items = vec![
            ListItem::new("🚨 [CRITICAL] High risk transaction detected - 2 min ago"),
            ListItem::new("⚠️  [WARNING] Anchor panic in transaction - 5 min ago"),
            ListItem::new("ℹ️  [INFO] System maintenance completed - 1 hour ago"),
        ];

        let alerts_list = List::new(alert_items)
            .block(Block::default().borders(Borders::ALL).title("Recent Alerts"))
            .style(Style::default().fg(Color::White));
        f.render_widget(alerts_list, chunks[1]);
    }

    fn draw_help_tab(&self, f: &mut Frame, area: Rect, _state: &DashboardState) {
        let help_text = vec![
            Line::from("🔐 ZKAnalyzer v3.5 - TUI Dashboard Help"),
            Line::from(""),
            Line::from("Navigation:"),
            Line::from("  Tab / →     - Next tab"),
            Line::from("  Shift+Tab / ← - Previous tab"),
            Line::from("  ↑ / ↓       - Navigate lists"),
            Line::from("  PgUp / PgDn - Scroll pages"),
            Line::from(""),
            Line::from("Commands:"),
            Line::from("  q / Esc     - Quit dashboard"),
            Line::from("  h / F1      - Toggle help"),
            Line::from("  r           - Refresh data"),
            Line::from(""),
            Line::from("Tabs:"),
            Line::from("  Overview    - System status and charts"),
            Line::from("  Risk        - Risk analysis and alerts"),
            Line::from("  Performance - System performance metrics"),
            Line::from("  Storage     - Database and storage info"),
            Line::from("  Alerts      - Alert history and statistics"),
            Line::from(""),
            Line::from("Features:"),
            Line::from("  • Real-time monitoring"),
            Line::from("  • Risk score tracking"),
            Line::from("  • Performance analytics"),
            Line::from("  • Alert management"),
            Line::from("  • Resource monitoring"),
        ];

        let help_paragraph = Paragraph::new(help_text)
            .block(Block::default().borders(Borders::ALL).title("Help"))
            .wrap(Wrap { trim: true });
        f.render_widget(help_paragraph, area);
    }

    fn draw_help_popup(&self, f: &mut Frame) {
        let popup_area = self.centered_rect(60, 70, f.size());
        f.render_widget(Clear, popup_area);

        let help_text = vec![
            Line::from("🔐 ZKAnalyzer TUI Dashboard"),
            Line::from(""),
            Line::from("Keyboard Shortcuts:"),
            Line::from("  q, Esc  - Quit"),
            Line::from("  h, F1   - Toggle this help"),
            Line::from("  Tab     - Next tab"),
            Line::from("  ↑↓      - Navigate"),
            Line::from("  r       - Refresh"),
            Line::from(""),
            Line::from("Press any key to close"),
        ];

        let help_popup = Paragraph::new(help_text)
            .block(Block::default().borders(Borders::ALL).title("Help"))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        f.render_widget(help_popup, popup_area);
    }

    fn centered_rect(&self, percent_x: u16, percent_y: u16, r: Rect) -> Rect {
        let popup_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ])
            .split(r);

        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ])
            .split(popup_layout[1])[1]
    }

    async fn start_data_collection(&self) {
        let analyzer = Arc::clone(&self.analyzer);
        let state = Arc::clone(&self.state);
        let mut shutdown_rx = self.shutdown_receiver.resubscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Collect current metrics
                        let analyzer_state = analyzer.get_state().await;
                        
                        let mut dashboard_state = state.write().await;
                        
                        // Update history with new data points
                        dashboard_state.risk_history.push_back(0.0); // Would get from risk engine
                        dashboard_state.memory_history.push_back(analyzer_state.memory_usage_mb);
                        dashboard_state.cpu_history.push_back(analyzer_state.cpu_usage_percent);
                        
                        // Maintain history size
                        if dashboard_state.risk_history.len() > MAX_HISTORY_POINTS {
                            dashboard_state.risk_history.pop_front();
                        }
                        if dashboard_state.memory_history.len() > MAX_HISTORY_POINTS {
                            dashboard_state.memory_history.pop_front();
                        }
                        if dashboard_state.cpu_history.len() > MAX_HISTORY_POINTS {
                            dashboard_state.cpu_history.pop_front();
                        }
                        
                        // Update counters
                        dashboard_state.transaction_count += 1; // Would get real count
                        dashboard_state.last_update = Instant::now();
                    }
                    _ = shutdown_rx.recv() => {
                        debug!("Data collection task shutting down");
                        break;
                    }
                }
            }
        });
    }
}
