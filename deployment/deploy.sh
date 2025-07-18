#!/bin/bash

# ZKAnalyzer Production Deployment Script
# Usage: ./deploy.sh [production|staging|development]

set -euo pipefail

# Configuration
ENVIRONMENT=${1:-production}
PROJECT_DIR="/home/ubuntu/Sandeep/projects/ZKanalyser"
LOG_DIR="/home/ubuntu/.zkanalyzer/logs"
DATA_DIR="/home/ubuntu/.zkanalyzer/data"
BACKUP_DIR="/home/ubuntu/.zkanalyzer/backups"
NGINX_SITE="zkanalyzer"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as correct user
check_user() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root"
        exit 1
    fi
    
    if [[ $(whoami) != "ubuntu" ]]; then
        error "This script should be run as the ubuntu user"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check available memory
    AVAILABLE_MEM=$(free -g | awk '/^Mem:/{print $7}')
    if [[ $AVAILABLE_MEM -lt 8 ]]; then
        error "Insufficient memory. Need at least 8GB available, found ${AVAILABLE_MEM}GB"
        exit 1
    fi
    
    # Check disk space
    AVAILABLE_DISK=$(df -BG "$PROJECT_DIR" | awk 'NR==2{print $4}' | sed 's/G//')
    if [[ $AVAILABLE_DISK -lt 10 ]]; then
        error "Insufficient disk space. Need at least 10GB available, found ${AVAILABLE_DISK}GB"
        exit 1
    fi
    
    # Check required commands
    for cmd in cargo pm2 nginx systemctl; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    success "System requirements check passed"
}

# Create necessary directories
setup_directories() {
    log "Setting up directories..."
    
    mkdir -p "$LOG_DIR" "$DATA_DIR" "$BACKUP_DIR"
    mkdir -p "$PROJECT_DIR/config"
    mkdir -p "$PROJECT_DIR/web/static"
    
    # Set proper permissions
    chmod 755 "$LOG_DIR" "$DATA_DIR" "$BACKUP_DIR"
    
    success "Directories created"
}

# Backup existing data
backup_data() {
    log "Creating backup..."
    
    BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_PATH="$BACKUP_DIR/zkanalyzer_backup_$BACKUP_TIMESTAMP"
    
    mkdir -p "$BACKUP_PATH"
    
    # Backup database if it exists
    if [[ -f "$DATA_DIR/zkanalyzer.db" ]]; then
        cp "$DATA_DIR/zkanalyzer.db" "$BACKUP_PATH/"
        log "Database backed up"
    fi
    
    # Backup configuration
    if [[ -d "$PROJECT_DIR/config" ]]; then
        cp -r "$PROJECT_DIR/config" "$BACKUP_PATH/"
        log "Configuration backed up"
    fi
    
    # Backup logs (last 7 days)
    find "$LOG_DIR" -name "*.log" -mtime -7 -exec cp {} "$BACKUP_PATH/" \;
    
    # Compress backup
    tar -czf "$BACKUP_PATH.tar.gz" -C "$BACKUP_DIR" "zkanalyzer_backup_$BACKUP_TIMESTAMP"
    rm -rf "$BACKUP_PATH"
    
    success "Backup created: $BACKUP_PATH.tar.gz"
}

# Build the application
build_application() {
    log "Building ZKAnalyzer..."
    
    cd "$PROJECT_DIR"
    
    # Clean previous build
    cargo clean
    
    # Build in release mode
    RUST_LOG=info cargo build --release
    
    # Verify binary
    if [[ ! -f "target/release/zkanalyzer" ]]; then
        error "Build failed - binary not found"
        exit 1
    fi
    
    # Check binary size (should be reasonable)
    BINARY_SIZE=$(du -m target/release/zkanalyzer | cut -f1)
    if [[ $BINARY_SIZE -gt 500 ]]; then
        warning "Binary size is large: ${BINARY_SIZE}MB"
    fi
    
    success "Build completed successfully"
}

# Configure PM2
setup_pm2() {
    log "Setting up PM2 configuration..."
    
    # Stop existing PM2 processes (safely)
    pm2 stop zkanalyzer-main zkanalyzer-api zkanalyzer-web zkanalyzer-metrics 2>/dev/null || true
    
    # Copy PM2 configuration
    cp deployment/pm2.config.js "$PROJECT_DIR/ecosystem.config.js"
    
    # Start PM2 processes
    pm2 start ecosystem.config.js --env "$ENVIRONMENT"
    
    # Save PM2 configuration
    pm2 save
    
    # Setup PM2 startup script
    pm2 startup systemd -u ubuntu --hp /home/ubuntu
    
    success "PM2 configured and started"
}

# Configure NGINX
setup_nginx() {
    log "Setting up NGINX configuration..."
    
    # Copy NGINX configuration
    sudo cp deployment/nginx.conf "/etc/nginx/sites-available/$NGINX_SITE"
    
    # Enable site
    sudo ln -sf "/etc/nginx/sites-available/$NGINX_SITE" "/etc/nginx/sites-enabled/$NGINX_SITE"
    
    # Remove default site if it exists
    sudo rm -f /etc/nginx/sites-enabled/default
    
    # Test NGINX configuration
    if ! sudo nginx -t; then
        error "NGINX configuration test failed"
        exit 1
    fi
    
    # Reload NGINX
    sudo systemctl reload nginx
    
    success "NGINX configured and reloaded"
}

# Setup SSL certificates (self-signed for development)
setup_ssl() {
    log "Setting up SSL certificates..."
    
    SSL_DIR="/etc/ssl"
    CERT_FILE="$SSL_DIR/certs/zkanalyzer.crt"
    KEY_FILE="$SSL_DIR/private/zkanalyzer.key"
    
    if [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]]; then
        log "Generating self-signed SSL certificate..."
        
        sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$KEY_FILE" \
            -out "$CERT_FILE" \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=zkanalyzer.local"
        
        sudo chmod 600 "$KEY_FILE"
        sudo chmod 644 "$CERT_FILE"
        
        success "SSL certificate generated"
    else
        log "SSL certificate already exists"
    fi
}

# Health check
health_check() {
    log "Performing health checks..."
    
    # Wait for services to start
    sleep 10
    
    # Check PM2 processes
    if ! pm2 list | grep -q "online"; then
        error "PM2 processes not running properly"
        pm2 logs --lines 20
        exit 1
    fi
    
    # Check API endpoint
    if ! curl -f -s http://localhost:9102/health > /dev/null; then
        error "API health check failed"
        exit 1
    fi
    
    # Check web interface
    if ! curl -f -s http://localhost:8080/ > /dev/null; then
        error "Web interface health check failed"
        exit 1
    fi
    
    # Check metrics endpoint
    if ! curl -f -s http://localhost:9090/metrics > /dev/null; then
        error "Metrics endpoint health check failed"
        exit 1
    fi
    
    # Check NGINX
    if ! sudo nginx -t; then
        error "NGINX configuration check failed"
        exit 1
    fi
    
    success "All health checks passed"
}

# Display deployment information
show_deployment_info() {
    log "Deployment completed successfully!"
    echo
    echo "🔐 ZKAnalyzer v3.5 Production Deployment"
    echo "========================================"
    echo
    echo "📊 Services:"
    echo "  • Main Service:    http://localhost:9101"
    echo "  • API Server:      http://localhost:9102"
    echo "  • Web Interface:   http://localhost:8080"
    echo "  • Metrics:         http://localhost:9090/metrics"
    echo
    echo "🌐 NGINX Proxy:"
    echo "  • HTTPS:           https://3.111.22.56"
    echo "  • HTTP (redirect): http://3.111.22.56"
    echo
    echo "📋 Management:"
    echo "  • PM2 Status:      pm2 status"
    echo "  • PM2 Logs:        pm2 logs"
    echo "  • PM2 Restart:     pm2 restart all"
    echo "  • NGINX Status:    sudo systemctl status nginx"
    echo "  • NGINX Reload:    sudo systemctl reload nginx"
    echo
    echo "📁 Important Paths:"
    echo "  • Project:         $PROJECT_DIR"
    echo "  • Logs:            $LOG_DIR"
    echo "  • Data:            $DATA_DIR"
    echo "  • Backups:         $BACKUP_DIR"
    echo
    echo "🔧 Configuration:"
    echo "  • Environment:     $ENVIRONMENT"
    echo "  • PM2 Config:      $PROJECT_DIR/ecosystem.config.js"
    echo "  • NGINX Config:    /etc/nginx/sites-available/$NGINX_SITE"
    echo
}

# Main deployment function
main() {
    log "Starting ZKAnalyzer deployment for environment: $ENVIRONMENT"
    
    check_user
    check_requirements
    setup_directories
    backup_data
    build_application
    setup_pm2
    setup_nginx
    setup_ssl
    health_check
    show_deployment_info
    
    success "🚀 ZKAnalyzer deployment completed successfully!"
}

# Cleanup function for errors
cleanup() {
    error "Deployment failed. Cleaning up..."
    
    # Stop PM2 processes
    pm2 stop zkanalyzer-main zkanalyzer-api zkanalyzer-web zkanalyzer-metrics 2>/dev/null || true
    
    # Show recent logs
    echo "Recent PM2 logs:"
    pm2 logs --lines 10 2>/dev/null || true
    
    exit 1
}

# Set trap for cleanup on error
trap cleanup ERR

# Run main function
main "$@"
