# 📡 ZKAnalyzer v3.5 API Reference

## Overview

ZKAnalyzer provides a comprehensive REST API for programmatic access to all system functionality. The API follows RESTful principles and returns JSON responses.

## Base URL

```
Production: https://your-domain.com/api
Development: http://localhost:9102/api
```

## Authentication

Most endpoints require authentication using Bearer tokens:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://your-domain.com/api/endpoint
```

### Token Types
- **Admin Token**: Full system access
- **ReadOnly Token**: Read-only access to data
- **Replay Token**: Replay engine access

## Core Endpoints

### Health & Status

#### GET /health
System health check
```json
{
  "status": "healthy",
  "uptime": 3600,
  "version": "3.5.0"
}
```

#### GET /ready
Readiness probe for Kubernetes
```json
{
  "status": "ready",
  "services": ["risk", "storage", "alerts"]
}
```

#### GET /metrics
Prometheus metrics endpoint
```
# HELP zk_risk_score_current Current risk score
# TYPE zk_risk_score_current gauge
zk_risk_score_current 0.25
```

### Risk Analysis

#### GET /api/risk/current
Get current system risk score
```json
{
  "risk_score": 0.25,
  "risk_level": "low",
  "last_updated": "2024-01-15T10:30:00Z",
  "factors": {
    "cpi_depth": 0.1,
    "anchor_panics": 0.05,
    "compute_units": 0.08,
    "signer_anomalies": 0.02
  }
}
```

#### GET /api/risk/transaction/{signature}
Analyze specific transaction
```json
{
  "signature": "5VfydnLu4XwV2H2dLHPv22JxhLbYJruaM9YTaGY30TZjd4re",
  "risk_score": 0.85,
  "risk_level": "high",
  "analysis": {
    "cpi_depth": 5,
    "anchor_panic_detected": true,
    "compute_units": 450000,
    "signer_count": 3,
    "unusual_patterns": ["high_cpi_depth", "anchor_panic"]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### GET /api/risk/history
Risk score history
```json
{
  "timeframe": "24h",
  "data_points": [
    {
      "timestamp": "2024-01-15T10:00:00Z",
      "risk_score": 0.23
    },
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "risk_score": 0.25
    }
  ],
  "statistics": {
    "average": 0.24,
    "max": 0.85,
    "min": 0.12
  }
}
```

### Storage & Data

#### GET /api/storage/stats
Storage system statistics
```json
{
  "database_size_mb": 125.5,
  "total_records": 15000,
  "compression_ratio": 2.8,
  "encryption_enabled": true,
  "last_vacuum": "2024-01-15T08:00:00Z"
}
```

#### POST /api/export
Export data in various formats
```bash
curl -X POST "http://localhost:9102/api/export" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "json",
    "start_slot": 250000000,
    "end_slot": 250001000,
    "include_risk_analysis": true
  }'
```

Response:
```json
{
  "export_id": "exp_123456",
  "status": "processing",
  "download_url": "/api/export/exp_123456/download",
  "estimated_completion": "2024-01-15T10:35:00Z"
}
```

### Replay Engine

#### POST /api/replay/slot/{slot}
Replay specific slot
```bash
curl -X POST "http://localhost:9102/api/replay/slot/250000000" \
  -H "Authorization: Bearer $REPLAY_TOKEN"
```

Response:
```json
{
  "replay_id": "replay_789",
  "slot": 250000000,
  "status": "started",
  "estimated_duration": "30s"
}
```

#### GET /api/replay/{replay_id}/status
Check replay status
```json
{
  "replay_id": "replay_789",
  "status": "completed",
  "progress": 100,
  "transactions_processed": 1250,
  "duration": "28s",
  "results_url": "/api/replay/replay_789/results"
}
```

### Alert Management

#### GET /api/alerts
List recent alerts
```json
{
  "alerts": [
    {
      "id": "alert_001",
      "severity": "warning",
      "title": "High risk transaction detected",
      "message": "Transaction 5Vfyd... has risk score 0.85",
      "timestamp": "2024-01-15T10:30:00Z",
      "acknowledged": false,
      "channels": ["slack", "webhook"]
    }
  ],
  "total": 8,
  "unacknowledged": 3
}
```

#### POST /api/alerts/{alert_id}/acknowledge
Acknowledge alert
```bash
curl -X POST "http://localhost:9102/api/alerts/alert_001/acknowledge" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### GET /api/alerts/rules
Get alert rules configuration
```json
{
  "rules": [
    {
      "name": "HighRiskTransaction",
      "enabled": true,
      "conditions": [
        {
          "field": "risk_score",
          "operator": "greater_than",
          "value": 0.8
        }
      ],
      "actions": [
        {
          "channel": "slack",
          "priority": "high"
        }
      ]
    }
  ]
}
```

### Plugin Management

#### GET /api/plugins
List loaded plugins
```json
{
  "plugins": [
    {
      "name": "risk_analyzer_plugin",
      "version": "1.2.0",
      "status": "active",
      "capabilities": ["RiskAnalysis", "DataProcessing"],
      "memory_usage_kb": 256,
      "last_activity": "2024-01-15T10:30:00Z"
    }
  ],
  "total_loaded": 3,
  "total_active": 3
}
```

#### POST /api/plugins/load
Load new plugin
```bash
curl -X POST "http://localhost:9102/api/plugins/load" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/path/to/plugin.so",
    "verify_signature": true
  }'
```

#### POST /api/plugins/{name}/reload
Hot reload plugin
```bash
curl -X POST "http://localhost:9102/api/plugins/risk_analyzer/reload" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### System Configuration

#### GET /api/config
Get system configuration (admin only)
```json
{
  "system": {
    "max_memory_gb": 10.5,
    "max_cpu_percent": 40.0,
    "max_disk_gb": 4.5
  },
  "risk_detection": {
    "enabled": true,
    "max_cpi_depth": 4,
    "risk_threshold": 0.7
  },
  "alerts": {
    "enabled": true,
    "delivery_timeout_secs": 3
  }
}
```

#### PATCH /api/config
Update configuration
```bash
curl -X PATCH "http://localhost:9102/api/config" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "risk_detection.risk_threshold": 0.75,
    "alerts.delivery_timeout_secs": 2
  }'
```

### Security & Audit

#### GET /api/security/audit
Get audit log entries
```json
{
  "entries": [
    {
      "id": 1001,
      "timestamp": "2024-01-15T10:30:00Z",
      "event_type": "Authentication",
      "user_id": "admin",
      "action": "login_success",
      "source_ip": "192.168.1.100",
      "hash": "a1b2c3d4..."
    }
  ],
  "total": 5000,
  "integrity_verified": true
}
```

#### POST /api/security/verify-audit
Verify audit log integrity
```json
{
  "verification_result": "valid",
  "total_entries": 5000,
  "chain_verified": true,
  "last_verification": "2024-01-15T10:30:00Z"
}
```

## WebSocket API

### Real-time Dashboard Updates

Connect to WebSocket for live data:
```javascript
const ws = new WebSocket('wss://your-domain.com/ws/dashboard');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Live update:', data);
};
```

Message format:
```json
{
  "type": "risk_update",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "risk_score": 0.25,
    "memory_usage": 8200,
    "cpu_usage": 25.5
  }
}
```

## Error Handling

All API endpoints return consistent error responses:

```json
{
  "error": {
    "code": "INVALID_TOKEN",
    "message": "Authentication token is invalid or expired",
    "details": {
      "token_expired": true,
      "expiry_time": "2024-01-15T09:00:00Z"
    }
  },
  "request_id": "req_123456",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Common Error Codes
- `INVALID_TOKEN`: Authentication failed
- `INSUFFICIENT_PERMISSIONS`: Authorization failed
- `RESOURCE_NOT_FOUND`: Requested resource doesn't exist
- `RATE_LIMITED`: Too many requests
- `INTERNAL_ERROR`: Server error
- `VALIDATION_ERROR`: Invalid request data

## Rate Limiting

API endpoints are rate limited:
- **General endpoints**: 100 requests/minute
- **Export endpoints**: 10 requests/minute
- **Admin endpoints**: 50 requests/minute

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248600
```

## SDK Examples

### Python
```python
import requests

class ZKAnalyzerClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {token}"}
    
    def get_risk_score(self):
        response = requests.get(
            f"{self.base_url}/api/risk/current",
            headers=self.headers
        )
        return response.json()

client = ZKAnalyzerClient("http://localhost:9102", "your-token")
risk_data = client.get_risk_score()
```

### JavaScript
```javascript
class ZKAnalyzerClient {
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        };
    }
    
    async getRiskScore() {
        const response = await fetch(`${this.baseUrl}/api/risk/current`, {
            headers: this.headers
        });
        return response.json();
    }
}

const client = new ZKAnalyzerClient('http://localhost:9102', 'your-token');
const riskData = await client.getRiskScore();
```

### Rust
```rust
use reqwest::Client;
use serde_json::Value;

pub struct ZKAnalyzerClient {
    client: Client,
    base_url: String,
    token: String,
}

impl ZKAnalyzerClient {
    pub fn new(base_url: String, token: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            token,
        }
    }
    
    pub async fn get_risk_score(&self) -> Result<Value, reqwest::Error> {
        let response = self.client
            .get(&format!("{}/api/risk/current", self.base_url))
            .bearer_auth(&self.token)
            .send()
            .await?;
        
        response.json().await
    }
}
```
