# CHRONOS: Temporal Analysis & Anomaly Detection for APT Hunting

Continuous Heuristic Recognition of Network Operations & Signatures

## Project Overview

CHRONOS is a multi-layered blue team platform that detects Advanced Persistent Threats (APTs) through:
- Temporal behavior analysis (time-series anomaly detection)
- Graph-based lateral movement detection
- Automated threat hunting
- SOAR integration for automated response

## Key Features

### Out-of-the-Box Operation
- **Demo Mode**: Generate synthetic data for testing and demonstration
- **Graceful Degradation**: System runs without external services (Kafka, ES, Neo4j)
- **No API Keys Required**: All integrations are optional and disabled by default

### External Services (Optional)
- **Kafka**: Message streaming for high-volume event processing
- **Elasticsearch**: Data storage and search
- **Neo4j**: Graph-based lateral movement detection
- **Redis**: Caching and real-time features
- **VirusTotal/AbuseIPDB**: Threat intelligence enrichment

## Quick Start (No External Services Required)

```bash
# Install dependencies
pip install -r requirements.txt

# Create ML model placeholders (optional - for ML features)
python create_placeholder_models.py

# Run with demo mode (generates synthetic data)
python -m chronos.core.detection.engine
```

The system will run in demo mode by default, generating synthetic security events for testing detection logic.

## Running with External Services

### Minimal Setup (API + Engine only)
```bash
# Start only the API and engine services
docker-compose up chronos-api chronos-engine
```

### Full Stack
```bash
# Start all services (requires significant resources)
docker-compose --profile full up

# Start with specific profiles
docker-compose --profile kafka --profile elasticsearch up
```

### Available Docker Profiles
- `default`: Core API and engine only
- `full`: All services
- `kafka`: Kafka and Zookeeper
- `elasticsearch`: Elasticsearch, Kibana, Logstash
- `graph`: Neo4j
- `visualization`: Grafana, frontend
- `cache`: Redis

## Configuration

### Environment Variables (Optional)
Copy `.env.example` to `.env` and configure:
- `VT_API_KEY`: VirusTotal API key
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key
- `EDR_API_KEY`: EDR integration (Wazuh/SentinelOne)
- etc.

### config/config.yaml

Key settings:
```yaml
# Demo mode - generates synthetic data for testing
data_sources:
  demo_mode:
    enabled: true  # Set to false when connecting to real data sources

# Service availability - set to true to enable external services
services:
  kafka:
    enabled: false  # Set to true if Kafka is available
  elasticsearch:
    enabled: false
  neo4j:
    enabled: false

# SOAR - disabled by default for safety
soar:
  dry_run: true  # Actions are logged but not executed
```

## Module Descriptions

### Core Detection Engines

- **Temporal Behavior Analysis (TBA)**: Detects C2 beaconing, DGA domains, abnormal login times
- **Graph-Based Detection**: Models network as graph, detects lateral movement patterns
- **Identity Threat Detection**: Detects compromised credentials, impossible travel, privilege escalation

### Data Pipeline

- **Demo Mode**: Synthetic event generation for testing
- **Kafka Producers**: Collect events from multiple sources (optional)
- **Logstash Filters**: Normalize and enrich data (optional)
- **Elasticsearch Storage**: Centralized log aggregation (optional)

### Threat Hunting

- **Automated Playbooks**: Hypothesis-driven hunting workflows
- **ML Alert Triage**: Prioritizes alerts based on risk scoring

### SOAR Integration

- **Dry-Run Mode**: All actions logged but not executed by default
- **Response Orchestrator**: Automated containment actions (when enabled)
- **Enrichment**: VirusTotal, AbuseIPDB, MISP integration (when configured)

## ML Models

Placeholder models are provided in `models/`:
- `dga_classifier.pth` - DGA domain detection
- `alert_prioritizer.pth` - Alert prioritization
- `beaconing_lstm.pth` - C2 beaconing detection
- `anomaly_detector.pkl` - General anomaly detection
- `graph_analyzer.pth` - Graph-based lateral movement

Replace with trained models for production use.

## Testing

```bash
# Run unit tests
pytest tests/

# Run with demo mode (no external services needed)
python -m chronos.core.detection.engine
```

## MITRE ATT&CK Coverage

CHRONOS provides detection coverage for:
- Initial Access (T1566, T1190)
- Execution (T1059, T1204)
- Persistence (T1547, T1136)
- Privilege Escalation (T1055, T1078)
- Lateral Movement (T1021, T1210)
- Collection (T1005, T1119)
- Exfiltration (T1041, T1048)
- Command & Control (T1071, T1105)

## Security Notes

- SOAR auto-response is disabled by default (`dry_run: true`)
- All response actions require explicit enablement in config
- Threat intelligence APIs require user configuration
- Endpoint agent is disabled by default

## License

MIT License - Educational Use Only
