# CHRONOS Quick Reference - Installation Checklist

## Pre-Installation Checklist

- [ ] Python 3.9+ installed
- [ ] Docker & docker-compose installed
- [ ] At least 5GB free disk space
- [ ] Administrator/sudo access for system commands
- [ ] Internet connection (for package downloads)

---

## Installation Steps

### 1️⃣ Install Python Packages (Choose ONE)

**Option A: Minimal Installation (RECOMMENDED)**
```bash
cd /home/alma/Documents/chronos
pip install -r requirements-prod.txt
```

**Option B: Full Installation (with PyTorch)**
```bash
pip install -r requirements.txt
```

**Option C: Manual Installation (selective packages)**
```bash
# Only install what's missing
pip install elasticsearch neo4j kafka-python fastapi uvicorn scikit-learn
```

### 2️⃣ Create Environment Configuration

```bash
# Copy template to actual file
cp config/.env.example config/.env

# Edit with your values
nano config/.env

# Fill in these REQUIRED values:
# - VT_API_KEY (VirusTotal API)
# - ABUSEIPDB_API_KEY (AbuseIPDB API)
# - WAZUH_API_KEY (Wazuh integration)
# - SLACK_WEBHOOK_URL (Slack alerts)
# - CHRONOS_API_KEY (Change from default)
```

### 3️⃣ Create ML Models

```bash
# Option A: Using automated script
python3 create_placeholder_models.py

# Option B: Manual creation
mkdir -p models
python3 << 'EOF'
import torch, os
os.makedirs('models', exist_ok=True)
torch.save({}, 'models/dga_classifier.pth')
torch.save({}, 'models/alert_prioritizer.pth')
torch.save({}, 'models/beaconing_lstm.pth')
print("Models created!")
EOF

# Verify models exist
ls -la models/
```

### 4️⃣ Start Docker Services

```bash
# Start all services
docker-compose up -d

# Verify they're running
docker-compose ps

# Check service logs
docker-compose logs -f elasticsearch
docker-compose logs -f kafka
docker-compose logs -f neo4j

# Wait for all services to be healthy (60 seconds)
sleep 60
```

### 5️⃣ Initialize Databases

```bash
# Create Elasticsearch indices
curl -X PUT http://localhost:9200/chronos-events \
  -H "Content-Type: application/json" \
  -d '{"settings":{"number_of_shards":1}}'

curl -X PUT http://localhost:9200/chronos-alerts \
  -H "Content-Type: application/json" \
  -d '{"settings":{"number_of_shards":1}}'

# Verify indices
curl http://localhost:9200/_cat/indices

# Neo4j: Access browser at http://localhost:7474
# Login: neo4j / chronos123
```

### 6️⃣ Set PYTHONPATH and Test

```bash
# For ALL commands, set PYTHONPATH
export PYTHONPATH=/home/alma/Documents:$PYTHONPATH

# Test if code can be imported
python3 -c "from chronos.config import config; print('✓ Config loaded')"

# If above fails, fix permission issues:
sudo chown -R $(whoami):$(whoami) /home/alma/Documents/chronos/logs/
```

### 7️⃣ Start Services

```bash
# Terminal 1: Start Detection Engine
cd /home/alma/Documents/chronos
export PYTHONPATH=/home/alma/Documents:$PYTHONPATH
python3 -m chronos.scripts.run engine

# Terminal 2: Start API Server
cd /home/alma/Documents/chronos
export PYTHONPATH=/home/alma/Documents:$PYTHONPATH
python3 -m chronos.scripts.run api

# Terminal 3: Monitor (optional)
cd /home/alma/Documents/chronos
export PYTHONPATH=/home/alma/Documents:$PYTHONPATH
python3 -m chronos.scripts.run test
```

---

## Service URLs After Setup

| Service | URL | Credentials |
|---------|-----|-------------|
| CHRONOS API | http://localhost:8000 | API Key in .env |
| Frontend | http://localhost:80 | None |
| Elasticsearch | http://localhost:9200 | elastic / password |
| Kibana | http://localhost:5601 | None |
| Grafana | http://localhost:3000 | admin / chronos123 |
| Neo4j | http://localhost:7474 | neo4j / chronos123 |
| Kafka UI | http://localhost:8080 | None |
| Redis | localhost:6379 | None |

---

## API Keys to Obtain

| Service | Where to Get | Required |
|---------|-------------|----------|
| **VirusTotal** | https://www.virustotal.com/gui/sign-up | Optional |
| **AbuseIPDB** | https://www.abuseipdb.com/register | Optional |
| **Slack** | https://api.slack.com/apps | Optional |
| **Wazuh** | Your own instance | If using Wazuh |
| **MISP** | Your own instance | If using MISP |

---

## Troubleshooting Quick Fixes

### Issue: "ModuleNotFoundError: No module named 'chronos'"
```bash
# Set PYTHONPATH before running
export PYTHONPATH=/home/alma/Documents:$PYTHONPATH
```

### Issue: "Permission denied" on log files
```bash
# Fix permissions
sudo chown -R $(whoami):$(whoami) /home/alma/Documents/chronos/logs/
chmod 755 /home/alma/Documents/chronos/logs/
```

### Issue: "Elasticsearch not available"
```bash
# Check if service is running
curl -v http://localhost:9200

# If not, start/restart
docker-compose restart elasticsearch
docker-compose logs elasticsearch
```

### Issue: "Can't connect to Kafka"
```bash
# Check Zookeeper first
docker exec -it chronos-zookeeper bash -c 'echo stat | nc localhost 2181'

# Restart Kafka
docker-compose restart kafka
docker-compose logs kafka
```

### Issue: "Port already in use"
```bash
# Find what's using the port (e.g., port 8000)
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or change port in docker-compose.yml or API script
```

### Issue: "PyTorch not found"
```bash
# Install CPU-only version (smaller)
pip install torch --index-url https://download.pytorch.org/whl/cpu

# Or install scikit-learn instead
pip install scikit-learn
```

---

## Installation Script (Automated)

```bash
# Run all steps automatically
chmod +x install.sh
./install.sh
```

---

## Disk Space Requirements

| Component | Size |
|-----------|------|
| Python packages (minimal) | 800MB |
| PyTorch (optional) | 500MB |
| ML Models | 150MB |
| Docker images | 2GB |
| Elasticsearch data | 1GB |
| **Total** | **~4-5GB** |

---

## Data Sources to Configure Later

After installation, configure these data sources:

1. **Sysmon** (Windows endpoints)
   - Deploy agent to Windows systems
   - Enable event IDs: 1, 3, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 26, 27, 28, 29

2. **Zeek** (Network traffic)
   - Install on network tap/mirror
   - Send logs to Elasticsearch or Kafka

3. **Wazuh** (Agent-based monitoring)
   - Deploy Wazuh agent to endpoints
   - Configure to forward to Elasticsearch

4. **CloudTrail** (AWS)
   - Enable CloudTrail in AWS console
   - Set S3 bucket for logs
   - Configure CHRONOS to read from S3

---

## Common Commands

```bash
# Set PYTHONPATH (do this in every terminal session)
export PYTHONPATH=/home/alma/Documents:$PYTHONPATH

# Start engine
python3 -m chronos.scripts.run engine

# Start API
python3 -m chronos.scripts.run api

# Run tests
python3 -m chronos.scripts.run test

# View Docker logs
docker-compose logs -f chronos-engine
docker-compose logs -f chronos-api

# Stop all Docker services
docker-compose down

# Remove Docker volumes (WARNING: deletes data)
docker-compose down -v

# Restart a specific service
docker-compose restart elasticsearch

# Access container shell
docker exec -it chronos-elasticsearch bash
```

---

## What Works After Installation

✅ Detection engine starts and loads models
✅ API server accepts requests
✅ WebSocket connections for real-time alerts
✅ Basic alert creation and storage
✅ Elasticsearch data indexing
✅ Dashboard access (Kibana/Grafana)
✅ Mock data ingestion

## What Still Needs Configuration

⚠️ Real data source connections (Sysmon, Zeek)
⚠️ ML model training
⚠️ API key integrations
⚠️ Automated response actions
⚠️ Threat intelligence feeds
⚠️ Slack/email notifications

---

## Support & Documentation

- Full setup guide: `SETUP_GUIDE.md`
- README: `README.md`
- Architecture: Check `core/` directory
- Example configs: `config/config.yaml`
