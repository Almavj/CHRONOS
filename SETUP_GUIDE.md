# CHRONOS Setup & Installation Guide

## 1. MISSING PYTHON PACKAGES TO INSTALL

### Critical Packages (Must Install)
```bash
# Machine Learning
pip install torch torchvision torchaudio

# Message Broker & Data
pip install kafka-python==2.0.2
pip install elasticsearch>=8.0.0
pip install neo4j>=5.0.0

# API & Web
pip install fastapi>=0.100.0
pip install uvicorn>=0.23.0
pip install websockets>=11.0.0

# ML & Analytics
pip install scikit-learn>=1.3.0
pip install scipy>=1.10.0

# Security & Integration
pip install requests-auth>=2.0.0
pip install python-nmap>=0.7.1
```

### Install with reduced dependencies (torch alternative)
```bash
# If torch is too large, install CPU-only version
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu

# Or install smaller alternative ML library
pip install xgboost lightgbm  # Lighter ML alternatives
```

---

## 2. ENVIRONMENT VARIABLES & API KEYS NEEDED

Create a `.env` file in `/home/alma/Documents/chronos/config/.env`:

```bash
# Threat Intelligence APIs
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
MISP_API_KEY=your_misp_api_key_here

# External Services
MISP_URL=https://misp.your-org.local
MITRE_ATT_CK_URL=https://attack.mitre.org

# Slack/Notification Webhooks
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/PATH
TEAMS_WEBHOOK_URL=https://outlook.webhook.office.com/webhookb2/...

# EDR Integration
WAZUH_API_URL=http://wazuh:55000
WAZUH_API_KEY=your_wazuh_api_key
SENTINEL_ONE_API_TOKEN=your_sentinelone_token

# Grafana
GRAFANA_API_KEY=your_grafana_api_key

# Caldera (Adversarial Testing)
CALDERA_API_KEY=your_caldera_api_key

# General
CHRONOS_API_KEY=chronos-secret-key-2024-change-in-production
ENVIRONMENT=lab  # or 'production'
```

---

## 3. INFRASTRUCTURE REQUIREMENTS

### Docker Services (In docker-compose.yml)
```
✓ Zookeeper (required for Kafka)
✓ Kafka (required for event streaming)
✓ Elasticsearch (required for data storage)
✓ Kibana (visualization)
✓ Logstash (log processing)
✓ Grafana (metrics visualization)
✓ Neo4j (graph database for lateral movement detection)
✓ Redis (caching & real-time)
```

### Start Docker Services
```bash
cd /home/alma/Documents/chronos
docker-compose up -d

# Verify services are running
docker-compose ps

# Check service health
curl http://localhost:9200  # Elasticsearch
curl http://localhost:7687  # Neo4j
redis-cli ping             # Redis
```

### Wait for Services to Start (health checks)
```bash
# Elasticsearch
until curl -s http://localhost:9200/_cluster/health | grep -q '"status":"yellow\|green'; do 
  echo "Waiting for Elasticsearch..."; sleep 5; 
done

# Kafka
until docker exec chronos-kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null; do 
  echo "Waiting for Kafka..."; sleep 5; 
done

# Neo4j
until curl -s -u neo4j:chronos123 http://localhost:7474/browser/ > /dev/null 2>&1; do 
  echo "Waiting for Neo4j..."; sleep 5; 
done
```

---

## 4. REQUIRED ML MODELS

### Models to Download or Train

#### A. Beaconing Detection Model (FreqAnalyzer)
```
Location: /home/alma/Documents/chronos/models/dga_classifier.pth
Size: ~50MB
Status: ❌ MISSING

Training script needed:
```python
# train_dga_model.py
import torch
import torch.nn as nn

class DGAClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.lstm = nn.LSTM(128, 256, 2, batch_first=True)
        self.fc = nn.Linear(256, 1)
    
    def forward(self, x):
        _, (h_n, _) = self.lstm(x)
        return torch.sigmoid(self.fc(h_n[-1]))

# Download OSINT DGA dataset or create synthetic samples
# Train with benign vs DGA domain names
```

#### B. Alert Prioritization Model
```
Location: /home/alma/Documents/chronos/models/alert_prioritizer.pth
Size: ~30MB
Status: ❌ MISSING

Should train on: Asset criticality, TTP similarity, alert context
```

#### C. Beaconing LSTM Model
```
Location: /home/alma/Documents/chronos/models/beaconing_lstm.pth
Size: ~40MB
Status: ❌ MISSING

Should detect: C2 communication patterns, regular intervals, data exfiltration
```

### How to Create Placeholder Models:
```python
# create_placeholder_models.py
import torch
import torch.nn as nn
import os

os.makedirs('models', exist_ok=True)

# DGA Classifier
class DGAModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(100, 1)
    
    def forward(self, x):
        return torch.sigmoid(self.fc(x))

model = DGAModel()
torch.save(model.state_dict(), 'models/dga_classifier.pth')

# Alert Prioritizer
model2 = DGAModel()
torch.save(model2.state_dict(), 'models/alert_prioritizer.pth')

# Beaconing LSTM
class BeaconingLSTM(nn.Module):
    def __init__(self):
        super().__init__()
        self.lstm = nn.LSTM(1, 64, 2, batch_first=True)
        self.fc = nn.Linear(64, 1)
    
    def forward(self, x):
        _, (h_n, _) = self.lstm(x)
        return torch.sigmoid(self.fc(h_n[-1]))

model3 = BeaconingLSTM()
torch.save(model3.state_dict(), 'models/beaconing_lstm.pth')

print("Placeholder models created!")
```

---

## 5. DATA SOURCES TO CONFIGURE

### A. Sysmon Configuration (Windows)
```
File: /home/alma/Documents/chronos/data/collectors/windows/sysmon_config.xml
Status: ✓ EXISTS (but needs deployment to Windows systems)

Steps:
1. Download Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
2. Deploy config to Windows: sysmon.exe -i sysmon_config.xml
3. Configure Wazuh agent to collect events
4. Point to Elasticsearch via Wazuh
```

### B. Zeek Configuration (Network)
```
File: /home/alma/Documents/chronos/data/collectors/network/zeek_config.zeek
Status: ✓ EXISTS (but needs Zeek installation on network tap/mirror)

Steps:
1. Install Zeek on network sensor/tap
2. Apply config: /opt/zeek/etc/zeek/zeek.cfg
3. Point to Kafka or Elasticsearch
4. Enable network traffic capture
```

### C. Wazuh Integration
```
Endpoint: http://wazuh:9200 (in docker)
Steps:
1. Deploy Wazuh agent to endpoints
2. Enable Windows Event Log (IDs: 4624, 4625, 4672, 4688, 4698, 4720, 4726)
3. Configure agent to forward to Wazuh manager
4. Wazuh manager forwards to Elasticsearch
```

### D. CloudTrail (AWS)
```
Status: ❌ Currently disabled in config.yaml
Steps to enable:
1. Create AWS IAM user with CloudTrail read permissions
2. Set AWS credentials in environment
3. Enable in config: cloudtrail.enabled = true
4. Configure region and S3 bucket
```

---

## 6. CONFIGURATION FILES TO UPDATE

### A. Update config.yaml
```yaml
# /home/alma/Documents/chronos/config/config.yaml

# Replace service endpoints
kafka:
  bootstrap_servers: "kafka:29092"  # Docker internal
  
elasticsearch:
  hosts: ["http://elasticsearch:9200"]
  
neo4j:
  uri: "bolt://neo4j:7687"
  password: "chronos123"
  
# Enable/disable features
tba:
  beaconing:
    enabled: true
    model_path: "models/dga_classifier.pth"
  
soar:
  enrichment:
    virustotal:
      api_key: "${VT_API_KEY}"
    abuseipdb:
      api_key: "${ABUSEIPDB_API_KEY}"
```

### B. Create config/.env.example
```bash
# Copy and populate:
cp config/config.yaml config/config.example.yaml
```

### C. Setup Logstash Configuration
```bash
# Copy logstash configs to Docker volume
docker cp pipeline/logstash-alerts.conf chronos-logstash:/usr/share/logstash/pipeline/
docker cp pipeline/logstash-events.conf chronos-logstash:/usr/share/logstash/pipeline/
docker exec chronos-logstash logstash -f /usr/share/logstash/pipeline/logstash-alerts.conf --config.test_and_exit
```

---

## 7. COMPLETE INSTALLATION STEPS

### Step 1: Install Python Dependencies
```bash
cd /home/alma/Documents/chronos

# Install only critical missing packages
pip install torch scikit-learn kafka-python elasticsearch neo4j fastapi uvicorn websockets scipy requests-auth python-nmap

# Or install specific to your CPU:
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install scikit-learn kafka-python elasticsearch neo4j fastapi uvicorn websockets scipy
```

### Step 2: Create Environment File
```bash
cp config/.env.example config/.env
# Edit and add your API keys
nano config/.env
```

### Step 3: Create ML Models
```bash
python create_placeholder_models.py
```

### Step 4: Start Docker Services
```bash
docker-compose up -d
sleep 60  # Wait for services to initialize
```

### Step 5: Initialize Databases
```bash
# Create Elasticsearch indices
curl -X PUT http://localhost:9200/chronos-events -H "Content-Type: application/json" -d '{
  "settings": {"number_of_shards": 1}
}'

curl -X PUT http://localhost:9200/chronos-alerts -H "Content-Type: application/json" -d '{
  "settings": {"number_of_shards": 1}
}'

# Initialize Neo4j (first login: https://localhost:7474)
# Username: neo4j, Password: chronos123
# Set new password when prompted
```

### Step 6: Start Detection Engine
```bash
PYTHONPATH=/home/alma/Documents python -m chronos.scripts.run engine
```

### Step 7: Start API Server
```bash
PYTHONPATH=/home/alma/Documents python -m chronos.api.main
```

### Step 8: Access UI
```
Frontend: http://localhost:80
Kibana: http://localhost:5601
Grafana: http://localhost:3000 (admin/chronos123)
Neo4j: http://localhost:7474
Kafka UI: http://localhost:8080
```

---

## 8. MISSING FILES TO CREATE

### A. create_placeholder_models.py
[See section 4 above for code]

### B. .env Configuration
[See section 2 above]

### C. Wazuh Configuration (optional)
```bash
# /etc/wazuh-agent/ossec.conf
<agent>
  <name>my-workstation</name>
  <ip>192.168.1.100</ip>
</agent>

<client>
  <server>
    <address>wazuh-manager.local</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

### D. Sysmon Installation Script (for Windows)
```powershell
# deploy_sysmon.ps1
$SysmonPath = "C:\Sysmon"
$ConfigPath = "$SysmonPath\sysmon_config.xml"

# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath $SysmonPath

# Install with config
& "$SysmonPath\sysmon64.exe" -i $ConfigPath -accepteula

Write-Host "Sysmon installed successfully"
```

---

## 9. DATA COLLECTION SETUP

### Quick Start with Mock Data
```bash
# Generate test alerts manually
curl -X POST http://localhost:8000/api/alerts \
  -H "Content-Type: application/json" \
  -H "X-API-Key: chronos-secret-key-2024-change-in-production" \
  -d '{
    "title": "Suspicious PowerShell Activity",
    "description": "Detected Invoke-WebRequest",
    "severity": "high",
    "technique": "T1059",
    "hostname": "WORKSTATION-01",
    "user": "admin"
  }'
```

### Real Data Collection
1. Deploy Wazuh agents to endpoints
2. Enable Sysmon on Windows systems
3. Deploy Zeek on network taps
4. Configure CloudTrail for AWS environments
5. Point all collectors to Elasticsearch

---

## 10. VERIFICATION CHECKLIST

- [ ] Python packages installed: `pip list | grep -E 'torch|kafka|elasticsearch|neo4j|fastapi'`
- [ ] .env file created with API keys
- [ ] Docker services running: `docker-compose ps`
- [ ] Elasticsearch responsive: `curl http://localhost:9200`
- [ ] Kafka topics created: `docker exec chronos-kafka kafka-topics --list --bootstrap-server kafka:9092`
- [ ] Neo4j accessible: Browse to http://localhost:7474
- [ ] ML models exist: `ls -la models/*.pth`
- [ ] Detection engine starts: `python -m chronos.scripts.run engine`
- [ ] API server starts: `python -m chronos.api.main`
- [ ] Frontend loads: Browse to http://localhost:80
- [ ] Test alert created and visible in UI

---

## 11. TROUBLESHOOTING

### PyTorch Installation Issues
```bash
# If install fails, try CPU-only version
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu

# Or use conda for better binary support
conda install pytorch::pytorch torchvision torchaudio -c pytorch
```

### Elasticsearch Connection Failed
```bash
# Check if ES is running
docker-compose logs elasticsearch

# Recreate service
docker-compose down elasticsearch
docker-compose up -d elasticsearch
docker-compose logs -f elasticsearch
```

### Kafka Not Responding
```bash
# Check Zookeeper health first
docker exec chronos-zookeeper bash -c 'echo stat | nc localhost 2181'

# Restart Kafka
docker-compose restart kafka
```

### Neo4j Authentication Failed
```bash
# Reset Neo4j password
docker exec chronos-neo4j neo4j-admin set-initial-password chronos123
docker restart chronos-neo4j
```

### Models not found
```bash
# Create placeholder models
python3 << 'EOF'
import torch, os
os.makedirs('models', exist_ok=True)
torch.save({}, 'models/dga_classifier.pth')
torch.save({}, 'models/alert_prioritizer.pth')
torch.save({}, 'models/beaconing_lstm.pth')
EOF
```

---

## 12. SIZE ESTIMATES

| Component | Approximate Size | Required |
|-----------|------------------|----------|
| PyTorch (CPU) | 500MB | ✓ Yes |
| Elasticsearch | 1GB | ✓ Yes |
| Neo4j | 200MB | ✓ Yes |
| Kafka | 400MB | ✓ Yes |
| Grafana | 200MB | ✓ Yes |
| ML Models | 150MB | ✓ Yes |
| **Total** | **~2.5GB** | - |

---

## 13. NEXT STEPS AFTER SETUP

1. **Train ML Models** with real detection data
2. **Calibrate Thresholds** based on your environment
3. **Deploy Data Collectors** to all endpoints
4. **Create Custom Rules** with Sigma/YARA
5. **Configure Automated Response** actions
6. **Enable Threat Intelligence** feeds
7. **Setup Alerting** to your SOC channels
8. **Perform Load Testing** with sample data
