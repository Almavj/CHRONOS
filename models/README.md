# CHRONOS ML Models Directory

This directory contains pre-trained machine learning models for CHRONOS detection.

## Current Models

### 1. dga_classifier.pth
- **Purpose**: Detects Domain Generation Algorithm (DGA) domains
- **Type**: LSTM-based classifier
- **Input**: Domain name (encoded)
- **Output**: Probability score (0-1, where 1 = likely DGA)
- **Training Data**: Should be trained on known DGA vs benign domains

### 2. alert_prioritizer.pth
- **Purpose**: Prioritizes alerts based on risk score
- **Type**: Feedforward neural network
- **Input**: Alert features (asset criticality, TTP similarity, etc.)
- **Output**: Priority score (0-1)
- **Training Data**: Historical alert data with assigned priorities

### 3. beaconing_lstm.pth
- **Purpose**: Detects C2 beaconing patterns
- **Type**: LSTM time-series model
- **Input**: Network communication intervals (sequence)
- **Output**: Beaconing probability (0-1)
- **Training Data**: C2 beacon samples vs normal traffic

### 4. anomaly_detector.pkl
- **Purpose**: General anomaly detection
- **Type**: Isolation Forest (scikit-learn)
- **Input**: Feature vector (20 dimensions)
- **Output**: Anomaly score

### 5. graph_analyzer.pth
- **Purpose**: Analyze lateral movement in network graphs
- **Type**: Feedforward neural network
- **Input**: Graph features (50 dimensions)
- **Output**: Anomaly probability (0-1)

## Training Your Own Models

### DGA Classifier
```python
# Requires dataset of:
# - Benign domains: google.com, facebook.com, etc.
# - DGA domains: glfgfgffff.com, xyzabc123.biz, etc.

from chronos.core.ml.models import train_dga_classifier
train_dga_classifier(
    benign_domains_file='data/benign_domains.txt',
    dga_domains_file='data/dga_domains.txt',
    output_path='models/dga_classifier.pth'
)
```

### Alert Prioritizer
```python
# Requires historical alert data with priority labels
from chronos.core.ml.models import train_alert_prioritizer
train_alert_prioritizer(
    training_data='data/historical_alerts.csv',
    output_path='models/alert_prioritizer.pth'
)
```

### Beaconing Detector
```python
# Requires network traffic with labeled beaconing patterns
from chronos.core.ml.models import train_beaconing_detector
train_beaconing_detector(
    traffic_data='data/network_traffic.pcap',
    output_path='models/beaconing_lstm.pth'
)
```

## Datasets for Training

### Public Datasets
- **DGA Domains**: https://www.malware-traffic-analysis.net/
- **Benign Domains**: Alexa 1M (top 1 million sites)
- **C2 Beaconing**: DARPA Cyber Defense Exercise data
- **Network Traffic**: UNSW-NB15, NSL-KDD, CIC-IDS datasets

### Recommended Tools
- **BERT-based Domain Classification**: Use transformer models
- **PyTorch Lightning**: For easier model training
- **Weights & Biases**: For experiment tracking
- **MLflow**: For model versioning

## Model Evaluation

Always evaluate models on:
1. **True Positive Rate** (sensitivity): Catch actual attacks
2. **False Positive Rate** (specificity): Minimize alert fatigue
3. **Precision**: Avoid false alarms
4. **ROC-AUC**: Trade-off between TPR and FPR
5. **F1-Score**: Balanced metric

## Notes

- These placeholder models should be replaced with trained versions
- Model paths are configurable in config/config.yaml
- Models are loaded on CHRONOS startup
- Failed model loads don't crash the system (graceful degradation)
- Retrain models quarterly with fresh data
- Monitor model drift and performance over time
