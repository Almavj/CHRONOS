export const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
export const WS_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8000/ws';
export const GRAFANA_URL = process.env.REACT_APP_GRAFANA_URL || 'http://localhost:3000';

export const ALERT_SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
};

export const ALERT_STATUS = {
  NEW: 'new',
  ACKNOWLEDGED: 'acknowledged',
  INVESTIGATING: 'investigating',
  RESOLVED: 'resolved',
  FALSE_POSITIVE: 'false_positive',
};

export const TECHNIQUE_CATEGORIES = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

export const TIME_RANGES = [
  { label: 'Last 15 minutes', value: '15m' },
  { label: 'Last 1 hour', value: '1h' },
  { label: 'Last 6 hours', value: '6h' },
  { label: 'Last 24 hours', value: '24h' },
  { label: 'Last 7 days', value: '7d' },
  { label: 'Last 30 days', value: '30d' },
];

export const PAGE_SIZES = [10, 25, 50, 100];
