import axios from 'axios';
import { API_BASE_URL } from '../assets/constants';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use(
  (config) => {
    const apiKey = localStorage.getItem('chronos_api_key');
    if (apiKey) {
      config.headers['X-API-Key'] = apiKey;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('chronos_api_key');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const alertService = {
  getAlerts: (params = {}) => apiClient.get('/api/alerts', { params }),
  getAlert: (id) => apiClient.get(`/api/alerts/${id}`),
  createAlert: (alert) => apiClient.post('/api/alerts', alert),
  acknowledgeAlert: (id) => apiClient.post(`/api/alerts/${id}/acknowledge`),
  respondToAlert: (id, action, target) =>
    apiClient.post(`/api/alerts/${id}/respond`, null, { params: { action, target } }),
  getStats: () => apiClient.get('/api/stats'),
};

export const agentService = {
  registerAgent: (data) => apiClient.post('/api/v1/agents/register', data),
  listAgents: () => apiClient.get('/api/v1/agents'),
  sendEvents: (agentId, events) =>
    apiClient.post('/api/v1/events', { agent_id: agentId, events }),
  getEvents: (limit = 100) => apiClient.get('/api/v1/events', { params: { limit } }),
};

export const huntingService = {
  runHunt: (hypothesis) => apiClient.post('/api/hunting/run', null, { params: { hypothesis } }),
  getHypotheses: () => apiClient.get('/api/hunting/hypotheses'),
  createHypothesis: (hypothesis) => apiClient.post('/api/hunting/hypotheses', hypothesis),
};

export const configService = {
  getConfig: () => apiClient.get('/api/config'),
  getMitreCoverage: () => apiClient.get('/api/mitre/coverage'),
  getHosts: () => apiClient.get('/api/hosts'),
};

export const healthService = {
  checkHealth: () => apiClient.get('/health'),
};

export default apiClient;
