import { create } from 'zustand';

const WS_URL = process.env.REACT_APP_WS_URL?.replace('http', 'ws') || 'ws://localhost:8000/ws';

export const useAlertStore = create((set, get) => ({
  alerts: [],
  filteredAlerts: [],
  selectedAlert: null,
  filters: {
    severity: [],
    status: [],
    timeRange: '24h',
    search: '',
  },
  isConnected: false,
  socket: null,
  stats: {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    mttd: 0,
    mttr: 0,
  },

  connect: () => {
    let socket;
    try {
      socket = new WebSocket(WS_URL);
    } catch (e) {
      console.log('[WS] Failed to create WebSocket');
      return;
    }

    socket.onopen = () => {
      set({ isConnected: true, socket });
      console.log('[WS] Connected');
    };

    socket.onclose = () => {
      set({ isConnected: false, socket: null });
      console.log('[WS] Disconnected');
    };

    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        const { alerts, stats } = get();
        
        if (message.type === 'alert:new') {
          const alert = message.data;
          const newAlerts = [alert, ...alerts].slice(0, 1000);
          
          const newStats = { ...stats };
          newStats.total += 1;
          if (alert.severity === 'critical') newStats.critical += 1;
          else if (alert.severity === 'high') newStats.high += 1;
          else if (alert.severity === 'medium') newStats.medium += 1;
          else newStats.low += 1;

          set({ 
            alerts: newAlerts,
            filteredAlerts: applyFilters(newAlerts, get().filters),
            stats: newStats,
          });
        }
      } catch (e) {
        console.log('[WS] Parse error:', e);
      }
    };
  },

  disconnect: () => {
    const { socket } = get();
    if (socket) {
      socket.close();
      set({ socket: null, isConnected: false });
    }
  },

  setFilters: (filters) => {
    const { alerts } = get();
    set({
      filters: { ...get().filters, ...filters },
      filteredAlerts: applyFilters(alerts, { ...get().filters, ...filters }),
    });
  },

  selectAlert: (alert) => {
    set({ selectedAlert: alert });
  },

  acknowledgeAlert: (alertId) => {
    const { socket } = get();
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'alert:acknowledge', alertId }));
    }
  },

  runPlaybook: (playbookId, target) => {
    const { socket } = get();
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'playbook:run', playbookId, target }));
    }
  },

  enrichAlert: async (alertId, enrichmentType) => {
    const { socket } = get();
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'alert:enrich', alertId, enrichmentType }));
    }
  },
}));

function applyFilters(alerts, filters) {
  let filtered = [...alerts];

  if (filters.severity?.length > 0) {
    filtered = filtered.filter(a => filters.severity.includes(a.severity));
  }

  if (filters.status?.length > 0) {
    filtered = filtered.filter(a => filters.status.includes(a.status));
  }

  if (filters.search) {
    const search = filters.search.toLowerCase();
    filtered = filtered.filter(a => 
      a.title?.toLowerCase().includes(search) ||
      a.description?.toLowerCase().includes(search) ||
      a.indicators?.some(i => i.toLowerCase().includes(search))
    );
  }

  return filtered;
}

export default useAlertStore;
