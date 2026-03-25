import { useState, useEffect, useCallback, useRef } from 'react';

const WS_URL = process.env.REACT_APP_WS_URL?.replace('http', 'ws') || 'ws://localhost:8000/ws';

export function useWebSocket() {
  const [socket, setSocket] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const socketRef = useRef(null);

  useEffect(() => {
    try {
      socketRef.current = new WebSocket(WS_URL);
    } catch (e) {
      console.log('[WS] Failed to create WebSocket');
      return;
    }

    socketRef.current.onopen = () => {
      console.log('WebSocket connected');
      setIsConnected(true);
    };

    socketRef.current.onclose = () => {
      console.log('WebSocket disconnected');
      setIsConnected(false);
    };

    setSocket(socketRef.current);

    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, []);

  const emit = useCallback((event, data) => {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: event, ...data }));
    }
  }, [socket]);

  const on = useCallback((event, callback) => {
    if (socket) {
      socket.addEventListener('message', (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.type === event) {
            callback(data.data || data);
          }
        } catch (err) {}
      });
    }
  }, [socket]);

  return { socket, isConnected, emit, on };
}

export function useAlerts() {
  const { on, emit } = useWebSocket();
  const [alerts, setAlerts] = useState([]);
  const [lastUpdate, setLastUpdate] = useState(null);

  useEffect(() => {
    const unsubscribe = on('alert:new', (alert) => {
      setAlerts(prev => [alert, ...prev].slice(0, 1000));
      setLastUpdate(new Date());
    });

    const unsubscribeBatch = on('alert:batch', (batch) => {
      setAlerts(prev => [...batch, ...prev].slice(0, 1000));
      setLastUpdate(new Date());
    });

    return () => {
      unsubscribe();
      unsubscribeBatch();
    };
  }, [on]);

  const acknowledgeAlert = useCallback((alertId) => {
    emit('alert:acknowledge', { alertId });
  }, [emit]);

  const runPlaybook = useCallback((playbookId, target) => {
    emit('playbook:run', { playbookId, target });
  }, [emit]);

  return { alerts, lastUpdate, acknowledgeAlert, runPlaybook };
}
