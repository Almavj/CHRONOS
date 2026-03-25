import { create } from 'zustand';
import { persist } from 'zustand/middleware';

const STORAGE_KEY = 'chronos_settings';

export const useSettingsStore = create(
  persist(
    (set, get) => ({
      darkMode: true,
      showNotifications: true,
      compactView: false,
      refreshInterval: 30000,
      apiKey: '',
      wsUrl: 'ws://localhost:8000',
      retentionDays: 30,
      integrations: [],
      notificationRules: [],

      setDarkMode: (value) => set({ darkMode: value }),
      setShowNotifications: (value) => set({ showNotifications: value }),
      setCompactView: (value) => set({ compactView: value }),
      setRefreshInterval: (value) => set({ refreshInterval: value }),
      setApiKey: (value) => set({ apiKey: value }),
      setWsUrl: (value) => set({ wsUrl: value }),
      setRetentionDays: (value) => set({ retentionDays: value }),

      toggleIntegration: (id) => {
        const integrations = get().integrations.map((int) =>
          int.id === id ? { ...int, status: int.status === 'connected' ? 'disconnected' : 'connected' } : int
        );
        set({ integrations });
      },

      updateIntegration: (id, updates) => {
        const integrations = get().integrations.map((int) =>
          int.id === id ? { ...int, ...updates } : int
        );
        set({ integrations });
      },

      addIntegration: (integration) => {
        const id = String(Date.now());
        set({ integrations: [...get().integrations, { ...integration, id }] });
      },

      removeIntegration: (id) => {
        set({ integrations: get().integrations.filter((int) => int.id !== id) });
      },

      toggleNotificationRule: (id) => {
        const notificationRules = get().notificationRules.map((rule) =>
          rule.id === id ? { ...rule, enabled: !rule.enabled } : rule
        );
        set({ notificationRules });
      },

      checkIntegrationHealth: async (id) => {
        const integration = get().integrations.find((int) => int.id === id);
        if (!integration || !integration.apiUrl) {
          return false;
        }

        try {
          const response = await fetch(integration.apiUrl, {
            method: 'GET',
            headers: integration.apiKey ? { 'Authorization': `Bearer ${integration.apiKey}` } : {},
            signal: AbortSignal.timeout(5000),
          });
          const isHealthy = response.ok;
          const integrations = get().integrations.map((int) =>
            int.id === id ? { ...int, status: isHealthy ? 'connected' : 'disconnected', lastChecked: new Date().toISOString() } : int
          );
          set({ integrations });
          return isHealthy;
        } catch (error) {
          const integrations = get().integrations.map((int) =>
            int.id === id ? { ...int, status: 'disconnected', lastChecked: new Date().toISOString(), error: error.message } : int
          );
          set({ integrations });
          return false;
        }
      },
    }),
    {
      name: STORAGE_KEY,
      partialize: (state) => ({
        darkMode: state.darkMode,
        showNotifications: state.showNotifications,
        compactView: state.compactView,
        refreshInterval: state.refreshInterval,
        apiKey: state.apiKey,
        wsUrl: state.wsUrl,
        retentionDays: state.retentionDays,
        integrations: state.integrations,
        notificationRules: state.notificationRules,
      }),
    }
  )
);

export default useSettingsStore;
