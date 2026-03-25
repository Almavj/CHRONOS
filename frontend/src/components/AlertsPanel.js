import React, { useState } from 'react';
import { Box, Paper, Typography, List, ListItem, ListItemText, Chip, IconButton, Button, Divider } from '@mui/material';
import { Close as CloseIcon, Warning as WarningIcon, OpenInNew as OpenInNewIcon } from '@mui/icons-material';
import { useAlertStore } from '../stores/alertStore';
import { useSettingsStore } from '../stores/settingsStore';

export default function AlertsPanel() {
  const [isOpen, setIsOpen] = useState(true);
  const { alerts, acknowledgeAlert } = useAlertStore();
  const { darkMode } = useSettingsStore();
  const recentAlerts = alerts.slice(0, 10);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      default: return '#22c55e';
    }
  };

  return (
    <Paper
      sx={{
        position: 'fixed',
        right: isOpen ? 0 : '-400px',
        top: 0,
        width: 400,
        height: '100vh',
        bgcolor: darkMode ? '#1a1a2e' : '#ffffff',
        borderLeft: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`,
        transition: 'right 0.3s ease',
        zIndex: 1200,
        overflow: 'auto',
      }}
    >
      <Box sx={{ 
        p: 2, 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between', 
        borderBottom: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` 
      }}>
        <Typography variant="h6" sx={{ color: darkMode ? '#fff' : '#000' }}>
          Recent Alerts
        </Typography>
        <Box>
          <Chip 
            label={`${recentAlerts.length} alerts`} 
            size="small" 
            sx={{ mr: 1, bgcolor: darkMode ? '#16213e' : '#f5f5f5' }}
          />
          <IconButton onClick={() => setIsOpen(false)} sx={{ color: darkMode ? '#fff' : '#000' }}>
            <CloseIcon />
          </IconButton>
        </Box>
      </Box>
      {recentAlerts.length === 0 ? (
        <Box sx={{ p: 4, textAlign: 'center' }}>
          <WarningIcon sx={{ fontSize: 48, color: darkMode ? '#4a4a6a' : '#ccc', mb: 2 }} />
          <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
            No recent alerts
          </Typography>
        </Box>
      ) : (
        <List>
          {recentAlerts.map((alert, index) => (
            <ListItem 
              key={index} 
              sx={{ 
                borderBottom: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`,
                flexDirection: 'column',
                alignItems: 'stretch'
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'flex-start', mb: 1 }}>
                <WarningIcon sx={{ color: getSeverityColor(alert.severity), mr: 2, mt: 0.5 }} />
                <Box sx={{ flex: 1 }}>
                  <Typography 
                    variant="body2" 
                    sx={{ 
                      fontWeight: 'bold', 
                      color: darkMode ? '#fff' : '#000',
                      mb: 0.5 
                    }}
                  >
                    {alert.title}
                  </Typography>
                  <Typography 
                    variant="caption" 
                    sx={{ color: darkMode ? '#9ca3af' : '#666', display: 'block' }}
                  >
                    {alert.description}
                  </Typography>
                  {alert.timestamp && (
                    <Typography 
                      variant="caption" 
                      sx={{ color: darkMode ? '#6b7280' : '#999', display: 'block', mt: 0.5 }}
                    >
                      {new Date(alert.timestamp).toLocaleString()}
                    </Typography>
                  )}
                </Box>
              </Box>
              <Box sx={{ display: 'flex', gap: 1, ml: 4 }}>
                <Chip
                  label={alert.severity}
                  size="small"
                  sx={{ bgcolor: getSeverityColor(alert.severity), color: '#fff' }}
                />
                <Chip
                  label={alert.status || 'new'}
                  size="small"
                  variant="outlined"
                  sx={{ color: darkMode ? '#9ca3af' : '#666' }}
                />
                <Button 
                  size="small" 
                  variant="text"
                  onClick={() => acknowledgeAlert(alert.id)}
                  sx={{ ml: 'auto', color: '#e94560' }}
                >
                  Acknowledge
                </Button>
              </Box>
            </ListItem>
          ))}
        </List>
      )}
      {recentAlerts.length > 0 && (
        <Box sx={{ p: 2, borderTop: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
          <Button 
            fullWidth 
            variant="outlined" 
            startIcon={<OpenInNewIcon />}
            onClick={() => window.location.href = '/alerts'}
            sx={{ color: '#e94560', borderColor: '#e94560' }}
          >
            View All Alerts
          </Button>
        </Box>
      )}
    </Paper>
  );
}
