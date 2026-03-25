import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Card, CardContent, Chip, TextField, FormControl, InputLabel,
  Select, MenuItem, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  IconButton, Button, Dialog, DialogTitle, DialogContent, DialogActions,
  Menu, Snackbar, Alert, LinearProgress, Tooltip
} from '@mui/material';
import { 
  Search as SearchIcon, 
  FilterList as FilterIcon, 
  MoreVert as MoreIcon,
  CheckCircle as AcknowledgeIcon,
  OpenInFull as ExpandIcon,
  Refresh as RefreshIcon,
  Download as ExportIcon,
  ZoomIn as EnrichIcon,
} from '@mui/icons-material';
import { useAlertStore } from '../stores/alertStore';
import { useSettingsStore } from '../stores/settingsStore';
import axios from 'axios';

const severityColors = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e'
};

const statusColors = {
  new: 'info',
  acknowledged: 'warning',
  investigating: 'warning',
  resolved: 'success',
  false_positive: 'default'
};

export default function Alerts() {
  const { 
    alerts, 
    filteredAlerts,
    filters, 
    setFilters, 
    selectAlert, 
    selectedAlert, 
    acknowledgeAlert,
    enrichAlert,
    stats 
  } = useAlertStore();
  const { darkMode, refreshInterval } = useSettingsStore();
  const [detailOpen, setDetailOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [menuAnchor, setMenuAnchor] = useState(null);
  const [selectedAlertForMenu, setSelectedAlertForMenu] = useState(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [enriching, setEnriching] = useState(false);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const apiKey = localStorage.getItem('chronos_api_key') || 'chronos-secret-key-change-in-production';
      
      const response = await axios.get(`${apiUrl}/api/alerts`, {
        headers: { 'X-API-Key': apiKey },
        params: { limit: 100 }
      });
      
      if (response.data && Array.isArray(response.data)) {
        response.data.forEach(alert => {
          if (!alerts.find(a => a.id === alert.id)) {
            useAlertStore.setState(state => ({
              alerts: [alert, ...state.alerts].slice(0, 1000),
              filteredAlerts: applyFilters([alert, ...state.alerts], state.filters).slice(0, 1000)
            }));
          }
        });
      }
    } catch (error) {
      console.log('Using cached alerts');
    }
    setLoading(false);
  };

  const applyFilters = (alerts, filters) => {
    let filtered = [...alerts];

    if (filters.severity?.length > 0) {
      filtered = filtered.filter(a => filters.severity.includes(a.severity));
    }

    if (filters.status?.length > 0) {
      filtered = filtered.filter(a => filters.status.includes(a.status || 'new'));
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
  };

  const handleAlertClick = (alert) => {
    selectAlert(alert);
    setDetailOpen(true);
  };

  const handleMenuOpen = (event, alert) => {
    event.stopPropagation();
    setMenuAnchor(event.currentTarget);
    setSelectedAlertForMenu(alert);
  };

  const handleMenuClose = () => {
    setMenuAnchor(null);
    setSelectedAlertForMenu(null);
  };

  const handleAcknowledge = async (alertId) => {
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const apiKey = localStorage.getItem('chronos_api_key') || 'chronos-secret-key-change-in-production';
      
      await axios.post(
        `${apiUrl}/api/alerts/${alertId}/acknowledge`,
        {},
        { headers: { 'X-API-Key': apiKey } }
      );
      
      acknowledgeAlert(alertId);
      setSnackbar({ open: true, message: 'Alert acknowledged successfully', severity: 'success' });
    } catch (error) {
      setSnackbar({ open: true, message: 'Failed to acknowledge alert', severity: 'error' });
    }
    handleMenuClose();
  };

  const handleEnrich = async (alertId) => {
    setEnriching(true);
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const apiKey = localStorage.getItem('chronos_api_key') || 'chronos-secret-key-change-in-production';
      
      await axios.post(
        `${apiUrl}/api/v1/threat-intel/enrich-alert/${alertId}`,
        {},
        { headers: { 'X-API-Key': apiKey } }
      );
      
      enrichAlert(alertId, 'threat_intel');
      setSnackbar({ open: true, message: 'Alert enriched successfully', severity: 'success' });
    } catch (error) {
      setSnackbar({ open: true, message: 'Failed to enrich alert', severity: 'error' });
    }
    setEnriching(false);
    handleMenuClose();
  };

  const handleExport = () => {
    const dataToExport = filteredAlerts.length > 0 ? filteredAlerts : alerts;
    const csv = [
      ['ID', 'Title', 'Severity', 'Status', 'Source', 'Timestamp'],
      ...dataToExport.map(a => [a.id, a.title, a.severity, a.status || 'new', a.source || a.hostname, a.timestamp])
    ].map(row => row.join(',')).join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `alerts_${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);
    handleMenuClose();
    setSnackbar({ open: true, message: 'Alerts exported successfully', severity: 'success' });
  };

  const handleClearFilters = () => {
    setFilters({ severity: [], status: [], search: '' });
  };

  const hasActiveFilters = filters.severity.length > 0 || filters.status.length > 0 || filters.search;

  const displayAlerts = filteredAlerts.length > 0 ? filteredAlerts : alerts;

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 'bold', color: darkMode ? '#fff' : '#000' }}>
          Alerts
          <Chip 
            label={`${displayAlerts.length} alerts`} 
            size="small" 
            sx={{ ml: 2, bgcolor: darkMode ? '#16213e' : '#f5f5f5' }} 
          />
        </Typography>
        <Box>
          <Button startIcon={<RefreshIcon />} onClick={fetchAlerts} disabled={loading} sx={{ mr: 1 }}>
            Refresh
          </Button>
          <Button startIcon={<ExportIcon />} onClick={handleExport}>
            Export
          </Button>
        </Box>
      </Box>
      
      {loading && <LinearProgress sx={{ mb: 2 }} />}
      
      <Card sx={{ mb: 3, bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
        <CardContent sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', alignItems: 'center' }}>
          <TextField
            placeholder="Search alerts..."
            size="small"
            value={filters.search}
            onChange={(e) => setFilters({ search: e.target.value })}
            InputProps={{ 
              startAdornment: <SearchIcon sx={{ mr: 1, color: darkMode ? '#9ca3af' : '#666' }} /> 
            }}
            sx={{ minWidth: 300 }}
          />
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Severity</InputLabel>
            <Select
              multiple
              value={filters.severity}
              onChange={(e) => setFilters({ severity: e.target.value })}
              label="Severity"
              renderValue={(selected) => (
                <Box sx={{ display: 'flex', gap: 0.5 }}>
                  {selected.map((value) => (
                    <Chip key={value} label={value} size="small" sx={{ bgcolor: severityColors[value], color: '#fff' }} />
                  ))}
                </Box>
              )}
            >
              {['critical', 'high', 'medium', 'low'].map((sev) => (
                <MenuItem key={sev} value={sev}>{sev.charAt(0).toUpperCase() + sev.slice(1)}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Status</InputLabel>
            <Select
              multiple
              value={filters.status}
              onChange={(e) => setFilters({ status: e.target.value })}
              label="Status"
              renderValue={(selected) => (
                <Box sx={{ display: 'flex', gap: 0.5 }}>
                  {selected.map((value) => (
                    <Chip key={value} label={value} size="small" />
                  ))}
                </Box>
              )}
            >
              {['new', 'acknowledged', 'investigating', 'resolved', 'false_positive'].map((status) => (
                <MenuItem key={status} value={status}>{status.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}</MenuItem>
              ))}
            </Select>
          </FormControl>
          {hasActiveFilters && (
            <Button variant="text" onClick={handleClearFilters} size="small">
              Clear Filters
            </Button>
          )}
        </CardContent>
      </Card>

      <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Severity</TableCell>
                <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Title</TableCell>
                <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Source</TableCell>
                <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Time</TableCell>
                <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Status</TableCell>
                <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666', width: 50 }}>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {displayAlerts.slice(0, 50).map((alert, idx) => (
                <TableRow 
                  key={idx} 
                  hover 
                  onClick={() => handleAlertClick(alert)}
                  sx={{ 
                    cursor: 'pointer',
                    bgcolor: darkMode ? (idx % 2 === 0 ? '#1a1a2e' : '#16213e') : (idx % 2 === 0 ? '#ffffff' : '#f5f5f5')
                  }}
                >
                  <TableCell>
                    <Chip 
                      label={alert.severity} 
                      size="small" 
                      sx={{ bgcolor: severityColors[alert.severity], color: '#fff' }} 
                    />
                  </TableCell>
                  <TableCell sx={{ color: darkMode ? '#fff' : '#000' }}>
                    <Typography variant="body2" sx={{ fontWeight: 'bold' }}>{alert.title}</Typography>
                    {alert.technique && (
                      <Typography variant="caption" sx={{ color: darkMode ? '#6b7280' : '#999' }}>
                        {alert.technique}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>{alert.source || alert.hostname || '-'}</TableCell>
                  <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
                    {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '-'}
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={alert.status || 'new'} 
                      size="small" 
                      color={statusColors[alert.status] || 'info'}
                      variant={alert.status ? 'filled' : 'outlined'}
                    />
                  </TableCell>
                  <TableCell>
                    <IconButton 
                      size="small" 
                      onClick={(e) => handleMenuOpen(e, alert)}
                      sx={{ color: darkMode ? '#9ca3af' : '#666' }}
                    >
                      <MoreIcon />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
              {displayAlerts.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} sx={{ textAlign: 'center', py: 4, color: darkMode ? '#9ca3af' : '#666' }}>
                    No alerts found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Card>

      <Dialog open={detailOpen} onClose={() => setDetailOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', color: darkMode ? '#fff' : '#000', borderBottom: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Chip 
              label={selectedAlert?.severity} 
              sx={{ bgcolor: severityColors[selectedAlert?.severity], color: '#fff' }} 
            />
            {selectedAlert?.title}
          </Box>
        </DialogTitle>
        <DialogContent sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', mt: 2 }}>
          <Typography variant="body1" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>
            {selectedAlert?.description || 'No description available'}
          </Typography>
          
          <Box sx={{ mb: 2 }}>
            <Typography variant="subtitle2" sx={{ color: darkMode ? '#9ca3af' : '#666', mb: 1 }}>
              Details:
            </Typography>
            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1 }}>
              <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
                Status: <strong style={{ color: darkMode ? '#fff' : '#000' }}>{selectedAlert?.status || 'new'}</strong>
              </Typography>
              <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
                Technique: <strong style={{ color: darkMode ? '#fff' : '#000' }}>{selectedAlert?.technique || '-'}</strong>
              </Typography>
              <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
                TTP: <strong style={{ color: darkMode ? '#fff' : '#000' }}>{selectedAlert?.ttp || '-'}</strong>
              </Typography>
              <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
                Source: <strong style={{ color: darkMode ? '#fff' : '#000' }}>{selectedAlert?.source || selectedAlert?.hostname || '-'}</strong>
              </Typography>
              <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
                User: <strong style={{ color: darkMode ? '#fff' : '#000' }}>{selectedAlert?.user || '-'}</strong>
              </Typography>
              <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
                Timestamp: <strong style={{ color: darkMode ? '#fff' : '#000' }}>
                  {selectedAlert?.timestamp ? new Date(selectedAlert.timestamp).toLocaleString() : '-'}
                </strong>
              </Typography>
            </Box>
          </Box>
          
          {selectedAlert?.indicators?.length > 0 && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" sx={{ color: darkMode ? '#9ca3af' : '#666', mb: 1 }}>
                Indicators:
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {selectedAlert.indicators.map((indicator, i) => (
                  <Chip key={i} label={indicator} size="small" sx={{ bgcolor: darkMode ? '#16213e' : '#f5f5f5' }} />
                ))}
              </Box>
            </Box>
          )}
          
          {enriching && <LinearProgress sx={{ mt: 2 }} />}
        </DialogContent>
        <DialogActions sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', borderTop: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
          <Button onClick={() => setDetailOpen(false)}>Close</Button>
          <Tooltip title="Enrich with threat intelligence">
            <Button 
              variant="outlined" 
              startIcon={<EnrichIcon />}
              onClick={() => handleEnrich(selectedAlert?.id)}
              disabled={enriching}
            >
              Enrich
            </Button>
          </Tooltip>
          <Button 
            variant="contained" 
            startIcon={<AcknowledgeIcon />}
            onClick={() => { 
              handleAcknowledge(selectedAlert?.id); 
              setDetailOpen(false); 
            }}
            disabled={selectedAlert?.status !== 'new'}
          >
            Acknowledge
          </Button>
        </DialogActions>
      </Dialog>

      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={() => { handleAlertClick(selectedAlertForMenu); handleMenuClose(); }}>
          <ExpandIcon sx={{ mr: 1 }} /> View Details
        </MenuItem>
        <MenuItem onClick={() => handleAcknowledge(selectedAlertForMenu?.id)}>
          <AcknowledgeIcon sx={{ mr: 1 }} /> Acknowledge
        </MenuItem>
        <MenuItem onClick={() => handleEnrich(selectedAlertForMenu?.id)} disabled={enriching}>
          <EnrichIcon sx={{ mr: 1 }} /> Enrich
        </MenuItem>
        <MenuItem onClick={handleExport}>
          <ExportIcon sx={{ mr: 1 }} /> Export
        </MenuItem>
      </Menu>

      <Snackbar 
        open={snackbar.open} 
        autoHideDuration={4000} 
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert 
          onClose={() => setSnackbar({ ...snackbar, open: false })} 
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}
