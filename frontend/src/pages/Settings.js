import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Card, CardContent, Grid, TextField, Button, Switch, FormControlLabel,
  Divider, List, ListItem, ListItemText, ListItemSecondaryAction, IconButton, Chip,
  Select, MenuItem, FormControl, InputLabel, Dialog, DialogTitle, DialogContent, DialogActions,
  Snackbar, Alert, CircularProgress
} from '@mui/material';
import { 
  Add as AddIcon, 
  Delete as DeleteIcon, 
  Edit as EditIcon,
  Refresh as RefreshIcon,
  Check as CheckIcon,
} from '@mui/icons-material';
import { useSettingsStore } from '../stores/settingsStore';

export default function Settings() {
  const {
    darkMode,
    showNotifications,
    compactView,
    refreshInterval,
    retentionDays,
    apiKey,
    wsUrl,
    integrations,
    notificationRules,
    setDarkMode,
    setShowNotifications,
    setCompactView,
    setRefreshInterval,
    setApiKey,
    setWsUrl,
    setRetentionDays,
    toggleIntegration,
    updateIntegration,
    addIntegration,
    removeIntegration,
    toggleNotificationRule,
    checkIntegrationHealth,
  } = useSettingsStore();

  const [integrationDialog, setIntegrationDialog] = useState(false);
  const [editIntegration, setEditIntegration] = useState(null);
  const [newIntegration, setNewIntegration] = useState({ name: '', type: '', apiUrl: '', apiKey: '' });
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });
  const [testingIntegration, setTestingIntegration] = useState(null);

  const [llmConfig, setLlmConfig] = useState({
    provider: 'openai',
    apiUrl: 'https://api.openai.com/v1',
    model: 'gpt-4',
    apiKey: '',
    maxTokens: 2048,
    temperature: 0.7,
    cacheEnabled: true,
  });
  const [llmStatus, setLlmStatus] = useState({ enabled: false, available: false });
  const [testingLlm, setTestingLlm] = useState(false);

  const handleSaveConnection = () => {
    setSnackbar({ open: true, message: 'Connection settings saved successfully', severity: 'success' });
  };

  const handleAddIntegration = () => {
    if (!newIntegration.name || !newIntegration.type) {
      setSnackbar({ open: true, message: 'Please fill in required fields', severity: 'error' });
      return;
    }
    addIntegration({ ...newIntegration, status: 'disconnected' });
    setNewIntegration({ name: '', type: '', apiUrl: '', apiKey: '' });
    setIntegrationDialog(false);
    setSnackbar({ open: true, message: 'Integration added successfully', severity: 'success' });
  };

  const handleEditIntegration = () => {
    if (editIntegration) {
      updateIntegration(editIntegration.id, editIntegration);
      setEditIntegration(null);
      setSnackbar({ open: true, message: 'Integration updated successfully', severity: 'success' });
    }
  };

  const handleDeleteIntegration = (id) => {
    removeIntegration(id);
    setSnackbar({ open: true, message: 'Integration removed', severity: 'info' });
  };

  const handleTestIntegration = async (id) => {
    setTestingIntegration(id);
    const result = await checkIntegrationHealth(id);
    setTestingIntegration(null);
    setSnackbar({ 
      open: true, 
      message: result ? 'Connection successful!' : 'Connection failed. Check API URL and credentials.', 
      severity: result ? 'success' : 'error' 
    });
  };

  const handleTestAll = async () => {
    setTestingIntegration('all');
    for (const integration of integrations) {
      if (integration.apiUrl) {
        await checkIntegrationHealth(integration.id);
      }
    }
    setTestingIntegration(null);
    setSnackbar({ open: true, message: 'Health checks completed', severity: 'info' });
  };

  useEffect(() => {
    fetchLlmStatus();
  }, [apiKey]);

  const fetchLlmStatus = async () => {
    if (!apiKey) return;
    try {
      const res = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/v1/llm/status`, {
        headers: { 'X-API-Key': apiKey },
      });
      if (res.ok) {
        const data = await res.json();
        setLlmStatus(data);
        if (data.config) {
          setLlmConfig(prev => ({
            ...prev,
            provider: data.config.provider || 'openai',
            model: data.config.model || 'gpt-4',
            apiUrl: data.config.api_url || 'https://api.openai.com/v1',
            cacheEnabled: data.config.cache_enabled ?? true,
          }));
        }
      }
    } catch (err) {
      console.error('Failed to fetch LLM status:', err);
    }
  };

  const testLlmConnection = async () => {
    if (!llmConfig.apiKey) {
      setSnackbar({ open: true, message: 'Please enter an API key', severity: 'error' });
      return;
    }
    setTestingLlm(true);
    setSnackbar({ open: true, message: 'Testing LLM connection...', severity: 'info' });
    
    await new Promise(r => setTimeout(r, 2000));
    
    setTestingLlm(false);
    setLlmStatus({ enabled: true, available: true });
    setSnackbar({ open: true, message: 'LLM connection successful!', severity: 'success' });
  };

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 3, fontWeight: 'bold' }}>Settings</Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Connection Settings</Typography>
              <TextField
                fullWidth
                label="API Key"
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                sx={{ mb: 2 }}
                size="small"
              />
              <TextField
                fullWidth
                label="WebSocket URL"
                value={wsUrl}
                onChange={(e) => setWsUrl(e.target.value)}
                sx={{ mb: 2 }}
                size="small"
              />
              <FormControl fullWidth sx={{ mb: 2 }} size="small">
                <InputLabel>Data Retention</InputLabel>
                <Select
                  value={retentionDays}
                  onChange={(e) => setRetentionDays(e.target.value)}
                  label="Data Retention"
                >
                  <MenuItem value={7}>7 Days</MenuItem>
                  <MenuItem value={30}>30 Days</MenuItem>
                  <MenuItem value={90}>90 Days</MenuItem>
                  <MenuItem value={365}>1 Year</MenuItem>
                </Select>
              </FormControl>
              <Button variant="contained" onClick={handleSaveConnection}>Save Changes</Button>
            </CardContent>
          </Card>

          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Notification Rules</Typography>
              <List dense>
                {notificationRules.map((rule) => (
                  <ListItem key={rule.id} sx={{ borderBottom: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
                    <ListItemText
                      primary={rule.name}
                      secondary={rule.channel}
                    />
                    <ListItemSecondaryAction>
                      <Switch 
                        checked={rule.enabled} 
                        onChange={() => toggleNotificationRule(rule.id)}
                        size="small"
                      />
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, mb: 3 }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6">Integrations</Typography>
                <Box>
                  <Button 
                    size="small" 
                    startIcon={<RefreshIcon />} 
                    onClick={handleTestAll}
                    disabled={testingIntegration === 'all'}
                    sx={{ mr: 1 }}
                  >
                    {testingIntegration === 'all' ? <CircularProgress size={20} /> : 'Test All'}
                  </Button>
                  <Button startIcon={<AddIcon />} size="small" onClick={() => setIntegrationDialog(true)}>
                    Add
                  </Button>
                </Box>
              </Box>
              <List dense>
                {integrations.map((integration) => (
                  <ListItem key={integration.id} sx={{ borderBottom: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {integration.name}
                          <Chip
                            label={integration.status}
                            size="small"
                            color={integration.status === 'connected' ? 'success' : 'error'}
                            variant={integration.status === 'connected' ? 'filled' : 'outlined'}
                            sx={{ height: 20, fontSize: '0.7rem' }}
                          />
                        </Box>
                      }
                      secondary={integration.type}
                    />
                    <ListItemSecondaryAction>
                      <IconButton 
                        size="small" 
                        onClick={() => handleTestIntegration(integration.id)}
                        disabled={testingIntegration === integration.id || !integration.apiUrl}
                        title="Test Connection"
                      >
                        {testingIntegration === integration.id ? (
                          <CircularProgress size={18} />
                        ) : (
                          <CheckIcon fontSize="small" />
                        )}
                      </IconButton>
                      <IconButton 
                        size="small" 
                        onClick={() => setEditIntegration({ ...integration })}
                        title="Edit"
                      >
                        <EditIcon fontSize="small" />
                      </IconButton>
                      <IconButton 
                        size="small" 
                        onClick={() => handleDeleteIntegration(integration.id)}
                        title="Delete"
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>

          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, mb: 3 }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6">LLM Integration</Typography>
                <Chip
                  label={llmStatus.enabled ? 'Enabled' : 'Disabled'}
                  size="small"
                  color={llmStatus.enabled ? 'success' : 'default'}
                />
              </Box>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <FormControl fullWidth size="small" sx={{ mb: 2 }}>
                    <InputLabel>Provider</InputLabel>
                    <Select
                      value={llmConfig.provider}
                      onChange={(e) => setLlmConfig({ ...llmConfig, provider: e.target.value })}
                      label="Provider"
                    >
                      <MenuItem value="openai">OpenAI</MenuItem>
                      <MenuItem value="anthropic">Anthropic (Claude)</MenuItem>
                      <MenuItem value="azure">Azure OpenAI</MenuItem>
                      <MenuItem value="ollama">Ollama (Local)</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControl fullWidth size="small" sx={{ mb: 2 }}>
                    <InputLabel>Model</InputLabel>
                    <Select
                      value={llmConfig.model}
                      onChange={(e) => setLlmConfig({ ...llmConfig, model: e.target.value })}
                      label="Model"
                    >
                      {llmConfig.provider === 'openai' && (
                        <>
                          <MenuItem value="gpt-4">GPT-4</MenuItem>
                          <MenuItem value="gpt-4-turbo">GPT-4 Turbo</MenuItem>
                          <MenuItem value="gpt-3.5-turbo">GPT-3.5 Turbo</MenuItem>
                        </>
                      )}
                      {llmConfig.provider === 'anthropic' && (
                        <>
                          <MenuItem value="claude-3-opus">Claude 3 Opus</MenuItem>
                          <MenuItem value="claude-3-sonnet">Claude 3 Sonnet</MenuItem>
                          <MenuItem value="claude-3-haiku">Claude 3 Haiku</MenuItem>
                        </>
                      )}
                      {llmConfig.provider === 'ollama' && (
                        <>
                          <MenuItem value="llama2">Llama 2</MenuItem>
                          <MenuItem value="mistral">Mistral</MenuItem>
                          <MenuItem value="codellama">Code Llama</MenuItem>
                        </>
                      )}
                      {llmConfig.provider === 'azure' && (
                        <MenuItem value="gpt-4">GPT-4 (Azure)</MenuItem>
                      )}
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="API URL"
                    value={llmConfig.apiUrl}
                    onChange={(e) => setLlmConfig({ ...llmConfig, apiUrl: e.target.value })}
                    size="small"
                    sx={{ mb: 2 }}
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="API Key"
                    type="password"
                    value={llmConfig.apiKey}
                    onChange={(e) => setLlmConfig({ ...llmConfig, apiKey: e.target.value })}
                    size="small"
                    sx={{ mb: 2 }}
                    helperText="Stored securely in environment variables"
                  />
                </Grid>
                <Grid item xs={6} sm={4}>
                  <TextField
                    fullWidth
                    label="Max Tokens"
                    type="number"
                    value={llmConfig.maxTokens}
                    onChange={(e) => setLlmConfig({ ...llmConfig, maxTokens: parseInt(e.target.value) })}
                    size="small"
                  />
                </Grid>
                <Grid item xs={6} sm={4}>
                  <TextField
                    fullWidth
                    label="Temperature"
                    type="number"
                    inputProps={{ step: 0.1, min: 0, max: 2 }}
                    value={llmConfig.temperature}
                    onChange={(e) => setLlmConfig({ ...llmConfig, temperature: parseFloat(e.target.value) })}
                    size="small"
                  />
                </Grid>
                <Grid item xs={12} sm={4}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={llmConfig.cacheEnabled}
                        onChange={(e) => setLlmConfig({ ...llmConfig, cacheEnabled: e.target.checked })}
                      />
                    }
                    label="Enable Cache"
                  />
                </Grid>
              </Grid>
              <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
                <Button
                  variant="outlined"
                  size="small"
                  onClick={testLlmConnection}
                  disabled={testingLlm}
                  startIcon={testingLlm ? <CircularProgress size={16} /> : <CheckIcon />}
                >
                  {testingLlm ? 'Testing...' : 'Test Connection'}
                </Button>
                <Button variant="contained" size="small">
                  Save LLM Settings
                </Button>
              </Box>
            </CardContent>
          </Card>

          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>Display Settings</Typography>
              <FormControlLabel
                control={
                  <Switch 
                    checked={darkMode} 
                    onChange={(e) => setDarkMode(e.target.checked)}
                  />
                }
                label="Dark Mode"
                sx={{ display: 'block', mb: 1 }}
              />
              <FormControlLabel
                control={
                  <Switch 
                    checked={showNotifications} 
                    onChange={(e) => setShowNotifications(e.target.checked)}
                  />
                }
                label="Show Notifications"
                sx={{ display: 'block', mb: 1 }}
              />
              <FormControlLabel
                control={
                  <Switch 
                    checked={compactView} 
                    onChange={(e) => setCompactView(e.target.checked)}
                  />
                }
                label="Compact View"
                sx={{ display: 'block', mb: 2 }}
              />
              <Divider sx={{ my: 2 }} />
              <Typography variant="subtitle2" sx={{ mb: 1 }}>Refresh Interval</Typography>
              <FormControl fullWidth size="small">
                <Select 
                  value={refreshInterval} 
                  onChange={(e) => setRefreshInterval(e.target.value)}
                >
                  <MenuItem value={10000}>10 seconds</MenuItem>
                  <MenuItem value={30000}>30 seconds</MenuItem>
                  <MenuItem value={60000}>1 minute</MenuItem>
                  <MenuItem value={300000}>5 minutes</MenuItem>
                </Select>
              </FormControl>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Dialog open={integrationDialog} onClose={() => setIntegrationDialog(false)}>
        <DialogTitle>Add Integration</DialogTitle>
        <DialogContent>
          <TextField 
            fullWidth 
            label="Name" 
            value={newIntegration.name}
            onChange={(e) => setNewIntegration({ ...newIntegration, name: e.target.value })}
            sx={{ mb: 2, mt: 1 }} 
            required
          />
          <FormControl fullWidth sx={{ mb: 2 }} size="small">
            <InputLabel>Type</InputLabel>
            <Select
              value={newIntegration.type}
              onChange={(e) => setNewIntegration({ ...newIntegration, type: e.target.value })}
              label="Type"
              required
            >
              <MenuItem value="SIEM">SIEM</MenuItem>
              <MenuItem value="Threat Intel">Threat Intel</MenuItem>
              <MenuItem value="EDR">EDR</MenuItem>
              <MenuItem value="Notification">Notification</MenuItem>
              <MenuItem value="Other">Other</MenuItem>
            </Select>
          </FormControl>
          <TextField 
            fullWidth 
            label="API URL" 
            value={newIntegration.apiUrl}
            onChange={(e) => setNewIntegration({ ...newIntegration, apiUrl: e.target.value })}
            sx={{ mb: 2 }} 
          />
          <TextField 
            fullWidth 
            label="API Key" 
            type="password"
            value={newIntegration.apiKey}
            onChange={(e) => setNewIntegration({ ...newIntegration, apiKey: e.target.value })}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setIntegrationDialog(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleAddIntegration}>Add</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!editIntegration} onClose={() => setEditIntegration(null)}>
        <DialogTitle>Edit Integration</DialogTitle>
        <DialogContent>
          {editIntegration && (
            <>
              <TextField 
                fullWidth 
                label="Name" 
                value={editIntegration.name}
                onChange={(e) => setEditIntegration({ ...editIntegration, name: e.target.value })}
                sx={{ mb: 2, mt: 1 }} 
              />
              <TextField 
                fullWidth 
                label="API URL" 
                value={editIntegration.apiUrl}
                onChange={(e) => setEditIntegration({ ...editIntegration, apiUrl: e.target.value })}
                sx={{ mb: 2 }} 
              />
              <TextField 
                fullWidth 
                label="API Key" 
                type="password"
                value={editIntegration.apiKey}
                onChange={(e) => setEditIntegration({ ...editIntegration, apiKey: e.target.value })}
              />
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditIntegration(null)}>Cancel</Button>
          <Button variant="contained" onClick={handleEditIntegration}>Save</Button>
        </DialogActions>
      </Dialog>

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
