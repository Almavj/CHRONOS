import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Card, CardContent, TextField, Button, Grid, FormControl,
  InputLabel, Select, MenuItem, Chip, Autocomplete, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, LinearProgress
} from '@mui/material';
import { Search as SearchIcon, PlayArrow as PlayIcon, Save as SaveIcon } from '@mui/icons-material';
import { useSettingsStore } from '../stores/settingsStore';
import axios from 'axios';

const MITRE_TECHNIQUES = [
  'T1078 - Valid Accounts', 'T1021 - Remote Services', 'T1059 - Command Execution',
  'T1005 - Data from Local System', 'T1071 - Application Layer Protocol', 'T1082 - System Info Discovery',
  'T1055 - Process Injection', 'T1566 - Phishing', 'T1046 - Network Service Discovery',
  'T1098 - Account Manipulation', 'T1110 - Brute Force', 'T1484 - Domain Trust Modification'
];

function EmptyState({ message }) {
  const { darkMode } = useSettingsStore();
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', py: 4 }}>
      <Typography variant="body2" sx={{ color: darkMode ? '#6b7280' : '#999' }}>
        {message}
      </Typography>
    </Box>
  );
}

export default function Hunting() {
  const { darkMode } = useSettingsStore();
  const [query, setQuery] = useState('');
  const [selectedTechniques, setSelectedTechniques] = useState([]);
  const [timeRange, setTimeRange] = useState('24h');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [savedQueries, setSavedQueries] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchSavedQueries();
  }, []);

  const fetchSavedQueries = async () => {
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const headers = { 'X-API-Key': localStorage.getItem('chronos_api_key') || 'chronos-secret-key-change-in-production' };
      const response = await axios.get(`${apiUrl}/api/hunting/queries`, { headers }).catch(() => ({ data: [] }));
      setSavedQueries(response.data || []);
    } catch (err) {
      console.error('Error fetching saved queries:', err);
      setSavedQueries([]);
    }
  };

  const runQuery = async () => {
    if (!query.trim()) {
      setError('Please enter a query');
      return;
    }
    
    setLoading(true);
    setError(null);
    
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const headers = { 'X-API-Key': localStorage.getItem('chronos_api_key') || 'chronos-secret-key-change-in-production' };
      
      const response = await axios.post(
        `${apiUrl}/api/hunting/query`,
        { query, timeRange, techniques: selectedTechniques },
        { headers }
      );
      
      setResults(response.data?.results || []);
    } catch (err) {
      console.error('Error running query:', err);
      setError('Failed to execute query. Please check your query syntax and try again.');
      setResults([]);
    }
    
    setLoading(false);
  };

  const saveQuery = async () => {
    if (!query.trim()) {
      setError('Please enter a query to save');
      return;
    }
    
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const headers = { 'X-API-Key': localStorage.getItem('chronos_api_key') || 'chronos-secret-key-change-in-production' };
      
      await axios.post(
        `${apiUrl}/api/hunting/queries`,
        { name: `Query ${new Date().toISOString()}`, query, techniques: selectedTechniques },
        { headers }
      );
      
      fetchSavedQueries();
    } catch (err) {
      console.error('Error saving query:', err);
    }
  };

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 3, fontWeight: 'bold', color: darkMode ? '#fff' : '#000' }}>Threat Hunting</Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>Query Builder</Typography>
              <TextField
                fullWidth
                multiline
                rows={4}
                placeholder="Enter KQL or SPL query... (e.g., event_type:authentication AND failed_login:>5)"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                error={!!error}
                helperText={error}
                sx={{ mb: 2, '& .MuiOutlinedInput-root': { color: darkMode ? '#fff' : '#000' } }}
              />
              <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                <FormControl size="small" sx={{ minWidth: 150 }}>
                  <InputLabel sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Time Range</InputLabel>
                  <Select value={timeRange} onChange={(e) => setTimeRange(e.target.value)} label="Time Range">
                    <MenuItem value="1h">Last Hour</MenuItem>
                    <MenuItem value="24h">Last 24 Hours</MenuItem>
                    <MenuItem value="7d">Last 7 Days</MenuItem>
                    <MenuItem value="30d">Last 30 Days</MenuItem>
                  </Select>
                </FormControl>
                <Autocomplete
                  multiple
                  size="small"
                  options={MITRE_TECHNIQUES}
                  value={selectedTechniques}
                  onChange={(_, newValue) => setSelectedTechniques(newValue)}
                  renderTags={(value, getTagProps) =>
                    value.map((option, index) => (
                      <Chip label={option} size="small" {...getTagProps({ index })} sx={{ bgcolor: '#e94560', color: '#fff' }} />
                    ))
                  }
                  renderInput={(params) => <TextField {...params} label="MITRE Techniques" />}
                  sx={{ minWidth: 300 }}
                />
              </Box>
              <Box sx={{ display: 'flex', gap: 2 }}>
                <Button variant="contained" startIcon={<PlayIcon />} onClick={runQuery} disabled={loading}>
                  Run Query
                </Button>
                <Button variant="outlined" startIcon={<SaveIcon />} onClick={saveQuery} disabled={!query}>
                  Save Query
                </Button>
              </Box>
            </CardContent>
          </Card>

          {loading && <LinearProgress sx={{ mb: 2 }} />}
          
          {results !== null && (
            <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>
                  Results ({results.length})
                </Typography>
                {results.length > 0 ? (
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Timestamp</TableCell>
                          <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Source</TableCell>
                          <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Event</TableCell>
                          <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Details</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {results.map((row, idx) => (
                          <TableRow key={idx}>
                            <TableCell sx={{ color: darkMode ? '#fff' : '#000' }}>{row.timestamp || 'N/A'}</TableCell>
                            <TableCell sx={{ color: darkMode ? '#fff' : '#000' }}>{row.source || row.hostname || 'Unknown'}</TableCell>
                            <TableCell sx={{ color: '#e94560' }}>{row.event || row.event_type || 'N/A'}</TableCell>
                            <TableCell sx={{ color: darkMode ? '#9ca3af' : '#666' }}>{row.details || JSON.stringify(row)}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                ) : (
                  <EmptyState message="No results found for this query" />
                )}
              </CardContent>
            </Card>
          )}
        </Grid>

        <Grid item xs={12} md={4}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>Saved Queries</Typography>
              {savedQueries.length > 0 ? (
                savedQueries.map((sq, idx) => (
                  <Box key={sq.id || idx} sx={{ p: 2, mb: 1, bgcolor: darkMode ? '#16213e' : '#f5f5f5', borderRadius: 1, cursor: 'pointer', '&:hover': { bgcolor: darkMode ? '#1a1a2e' : '#e0e0e0' } }}
                    onClick={() => setQuery(sq.query)}>
                    <Typography variant="body2" sx={{ fontWeight: 'bold', color: darkMode ? '#fff' : '#000' }}>{sq.name}</Typography>
                    <Typography variant="caption" sx={{ color: darkMode ? '#9ca3af' : '#666', display: 'block', mt: 0.5 }}>{sq.query}</Typography>
                  </Box>
                ))
              ) : (
                <EmptyState message="No saved queries yet" />
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
