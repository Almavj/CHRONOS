import React, { useEffect, useState } from 'react';
import { Box, Typography, Card, CardContent, Grid, CircularProgress } from '@mui/material';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell, AreaChart, Area
} from 'recharts';
import { useSettingsStore } from '../stores/settingsStore';
import axios from 'axios';

const COLORS = ['#e94560', '#3b82f6', '#22c55e', '#f97316'];

function EmptyState({ message }) {
  const { darkMode } = useSettingsStore();
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', minHeight: 150 }}>
      <Typography variant="body2" sx={{ color: darkMode ? '#6b7280' : '#999' }}>
        {message}
      </Typography>
    </Box>
  );
}

export default function Analytics() {
  const { darkMode } = useSettingsStore();
  const [timelineData, setTimelineData] = useState([]);
  const [responseTimeData, setResponseTimeData] = useState([]);
  const [attackVectorData, setAttackVectorData] = useState([]);
  const [sourceData, setSourceData] = useState([]);
  const [metrics, setMetrics] = useState({ totalAlerts: 0, resolutionRate: 0, avgMttd: 0, avgMttr: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAnalyticsData();
    const interval = setInterval(fetchAnalyticsData, 60000);
    return () => clearInterval(interval);
  }, []);

  const fetchAnalyticsData = async () => {
    setLoading(true);
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const headers = { 'X-API-Key': localStorage.getItem('chronos_api_key') || 'chronos-secret-key-change-in-production' };

      const [timelineRes, responseRes, vectorsRes, sourcesRes, metricsRes] = await Promise.all([
        axios.get(`${apiUrl}/api/analytics/timeline?range=30d`, { headers }).catch(() => ({ data: [] })),
        axios.get(`${apiUrl}/api/analytics/response-time`, { headers }).catch(() => ({ data: [] })),
        axios.get(`${apiUrl}/api/analytics/attack-vectors`, { headers }).catch(() => ({ data: [] })),
        axios.get(`${apiUrl}/api/analytics/sources`, { headers }).catch(() => ({ data: [] })),
        axios.get(`${apiUrl}/api/analytics/metrics`, { headers }).catch(() => ({ data: {} })),
      ]);

      setTimelineData(timelineRes.data || []);
      setResponseTimeData(responseRes.data || []);
      setAttackVectorData(vectorsRes.data || []);
      setSourceData(sourcesRes.data || []);
      setMetrics(metricsRes.data || metrics);
    } catch (error) {
      console.error('Error fetching analytics data:', error);
    }
    setLoading(false);
  };

  if (loading && timelineData.length === 0) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 3, fontWeight: 'bold', color: darkMode ? '#fff' : '#000' }}>Analytics</Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>Alert Trend (30 Days)</Typography>
              {timelineData.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={timelineData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#2d2d44' : '#e0e0e0'} />
                    <XAxis dataKey="date" stroke={darkMode ? '#9ca3af' : '#666'} />
                    <YAxis stroke={darkMode ? '#9ca3af' : '#666'} />
                    <Tooltip contentStyle={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }} />
                    <Area type="monotone" dataKey="alerts" stroke="#e94560" fill="#e94560" fillOpacity={0.3} />
                    <Area type="monotone" dataKey="resolved" stroke="#22c55e" fill="#22c55e" fillOpacity={0.3} />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No alert trend data available" />
              )}
            </CardContent>
          </Card>

          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>Response Time (Hours)</Typography>
              {responseTimeData.length > 0 ? (
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={responseTimeData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#2d2d44' : '#e0e0e0'} />
                    <XAxis dataKey="day" stroke={darkMode ? '#9ca3af' : '#666'} />
                    <YAxis stroke={darkMode ? '#9ca3af' : '#666'} />
                    <Tooltip contentStyle={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }} />
                    <Bar dataKey="mttd" name="MTTD" fill="#3b82f6" />
                    <Bar dataKey="mttr" name="MTTR" fill="#e94560" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No response time data available" />
              )}
            </CardContent>
          </Card>

          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>Attack Vectors</Typography>
              {attackVectorData.length > 0 ? (
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={attackVectorData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#2d2d44' : '#e0e0e0'} />
                    <XAxis type="number" stroke={darkMode ? '#9ca3af' : '#666'} />
                    <YAxis dataKey="vector" type="category" stroke={darkMode ? '#9ca3af' : '#666'} width={100} />
                    <Tooltip contentStyle={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }} />
                    <Bar dataKey="count" fill="#e94560" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No attack vector data available" />
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>Alert Sources</Typography>
              {sourceData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={sourceData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      dataKey="value"
                      label={({ name, value }) => `${name}: ${value}%`}
                    >
                      {sourceData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No source data available" />
              )}
            </CardContent>
          </Card>

          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>Key Metrics</Typography>
              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Total Alerts (30d)</Typography>
                <Typography variant="h4" sx={{ fontWeight: 'bold', color: darkMode ? '#fff' : '#000' }}>{metrics.totalAlerts || 0}</Typography>
              </Box>
              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Resolution Rate</Typography>
                <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#22c55e' }}>{metrics.resolutionRate || 0}%</Typography>
              </Box>
              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Avg. MTTD</Typography>
                <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#3b82f6' }}>{metrics.avgMttd || 0}h</Typography>
              </Box>
              <Box>
                <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Avg. MTTR</Typography>
                <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#f97316' }}>{metrics.avgMttr || 0}h</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
