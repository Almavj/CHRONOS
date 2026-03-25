import React, { useEffect, useState } from 'react';
import { Box, Grid, Card, CardContent, Typography, Chip, LinearProgress, Button, Dialog, DialogTitle, DialogContent, DialogActions } from '@mui/material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { Speed as SpeedIcon, Warning as WarningIcon, Security as SecurityIcon, Timeline as TimelineIcon, Refresh as RefreshIcon } from '@mui/icons-material';
import { useAlertStore } from '../stores/alertStore';
import { useSettingsStore } from '../stores/settingsStore';
import axios from 'axios';

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e'];

function StatCard({ title, value, subtitle, icon, color }) {
  const { darkMode } = useSettingsStore();
  return (
    <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box>
            <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
              {title}
            </Typography>
            <Typography variant="h4" sx={{ fontWeight: 'bold', my: 1, color: darkMode ? '#fff' : '#000' }}>
              {value}
            </Typography>
            <Typography variant="caption" sx={{ color: darkMode ? '#6b7280' : '#999' }}>
              {subtitle}
            </Typography>
          </Box>
          <Box sx={{ p: 1.5, borderRadius: 2, bgcolor: color || '#e94560', opacity: 0.2 }}>
            {icon}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
}

function EmptyState({ message }) {
  const { darkMode } = useSettingsStore();
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', minHeight: 200 }}>
      <Typography variant="body1" sx={{ color: darkMode ? '#6b7280' : '#999' }}>
        {message}
      </Typography>
    </Box>
  );
}

export default function Dashboard() {
  const { stats, alerts, connect } = useAlertStore();
  const { darkMode, refreshInterval } = useSettingsStore();
  const [hosts, setHosts] = useState([]);
  const [mitreCoverage, setMitreCoverage] = useState(null);
  const [timelineData, setTimelineData] = useState([]);
  const [topTechniques, setTopTechniques] = useState([]);
  const [loading, setLoading] = useState(false);
  const [detailDialog, setDetailDialog] = useState({ open: false, type: null, data: null });

  useEffect(() => {
    const interval = setInterval(() => {
      fetchDashboardData();
    }, refreshInterval);
    
    fetchDashboardData();
    
    return () => clearInterval(interval);
  }, [refreshInterval]);

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const headers = { 'X-API-Key': localStorage.getItem('chronos_api_key') || 'chronos-secret-key-change-in-production' };
      
      const [hostsRes, mitreRes, statsRes, timelineRes, techniquesRes] = await Promise.all([
        axios.get(`${apiUrl}/api/hosts`, { headers }).catch(() => ({ data: [] })),
        axios.get(`${apiUrl}/api/mitre/coverage`, { headers }).catch(() => ({ data: null })),
        axios.get(`${apiUrl}/api/stats`, { headers }).catch(() => ({ data: null })),
        axios.get(`${apiUrl}/api/analytics/timeline`, { headers }).catch(() => ({ data: [] })),
        axios.get(`${apiUrl}/api/analytics/techniques`, { headers }).catch(() => ({ data: [] })),
      ]);
      
      setHosts(hostsRes.data || []);
      setMitreCoverage(mitreRes.data);
      setTimelineData(timelineRes.data || []);
      setTopTechniques(techniquesRes.data || []);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setHosts([]);
      setTimelineData([]);
      setTopTechniques([]);
    }
    setLoading(false);
  };

  const severityData = [
    { name: 'Critical', value: stats.critical || 0, color: '#ef4444' },
    { name: 'High', value: stats.high || 0, color: '#f97316' },
    { name: 'Medium', value: stats.medium || 0, color: '#eab308' },
    { name: 'Low', value: stats.low || 0, color: '#22c55e' },
  ];

  const openDetail = (type, data) => {
    setDetailDialog({ open: true, type, data });
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 'bold', color: darkMode ? '#fff' : '#000' }}>
          Security Overview
        </Typography>
        <Button 
          startIcon={<RefreshIcon />} 
          onClick={fetchDashboardData}
          disabled={loading}
          size="small"
        >
          Refresh
        </Button>
      </Box>

      {loading && <LinearProgress sx={{ mb: 2 }} />}

      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Alerts"
            value={stats.total || alerts.length || 0}
            subtitle="Last 24 hours"
            icon={<SecurityIcon />}
            color="#e94560"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Critical"
            value={stats.critical || 0}
            subtitle="Requires immediate action"
            icon={<WarningIcon />}
            color="#ef4444"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="MTTD"
            value={`${stats.mttd || 0}h`}
            subtitle="Mean Time to Detect"
            icon={<SpeedIcon />}
            color="#22c55e"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="MTTR"
            value={`${stats.mttr || 0}h`}
            subtitle="Mean Time to Respond"
            icon={<TimelineIcon />}
            color="#3b82f6"
          />
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        <Grid item xs={12} md={8}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, height: 400 }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6" sx={{ color: darkMode ? '#fff' : '#000' }}>Alert Timeline</Typography>
                {timelineData.length > 0 && <Button size="small" onClick={() => openDetail('timeline', timelineData)}>View Details</Button>}
              </Box>
              {timelineData.length > 0 ? (
                <ResponsiveContainer width="100%" height={320}>
                  <LineChart data={timelineData}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#2d2d44' : '#e0e0e0'} />
                    <XAxis dataKey="time" stroke={darkMode ? '#9ca3af' : '#666'} />
                    <YAxis stroke={darkMode ? '#9ca3af' : '#666'} />
                    <Tooltip contentStyle={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }} />
                    <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} />
                    <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} />
                    <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No timeline data available" />
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, height: 400 }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6" sx={{ color: darkMode ? '#fff' : '#000' }}>Severity Distribution</Typography>
                <Button size="small" onClick={() => openDetail('severity', severityData)}>View Details</Button>
              </Box>
              {severityData.some(d => d.value > 0) ? (
                <>
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie
                        data={severityData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }} />
                    </PieChart>
                  </ResponsiveContainer>
                  <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, flexWrap: 'wrap' }}>
                    {severityData.map((item) => (
                      <Chip
                        key={item.name}
                        label={`${item.name}: ${item.value}`}
                        size="small"
                        sx={{ bgcolor: item.color, color: '#fff' }}
                      />
                    ))}
                  </Box>
                </>
              ) : (
                <EmptyState message="No alerts yet" />
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, height: 350 }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6" sx={{ color: darkMode ? '#fff' : '#000' }}>Top Attack Techniques</Typography>
                {topTechniques.length > 0 && <Button size="small" onClick={() => openDetail('techniques', topTechniques)}>View Details</Button>}
              </Box>
              {topTechniques.length > 0 ? (
                <ResponsiveContainer width="100%" height={270}>
                  <BarChart data={topTechniques} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? '#2d2d44' : '#e0e0e0'} />
                    <XAxis type="number" stroke={darkMode ? '#9ca3af' : '#666'} />
                    <YAxis dataKey="name" type="category" stroke={darkMode ? '#9ca3af' : '#666'} width={150} />
                    <Tooltip contentStyle={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }} />
                    <Bar dataKey="count" fill="#e94560" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No technique data available" />
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, height: 350 }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6" sx={{ color: darkMode ? '#fff' : '#000' }}>Host Risk Scores</Typography>
                {hosts.length > 0 && <Button size="small" onClick={() => openDetail('hosts', hosts)}>View Details</Button>}
              </Box>
              {hosts.length > 0 ? (
                hosts.map((host) => (
                  <Box key={host.hostname || host.name} sx={{ mb: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                      <Typography variant="body2" sx={{ color: darkMode ? '#fff' : '#000' }}>{host.hostname || host.name}</Typography>
                      <Typography variant="body2" sx={{ 
                        color: (host.risk_score || host.risk) > 70 ? '#ef4444' : (host.risk_score || host.risk) > 40 ? '#f97316' : '#22c55e',
                        fontWeight: 'bold'
                      }}>
                        {host.risk_score || host.risk || 0}
                      </Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={host.risk_score || host.risk || 0}
                      sx={{
                        height: 8,
                        borderRadius: 4,
                        bgcolor: darkMode ? '#2d2d44' : '#e0e0e0',
                        '& .MuiLinearProgress-bar': {
                          bgcolor: (host.risk_score || host.risk) > 70 ? '#ef4444' : (host.risk_score || host.risk) > 40 ? '#f97316' : '#22c55e',
                        },
                      }}
                    />
                  </Box>
                ))
              ) : (
                <EmptyState message="No hosts configured" />
              )}
            </CardContent>
          </Card>
        </Grid>

        {mitreCoverage && (
          <Grid item xs={12}>
            <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
              <CardContent>
                <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>
                  MITRE ATT&CK Coverage - Overall: {mitreCoverage.overall || 0}%
                </Typography>
                {mitreCoverage.tactics && mitreCoverage.tactics.length > 0 ? (
                  <Grid container spacing={2}>
                    {mitreCoverage.tactics?.map((tactic, idx) => (
                      <Grid item xs={12} sm={6} md={3} key={idx}>
                        <Box sx={{ p: 2, bgcolor: darkMode ? '#16213e' : '#f5f5f5', borderRadius: 1 }}>
                          <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>{tactic.name}</Typography>
                          <LinearProgress 
                            variant="determinate" 
                            value={tactic.coverage || 0} 
                            sx={{ 
                              height: 8, 
                              borderRadius: 4, 
                              bgcolor: darkMode ? '#2d2d44' : '#e0e0e0',
                              mb: 0.5
                            }}
                          />
                          <Typography variant="caption" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
                            {tactic.detected || 0}/{tactic.total || 0} techniques
                          </Typography>
                        </Box>
                      </Grid>
                    ))}
                  </Grid>
                ) : (
                  <EmptyState message="No MITRE coverage data available" />
                )}
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>

      <Dialog 
        open={detailDialog.open} 
        onClose={() => setDetailDialog({ ...detailDialog, open: false })} 
        maxWidth="md" 
        fullWidth
      >
        <DialogTitle sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', color: darkMode ? '#fff' : '#000' }}>
          {detailDialog.type === 'timeline' && 'Alert Timeline Details'}
          {detailDialog.type === 'severity' && 'Severity Distribution Details'}
          {detailDialog.type === 'techniques' && 'Attack Techniques Details'}
          {detailDialog.type === 'hosts' && 'Host Risk Details'}
        </DialogTitle>
        <DialogContent sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff' }}>
          <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
            {detailDialog.type === 'timeline' && 'Historical alert count across different times of day.'}
            {detailDialog.type === 'severity' && 'Distribution of alerts by severity level.'}
            {detailDialog.type === 'techniques' && 'Top MITRE ATT&CK techniques detected.'}
            {detailDialog.type === 'hosts' && 'Current risk scores for monitored hosts.'}
          </Typography>
        </DialogContent>
        <DialogActions sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff' }}>
          <Button onClick={() => setDetailDialog({ ...detailDialog, open: false })}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
