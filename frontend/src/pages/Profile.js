import React, { useState, useEffect } from 'react';
import {
  Box, Typography, Card, CardContent, Grid, TextField, Button, Avatar, Chip,
  Divider, List, ListItem, ListItemText, Dialog, DialogTitle, DialogContent, DialogActions
} from '@mui/material';
import {
  Person as PersonIcon,
  Email as EmailIcon,
  Work as WorkIcon,
  Security as SecurityIcon,
  Edit as EditIcon,
  Save as SaveIcon,
  Notifications as NotificationsIcon,
  History as HistoryIcon,
  Shield as ShieldIcon,
} from '@mui/icons-material';
import { useSettingsStore } from '../stores/settingsStore';
import { useAlertStore } from '../stores/alertStore';
import axios from 'axios';

function EmptyState({ message }) {
  const { darkMode } = useSettingsStore();
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', py: 3 }}>
      <Typography variant="body2" sx={{ color: darkMode ? '#6b7280' : '#999' }}>
        {message}
      </Typography>
    </Box>
  );
}

export default function Profile() {
  const { darkMode } = useSettingsStore();
  const { stats, alerts } = useAlertStore();
  const [editMode, setEditMode] = useState(false);
  const [profile, setProfile] = useState({
    name: '',
    email: '',
    role: '',
    department: '',
    lastLogin: '',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  });
  const [editedProfile, setEditedProfile] = useState(profile);
  const [activityDialogOpen, setActivityDialogOpen] = useState(false);
  const [activityLog, setActivityLog] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchProfileData();
    fetchActivityLog();
  }, []);

  const fetchProfileData = async () => {
    setLoading(true);
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const headers = { 'X-API-Key': localStorage.getItem('chronos_api_key') || 'chronos-secret-key-change-in-production' };
      const response = await axios.get(`${apiUrl}/api/profile`, { headers }).catch(() => ({ data: null }));
      
      if (response.data) {
        setProfile(response.data);
        setEditedProfile(response.data);
      }
    } catch (error) {
      console.error('Error fetching profile:', error);
    }
    setLoading(false);
  };

  const fetchActivityLog = async () => {
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      const headers = { 'X-API-Key': localStorage.getItem('chronos_api_key') || 'chronos-secret-key-change-in-production' };
      const response = await axios.get(`${apiUrl}/api/profile/activity`, { headers }).catch(() => ({ data: [] }));
      setActivityLog(response.data || []);
    } catch (error) {
      console.error('Error fetching activity log:', error);
      setActivityLog([]);
    }
  };

  const handleSave = () => {
    setProfile(editedProfile);
    setEditMode(false);
    localStorage.setItem('chronos_user_profile', JSON.stringify(editedProfile));
  };

  const handleCancel = () => {
    setEditedProfile(profile);
    setEditMode(false);
  };

  return (
    <Box>
      <Typography variant="h5" sx={{ mb: 3, fontWeight: 'bold', color: darkMode ? '#fff' : '#000' }}>Profile</Typography>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, mb: 3 }}>
            <CardContent sx={{ textAlign: 'center' }}>
              <Avatar sx={{ width: 120, height: 120, bgcolor: '#e94560', fontSize: '48px', mx: 'auto', mb: 2 }}>
                <PersonIcon sx={{ fontSize: 60 }} />
              </Avatar>
              {!editMode ? (
                <>
                  <Typography variant="h5" sx={{ fontWeight: 'bold', mb: 1, color: darkMode ? '#fff' : '#000' }}>{profile.name || 'User'}</Typography>
                  <Chip label={profile.role || 'No Role'} sx={{ mb: 2, bgcolor: '#e94560', color: '#fff' }} />
                  <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666', mb: 1 }}>
                    <EmailIcon sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
                    {profile.email || 'No email'}
                  </Typography>
                  <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666', mb: 1 }}>
                    <WorkIcon sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
                    {profile.department || 'No department'}
                  </Typography>
                  <Button 
                    variant="outlined" 
                    startIcon={<EditIcon />} 
                    sx={{ mt: 2 }}
                    onClick={() => setEditMode(true)}
                  >
                    Edit Profile
                  </Button>
                </>
              ) : (
                <>
                  <TextField
                    fullWidth
                    label="Name"
                    value={editedProfile.name}
                    onChange={(e) => setEditedProfile({ ...editedProfile, name: e.target.value })}
                    sx={{ mb: 2 }}
                    size="small"
                  />
                  <TextField
                    fullWidth
                    label="Email"
                    value={editedProfile.email}
                    onChange={(e) => setEditedProfile({ ...editedProfile, email: e.target.value })}
                    sx={{ mb: 2 }}
                    size="small"
                  />
                  <TextField
                    fullWidth
                    label="Role"
                    value={editedProfile.role}
                    onChange={(e) => setEditedProfile({ ...editedProfile, role: e.target.value })}
                    sx={{ mb: 2 }}
                    size="small"
                  />
                  <Box sx={{ display: 'flex', gap: 1, justifyContent: 'center', mt: 2 }}>
                    <Button variant="contained" startIcon={<SaveIcon />} onClick={handleSave}>Save</Button>
                    <Button variant="outlined" onClick={handleCancel}>Cancel</Button>
                  </Box>
                </>
              )}
            </CardContent>
          </Card>

          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>
                <ShieldIcon sx={{ fontSize: 20, mr: 1, verticalAlign: 'middle' }} />
                Security Info
              </Typography>
              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Last Login</Typography>
                <Typography variant="body1" sx={{ color: darkMode ? '#fff' : '#000' }}>{profile.lastLogin || 'Unknown'}</Typography>
              </Box>
              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Timezone</Typography>
                <Typography variant="body1" sx={{ color: darkMode ? '#fff' : '#000' }}>{profile.timezone}</Typography>
              </Box>
              <Divider sx={{ my: 2 }} />
              <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666', mb: 1 }}>
                <SecurityIcon sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
                Session Status
              </Typography>
              <Chip label="Active" color="success" size="small" />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={8}>
          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`, mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: darkMode ? '#fff' : '#000' }}>
                <NotificationsIcon sx={{ fontSize: 20, mr: 1, verticalAlign: 'middle' }} />
                Activity Summary
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={6} sm={3}>
                  <Box sx={{ textAlign: 'center', p: 2, bgcolor: darkMode ? '#16213e' : '#f5f5f5', borderRadius: 2 }}>
                    <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#e94560' }}>{stats.total || alerts.length || 0}</Typography>
                    <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Total Alerts</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box sx={{ textAlign: 'center', p: 2, bgcolor: darkMode ? '#16213e' : '#f5f5f5', borderRadius: 2 }}>
                    <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#ef4444' }}>{stats.critical || 0}</Typography>
                    <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Critical</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box sx={{ textAlign: 'center', p: 2, bgcolor: darkMode ? '#16213e' : '#f5f5f5', borderRadius: 2 }}>
                    <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#f97316' }}>{stats.high || 0}</Typography>
                    <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>High</Typography>
                  </Box>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Box sx={{ textAlign: 'center', p: 2, bgcolor: darkMode ? '#16213e' : '#f5f5f5', borderRadius: 2 }}>
                    <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#22c55e' }}>{stats.mttr || 0}h</Typography>
                    <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>Avg MTTR</Typography>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>

          <Card sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', border: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                <Typography variant="h6" sx={{ color: darkMode ? '#fff' : '#000' }}>
                  <HistoryIcon sx={{ fontSize: 20, mr: 1, verticalAlign: 'middle' }} />
                  Recent Activity
                </Typography>
                <Button size="small" onClick={() => setActivityDialogOpen(true)}>View All</Button>
              </Box>
              {activityLog.length > 0 ? (
                <List>
                  {activityLog.slice(0, 5).map((item, idx) => (
                    <ListItem key={idx} sx={{ borderBottom: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
                      <ListItemText
                        primary={item.action || 'Activity'}
                        secondary={
                          <Box component="span">
                            <Typography variant="caption" sx={{ color: darkMode ? '#6b7280' : '#999', display: 'block' }}>
                              {item.timestamp || 'Unknown time'}
                            </Typography>
                            <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
                              {item.details || 'No details'}
                            </Typography>
                          </Box>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              ) : (
                <EmptyState message="No recent activity" />
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Dialog open={activityDialogOpen} onClose={() => setActivityDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff', color: darkMode ? '#fff' : '#000' }}>
          Activity Log
        </DialogTitle>
        <DialogContent sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff' }}>
          {activityLog.length > 0 ? (
            <List>
              {activityLog.map((item, idx) => (
                <ListItem key={idx} sx={{ borderBottom: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}` }}>
                  <ListItemText
                    primary={item.action || 'Activity'}
                    secondary={
                      <Box component="span">
                        <Typography variant="caption" sx={{ color: darkMode ? '#6b7280' : '#999', display: 'block' }}>
                          {item.timestamp || 'Unknown time'}
                        </Typography>
                        <Typography variant="body2" sx={{ color: darkMode ? '#9ca3af' : '#666' }}>
                          {item.details || 'No details'}
                        </Typography>
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
          ) : (
            <EmptyState message="No activity records found" />
          )}
        </DialogContent>
        <DialogActions sx={{ bgcolor: darkMode ? '#1a1a2e' : '#ffffff' }}>
          <Button onClick={() => setActivityDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
