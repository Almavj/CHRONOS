import React, { useState, useEffect, useMemo } from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  IconButton,
  Badge,
  Chip,
  Avatar,
  Divider,
  ThemeProvider,
  createTheme,
  CssBaseline,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  PlayArrow as HuntIcon,
  Settings as SettingsIcon,
  Notifications as NotificationsIcon,
  Person as PersonIcon,
  Warning as WarningIcon,
  Speed as SpeedIcon,
} from '@mui/icons-material';
import { useWebSocket } from './hooks/useWebSocket';
import { useAlertStore } from './stores/alertStore';
import { useSettingsStore } from './stores/settingsStore';
import AlertsPanel from './components/AlertsPanel';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Hunting from './pages/Hunting';
import Analytics from './pages/Analytics';
import Settings from './pages/Settings';
import Profile from './pages/Profile';

const drawerWidth = 240;

const menuItems = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { text: 'Alerts', icon: <SecurityIcon />, path: '/alerts' },
  { text: 'Threat Hunting', icon: <HuntIcon />, path: '/hunting' },
  { text: 'Analytics', icon: <AssessmentIcon />, path: '/analytics' },
  { text: 'Settings', icon: <SettingsIcon />, path: '/settings' },
];

function App() {
  const [currentPage, setCurrentPage] = useState('/');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const { alerts, connect, disconnect } = useAlertStore();
  const { darkMode, compactView, showNotifications } = useSettingsStore();
  const { isConnected } = useWebSocket();

  const theme = useMemo(() => createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
      primary: { main: '#e94560' },
      background: {
        default: darkMode ? '#0f0f1a' : '#f5f5f5',
        paper: darkMode ? '#1a1a2e' : '#ffffff',
      },
    },
    typography: {
      fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    },
    components: {
      MuiListItemButton: { defaultProps: { disableTouchRipple: true } },
      MuiCard: {
        styleOverrides: {
          root: {
            transition: compactView ? 'none' : 'box-shadow 0.2s ease-in-out',
          },
        },
      },
      MuiCardContent: {
        styleOverrides: {
          root: compactView ? { padding: '12px' } : {},
        },
      },
    },
  }), [darkMode, compactView]);

  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;
  const highAlerts = alerts.filter(a => a.severity === 'high').length;

  const renderPage = () => {
    switch (currentPage) {
      case '/':
        return <Dashboard />;
      case '/alerts':
        return <Alerts />;
      case '/hunting':
        return <Hunting />;
      case '/analytics':
        return <Analytics />;
      case '/settings':
        return <Settings />;
      case '/profile':
        return <Profile />;
      default:
        return <Dashboard />;
    }
  };

  function DrawerContent() {
    return (
      <Box>
        <Box sx={{ p: 2, display: 'flex', alignItems: 'center', gap: 2 }}>
          <Avatar sx={{ bgcolor: '#e94560', width: 40, height: 40 }}>
            <SecurityIcon />
          </Avatar>
          <Typography variant="h6" sx={{ fontWeight: 'bold' }}>
            CHRONOS
          </Typography>
        </Box>
        <Divider sx={{ bgcolor: darkMode ? '#2d2d44' : '#e0e0e0' }} />
        <List>
          {menuItems.map((item) => (
            <ListItemButton
              key={item.text}
              onClick={() => setCurrentPage(item.path)}
              selected={currentPage === item.path}
              sx={{
                '&:hover': { bgcolor: darkMode ? '#1a1a2e' : '#f0f0f0' },
                '&.Mui-selected': { bgcolor: darkMode ? '#1a1a2e' : '#f0f0f0', borderLeft: '3px solid #e94560' },
              }}
            >
              <ListItemIcon sx={{ color: '#e94560' }}>{item.icon}</ListItemIcon>
              <ListItemText primary={item.text} />
            </ListItemButton>
          ))}
        </List>
      </Box>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box sx={{ display: 'flex' }}>
        <AppBar
          position="fixed"
          sx={{
            width: { sm: `calc(100% - ${drawerWidth}px)` },
            ml: { sm: `${drawerWidth}px` },
            bgcolor: darkMode ? '#1a1a2e' : '#ffffff',
            color: darkMode ? '#ffffff' : '#000000',
            borderBottom: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`,
          }}
        >
          <Toolbar>
            <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1, fontWeight: 'bold' }}>
              CHRONOS
            </Typography>
            
            <Chip
              icon={<SpeedIcon />}
              label={isConnected ? 'Online' : 'Offline'}
              color={isConnected ? 'success' : 'error'}
              size="small"
              sx={{ mr: 2 }}
            />
            
            {showNotifications && (
              <>
                <IconButton color="inherit" sx={{ mr: 2 }}>
                  <Badge badgeContent={criticalAlerts} color="error">
                    <WarningIcon />
                  </Badge>
                </IconButton>
                
                <IconButton color="inherit" sx={{ mr: 2 }} onClick={() => setCurrentPage('/alerts')}>
                  <Badge badgeContent={highAlerts + criticalAlerts} color="warning">
                    <NotificationsIcon />
                  </Badge>
                </IconButton>
              </>
            )}
            
            <IconButton color="inherit" sx={{ ml: 2 }} onClick={() => setCurrentPage('/profile')}>
              <PersonIcon />
            </IconButton>
          </Toolbar>
        </AppBar>

        <Box
          component="nav"
          sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
        >
          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={() => setMobileOpen(!mobileOpen)}
            ModalProps={{ keepMounted: true }}
            sx={{
              display: { xs: 'block', sm: 'none' },
              '& .MuiDrawer-paper': { 
                boxSizing: 'border-box', 
                width: drawerWidth, 
                bgcolor: darkMode ? '#16213e' : '#ffffff', 
                color: darkMode ? '#fff' : '#000' 
              },
            }}
          >
            <DrawerContent />
          </Drawer>
          <Drawer
            variant="permanent"
            sx={{
              display: { xs: 'none', sm: 'block' },
              '& .MuiDrawer-paper': { 
                boxSizing: 'border-box', 
                width: drawerWidth, 
                bgcolor: darkMode ? '#16213e' : '#ffffff', 
                color: darkMode ? '#fff' : '#000',
                borderRight: `1px solid ${darkMode ? '#2d2d44' : '#e0e0e0'}`
              },
            }}
            open
          >
            <DrawerContent />
          </Drawer>
        </Box>

        <Box
          component="main"
          sx={{
            flexGrow: 1,
            p: compactView ? 1 : 3,
            width: { sm: `calc(100% - ${drawerWidth}px)` },
            minHeight: '100vh',
            bgcolor: darkMode ? '#0f0f1a' : '#f5f5f5',
          }}
        >
          <Toolbar />
          {renderPage()}
        </Box>

        {showNotifications && <AlertsPanel />}
      </Box>
    </ThemeProvider>
  );
}

export default App;
