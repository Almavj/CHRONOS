import { ALERT_SEVERITY } from '../assets/constants';

export const getSeverityColor = (severity) => {
  const colors = {
    [ALERT_SEVERITY.CRITICAL]: '#b71c1c',
    [ALERT_SEVERITY.HIGH]: '#f44336',
    [ALERT_SEVERITY.MEDIUM]: '#ff9800',
    [ALERT_SEVERITY.LOW]: '#4caf50',
    [ALERT_SEVERITY.INFO]: '#2196f3',
  };
  return colors[severity] || colors.info;
};

export const getSeverityClass = (severity) => {
  return `severity-${severity?.toLowerCase()}`;
};

export const getStatusColor = (status) => {
  const colors = {
    new: '#2196f3',
    acknowledged: '#ff9800',
    investigating: '#9c27b0',
    resolved: '#4caf50',
    false_positive: '#9e9e9e',
  };
  return colors[status] || colors.new;
};

export const getRiskScoreColor = (score) => {
  if (score >= 80) return '#b71c1c';
  if (score >= 60) return '#f44336';
  if (score >= 40) return '#ff9800';
  if (score >= 20) return '#ffeb3b';
  return '#4caf50';
};

export const getCoverageColor = (coverage) => {
  if (coverage >= 80) return '#4caf50';
  if (coverage >= 60) return '#8bc34a';
  if (coverage >= 40) return '#ff9800';
  if (coverage >= 20) return '#ff5722';
  return '#f44336';
};
