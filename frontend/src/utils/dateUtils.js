import { format, formatDistanceToNow, parseISO, isValid } from 'date-fns';

export const formatDate = (date, formatStr = 'yyyy-MM-dd HH:mm:ss') => {
  if (!date) return '-';
  const parsed = typeof date === 'string' ? parseISO(date) : date;
  if (!isValid(parsed)) return '-';
  return format(parsed, formatStr);
};

export const formatRelativeTime = (date) => {
  if (!date) return '-';
  const parsed = typeof date === 'string' ? parseISO(date) : date;
  if (!isValid(parsed)) return '-';
  return formatDistanceToNow(parsed, { addSuffix: true });
};

export const formatDuration = (seconds) => {
  if (!seconds || seconds < 0) return '-';
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }
  return `${secs}s`;
};

export const getTimeRangeSeconds = (range) => {
  const multipliers = {
    '15m': 15 * 60,
    '1h': 60 * 60,
    '6h': 6 * 60 * 60,
    '24h': 24 * 60 * 60,
    '7d': 7 * 24 * 60 * 60,
    '30d': 30 * 24 * 60 * 60,
  };
  return multipliers[range] || 24 * 60 * 60;
};
