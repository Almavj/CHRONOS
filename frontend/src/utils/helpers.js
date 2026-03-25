export const truncateText = (text, maxLength = 50) => {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '...';
};

export const capitalize = (str) => {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
};

export const formatIndicator = (indicator) => {
  if (!indicator) return '';
  const cleaned = indicator.trim();
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleaned);
  const isDomain = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z]{2,})+$/.test(cleaned);
  const isHash = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(cleaned);
  
  if (isIP) return { text: cleaned, type: 'ip' };
  if (isDomain) return { text: cleaned, type: 'domain' };
  if (isHash) return { text: cleaned, type: 'hash' };
  return { text: cleaned, type: 'unknown' };
};

export const debounce = (func, wait) => {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
};

export const throttle = (func, limit) => {
  let inThrottle;
  return (...args) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
};

export const sortByKey = (array, key, ascending = true) => {
  return [...array].sort((a, b) => {
    if (ascending) {
      return a[key] > b[key] ? 1 : -1;
    }
    return a[key] < b[key] ? 1 : -1;
  });
};

export const groupBy = (array, key) => {
  return array.reduce((groups, item) => {
    const group = item[key];
    groups[group] = groups[group] ?? [];
    groups[group].push(item);
    return groups;
  }, {});
};
