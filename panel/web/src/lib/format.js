// Small display helpers shared by the pages.
import { t } from './i18n.js';

// bytes -> "1.5 GB"
export function bytes(n) {
  if (typeof n !== 'number' || !isFinite(n) || n < 0) return '-';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${i === 0 || n >= 100 ? Math.round(n) : n.toFixed(1)} ${u[i]}`;
}

// MiB -> "1.5 GB"
export const mib = (n) => bytes(typeof n === 'number' ? n * 1048576 : n);

// ISO time -> "5 min ago"; null -> "never"
export function ago(iso) {
  if (!iso) return t('tr.never');
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (!isFinite(s)) return t('tr.never');
  if (s < 90) return t('tr.justNow');
  if (s < 3600) return t('tr.minAgo', { n: Math.round(s / 60) });
  if (s < 86400) return t('tr.hourAgo', { n: Math.round(s / 3600) });
  return t('tr.dayAgo', { n: Math.round(s / 86400) });
}
