import {
  Ban, Globe, Image, KeyRound, Link2, Lock, Mail, MapPin, Package, Plug, RefreshCw,
  Rocket, Shield, ShieldCheck, SlidersHorizontal, Sparkles, Timer, Zap,
} from 'lucide-react';

export const formatBytes = (bytes, decimals = 2) => {
  if (bytes === null || bytes === undefined || isNaN(bytes) || bytes < 1) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

// Full thousands separators everywhere a number is read (see docs/UI_CONVENTIONS.md).
export const formatNumber = (num) => {
  if (num === null || num === undefined || isNaN(num)) return '0';
  return Number(num).toLocaleString();
};

// Abbreviated form for chart axes only, where width is constrained.
export const formatCompact = (num) => {
  if (num >= 1000000000) return (num / 1000000000).toFixed(1) + 'B';
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num?.toString() || '0';
};

// Backend stores all timestamps as UTC but serializes without timezone suffix.
// Ensure naive ISO strings are parsed as UTC, not local time.
export const parseUTC = (dateString) => {
  if (!dateString) return null;
  if (dateString.endsWith('Z') || dateString.includes('+') || dateString.includes('-', 10)) return new Date(dateString);
  return new Date(dateString + 'Z');
};

// Dates render in the viewer's own timezone (no timeZone option) with the
// zone name shown so the reading is unambiguous.
export const formatDate = (dateString) => {
  if (!dateString) return 'N/A';
  return parseUTC(dateString).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short'
  });
};

export const formatDateShort = (dateString) => {
  if (!dateString) return 'N/A';
  return parseUTC(dateString).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric'
  });
};

export const getTimeAgo = (dateString) => {
  if (!dateString) return 'Never';
  const now = new Date();
  const date = parseUTC(dateString);
  const seconds = Math.floor((now - date) / 1000);
  
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  return formatDate(dateString);
};

export const truncate = (str, len = 30) => {
  if (!str) return '';
  return str.length > len ? str.substring(0, len) + '...' : str;
};

// Lucide icon component for a Cloudflare zone setting (see docs/UI_CONVENTIONS.md).
export const getSecurityIcon = (settingName) => {
  const icons = {
    ssl: Lock,
    always_use_https: Lock,
    min_tls_version: ShieldCheck,
    tls_1_3: ShieldCheck,
    automatic_https_rewrites: RefreshCw,
    opportunistic_encryption: KeyRound,
    security_level: Shield,
    waf: Shield,
    browser_check: Globe,
    challenge_ttl: Timer,
    email_obfuscation: Mail,
    server_side_exclude: Ban,
    hotlink_protection: Link2,
    ip_geolocation: MapPin,
    websockets: Plug,
    http2: Zap,
    http3: Zap,
    '0rtt': Zap,
    minify: Package,
    brotli: Package,
    rocket_loader: Rocket,
    mirage: Image,
    polish: Sparkles,
  };
  return icons[settingName] || SlidersHorizontal;
};
