import React, { useState, useEffect } from 'react';
import { LayoutDashboard, Globe, CheckCircle2, List, Cloud, Activity, HardDrive, Zap, Shield, RefreshCw, X } from 'lucide-react';
import api from '../utils/api';
import { formatBytes, formatNumber } from '../utils/helpers';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState(null);

  useEffect(() => { fetchData(); }, []);

  const fetchData = async () => {
    try {
      const s = await api.get('/dashboard/stats');
      setStats(s);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  const handleSync = async () => {
    setSyncing(true);
    setSyncError(null);
    // Notify Layout to immediately start polling sync progress
    window.dispatchEvent(new CustomEvent('sync-started'));
    try {
      await api.post('/sync-all');
      // Sync runs in the background; refetching immediately would show the
      // old (cached) stats and pretend the sync finished. Poll until done.
      // Between configs the tracker flips inactive briefly, so completion is
      // "inactive AND every config processed", not just "inactive".
      let lastProgress = null;
      for (let i = 0; i < 900; i++) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        lastProgress = await api.get('/sync/progress');
        if (!lastProgress.active && (lastProgress.configs_processed || 0) >= (lastProgress.configs_total || 0)) break;
      }
      if (lastProgress?.result === 'failed') {
        setSyncError(lastProgress.error || 'Sync failed.');
      }
      await fetchData();
    }
    catch (e) {
      setSyncError(e.message || 'Sync failed. Check the banner for details.');
      console.error(e);
    }
    finally { setSyncing(false); }
  };

  if (loading) return <div className="loading-inline"><div className="spinner spinner-large" /></div>;

  // Headline KPI per docs/UI_CONVENTIONS.md: total zones.
  const kpis = [
    { icon: Globe, label: 'Total zones', value: formatNumber(stats?.total_zones || 0), headline: true },
    { icon: CheckCircle2, label: 'Active zones', value: formatNumber(stats?.active_zones || 0) },
    { icon: List, label: 'DNS records', value: formatNumber(stats?.total_dns_records || 0) },
    { icon: Cloud, label: 'Proxied records', value: formatNumber(stats?.proxied_records || 0) },
    { icon: Activity, label: 'Requests (24h)', value: formatNumber(stats?.total_requests_24h || 0) },
    { icon: HardDrive, label: 'Bandwidth (24h)', value: formatBytes(stats?.total_bandwidth_24h || 0) },
    { icon: Zap, label: 'Cache ratio', value: `${(stats?.cache_hit_ratio || 0).toFixed(1)}%` },
    { icon: Shield, label: 'Threats blocked (24h)', value: formatNumber(stats?.total_threats_24h || 0) },
  ];

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><LayoutDashboard className="page-title-icon" /> Dashboard</h1>
        <div className="page-actions">
          <button className="btn btn-primary" onClick={handleSync} disabled={syncing}>
            <RefreshCw /> {syncing ? 'Syncing...' : 'Sync all'}
          </button>
        </div>
      </div>

      {syncError && (
        <div className="callout callout-critical callout-row">
          <span>{syncError}</span>
          <button className="btn-icon" onClick={() => setSyncError(null)} aria-label="Dismiss"><X /></button>
        </div>
      )}

      <div className="stats-grid">
        {kpis.map(k => {
          const Icon = k.icon;
          return (
            <div key={k.label} className={`stat-card ${k.headline ? 'headline' : ''}`}>
              <div className="stat-label"><Icon /> {k.label}</div>
              <div className="stat-value">{k.value}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default Dashboard;
