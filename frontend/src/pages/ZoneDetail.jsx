import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft, List, Shield, Activity, Radio, RefreshCw, Cloud, CloudOff, XCircle,
  BarChart3, HardDrive, Zap,
} from 'lucide-react';
import api from '../utils/api';
import { formatDate, formatBytes, formatNumber, getSecurityIcon, truncate, getTimeAgo } from '../utils/helpers';
import useSortedData from '../utils/useSortedData';
import TrafficChart from '../components/TrafficChart';

// Zone status -> tier per docs/UI_CONVENTIONS.md
const ZONE_STATUS_CLS = {
  active: 'badge-success',
  pending: 'badge-medium', initializing: 'badge-medium', paused: 'badge-medium', inactive: 'badge-medium',
  moved: 'badge-critical', deleted: 'badge-critical', deactivated: 'badge-critical',
};

// Readable form of a raw Cloudflare setting value; plain on/off is already
// conveyed by the enabled state so it is dropped.
const settingValueLabel = (value) => {
  if (value === null || value === undefined || typeof value === 'boolean') return '';
  if (typeof value === 'object') return Object.entries(value).filter(([, v]) => v === 'on').map(([k]) => k).join(', ');
  const text = String(value);
  return text === 'on' || text === 'off' ? '' : text;
};

// Probe result -> tier per docs/UI_CONVENTIONS.md: 3xx redirect = medium, 4xx/5xx = high, error = critical.
const probeBadge = (code, error) => {
  if (error) return <span className="badge badge-critical" title={error}>error</span>;
  if (!code) return <span className="badge badge-neutral">n/a</span>;
  if (code >= 200 && code < 300) return <span className="badge badge-success">{code}</span>;
  if (code >= 300 && code < 400) return <span className="badge badge-medium">{code}</span>;
  return <span className="badge badge-high">{code}</span>;
};

const ZoneDetail = () => {
  const { zoneId } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('overview');
  const [reachability, setReachability] = useState([]);
  const [reachabilityLoading, setReachabilityLoading] = useState(false);
  const [checking, setChecking] = useState(false);

  useEffect(() => { api.get(`/zones/${zoneId}`).then(setData).catch(console.error).finally(() => setLoading(false)); }, [zoneId]);

  useEffect(() => {
    if (tab === 'reachability') {
      setReachabilityLoading(true);
      api.get(`/reachability/latest?zone_id=${zoneId}`)
        .then(setReachability)
        .catch(console.error)
        .finally(() => setReachabilityLoading(false));
    }
  }, [tab, zoneId]);

  const runZoneCheck = async () => {
    setChecking(true);
    // Notify Layout to immediately start polling reachability progress
    window.dispatchEvent(new CustomEvent('reachability-started'));
    try {
      await api.post(`/reachability/check-zone/${zoneId}`, {});
      // The check runs in the background; poll until it finishes, then reload
      for (let i = 0; i < 900; i++) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        const progress = await api.get('/reachability/progress');
        if (!progress.active) break;
      }
      const updated = await api.get(`/reachability/latest?zone_id=${zoneId}`);
      setReachability(updated);
    } catch (err) {
      console.error(err);
    } finally {
      setChecking(false);
    }
  };

  // Always call hooks BEFORE any conditional returns - they must be called the same number of times on every render
  const { items: sortedDNS, requestSort: requestSortDNS, getSortIndicator: getIndicatorDNS } = useSortedData(data?.dns_records || [], { key: 'name', direction: 'asc' });
  const { items: sortedReachability, requestSort: requestSortReachability, getSortIndicator: getIndicatorReachability } = useSortedData(reachability || [], { key: 'hostname', direction: 'asc' });

  if (loading) return <div className="loading-inline"><div className="spinner spinner-large" /></div>;
  if (!data) {
    return (
      <div className="empty-state">
        <XCircle className="empty-icon" />
        <div className="empty-title">Zone not found</div>
        <div className="empty-text">This zone is not in the local inventory. It may have been removed or not synced yet.</div>
        <Link to="/zones" className="btn btn-secondary"><ArrowLeft /> Back to zones</Link>
      </div>
    );
  }

  const { zone, dns_records, security_settings, metrics } = data;

  // metrics is the last 24 hourly buckets (newest first). Showing a single
  // bucket would misrepresent a partial in-progress hour as the zone's
  // traffic, so totals are summed across the whole window.
  const metricTotals = (metrics || []).reduce((acc, m) => {
    acc.requests += m.requests_all || 0;
    acc.cached += m.requests_cached || 0;
    acc.bandwidth += m.bandwidth_all || 0;
    acc.threats += m.threats_all || 0;
    return acc;
  }, { requests: 0, cached: 0, bandwidth: 0, threats: 0 });
  const metricsChartData = (metrics || [])
    .map(m => ({ timestamp: m.timestamp, requests: m.requests_all || 0, cached: m.requests_cached || 0, bandwidth: m.bandwidth_all || 0, threats: m.threats_all || 0 }))
    .sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));

  const hours = metrics?.length || 0;
  const windowLabel = hours ? ` (${hours}h)` : '';
  const cacheRatio = metricTotals.requests > 0 ? (metricTotals.cached / metricTotals.requests) * 100 : 0;
  const proxiedCount = dns_records?.filter(r => r.proxied).length || 0;
  const enabledCount = security_settings?.filter(s => s.enabled).length || 0;

  const cacheRatioBar = (
    <div className="ratio-bar">
      <div className="ratio-track"><div className="ratio-fill" style={{ width: `${cacheRatio}%` }} /></div>
      <span className="ratio-value">{cacheRatio.toFixed(1)}%</span>
    </div>
  );

  return (
    <div>
      <div className="zone-detail-header">
        <div className="zone-info">
          <h1>{zone.name}</h1>
          <div className="row">
            <span className={`badge ${ZONE_STATUS_CLS[zone.status] || 'badge-neutral'}`}>{zone.status || 'unknown'}</span>
            {zone.paused && <span className="badge badge-medium">paused</span>}
            <span className="badge badge-neutral">{zone.type || 'full'}</span>
          </div>
          <div className="zone-meta">
            <div className="zone-meta-item"><span className="zone-meta-label">Zone ID</span><span className="zone-meta-value">{zone.zone_id}</span></div>
            <div className="zone-meta-item"><span className="zone-meta-label">Account</span><span className="zone-meta-value">{zone.account_name || 'N/A'}</span></div>
            <div className="zone-meta-item"><span className="zone-meta-label">Created</span><span className="zone-meta-value">{formatDate(zone.created_on)}</span></div>
            <div className="zone-meta-item"><span className="zone-meta-label">Last synced</span><span className="zone-meta-value" title={formatDate(zone.last_synced)}>{getTimeAgo(zone.last_synced)}</span></div>
          </div>
        </div>
        <div className="page-actions">
          <Link to="/zones" className="btn btn-secondary"><ArrowLeft /> All zones</Link>
        </div>
      </div>

      <div className="tabs">
        <button className={`tab ${tab === 'overview' ? 'active' : ''}`} onClick={() => setTab('overview')}>Overview</button>
        <button className={`tab ${tab === 'dns' ? 'active' : ''}`} onClick={() => setTab('dns')}>DNS records ({formatNumber(dns_records?.length || 0)})</button>
        <button className={`tab ${tab === 'security' ? 'active' : ''}`} onClick={() => setTab('security')}>Security</button>
        <button className={`tab ${tab === 'metrics' ? 'active' : ''}`} onClick={() => setTab('metrics')}>Metrics</button>
        <button className={`tab ${tab === 'reachability' ? 'active' : ''}`} onClick={() => setTab('reachability')}>Reachability</button>
      </div>

      {tab === 'overview' && (
        <div className="stats-grid">
          <div className="stat-card headline">
            <div className="stat-label"><Activity /> Requests{windowLabel}</div>
            <div className="stat-value">{formatNumber(metricTotals.requests)}</div>
            <div className="stat-sub">{hours ? `${formatBytes(metricTotals.bandwidth)} transferred` : 'No metrics synced yet'}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label"><Zap /> Cached{windowLabel}</div>
            <div className="stat-value">{formatNumber(metricTotals.cached)}</div>
            <div className="stat-sub">{cacheRatioBar}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label"><List /> DNS records</div>
            <div className="stat-value">{formatNumber(dns_records?.length || 0)}</div>
            <div className="stat-sub">{formatNumber(proxiedCount)} proxied</div>
          </div>
          <div className="stat-card">
            <div className="stat-label"><Shield /> Security settings</div>
            <div className="stat-value">{formatNumber(enabledCount)}</div>
            <div className="stat-sub">enabled of {formatNumber(security_settings?.length || 0)} tracked</div>
          </div>
        </div>
      )}

      {tab === 'dns' && (sortedDNS?.length > 0 ? (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => requestSortDNS('type')}>Type{getIndicatorDNS('type')}</th>
                <th className="sortable" onClick={() => requestSortDNS('name')}>Name{getIndicatorDNS('name')}</th>
                <th className="sortable" onClick={() => requestSortDNS('content')}>Content{getIndicatorDNS('content')}</th>
                <th className="sortable" onClick={() => requestSortDNS('proxied')}>Proxied{getIndicatorDNS('proxied')}</th>
                <th className="sortable num" onClick={() => requestSortDNS('ttl')}>TTL{getIndicatorDNS('ttl')}</th>
              </tr>
            </thead>
            <tbody>
              {sortedDNS.map(r => (
                <tr key={r.record_id}>
                  <td><span className="badge badge-neutral dns-record-type">{r.type}</span></td>
                  <td className="cell-host">{r.name}</td>
                  <td className="content-cell"><span className="cell-mono" title={r.content}>{truncate(r.content, 40)}</span></td>
                  <td>
                    <span className={`proxied-badge ${r.proxied ? 'on' : 'off'}`}>
                      {r.proxied ? <Cloud /> : <CloudOff />} {r.proxied ? 'Proxied' : 'DNS only'}
                    </span>
                  </td>
                  <td className="cell-num">{r.ttl === 1 ? 'Auto' : `${r.ttl}s`}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state">
          <List className="empty-icon" />
          <div className="empty-title">No DNS records</div>
          <div className="empty-text">No DNS records were found for this zone in the last sync.</div>
        </div>
      ))}

      {tab === 'security' && (security_settings?.length > 0 ? (
        <div className="security-grid">
          {security_settings.map(s => {
            const Icon = getSecurityIcon(s.setting_name);
            const value = settingValueLabel(s.setting_value);
            return (
              <div key={s.id} className={`security-item ${s.enabled ? 'enabled' : 'disabled'}`}>
                <Icon className="security-icon" />
                <div className="security-body">
                  <div className="security-name">{s.setting_name.replace(/_/g, ' ')}</div>
                  <div className="security-status">{s.enabled ? 'on' : 'off'}{value ? ` · ${value}` : ''}</div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="empty-state">
          <Shield className="empty-icon" />
          <div className="empty-title">No security settings</div>
          <div className="empty-text">Zone settings appear after the next sync.</div>
        </div>
      ))}

      {tab === 'metrics' && (metrics?.length > 0 ? (
        <div>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-label"><Activity /> Requests{windowLabel}</div>
              <div className="stat-value">{formatNumber(metricTotals.requests)}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label"><Zap /> Cached{windowLabel}</div>
              <div className="stat-value">{formatNumber(metricTotals.cached)}</div>
              <div className="stat-sub">{cacheRatioBar}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label"><HardDrive /> Bandwidth{windowLabel}</div>
              <div className="stat-value">{formatBytes(metricTotals.bandwidth)}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label"><Shield /> Threats{windowLabel}</div>
              <div className="stat-value">{formatNumber(metricTotals.threats)}</div>
            </div>
          </div>
          <TrafficChart data={metricsChartData} height={280} />
        </div>
      ) : (
        <div className="empty-state">
          <BarChart3 className="empty-icon" />
          <div className="empty-title">No metrics</div>
          <div className="empty-text">Hourly traffic analytics appear after the next sync.</div>
        </div>
      ))}

      {tab === 'reachability' && (
        <div>
          <div className="row-between mb-4">
            <div className="text-secondary text-12">HTTP and HTTPS probes against every hostname in this zone.</div>
            <button className="btn btn-primary" onClick={runZoneCheck} disabled={checking}>
              <RefreshCw /> {checking ? 'Checking...' : 'Check now'}
            </button>
          </div>
          {reachabilityLoading ? (
            <div className="loading-inline"><div className="spinner" /></div>
          ) : sortedReachability.length > 0 ? (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="sortable" onClick={() => requestSortReachability('hostname')}>Hostname{getIndicatorReachability('hostname')}</th>
                    <th className="sortable" onClick={() => requestSortReachability('resolved_ip')}>Resolved IP{getIndicatorReachability('resolved_ip')}</th>
                    <th className="sortable" onClick={() => requestSortReachability('http_status_code')}>HTTP{getIndicatorReachability('http_status_code')}</th>
                    <th className="sortable num" onClick={() => requestSortReachability('http_response_time_ms')}>HTTP time{getIndicatorReachability('http_response_time_ms')}</th>
                    <th className="sortable" onClick={() => requestSortReachability('https_status_code')}>HTTPS{getIndicatorReachability('https_status_code')}</th>
                    <th className="sortable num" onClick={() => requestSortReachability('https_response_time_ms')}>HTTPS time{getIndicatorReachability('https_response_time_ms')}</th>
                    <th className="sortable" onClick={() => requestSortReachability('checked_at')}>Checked{getIndicatorReachability('checked_at')}</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedReachability.map(r => (
                    <tr key={r.id}>
                      <td className="cell-host">{r.hostname}</td>
                      <td className="cell-mono">{r.resolved_ip || '-'}</td>
                      <td>{probeBadge(r.http_status_code, r.http_error)}</td>
                      <td className="cell-num">{r.http_response_time_ms ? `${formatNumber(r.http_response_time_ms)}ms` : '-'}</td>
                      <td>{probeBadge(r.https_status_code, r.https_error)}</td>
                      <td className="cell-num">{r.https_response_time_ms ? `${formatNumber(r.https_response_time_ms)}ms` : '-'}</td>
                      <td className="cell-time">{formatDate(r.checked_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <Radio className="empty-icon" />
              <div className="empty-title">No reachability data</div>
              <div className="empty-text">Run a check to probe HTTP and HTTPS for this zone's DNS records.</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ZoneDetail;
