import React, { useState, useEffect } from 'react';
import { Radio, RefreshCw, WifiOff, CheckCircle2, AlertTriangle, List, TrendingUp } from 'lucide-react';
import api from '../utils/api';
import useSortedData from '../utils/useSortedData';
import { formatDate, formatNumber, formatCompact, parseUTC } from '../utils/helpers';
import Modal from '../components/Modal';
import { CHART, CHART_TOOLTIP_STYLE, CHART_TICK } from '../components/TrafficChart';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, Legend } from 'recharts';

// Response-time trend for one hostname's check history
const HistoryChart = ({ history }) => {
  const data = history.map(h => ({
    checked_at: h.checked_at,
    http: h.http_response_time_ms,
    https: h.https_response_time_ms,
  }));
  const formatTick = (ts) => {
    const d = parseUTC(ts);
    return d ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '';
  };
  return (
    <ResponsiveContainer width="100%" height={260}>
      <LineChart data={data}>
        <CartesianGrid stroke={CHART.grid} vertical={false} />
        <XAxis dataKey="checked_at" tickFormatter={formatTick} tick={CHART_TICK} axisLine={{ stroke: CHART.grid }} tickLine={false} minTickGap={40} />
        <YAxis tickFormatter={(v) => `${formatCompact(v)} ms`} tick={CHART_TICK} axisLine={false} tickLine={false} width={64} />
        <Tooltip
          labelFormatter={formatTick}
          formatter={(value) => (value === null || value === undefined ? 'failed' : `${formatNumber(value)} ms`)}
          contentStyle={CHART_TOOLTIP_STYLE}
          labelStyle={{ color: CHART.text }}
          cursor={{ stroke: CHART.axis }}
        />
        <Legend wrapperStyle={{ fontSize: 11 }} iconSize={10} />
        <Line type="monotone" dataKey="http" name="HTTP" stroke={CHART.bandwidth} strokeWidth={1.5} dot={{ r: 2 }} connectNulls={false} />
        <Line type="monotone" dataKey="https" name="HTTPS" stroke={CHART.requests} strokeWidth={1.5} dot={{ r: 2 }} connectNulls={false} />
      </LineChart>
    </ResponsiveContainer>
  );
};

const Reachability = () => {
  const [results, setResults] = useState([]);
  const [zones, setZones] = useState([]);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [filters, setFilters] = useState({ zone: '', status: '', search: '' });
  const [historyFor, setHistoryFor] = useState(null); // row whose history modal is open
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const openHistory = (row) => {
    setHistoryFor(row);
    setHistoryLoading(true);
    api.get(`/reachability/history?dns_record_id=${encodeURIComponent(row.dns_record_id)}&hours=720`)
      .then(setHistory)
      .catch(console.error)
      .finally(() => setHistoryLoading(false));
  };

  const loadData = () => {
    setLoading(true);
    Promise.all([api.get('/reachability/latest'), api.get('/zones')])
      .then(([r, z]) => { setResults(r); setZones(z); })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const runChecks = async () => {
    setChecking(true);
    // Notify Layout to immediately start polling reachability progress
    window.dispatchEvent(new CustomEvent('reachability-started'));
    try {
      await api.post('/reachability/check-all', {});
      // The check runs in the background; poll until it finishes, then reload
      for (let i = 0; i < 900; i++) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        const progress = await api.get('/reachability/progress');
        if (!progress.active) break;
      }
      loadData();
    } catch (err) {
      console.error(err);
    } finally {
      setChecking(false);
    }
  };

  // Per-protocol probe outcome -> status tier per docs/UI_CONVENTIONS.md
  const getStatusBadge = (code, error, redirectTo) => {
    if (error) return <span className="badge badge-critical" title={error}>Unreachable</span>;
    if (!code) return <span className="badge badge-neutral">Not checked</span>;
    if (code >= 200 && code < 300) {
      return <span className="row"><span className="badge badge-success">Reachable</span><span className="cell-mono">{code}</span></span>;
    }
    if (code >= 300 && code < 400) {
      return (
        <span className="row" title={redirectTo ? `Redirects to ${redirectTo}` : undefined}>
          <span className="badge badge-medium">Redirect</span><span className="cell-mono">{code}</span>
        </span>
      );
    }
    return <span className="row"><span className="badge badge-high">Error</span><span className="cell-mono">{code}</span></span>;
  };

  const getOverallStatus = (r) => {
    const httpOk = r.http_status_code && r.http_status_code >= 200 && r.http_status_code < 300 && !r.http_error;
    const httpsOk = r.https_status_code && r.https_status_code >= 200 && r.https_status_code < 300 && !r.https_error;
    const httpRedirect = r.http_status_code && r.http_status_code >= 300 && r.http_status_code < 400 && !r.http_error;
    const httpsRedirect = r.https_status_code && r.https_status_code >= 300 && r.https_status_code < 400 && !r.https_error;

    // Fully reachable if EITHER protocol answered 2xx
    if (httpOk || httpsOk) return 'ok';

    // Reachable but only via redirect - flag as warning with the target visible
    if (httpRedirect || httpsRedirect) return 'warning';

    const hasHttpError = r.http_error || (r.http_status_code && r.http_status_code >= 400);
    const hasHttpsError = r.https_error || (r.https_status_code && r.https_status_code >= 400);

    if (hasHttpError || hasHttpsError) return 'error';
    return 'unknown';
  };

  const filtered = results.filter(r => {
    if (filters.zone && r.zone_id !== filters.zone) return false;
    if (filters.search && !r.hostname.toLowerCase().includes(filters.search.toLowerCase())) return false;
    if (filters.status) {
      const overall = getOverallStatus(r);
      if (filters.status !== overall) return false;
    }
    return true;
  });

  const { items: sortedResults, requestSort, getSortIndicator } = useSortedData(filtered, { key: 'hostname', direction: 'asc' });

  const stats = {
    total: results.length,
    ok: results.filter(r => getOverallStatus(r) === 'ok').length,
    warning: results.filter(r => getOverallStatus(r) === 'warning').length,
    error: results.filter(r => getOverallStatus(r) === 'error').length
  };
  const successRate = stats.total > 0 ? (stats.ok / stats.total) * 100 : 0;

  const latency = (ms) => (ms ? `${formatNumber(ms)} ms` : '-');

  if (loading) return <div className="loading-inline"><div className="spinner spinner-large" /></div>;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><Radio className="page-title-icon" /> Reachability</h1>
          <div className="page-subtitle">Latest HTTP and HTTPS probe for each DNS record.</div>
        </div>
        <div className="page-actions">
          <button className="btn btn-primary" onClick={runChecks} disabled={checking}>
            <RefreshCw /> {checking ? 'Checking...' : 'Check now'}
          </button>
        </div>
      </div>

      {checking && (
        <div className="card">
          <div className="row">
            <span className="spinner" />
            <div>
              <div className="text-data">Reachability check running</div>
              <div className="text-tertiary text-12">Probing every DNS record over HTTP and HTTPS; results refresh when the check completes.</div>
            </div>
          </div>
        </div>
      )}

      {/* Headline KPI per docs/UI_CONVENTIONS.md: unreachable hosts. */}
      <div className="stats-grid">
        <div className="stat-card headline">
          <div className="stat-label"><WifiOff /> Unreachable hosts</div>
          <div className="stat-value">{formatNumber(stats.error)}</div>
          <div className="stat-sub">connection failures or 4xx / 5xx on both protocols</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><CheckCircle2 /> Reachable</div>
          <div className="stat-value">{formatNumber(stats.ok)}</div>
          <div className="stat-sub">
            <div className="ratio-bar">
              <div className="ratio-track"><div className="ratio-fill success" style={{ width: `${successRate}%` }} /></div>
              <span className="ratio-value">{successRate.toFixed(1)}%</span>
            </div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><AlertTriangle /> Redirect only</div>
          <div className="stat-value">{formatNumber(stats.warning)}</div>
          <div className="stat-sub">no 2xx answer, 3xx on at least one protocol</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><List /> Total records</div>
          <div className="stat-value">{formatNumber(stats.total)}</div>
          <div className="stat-sub">DNS records with a probe result</div>
        </div>
      </div>

      <div className="filters-bar">
        <div className="filter-group">
          <label className="filter-label">Search</label>
          <input className="filter-input" placeholder="Filter by hostname" value={filters.search} onChange={e => setFilters({ ...filters, search: e.target.value })} />
        </div>
        <div className="filter-group">
          <label className="filter-label">Zone</label>
          <select className="filter-input" value={filters.zone} onChange={e => setFilters({ ...filters, zone: e.target.value })}>
            <option value="">All zones</option>
            {zones.map(z => <option key={z.zone_id} value={z.zone_id}>{z.name}</option>)}
          </select>
        </div>
        <div className="filter-group">
          <label className="filter-label">Status</label>
          <select className="filter-input" value={filters.status} onChange={e => setFilters({ ...filters, status: e.target.value })}>
            <option value="">All statuses</option>
            <option value="ok">Reachable</option>
            <option value="warning">Redirect only</option>
            <option value="error">Unreachable</option>
          </select>
        </div>
      </div>

      {sortedResults.length > 0 ? (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">
              <Radio className="card-title-icon" />Latest results
              <span className="card-subtitle">{formatNumber(filtered.length)} of {formatNumber(results.length)} records</span>
            </h2>
          </div>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th className="sortable" onClick={() => requestSort('hostname')}>Hostname{getSortIndicator('hostname')}</th>
                  <th className="sortable" onClick={() => requestSort('resolved_ip')}>IP address{getSortIndicator('resolved_ip')}</th>
                  <th className="sortable" onClick={() => requestSort('zone_name')}>Zone{getSortIndicator('zone_name')}</th>
                  <th className="sortable" onClick={() => requestSort('http_status_code')}>HTTP{getSortIndicator('http_status_code')}</th>
                  <th className="sortable num" onClick={() => requestSort('http_response_time_ms')}>HTTP time{getSortIndicator('http_response_time_ms')}</th>
                  <th className="sortable" onClick={() => requestSort('https_status_code')}>HTTPS{getSortIndicator('https_status_code')}</th>
                  <th className="sortable num" onClick={() => requestSort('https_response_time_ms')}>HTTPS time{getSortIndicator('https_response_time_ms')}</th>
                  <th className="sortable" onClick={() => requestSort('checked_at')}>Checked{getSortIndicator('checked_at')}</th>
                  <th>History</th>
                </tr>
              </thead>
              <tbody>
                {sortedResults.map(r => (
                  <tr key={r.id}>
                    <td className="cell-host">{r.hostname}</td>
                    <td className="cell-mono">{r.resolved_ip || '-'}</td>
                    <td><span className="badge badge-neutral">{r.zone_name}</span></td>
                    <td>{getStatusBadge(r.http_status_code, r.http_error, r.http_redirect_location)}</td>
                    <td className="cell-num">{latency(r.http_response_time_ms)}</td>
                    <td>{getStatusBadge(r.https_status_code, r.https_error, r.https_redirect_location)}</td>
                    <td className="cell-num">{latency(r.https_response_time_ms)}</td>
                    <td className="cell-time">{formatDate(r.checked_at)}</td>
                    <td>
                      <button className="btn-icon" onClick={() => openHistory(r)} title="Response time history" aria-label="Response time history">
                        <TrendingUp />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : results.length > 0 ? (
        <div className="empty-state">
          <Radio className="empty-icon" />
          <div className="empty-title">No matching records</div>
          <div className="empty-text">No results match the current filters.</div>
        </div>
      ) : (
        <div className="empty-state">
          <Radio className="empty-icon" />
          <div className="empty-title">No reachability data</div>
          <div className="empty-text">Run a check to see reachability status for your DNS records.</div>
        </div>
      )}

      <Modal isOpen={!!historyFor} onClose={() => { setHistoryFor(null); setHistory([]); }} title={`Response time history · ${historyFor?.hostname || ''}`}>
        {historyLoading ? (
          <div className="loading-inline"><div className="spinner" /></div>
        ) : history.length > 1 ? (
          <div>
            <HistoryChart history={history} />
            <div className="text-tertiary text-12 mt-3">
              {formatNumber(history.length)} checks over the last 30 days. Gaps indicate failed checks.
              Schedule recurring checks (REACHABILITY_INTERVAL_MINUTES) to build a denser trend.
            </div>
          </div>
        ) : (
          <div className="empty-state mb-0">
            <TrendingUp className="empty-icon" />
            <div className="empty-title">Not enough history</div>
            <div className="empty-text mb-0">Run checks over time (or enable scheduled checks) to see a trend for this hostname.</div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default Reachability;
