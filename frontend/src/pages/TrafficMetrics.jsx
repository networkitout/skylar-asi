import React, { useState, useEffect } from 'react';
import { Activity, Database, HardDrive, Shield, Eye, Users, Zap, Cloud, Hash, Globe, List } from 'lucide-react';
import api from '../utils/api';
import { formatBytes, formatNumber, formatDate } from '../utils/helpers';
import useSortedData from '../utils/useSortedData';
import TrafficChart from '../components/TrafficChart';

// Top-N share list for a {label: count} map, one ratio bar per entry (see docs/UI_CONVENTIONS.md)
const BreakdownList = ({ title, icon: Icon, data, mono = false, limit = 8 }) => {
  const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1]).slice(0, limit);
  if (entries.length === 0) return null;
  const all = Object.keys(data).length;
  const total = Object.values(data).reduce((s, v) => s + v, 0) || 1;
  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <Icon className="card-title-icon" />{title}
          {all > entries.length && <span className="card-subtitle">top {entries.length} of {all}</span>}
        </h2>
      </div>
      {entries.map(([label, count]) => {
        const pct = (count / total) * 100;
        return (
          <div key={label} className="mb-2">
            <div className="row-between text-12">
              <span className={mono ? 'cell-mono' : 'text-secondary'}>{label}</span>
              <span className="mono text-11 text-tertiary">{formatNumber(count)}</span>
            </div>
            <div className="ratio-bar">
              <div className="ratio-track"><div className="ratio-fill" style={{ width: `${pct}%` }} /></div>
              <span className="ratio-value">{pct.toFixed(1)}%</span>
            </div>
          </div>
        );
      })}
    </div>
  );
};

const TrafficMetrics = () => {
  const [metrics, setMetrics] = useState([]);
  const [zones, setZones] = useState([]);
  const [aggregate, setAggregate] = useState(null);
  const [breakdown, setBreakdown] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedZone, setSelectedZone] = useState('');
  const [hours, setHours] = useState(24);

  useEffect(() => { fetchData(); }, [selectedZone, hours]);

  const fetchData = async () => {
    setLoading(true);
    try {
      // Aggregate must honor the zone filter or the stat cards misreport
      // all-zone totals as the selected zone's traffic
      const aggParams = new URLSearchParams({ hours: hours.toString() });
      if (selectedZone) aggParams.append('zone_id', selectedZone);
      const [z, a, b] = await Promise.all([
        api.get('/zones'),
        api.get(`/metrics/aggregate?${aggParams}`),
        api.get(`/metrics/breakdown?${aggParams}`)
      ]);
      // Fetch every metrics page so per-zone totals cover the full window
      const pageSize = 1000;
      let page = 1;
      let rows = [];
      let total = 0;
      do {
        const params = new URLSearchParams({ hours: hours.toString(), page: page.toString(), page_size: pageSize.toString() });
        if (selectedZone) params.append('zone_id', selectedZone);
        const res = await api.get(`/metrics?${params}`);
        rows = rows.concat(res.data || []);
        total = res.total || 0;
        page += 1;
      } while (rows.length < total && page <= 20);
      setMetrics(rows);
      setZones(z);
      setAggregate(a);
      setBreakdown(b);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  const getZone = (id) => zones.find(z => z.zone_id === id)?.name || id;

  // Each metric row is one hourly bucket; roll them up per zone so the table
  // shows window totals consistent with the aggregate stat cards above
  const zoneTotals = Object.values(metrics.reduce((acc, m) => {
    if (!acc[m.zone_id]) {
      acc[m.zone_id] = {
        zone_id: m.zone_id,
        zone_name: getZone(m.zone_id),
        requests_all: 0,
        requests_cached: 0,
        bandwidth_all: 0,
        threats_all: 0,
        peak_uniques: 0,
        buckets: 0,
        latest_timestamp: m.timestamp
      };
    }
    const t = acc[m.zone_id];
    t.requests_all += m.requests_all || 0;
    t.requests_cached += m.requests_cached || 0;
    t.bandwidth_all += m.bandwidth_all || 0;
    t.threats_all += m.threats_all || 0;
    t.peak_uniques = Math.max(t.peak_uniques, m.uniques_all || 0);
    t.buckets += 1;
    if (m.timestamp > t.latest_timestamp) t.latest_timestamp = m.timestamp;
    return acc;
  }, {}));

  const { items: sortedMetrics, requestSort, getSortIndicator } = useSortedData(zoneTotals, { key: 'zone_name', direction: 'asc' });

  // Roll buckets up per hour (across the selected zones) for the time series
  const chartData = Object.values(metrics.reduce((acc, m) => {
    if (!acc[m.timestamp]) {
      acc[m.timestamp] = { timestamp: m.timestamp, requests: 0, cached: 0, bandwidth: 0, threats: 0 };
    }
    const h = acc[m.timestamp];
    h.requests += m.requests_all || 0;
    h.cached += m.requests_cached || 0;
    h.bandwidth += m.bandwidth_all || 0;
    h.threats += m.threats_all || 0;
    return acc;
  }, {})).sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  const hasBreakdown = breakdown && (
    Object.keys(breakdown.http_status || {}).length > 0 ||
    Object.keys(breakdown.country || {}).length > 0 ||
    Object.keys(breakdown.content_type || {}).length > 0
  );

  // Headline KPI per docs/UI_CONVENTIONS.md: total requests in the window.
  const kpis = aggregate ? [
    { icon: Activity, label: 'Total requests', value: formatNumber(aggregate.total_requests), headline: true },
    { icon: Database, label: 'Cached requests', value: formatNumber(aggregate.total_cached) },
    { icon: HardDrive, label: 'Bandwidth', value: formatBytes(aggregate.total_bandwidth) },
    { icon: Shield, label: 'Threats', value: formatNumber(aggregate.total_threats) },
    { icon: Eye, label: 'Page views', value: formatNumber(aggregate.total_pageviews) },
    { icon: Users, label: 'Peak uniques', value: formatNumber(aggregate.total_uniques), sub: 'hourly, approximate' },
    { icon: Zap, label: 'Cache ratio', value: `${(aggregate.cache_ratio || 0).toFixed(1)}%` },
    { icon: Cloud, label: 'Cached bandwidth', value: formatBytes(aggregate.bandwidth_cached) },
  ] : [];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><Activity className="page-title-icon" /> Traffic metrics</h1>
          <div className="page-subtitle">Hourly request, bandwidth and threat totals per zone.</div>
        </div>
      </div>

      {aggregate && (
        <div className="stats-grid">
          {kpis.map(k => {
            const Icon = k.icon;
            return (
              <div key={k.label} className={`stat-card ${k.headline ? 'headline' : ''}`}>
                <div className="stat-label"><Icon /> {k.label}</div>
                <div className="stat-value">{k.value}</div>
                {k.sub && <div className="stat-sub">{k.sub}</div>}
              </div>
            );
          })}
        </div>
      )}

      <div className="filters-bar">
        <div className="filter-group">
          <label className="filter-label">Zone</label>
          <select className="filter-input" value={selectedZone} onChange={e => setSelectedZone(e.target.value)}>
            <option value="">All zones</option>
            {zones.map(z => <option key={z.zone_id} value={z.zone_id}>{z.name}</option>)}
          </select>
        </div>
        <div className="filter-group">
          <label className="filter-label">Period</label>
          <select className="filter-input" value={hours} onChange={e => setHours(Number(e.target.value))}>
            <option value={1}>Last hour</option>
            <option value={6}>Last 6 hours</option>
            <option value={24}>Last 24 hours</option>
            <option value={72}>Last 3 days</option>
            <option value={168}>Last 7 days</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="loading-inline"><div className="spinner spinner-large" /></div>
      ) : sortedMetrics.length > 0 ? (
        <>
          <TrafficChart data={chartData} />

          {hasBreakdown && (
            <div className="content-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))' }}>
              <BreakdownList title="HTTP status codes" icon={Hash} data={breakdown.http_status} mono />
              <BreakdownList title="Top countries" icon={Globe} data={breakdown.country} />
              <BreakdownList title="Content types" icon={List} data={breakdown.content_type} mono />
            </div>
          )}

          <div className="card">
            <div className="card-header">
              <h2 className="card-title">
                <Globe className="card-title-icon" />Per-zone totals
                <span className="card-subtitle">{formatNumber(sortedMetrics.length)} zones · last {hours}h</span>
              </h2>
            </div>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="sortable" onClick={() => requestSort('zone_name')}>Zone{getSortIndicator('zone_name')}</th>
                    <th className="sortable num" onClick={() => requestSort('requests_all')}>Requests{getSortIndicator('requests_all')}</th>
                    <th className="sortable num" onClick={() => requestSort('requests_cached')}>Cached{getSortIndicator('requests_cached')}</th>
                    <th style={{ minWidth: '140px' }}>Cache ratio</th>
                    <th className="sortable num" onClick={() => requestSort('bandwidth_all')}>Bandwidth{getSortIndicator('bandwidth_all')}</th>
                    <th className="sortable num" onClick={() => requestSort('threats_all')}>Threats{getSortIndicator('threats_all')}</th>
                    <th className="sortable num" onClick={() => requestSort('buckets')}>Hours of data{getSortIndicator('buckets')}</th>
                    <th className="sortable" onClick={() => requestSort('latest_timestamp')}>Latest data{getSortIndicator('latest_timestamp')}</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedMetrics.map(m => {
                    const ratio = m.requests_all > 0 ? (m.requests_cached / m.requests_all) * 100 : 0;
                    return (
                      <tr key={m.zone_id}>
                        <td className="cell-host">{m.zone_name}</td>
                        <td className="cell-num">{formatNumber(m.requests_all)}</td>
                        <td className="cell-num">{formatNumber(m.requests_cached)}</td>
                        <td>
                          <div className="ratio-bar">
                            <div className="ratio-track"><div className="ratio-fill" style={{ width: `${ratio}%` }} /></div>
                            <span className="ratio-value">{ratio.toFixed(1)}%</span>
                          </div>
                        </td>
                        <td className="cell-num">{formatBytes(m.bandwidth_all)}</td>
                        <td className="cell-num">{formatNumber(m.threats_all)}</td>
                        <td className="cell-num">{formatNumber(m.buckets)}</td>
                        <td className="cell-time">{formatDate(m.latest_timestamp)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : (
        <div className="empty-state">
          <Activity className="empty-icon" />
          <div className="empty-title">No traffic data</div>
          <div className="empty-text">Sync your Cloudflare data to see traffic metrics for this window.</div>
        </div>
      )}
    </div>
  );
};

export default TrafficMetrics;
