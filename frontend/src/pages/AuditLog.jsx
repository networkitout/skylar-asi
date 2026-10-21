import React, { useState, useEffect } from 'react';
import {
  ScrollText, KeyRound, RefreshCw, Pencil, ChevronUp, ChevronDown, ChevronsUpDown, ChevronLeft, ChevronRight,
} from 'lucide-react';
import api from '../utils/api';
import { formatDate, formatNumber, getTimeAgo } from '../utils/helpers';

// Action -> badge tier and leading status dot (see docs/UI_CONVENTIONS.md).
// Order matters: failures win over everything, then verified-positive
// outcomes, then exposure/security, then informational job and auth events.
const classifyAction = (action = '') => {
  if (action.endsWith('_FAILED') || action === 'USER_DELETED' || action === 'CONFIG_DELETED') {
    return { badge: 'badge-critical', dot: 'critical' };
  }
  if (['CONFIG_CREATED', 'USER_CREATED', 'SETUP_ADMIN_CREATED', 'PASSWORD_CHANGED'].includes(action) || action.endsWith('_VERIFIED')) {
    return { badge: 'badge-success', dot: 'success' };
  }
  if (action.startsWith('EXPOSURE_') || action.includes('WAF') || action.includes('SECURITY')) {
    return { badge: 'badge-low', dot: action.endsWith('_STARTED') || action.endsWith('_SUCCESS') ? 'running' : '' };
  }
  if (action.startsWith('LOGIN') || action === 'LOGOUT' || action.startsWith('SYNC_') || action.startsWith('REACHABILITY_')
    || action.startsWith('REPORT_') || action.endsWith('_VIEWED')) {
    return { badge: 'badge-neutral', dot: 'running' };
  }
  return { badge: 'badge-neutral', dot: '' };
};

const actionLabel = (action) => (action ? action.replace(/_/g, ' ') : '-');

const AuditLog = () => {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [users, setUsers] = useState([]);
  const [actions, setActions] = useState({});
  const [loading, setLoading] = useState(true);
  const [expandedLog, setExpandedLog] = useState(null);
  const [filters, setFilters] = useState({
    action: '',
    user_id: '',
    resource_type: '',
    start_date: '',
    end_date: '',
    search: ''
  });
  const [page, setPage] = useState(0);
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });
  // Debounced copy of filters.search, sent to the server as the q param so
  // search covers the whole dataset instead of just the loaded page
  const [searchQuery, setSearchQuery] = useState('');
  const limit = 50;

  useEffect(() => {
    Promise.all([
      api.get('/users'),
      api.get('/audit-logs/actions')
    ]).then(([u, a]) => {
      setUsers(u);
      setActions(a);
    }).catch(console.error);
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => {
      setSearchQuery(filters.search);
      setPage(0);
    }, 300);
    return () => clearTimeout(timer);
  }, [filters.search]);

  useEffect(() => {
    loadLogs();
  }, [page, filters.action, filters.user_id, filters.resource_type, filters.start_date, filters.end_date, searchQuery, sortConfig]);

  const requestSort = (key) => {
    let direction = 'asc';
    if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = 'desc';
    }
    setSortConfig({ key, direction });
    setPage(0); // Reset to first page when sorting changes
  };

  // Mirrors useSortedData's indicator so this server-sorted table matches the rest
  const getSortIndicator = (name) => {
    const style = { width: 11, height: 11, marginLeft: 4, verticalAlign: 'middle' };
    if (sortConfig.key !== name) {
      return <ChevronsUpDown style={{ ...style, opacity: 0.4 }} />;
    }
    return sortConfig.direction === 'asc' ? <ChevronUp style={style} /> : <ChevronDown style={style} />;
  };

  const loadLogs = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.append('limit', limit);
      params.append('offset', page * limit);
      params.append('sort_by', sortConfig.key);
      params.append('sort_order', sortConfig.direction);
      if (filters.action) params.append('action', filters.action);
      if (filters.user_id) params.append('user_id', filters.user_id);
      if (filters.resource_type) params.append('resource_type', filters.resource_type);
      if (filters.start_date) params.append('start_date', filters.start_date);
      if (filters.end_date) params.append('end_date', filters.end_date);
      if (searchQuery) params.append('q', searchQuery);

      const response = await api.get(`/audit-logs?${params.toString()}`);
      setLogs(response.logs);
      setTotal(response.total);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const getActionBadge = (action) => {
    const { badge } = classifyAction(action);
    return <span className={`badge ${badge}`}>{actionLabel(action)}</span>;
  };

  // Resource types are categorical, not status: always the neutral badge
  const getResourceBadge = (type) => {
    if (!type) return <span className="text-tertiary">-</span>;
    return <span className="badge badge-neutral">{type}</span>;
  };

  // Search is applied server-side (q param), so the page is shown as-is
  const filtered = logs;

  const resourceTypes = ['user', 'config', 'reachability', 'report', 'exposure'];
  const totalPages = Math.ceil(total / limit);

  const stats = {
    total: total,
    logins: Object.entries(actions).filter(([k]) => k.startsWith('LOGIN')).reduce((a, [, v]) => a + v, 0),
    syncs: Object.entries(actions).filter(([k]) => k.startsWith('SYNC')).reduce((a, [, v]) => a + v, 0),
    changes: Object.entries(actions).filter(([k]) => k.includes('CREATED') || k.includes('UPDATED') || k.includes('DELETED')).reduce((a, [, v]) => a + v, 0)
  };

  if (loading && logs.length === 0) {
    return <div className="loading-inline"><div className="spinner spinner-large" /></div>;
  }

  // Headline KPI for this page: total events.
  const kpis = [
    { icon: ScrollText, label: 'Total events', value: formatNumber(stats.total), headline: true },
    { icon: KeyRound, label: 'Login events', value: formatNumber(stats.logins) },
    { icon: RefreshCw, label: 'Sync events', value: formatNumber(stats.syncs) },
    { icon: Pencil, label: 'Changes', value: formatNumber(stats.changes) },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><ScrollText className="page-title-icon" /> Audit log</h1>
          <div className="page-subtitle">Who did what, when, and from where: sign-ins, syncs, configuration changes, and exposure runs.</div>
        </div>
      </div>

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

      <div className="filters-bar">
        <div className="filter-group">
          <label className="filter-label">Search</label>
          <input
            className="filter-input"
            value={filters.search}
            onChange={e => setFilters({ ...filters, search: e.target.value })}
          />
        </div>
        <div className="filter-group">
          <label className="filter-label">User</label>
          <select
            className="filter-input"
            value={filters.user_id}
            onChange={e => { setFilters({ ...filters, user_id: e.target.value }); setPage(0); }}
          >
            <option value="">All users</option>
            {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
        </div>
        <div className="filter-group">
          <label className="filter-label">Action</label>
          <select
            className="filter-input"
            value={filters.action}
            onChange={e => { setFilters({ ...filters, action: e.target.value }); setPage(0); }}
          >
            <option value="">All actions</option>
            {Object.entries(actions).map(([a, count]) => (
              <option key={a} value={a}>{a.replace(/_/g, ' ')} ({count})</option>
            ))}
          </select>
        </div>
        <div className="filter-group">
          <label className="filter-label">Resource</label>
          <select
            className="filter-input"
            value={filters.resource_type}
            onChange={e => { setFilters({ ...filters, resource_type: e.target.value }); setPage(0); }}
          >
            <option value="">All resources</option>
            {resourceTypes.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className="filter-group">
          <label className="filter-label">From</label>
          <input
            type="date"
            className="filter-input"
            value={filters.start_date}
            onChange={e => { setFilters({ ...filters, start_date: e.target.value }); setPage(0); }}
          />
        </div>
        <div className="filter-group">
          <label className="filter-label">To</label>
          <input
            type="date"
            className="filter-input"
            value={filters.end_date}
            onChange={e => { setFilters({ ...filters, end_date: e.target.value }); setPage(0); }}
          />
        </div>
      </div>

      <div className="row text-tertiary text-12 mb-3">
        <span>Showing {formatNumber(filtered.length)} of {formatNumber(total)} events</span>
        {loading && <span className="spinner" />}
      </div>

      {filtered.length > 0 ? (
        <>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: '32px' }}></th>
                  <th className="sortable" onClick={() => requestSort('timestamp')}>Timestamp{getSortIndicator('timestamp')}</th>
                  <th className="sortable" onClick={() => requestSort('user_id')}>User{getSortIndicator('user_id')}</th>
                  <th className="sortable" onClick={() => requestSort('action')}>Action{getSortIndicator('action')}</th>
                  <th className="sortable" onClick={() => requestSort('resource_type')}>Resource{getSortIndicator('resource_type')}</th>
                  <th>Details</th>
                  <th className="sortable" onClick={() => requestSort('ip_address')}>IP address{getSortIndicator('ip_address')}</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(log => {
                  const { dot } = classifyAction(log.action);
                  const isOpen = expandedLog === log.id;
                  const detailText = log.details ? JSON.stringify(log.details) : '';
                  const hasDetails = !!log.details && Object.keys(log.details).length > 0;
                  return (
                    <React.Fragment key={log.id}>
                      <tr
                        className={`row-link ${isOpen ? 'row-selected' : ''}`}
                        onClick={() => setExpandedLog(isOpen ? null : log.id)}
                      >
                        <td><span className={`status-dot ${dot}`} /></td>
                        <td className="cell-time" title={getTimeAgo(log.timestamp)}>{formatDate(log.timestamp)}</td>
                        <td className="cell-mono">{log.username || 'System'}</td>
                        <td>{getActionBadge(log.action)}</td>
                        <td>{getResourceBadge(log.resource_type)}</td>
                        <td className="cell-mono truncate" style={{ maxWidth: '280px' }} title={detailText || undefined}>
                          {detailText || '-'}
                        </td>
                        <td className="cell-mono">{log.ip_address || '-'}</td>
                      </tr>
                      {isOpen && (
                        <tr className="row-detail">
                          <td colSpan={7}>
                            <div className="content-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
                              <div>
                                <div className="section-label">Event</div>
                                <dl className="kv">
                                  <dt>Event ID</dt><dd className="mono">{log.id}</dd>
                                  <dt>Timestamp</dt><dd className="mono">{formatDate(log.timestamp)}</dd>
                                  <dt>User</dt><dd className="mono">{log.username || 'System'}{log.user_id ? ` (ID ${log.user_id})` : ''}</dd>
                                  <dt>IP address</dt><dd className="mono">{log.ip_address || '-'}</dd>
                                  <dt>Action</dt><dd>{getActionBadge(log.action)}</dd>
                                  <dt>Resource</dt>
                                  <dd className="row">
                                    {getResourceBadge(log.resource_type)}
                                    {log.resource_id && <span className="mono">ID {log.resource_id}</span>}
                                  </dd>
                                </dl>
                              </div>
                              <div>
                                <div className="section-label">Details</div>
                                {hasDetails ? (
                                  <dl className="kv">
                                    {Object.entries(log.details).map(([key, value]) => (
                                      <React.Fragment key={key}>
                                        <dt className="mono">{key}</dt>
                                        <dd className="mono" style={{ wordBreak: 'break-all' }}>
                                          {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                                        </dd>
                                      </React.Fragment>
                                    ))}
                                  </dl>
                                ) : (
                                  <div className="text-tertiary text-12">No additional details.</div>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="row" style={{ justifyContent: 'center' }}>
              <button
                className="btn btn-secondary btn-small"
                disabled={page === 0}
                onClick={() => setPage(p => p - 1)}
              >
                <ChevronLeft /> Previous
              </button>
              <span className="text-12 text-secondary tnum">Page {page + 1} of {totalPages}</span>
              <button
                className="btn btn-secondary btn-small"
                disabled={page >= totalPages - 1}
                onClick={() => setPage(p => p + 1)}
              >
                Next <ChevronRight />
              </button>
            </div>
          )}
        </>
      ) : (
        <div className="empty-state">
          <ScrollText className="empty-icon" />
          <div className="empty-title">No audit events</div>
          <div className="empty-text">No events match the current filters.</div>
        </div>
      )}
    </div>
  );
};

export default AuditLog;
