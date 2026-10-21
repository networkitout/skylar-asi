import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Globe, Settings } from 'lucide-react';
import api from '../utils/api';
import useSortedData from '../utils/useSortedData';
import { formatDate, formatNumber, getTimeAgo } from '../utils/helpers';

// Zone status -> tier per docs/UI_CONVENTIONS.md
const ZONE_STATUS_CLS = {
  active: 'badge-success',
  pending: 'badge-medium', initializing: 'badge-medium', paused: 'badge-medium', inactive: 'badge-medium',
  moved: 'badge-critical', deleted: 'badge-critical', deactivated: 'badge-critical',
};

const Zones = () => {
  const navigate = useNavigate();
  const [zones, setZones] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');

  useEffect(() => { api.get('/zones').then(setZones).finally(() => setLoading(false)); }, []);

  const filtered = zones.filter(z => z.name.toLowerCase().includes(search.toLowerCase()) && (status === 'all' || z.status === status));

  const { items: sortedZones, requestSort, getSortIndicator } = useSortedData(filtered, { key: 'name', direction: 'asc' });

  if (loading) return <div className="loading-inline"><div className="spinner spinner-large" /></div>;

  const hasFilters = search !== '' || status !== 'all';
  const activeCount = zones.filter(z => z.status === 'active').length;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><Globe className="page-title-icon" /> Zones</h1>
          <div className="page-subtitle">{formatNumber(zones.length)} zones · {formatNumber(activeCount)} active</div>
        </div>
      </div>

      <div className="filters-bar">
        <div className="filter-group">
          <label className="filter-label">Search</label>
          <input className="filter-input" placeholder="Zone name" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <div className="filter-group">
          <label className="filter-label">Status</label>
          <select className="filter-input" value={status} onChange={e => setStatus(e.target.value)}>
            <option value="all">All</option>
            <option value="active">Active</option>
            <option value="pending">Pending</option>
          </select>
        </div>
      </div>

      {sortedZones.length > 0 ? (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => requestSort('name')}>Zone{getSortIndicator('name')}</th>
                <th className="sortable" onClick={() => requestSort('status')}>Status{getSortIndicator('status')}</th>
                <th className="sortable" onClick={() => requestSort('type')}>Type{getSortIndicator('type')}</th>
                <th className="sortable" onClick={() => requestSort('account_name')}>Account{getSortIndicator('account_name')}</th>
                <th className="sortable num" onClick={() => requestSort('dns_records_count')}>Records{getSortIndicator('dns_records_count')}</th>
                <th className="sortable num" onClick={() => requestSort('proxied_records_count')}>Proxied{getSortIndicator('proxied_records_count')}</th>
                <th className="sortable" onClick={() => requestSort('last_synced')}>Last synced{getSortIndicator('last_synced')}</th>
              </tr>
            </thead>
            <tbody>
              {sortedZones.map(z => (
                <tr key={z.zone_id} className="row-link" onClick={() => navigate(`/zones/${z.zone_id}`)}>
                  <td><Link to={`/zones/${z.zone_id}`} className="cell-host" onClick={e => e.stopPropagation()}>{z.name}</Link></td>
                  <td>
                    <div className="row">
                      <span className={`badge ${ZONE_STATUS_CLS[z.status] || 'badge-neutral'}`}>{z.status || 'unknown'}</span>
                      {z.paused && <span className="badge badge-medium">paused</span>}
                    </div>
                  </td>
                  <td><span className="badge badge-neutral">{z.type || 'full'}</span></td>
                  <td>{z.account_name || '-'}</td>
                  <td className="cell-num">{formatNumber(z.dns_records_count || 0)}</td>
                  <td className="cell-num">{formatNumber(z.proxied_records_count || 0)}</td>
                  <td className="cell-time" title={formatDate(z.last_synced)}>{getTimeAgo(z.last_synced)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-state">
          <Globe className="empty-icon" />
          <div className="empty-title">No zones found</div>
          <div className="empty-text">
            {hasFilters
              ? 'No zones match the current filters.'
              : 'Add a Cloudflare API token in Settings and run a sync to import your zones.'}
          </div>
          {!hasFilters && <Link to="/settings" className="btn btn-secondary"><Settings /> Go to settings</Link>}
        </div>
      )}
    </div>
  );
};

export default Zones;
