import React, { useState, useEffect } from 'react';
import { List, Cloud, CloudOff, ChevronUp, ChevronDown, ChevronsUpDown, ChevronLeft, ChevronRight } from 'lucide-react';
import api from '../utils/api';
import { formatNumber, truncate } from '../utils/helpers';

const PAGE_SIZE = 50;

const DNSRecords = () => {
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [zones, setZones] = useState([]);
  const [types, setTypes] = useState({});
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ zone: '', type: '', proxied: '', search: '' });
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState({ key: 'name', direction: 'asc' });

  // Static filter sources load once
  useEffect(() => {
    Promise.all([api.get('/zones'), api.get('/dns-records/types')])
      .then(([z, t]) => { setZones(z); setTypes(t); })
      .catch(console.error);
  }, []);

  // Debounce free-text search so we don't hit the API per keystroke
  useEffect(() => {
    const handle = setTimeout(() => setDebouncedSearch(filters.search), 400);
    return () => clearTimeout(handle);
  }, [filters.search]);

  // Any filter/sort change restarts from page 1
  useEffect(() => { setPage(1); }, [filters.zone, filters.type, filters.proxied, debouncedSearch, sort]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    const params = new URLSearchParams({
      page: page.toString(),
      page_size: PAGE_SIZE.toString(),
      sort_by: sort.key,
      sort_order: sort.direction
    });
    if (filters.zone) params.append('zone_id', filters.zone);
    if (filters.type) params.append('record_type', filters.type);
    if (filters.proxied) params.append('proxied', filters.proxied);
    if (debouncedSearch) params.append('q', debouncedSearch);
    api.get(`/dns-records?${params}`)
      .then(res => {
        // Ignore responses that arrive after the query changed (stale page/filter)
        if (cancelled) return;
        setRows(res.data || []);
        setTotal(res.total || 0);
      })
      .catch(err => { if (!cancelled) console.error(err); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [filters.zone, filters.type, filters.proxied, debouncedSearch, page, sort]);

  const requestSort = (key) => {
    setSort(prev => ({ key, direction: prev.key === key && prev.direction === 'asc' ? 'desc' : 'asc' }));
  };

  // Sorting is server-side here, so this mirrors useSortedData's indicator.
  const getSortIndicator = (key) => {
    const style = { width: 11, height: 11, marginLeft: 4, verticalAlign: 'middle' };
    if (sort.key !== key) return <ChevronsUpDown style={{ ...style, opacity: 0.4 }} />;
    const Icon = sort.direction === 'asc' ? ChevronUp : ChevronDown;
    return <Icon style={style} />;
  };

  const totalPages = Math.max(Math.ceil(total / PAGE_SIZE), 1);
  const hasFilters = !!(filters.search || filters.zone || filters.type || filters.proxied);
  const rangeStart = (page - 1) * PAGE_SIZE + 1;
  const rangeEnd = Math.min(page * PAGE_SIZE, total);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><List className="page-title-icon" /> DNS records</h1>
          <div className="page-subtitle">{formatNumber(total)} {hasFilters ? 'records match the current filters' : 'records'}</div>
        </div>
      </div>

      <div className="filters-bar">
        <div className="filter-group">
          <label className="filter-label">Search</label>
          <input className="filter-input" placeholder="Name or content" value={filters.search} onChange={e => setFilters({ ...filters, search: e.target.value })} />
        </div>
        <div className="filter-group">
          <label className="filter-label">Zone</label>
          <select className="filter-input" value={filters.zone} onChange={e => setFilters({ ...filters, zone: e.target.value })}>
            <option value="">All zones</option>
            {zones.map(z => <option key={z.zone_id} value={z.zone_id}>{z.name}</option>)}
          </select>
        </div>
        <div className="filter-group">
          <label className="filter-label">Type</label>
          <select className="filter-input" value={filters.type} onChange={e => setFilters({ ...filters, type: e.target.value })}>
            <option value="">All types</option>
            {Object.entries(types).map(([t, c]) => <option key={t} value={t}>{t} ({formatNumber(c)})</option>)}
          </select>
        </div>
        <div className="filter-group">
          <label className="filter-label">Proxied</label>
          <select className="filter-input" value={filters.proxied} onChange={e => setFilters({ ...filters, proxied: e.target.value })}>
            <option value="">All</option>
            <option value="true">Proxied</option>
            <option value="false">DNS only</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="loading-inline"><div className="spinner spinner-large" /></div>
      ) : rows.length > 0 ? (
        <>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th className="sortable" onClick={() => requestSort('type')}>Type{getSortIndicator('type')}</th>
                  <th className="sortable" onClick={() => requestSort('name')}>Name{getSortIndicator('name')}</th>
                  <th className="sortable" onClick={() => requestSort('content')}>Content{getSortIndicator('content')}</th>
                  <th className="sortable" onClick={() => requestSort('zone_name')}>Zone{getSortIndicator('zone_name')}</th>
                  <th className="sortable" onClick={() => requestSort('proxied')}>Proxied{getSortIndicator('proxied')}</th>
                  <th className="sortable num" onClick={() => requestSort('ttl')}>TTL{getSortIndicator('ttl')}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(r => (
                  <tr key={r.record_id}>
                    <td><span className="badge badge-neutral dns-record-type">{r.type}</span></td>
                    <td className="cell-host">{r.name}</td>
                    <td className="content-cell"><span className="cell-mono" title={r.content}>{truncate(r.content, 35)}</span></td>
                    <td><span className="badge badge-neutral">{r.zone_name || r.zone_id}</span></td>
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
          <div className="row-between">
            <span className="text-tertiary text-12">
              Showing <span className="mono">{formatNumber(rangeStart)}–{formatNumber(rangeEnd)}</span> of <span className="mono">{formatNumber(total)}</span>
            </span>
            <div className="row">
              <button className="btn btn-small btn-secondary" disabled={page <= 1} onClick={() => setPage(p => p - 1)}><ChevronLeft /> Previous</button>
              <span className="text-secondary text-12">Page {formatNumber(page)} of {formatNumber(totalPages)}</span>
              <button className="btn btn-small btn-secondary" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next <ChevronRight /></button>
            </div>
          </div>
        </>
      ) : (
        <div className="empty-state">
          <List className="empty-icon" />
          <div className="empty-title">No records found</div>
          <div className="empty-text">{hasFilters ? 'No records match the current filters.' : 'Sync your Cloudflare data to see DNS records.'}</div>
        </div>
      )}
    </div>
  );
};

export default DNSRecords;
