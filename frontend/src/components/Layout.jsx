import React, { useState, useEffect, useRef, useCallback } from 'react';
import { NavLink, Link, Outlet } from 'react-router-dom';
import {
  LayoutDashboard, Globe, List, Shield, Activity, Radio, ScanSearch, FileDown,
  Users, ScrollText, Settings, LogOut, X,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';
import { parseUTC } from '../utils/helpers';
import Wordmark from './Wordmark';

// Sidebar sections per docs/UI_CONVENTIONS.md
const SECTIONS = [
  { label: 'Overview', items: [{ path: '/', icon: LayoutDashboard, label: 'Dashboard', exact: true }] },
  { label: 'Inventory', items: [
    { path: '/zones', icon: Globe, label: 'Zones' },
    { path: '/dns-records', icon: List, label: 'DNS records' },
    { path: '/security', icon: Shield, label: 'Security' },
  ] },
  { label: 'Monitoring', items: [
    { path: '/traffic', icon: Activity, label: 'Traffic' },
    { path: '/reachability', icon: Radio, label: 'Reachability' },
    { path: '/exposure', icon: ScanSearch, label: 'Exposure' },
  ] },
  { label: 'Output', items: [{ path: '/reports', icon: FileDown, label: 'Reports' }] },
];

const ADMIN_SECTION = { label: 'Administration', items: [
  { path: '/users', icon: Users, label: 'Users' },
  { path: '/audit-log', icon: ScrollText, label: 'Audit log' },
  { path: '/settings', icon: Settings, label: 'Settings' },
] };

const timeOf = (iso) => (iso ? parseUTC(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : null);

// Top-bar job indicator (5.1): idle / running / success / failed.
const JobIndicator = ({ label, progress, to, counter }) => {
  if (!progress) return null;
  const state = progress.active ? 'running' : progress.result === 'failed' ? 'failed' : progress.result === 'success' ? 'success' : '';
  const text = progress.active ? `${label} running` : progress.result === 'failed' ? `${label} failed` : label;
  const meta = progress.active
    ? counter
    : progress.completed_at ? timeOf(progress.completed_at) : null;
  return (
    <Link to={to} className={`job-indicator ${state}`} title={progress.message || progress.error || text}>
      <span className="job-dot" />
      <span>{text}</span>
      {meta && <span className="job-meta">{meta}</span>}
    </Link>
  );
};

const usePolled = (path, eventName) => {
  const [value, setValue] = useState(null);
  const ref = useRef(null);
  const fetchIt = useCallback(async () => {
    try { setValue(await api.get(path)); } catch (err) { console.error(`Failed to fetch ${path}:`, err); }
  }, [path]);
  useEffect(() => {
    fetchIt();
    clearInterval(ref.current);
    ref.current = setInterval(fetchIt, value?.active ? 2000 : 10000);
    return () => clearInterval(ref.current);
  }, [value?.active, fetchIt]);
  useEffect(() => {
    if (!eventName) return undefined;
    window.addEventListener(eventName, fetchIt);
    return () => window.removeEventListener(eventName, fetchIt);
  }, [eventName, fetchIt]);
  return value;
};

const Layout = () => {
  const { user, logout } = useAuth();
  const [syncStatus, setSyncStatus] = useState(null);
  const [showSyncBanner, setShowSyncBanner] = useState(true);

  const syncProgress = usePolled('/sync/progress', 'sync-started');
  const reachabilityProgress = usePolled('/reachability/progress', 'reachability-started');
  const exposureProgress = usePolled('/exposure/runs/progress', 'exposure-started');

  const fetchSyncStatus = useCallback(async () => {
    try { setSyncStatus(await api.get('/sync/status')); } catch (err) { console.error('Failed to fetch sync status:', err); }
  }, []);

  useEffect(() => {
    fetchSyncStatus();
    const id = setInterval(fetchSyncStatus, 30000);
    return () => clearInterval(id);
  }, [fetchSyncStatus]);

  // When a sync finishes, refresh the banner and show it again
  const lastSyncActive = useRef(false);
  useEffect(() => {
    if (lastSyncActive.current && syncProgress && !syncProgress.active) {
      fetchSyncStatus();
      setShowSyncBanner(true);
    }
    lastSyncActive.current = !!syncProgress?.active;
  }, [syncProgress, fetchSyncStatus]);

  const sections = user?.is_admin ? [...SECTIONS, ADMIN_SECTION] : SECTIONS;

  const exposureCounter = exposureProgress?.stage === 'verifying'
    ? `${exposureProgress.hosts_verified || 0}/${exposureProgress.hosts_total || 0} hosts`
    : `${exposureProgress?.zones_processed || 0}/${exposureProgress?.zones_total || 0} zones`;

  const bannerKind = syncStatus?.status === 'success' ? 'callout-success' : syncStatus?.status === 'failed' ? 'callout-critical' : '';

  return (
    <div className="app-layout">
      <header className="topbar">
        <Wordmark size={18} />
        <div className="topbar-status">
          <JobIndicator label="Sync" progress={syncProgress} to="/settings"
            counter={`${syncProgress?.zones_processed || 0}/${syncProgress?.zones_total || 0} zones`} />
          <JobIndicator label="Reachability" progress={reachabilityProgress} to="/reachability"
            counter={`${reachabilityProgress?.records_checked || 0}/${reachabilityProgress?.records_total || 0} records`} />
          <JobIndicator label="Exposure" progress={exposureProgress} to="/exposure" counter={exposureCounter} />
          <div className="topbar-user">
            <span>{user?.username}</span>
            {user?.is_admin && <span className="badge badge-low">admin</span>}
            <button onClick={logout} className="btn-icon" title="Sign out" aria-label="Sign out"><LogOut /></button>
          </div>
        </div>
      </header>

      <aside className="sidebar">
        {sections.map(section => (
          <div key={section.label} className="sidebar-section">
            <div className="sidebar-section-label">{section.label}</div>
            {section.items.map(item => {
              const Icon = item.icon;
              return (
                <NavLink key={item.path} to={item.path} end={item.exact}
                  className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
                  <Icon className="nav-item-icon" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </div>
        ))}
      </aside>

      <main className="main-content">
        {showSyncBanner && syncStatus && (
          <div className={`callout callout-row ${bannerKind}`}>
            <div>
              {syncStatus.status === 'never' ? (
                <span>No data synced yet. <Link to="/settings">Go to Settings</Link> to add a Cloudflare API token and sync.</span>
              ) : (
                <>
                  <span>Last sync <strong className="mono">{parseUTC(syncStatus.last_sync).toLocaleString(undefined, { timeZoneName: 'short' })}</strong></span>
                  {' '}
                  {syncStatus.status === 'success'
                    ? <span className="text-success">succeeded</span>
                    : <span className="text-critical">failed</span>}
                  {syncStatus.status === 'failed' && syncStatus.details?.error && (
                    <div className="mt-1 mono text-11">{syncStatus.details.error}</div>
                  )}
                </>
              )}
            </div>
            <button className="btn-icon" onClick={() => setShowSyncBanner(false)} aria-label="Dismiss"><X /></button>
          </div>
        )}
        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
