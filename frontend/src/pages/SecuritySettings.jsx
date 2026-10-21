import React, { useState, useEffect } from 'react';
import { Shield, ShieldOff, Globe, CheckCircle2, SlidersHorizontal } from 'lucide-react';
import api from '../utils/api';
import { formatNumber, getSecurityIcon } from '../utils/helpers';

// Readable form of a raw Cloudflare setting value; plain on/off is already
// conveyed by the enabled state so it is dropped.
const settingValueLabel = (value) => {
  if (value === null || value === undefined || typeof value === 'boolean') return '';
  if (typeof value === 'object') return Object.entries(value).filter(([, v]) => v === 'on').map(([k]) => k).join(', ');
  const text = String(value);
  return text === 'on' || text === 'off' ? '' : text;
};

const SecuritySettings = () => {
  const [summary, setSummary] = useState({});
  const [loading, setLoading] = useState(true);
  const [selectedZone, setSelectedZone] = useState('all');

  useEffect(() => { api.get('/security-settings/summary').then(setSummary).finally(() => setLoading(false)); }, []);

  if (loading) return <div className="loading-inline"><div className="spinner spinner-large" /></div>;

  const zones = Object.entries(summary);
  const totalEnabled = zones.reduce((acc, [, z]) => acc + z.enabled_features, 0);
  const totalFeatures = zones.reduce((acc, [, z]) => acc + z.total_features, 0);

  const displayZones = selectedZone === 'all' ? zones : zones.filter(([id]) => id === selectedZone);

  // Headline KPI per docs/UI_CONVENTIONS.md: zones whose WAF setting is off.
  // Zones with no settings synced are not counted either way.
  const wafDisabled = zones.filter(([, z]) => z.total_features > 0 && !z.settings?.waf?.enabled).length;
  const coverage = totalFeatures > 0 ? (totalEnabled / totalFeatures) * 100 : 0;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><Shield className="page-title-icon" /> Security settings</h1>
          <div className="page-subtitle">Zone-level protections as of the last sync.</div>
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card headline">
          <div className="stat-label"><ShieldOff /> WAF disabled</div>
          <div className="stat-value">{formatNumber(wafDisabled)}</div>
          <div className="stat-sub">zones with the WAF setting off</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><Globe /> Zones</div>
          <div className="stat-value">{formatNumber(zones.length)}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><CheckCircle2 /> Settings enabled</div>
          <div className="stat-value">{formatNumber(totalEnabled)}</div>
          <div className="stat-sub">of {formatNumber(totalFeatures)} tracked</div>
        </div>
        <div className="stat-card">
          <div className="stat-label"><SlidersHorizontal /> Coverage</div>
          <div className="stat-value">{coverage.toFixed(0)}%</div>
          <div className="stat-sub">
            <div className="ratio-bar">
              <div className="ratio-track"><div className="ratio-fill" style={{ width: `${coverage}%` }} /></div>
            </div>
          </div>
        </div>
      </div>

      <div className="filters-bar">
        <div className="filter-group">
          <label className="filter-label">Zone</label>
          <select className="filter-input" value={selectedZone} onChange={e => setSelectedZone(e.target.value)}>
            <option value="all">All zones</option>
            {zones.map(([id, z]) => <option key={id} value={id}>{z.zone_name}</option>)}
          </select>
        </div>
      </div>

      {displayZones.length > 0 ? displayZones.map(([zoneId, zoneData]) => {
        const waf = zoneData.settings?.waf;
        const settings = Object.entries(zoneData.settings || {});
        return (
          <div key={zoneId} className="card">
            <div className="card-header">
              <h2 className="card-title">
                <Globe className="card-title-icon" />
                <span className="mono">{zoneData.zone_name}</span>
                <span className="card-subtitle">{formatNumber(zoneData.enabled_features)} of {formatNumber(zoneData.total_features)} enabled</span>
              </h2>
              {waf && (
                <span className={`badge ${waf.enabled ? 'badge-success' : 'badge-medium'}`}>
                  {waf.enabled ? 'WAF enabled' : 'WAF disabled'}
                </span>
              )}
            </div>
            {settings.length > 0 ? (
              <div className="security-grid">
                {settings.map(([name, data]) => {
                  const Icon = getSecurityIcon(name);
                  const value = settingValueLabel(data.value);
                  return (
                    <div key={name} className={`security-item ${data.enabled ? 'enabled' : 'disabled'}`}>
                      <Icon className="security-icon" />
                      <div className="security-body">
                        <div className="security-name">{name.replace(/_/g, ' ')}</div>
                        <div className="security-status">{data.enabled ? 'on' : 'off'}{value ? ` · ${value}` : ''}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-tertiary text-12">No settings synced for this zone yet.</div>
            )}
          </div>
        );
      }) : (
        <div className="empty-state">
          <Shield className="empty-icon" />
          <div className="empty-title">No security settings</div>
          <div className="empty-text">Sync your Cloudflare data to see security settings.</div>
        </div>
      )}
    </div>
  );
};

export default SecuritySettings;
