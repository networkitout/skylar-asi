import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  ScanSearch, Play, GitCompare, Download, ChevronRight, ChevronDown, Copy, Check,
  AlertTriangle, Shield, Server, Bandage,
} from 'lucide-react';
import api, { API_BASE } from '../utils/api';
import { formatDate, formatNumber } from '../utils/helpers';
import { useAuth } from '../context/AuthContext';
import Modal, { NoticeModal } from '../components/Modal';

// Verdict -> status tier per docs/UI_CONVENTIONS.md
const VERDICT_SECTIONS = [
  { key: 'likely_affected', label: 'Likely affected', cls: 'badge-critical', blurb: 'Matching paths answered by the origin from many distinct clients, or confirmed by a version header.' },
  { key: 'misrouted', label: 'Misrouted DNS', cls: 'badge-high', blurb: 'A record points into Cloudflare IP space or duplicates exist; origin status in the logs is untrusted for these hosts.' },
  { key: 'catch_all', label: 'Catch-all (excluded)', cls: 'badge-low', blurb: 'The origin answers 2xx for impossible paths, so matching hits prove nothing here.' },
  { key: 'other', label: 'Other hosts seen', cls: 'badge-neutral', blurb: 'Hosts with matching traffic that did not meet a detection threshold, plus informational signals.' },
];

const DECISIONS = ['', 'patch', 'restrict', 'offline', 'n/a'];

const verdictBadge = (verdict) => {
  const section = VERDICT_SECTIONS.find(s => s.key === verdict);
  if (!section) return <span className="badge badge-neutral">none</span>;
  return <span className={`badge ${section.cls}`}>{section.label}</span>;
};

const confidenceBadge = (c) => <span className="badge badge-neutral">{c}</span>;

const VERSION_CLS = { current: 'badge-success', behind: 'badge-high', eol: 'badge-critical', unknown: 'badge-neutral' };
const versionBadge = (status, version) => (
  <span className={`badge ${VERSION_CLS[status] || 'badge-neutral'}`} title={status}>{version || status || 'unknown'}</span>
);

const WAF_CLS = { enabled: 'badge-success', disabled: 'badge-medium', unknown: 'badge-neutral' };

const MITIGATION_KINDS = {
  cloudflare_waf: { icon: Shield, label: 'WAF rule' },
  origin: { icon: Server, label: 'Origin' },
  patch: { icon: Bandage, label: 'Patch' },
};

const CopyButton = ({ text, label }) => {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (err) {
      console.error(err);
    }
  };
  return (
    <button type="button" className={`btn-icon ${copied ? 'confirmed' : ''}`} onClick={copy} title={`Copy ${label || 'to clipboard'}`} aria-label="Copy">
      {copied ? <Check /> : <Copy />}
    </button>
  );
};

const CodeBlock = ({ text, label }) => (
  <div className="code-block">
    <pre>{text}</pre>
    <CopyButton text={text} label={label} />
  </div>
);

const MitigationsCard = ({ signature }) => {
  const [open, setOpen] = useState({});
  const mitigations = signature?.mitigations || [];
  if (mitigations.length === 0) return null;
  const toggle = (id) => setOpen(o => ({ ...o, [id]: !(o[id] ?? mitigations.find(m => m.id === id)?.kind === 'cloudflare_waf') }));
  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title"><Shield className="card-title-icon" />Mitigations<span className="card-subtitle">{signature.title}</span></h2>
      </div>
      <div className="callout">
        Shipped with the signature file; nothing is applied automatically - SKYLAR stays read-only against Cloudflare.
        Pick the WAF rule that matches the zone's plan; request-body fields are Enterprise-only.
      </div>
      {mitigations.map(m => {
        const kind = MITIGATION_KINDS[m.kind] || { icon: Shield, label: m.kind };
        const KindIcon = kind.icon;
        const isOpen = open[m.id] ?? m.kind === 'cloudflare_waf';
        return (
          <div key={m.id} className="collapsible">
            <div className="collapsible-head" onClick={() => toggle(m.id)}>
              {isOpen ? <ChevronDown className="chev" /> : <ChevronRight className="chev" />}
              <span className="badge badge-neutral"><KindIcon /> {kind.label}</span>
              <span className="collapsible-title">{m.title}</span>
              {m.action && <span className="badge badge-neutral">action: {m.action}</span>}
            </div>
            {isOpen && (
              <div className="collapsible-body">
                {m.summary && <div className="mb-3">{m.summary}</div>}
                {m.expressions.map((e, i) => (
                  <div key={i} className="mb-3">
                    <div className="row">
                      <span className="section-label mb-0">Expression</span>
                      {e.plan && <span className="badge badge-neutral">{e.plan}</span>}
                    </div>
                    {e.note && <div className="text-tertiary text-11">{e.note}</div>}
                    <CodeBlock text={e.expression} label="expression" />
                  </div>
                ))}
                {m.snippet && (
                  <div className="mb-3">
                    <div className="section-label">Config</div>
                    <CodeBlock text={m.snippet} label="snippet" />
                  </div>
                )}
                {m.steps.length > 0 && (
                  <div className="mb-3">
                    <div className="section-label">Steps</div>
                    <ol style={{ marginLeft: 'var(--space-5)' }}>
                      {m.steps.map((s, i) => <li key={i}>{s}</li>)}
                    </ol>
                  </div>
                )}
                {m.caveats && <div className="callout callout-caution mb-0">{m.caveats}</div>}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

const Exposure = () => {
  const { user } = useAuth();
  const [configs, setConfigs] = useState([]);
  const [signatures, setSignatures] = useState([]);
  const [runs, setRuns] = useState([]);
  const [selectedRunId, setSelectedRunId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [progress, setProgress] = useState(null);
  const [form, setForm] = useState({ config_id: '', signature_name: '', window_days: 7, verify: false });
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState('');
  const [expanded, setExpanded] = useState({});
  const [edits, setEdits] = useState({});
  const [saving, setSaving] = useState({});
  const [downloading, setDownloading] = useState(false);
  const [diff, setDiff] = useState(null);
  const [diffOpen, setDiffOpen] = useState(false);
  const [notice, setNotice] = useState(null);
  const pollRef = useRef(null);
  const wasActiveRef = useRef(false);

  const loadRuns = useCallback(async () => {
    const r = await api.get('/exposure/runs');
    setRuns(r);
    return r;
  }, []);

  const loadDetail = useCallback(async (runId) => {
    if (!runId) { setDetail(null); return; }
    setDetailLoading(true);
    try {
      const d = await api.get(`/exposure/runs/${runId}`);
      setDetail(d);
      setEdits({});
      setExpanded({});
    } catch (err) {
      console.error(err);
      setDetail(null);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const [c, s, r, p] = await Promise.all([
          api.get('/configs'), api.get('/exposure/signatures'), api.get('/exposure/runs'), api.get('/exposure/runs/progress'),
        ]);
        setConfigs(c);
        setSignatures(s);
        setRuns(r);
        setProgress(p);
        setForm(f => ({ ...f, config_id: c[0]?.id || '', signature_name: s[0]?.name || '' }));
        const latest = r.find(x => x.status === 'success') || r[0];
        if (latest) { setSelectedRunId(latest.id); }
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  useEffect(() => { loadDetail(selectedRunId); }, [selectedRunId, loadDetail]);

  // Poll progress - fast while a run is active, slow when idle
  useEffect(() => {
    const tick = async () => {
      try {
        const p = await api.get('/exposure/runs/progress');
        const justFinished = wasActiveRef.current && !p.active;
        wasActiveRef.current = !!p.active;
        setProgress(p);
        if (justFinished) {
          // A run just finished: refresh the run list and select it
          const r = await loadRuns();
          if (p.run_id) setSelectedRunId(p.run_id); else if (r[0]) setSelectedRunId(r[0].id);
        }
      } catch (err) { console.error(err); }
    };
    clearInterval(pollRef.current);
    pollRef.current = setInterval(tick, progress?.active ? 2000 : 10000);
    return () => clearInterval(pollRef.current);
  }, [progress?.active, loadRuns]);

  const startRun = async (e) => {
    e.preventDefault();
    setError('');
    setStarting(true);
    try {
      const run = await api.post('/exposure/runs', {
        config_id: Number(form.config_id), signature_name: form.signature_name,
        window_days: Number(form.window_days), verify: form.verify,
      });
      window.dispatchEvent(new CustomEvent('exposure-started'));
      wasActiveRef.current = true;
      setProgress(p => ({ ...(p || {}), active: true, run_id: run.id, stage: 'queued', message: 'Queued...' }));
      await loadRuns();
    } catch (err) {
      setError(err.message || 'Failed to start run');
    } finally {
      setStarting(false);
    }
  };

  const hostEdit = (host, field) => {
    const pending = edits[host]?.[field];
    if (pending !== undefined) return pending;
    const row = detail?.hosts.find(h => h.host === host);
    return row?.[field] ?? '';
  };

  const setHostEdit = (host, field, value) => {
    setEdits(prev => ({ ...prev, [host]: { ...(prev[host] || {}), [field]: value } }));
  };

  const saveHost = async (host, field) => {
    const pending = edits[host]?.[field];
    if (pending === undefined) return;
    const row = detail.hosts.find(h => h.host === host);
    if ((row?.[field] ?? '') === pending) return;
    setSaving(prev => ({ ...prev, [host]: true }));
    try {
      const updated = await api.patch(`/exposure/hosts/${detail.run.id}/${encodeURIComponent(host)}`, { [field]: pending || null });
      setDetail(d => ({ ...d, hosts: d.hosts.map(h => (h.host === host ? updated : h)) }));
      setEdits(prev => { const next = { ...prev }; if (next[host]) { delete next[host][field]; } return next; });
    } catch (err) {
      setNotice({ title: 'Save failed', message: `Could not save ${field} for ${host}: ${err.message}` });
    } finally {
      setSaving(prev => ({ ...prev, [host]: false }));
    }
  };

  const downloadWorkbook = async () => {
    if (!detail) return;
    setDownloading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}/exposure/runs/${detail.run.id}/export.xlsx`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error('Download failed');
      const cd = response.headers.get('Content-Disposition');
      const match = cd && cd.match(/filename="?([^";]+)"?/);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = match ? match[1] : `exposure_run${detail.run.id}.xlsx`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      setNotice({ title: 'Download failed', message: 'The workbook could not be downloaded. Check the backend log for details.' });
    } finally {
      setDownloading(false);
    }
  };

  const previousRun = detail
    ? runs.find(r => r.signature_name === detail.run.signature_name && r.status === 'success' && r.id < detail.run.id)
    : null;

  const openDiff = async () => {
    if (!detail || !previousRun) return;
    setDiffOpen(true);
    setDiff(null);
    try {
      setDiff(await api.get(`/exposure/runs/${detail.run.id}/diff/${previousRun.id}`));
    } catch (err) {
      setDiff({ error: err.message });
    }
  };

  const findingsFor = (host) => (detail?.findings || []).filter(f => f.host === host);
  const probesFor = (host) => (detail?.probes || []).filter(p => p.host === host);

  const grouped = VERDICT_SECTIONS.map(section => ({
    ...section,
    hosts: (detail?.hosts || []).filter(h => (section.key === 'other'
      ? !['likely_affected', 'misrouted', 'catch_all'].includes(h.verdict)
      : h.verdict === section.key)),
  }));

  const zoneFindings = (detail?.findings || []).filter(f => f.rule_id === 'EXP-006');
  const verdictCounts = detail?.run?.stats?.verdicts || {};

  if (loading) return <div className="loading-inline"><div className="spinner spinner-large" /></div>;

  const activeSignature = detail?.signature || signatures.find(s => s.name === (detail?.run?.signature_name || form.signature_name));

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><ScanSearch className="page-title-icon" /> Exposure analysis</h1>
          <div className="page-subtitle">Which internet-facing sites run an affected technology, who hosts them, and who can patch them. Read-only against Cloudflare; counts are sampled estimates.</div>
        </div>
        {detail && (
          <div className="page-actions">
            <button className="btn btn-secondary" onClick={openDiff} disabled={!previousRun} title={previousRun ? `Compare with run #${previousRun.id}` : 'No earlier successful run for this signature'}>
              <GitCompare /> Diff vs previous
            </button>
            <button className="btn btn-secondary" onClick={downloadWorkbook} disabled={downloading}>
              <Download /> {downloading ? 'Building...' : 'Download workbook'}
            </button>
          </div>
        )}
      </div>

      {user?.is_admin && (
        <div className="card">
          <div className="card-header"><h2 className="card-title"><Play className="card-title-icon" />Start a run</h2></div>
          <form onSubmit={startRun}>
            <div className="form-row">
              <div className="form-field">
                <label>Cloudflare config</label>
                <select value={form.config_id} onChange={e => setForm({ ...form, config_id: e.target.value })} required>
                  {configs.length === 0 && <option value="">No configs - add one in Settings</option>}
                  {configs.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </div>
              <div className="form-field">
                <label>Signature</label>
                <select value={form.signature_name} onChange={e => setForm({ ...form, signature_name: e.target.value })} required>
                  {signatures.length === 0 && <option value="">No signature files found</option>}
                  {signatures.map(s => <option key={s.name} value={s.name}>{s.title}</option>)}
                </select>
              </div>
              <div className="form-field">
                <label>Window (days)</label>
                <input type="number" min="1" max="30" value={form.window_days} onChange={e => setForm({ ...form, window_days: e.target.value })} />
              </div>
              <div className="form-field">
                <label>Active verify</label>
                <label className="checkbox-field" style={{ height: '32px' }}>
                  <input type="checkbox" checked={form.verify} onChange={e => setForm({ ...form, verify: e.target.checked })} />
                  Send GET probes (opt-in)
                </label>
              </div>
            </div>
            {form.verify && (
              <div className="callout callout-caution">
                Active verify sends GET requests (no redirects, no payloads) to candidate hosts <strong>from this server's egress</strong>,
                resolving through a public resolver and refusing private addresses. Results record which resolver answered so a
                filtered vantage point is not mistaken for "clean". Only metadata is stored - never response bodies.
              </div>
            )}
            {error && <div className="error-message mb-3">{error}</div>}
            <button type="submit" className="btn btn-primary" disabled={starting || progress?.active || !form.config_id || !form.signature_name}>
              <Play /> {progress?.active ? 'Run in progress...' : starting ? 'Starting...' : 'Run analysis'}
            </button>
          </form>
        </div>
      )}

      {progress?.active && (
        <div className="card">
          <div className="row">
            <span className="spinner" />
            <div>
              <div className="text-data">Run #{progress.run_id} · {progress.stage}</div>
              <div className="text-tertiary text-12">{progress.message}</div>
              {progress.zones_total > 0 && <div className="mono text-11 text-secondary">Zones {progress.zones_processed} / {progress.zones_total}</div>}
              {progress.hosts_total > 0 && <div className="mono text-11 text-secondary">Hosts probed {progress.hosts_verified} / {progress.hosts_total}</div>}
            </div>
          </div>
        </div>
      )}

      <div className="filters-bar">
        <div className="filter-group">
          <label className="filter-label">Run</label>
          <select className="filter-input" value={selectedRunId || ''} onChange={e => setSelectedRunId(Number(e.target.value) || null)}>
            {runs.length === 0 && <option value="">No runs yet</option>}
            {runs.map(r => (
              <option key={r.id} value={r.id}>
                #{r.id} · {r.signature_name} · {r.status}{r.verify_enabled ? ' · verified' : ''} · {formatDate(r.started_at)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {detailLoading && <div className="loading-inline"><div className="spinner" /></div>}

      {!detailLoading && !detail && (
        <>
          <div className="empty-state">
            <ScanSearch className="empty-icon" />
            <div className="empty-title">No exposure runs</div>
            <p className="empty-text">Start a run against a signature to find which hosts actually run the affected technology.</p>
          </div>
          <MitigationsCard signature={activeSignature} />
        </>
      )}

      {!detailLoading && detail && (
        <>
          {detail.run.status === 'failed' && (
            <div className="callout callout-critical">Run failed: {detail.run.error}</div>
          )}

          <div className="stats-grid">
            <div className="stat-card headline"><div className="stat-label">Likely affected</div><div className="stat-value">{formatNumber(verdictCounts.likely_affected || 0)}</div></div>
            <div className="stat-card"><div className="stat-label">Misrouted DNS</div><div className="stat-value">{formatNumber(verdictCounts.misrouted || 0)}</div></div>
            <div className="stat-card"><div className="stat-label">Catch-all</div><div className="stat-value">{formatNumber(verdictCounts.catch_all || 0)}</div></div>
            <div className="stat-card"><div className="stat-label">Hosts seen</div><div className="stat-value">{formatNumber(detail.run.stats?.hosts || 0)}</div></div>
          </div>

          <div className="card">
            <div className="card-header">
              <h2 className="card-title">{detail.signature?.title || detail.run.signature_name}<span className="card-subtitle">run #{detail.run.id} · v{detail.run.signature_version}</span></h2>
            </div>
            <dl className="kv mb-3">
              <dt>Window</dt><dd className="mono">{formatDate(detail.run.window_start)} → {formatDate(detail.run.window_end)}</dd>
              <dt>Mode</dt><dd>{detail.run.verify_enabled ? 'passive + active verify' : 'passive only'}</dd>
              <dt>Queries</dt><dd className="mono">{detail.run.stats?.graphql_queries ?? '-'}</dd>
            </dl>
            {detail.signature?.description && <p className="text-secondary text-12 mb-3">{detail.signature.description}</p>}
            <div className="callout mb-0"><strong>Coverage:</strong> {detail.run.coverage_note || 'n/a'}</div>
            {Object.keys(detail.run.edge_coverage || {}).length > 0 && (
              <div className="mt-3">
                <div className="section-label">Managed WAF coverage</div>
                <div className="row" style={{ flexWrap: 'wrap' }}>
                  {Object.entries(detail.run.edge_coverage).map(([zone, state]) => (
                    <span key={zone} className={`badge ${WAF_CLS[state] || 'badge-neutral'}`}>{zone}: {state}</span>
                  ))}
                </div>
                {zoneFindings.length > 0 && <div className="text-tertiary text-11 mt-1">Zones marked disabled/unknown would not be covered by an emergency managed rule.</div>}
              </div>
            )}
          </div>

          <MitigationsCard signature={activeSignature} />

          {grouped.map(section => (
            <div key={section.key} className="card">
              <div className="card-header">
                <h2 className="card-title">
                  <span className={`badge ${section.cls}`}>{section.label}</span>
                  <span className="mono text-secondary">{section.hosts.length}</span>
                  <span className="card-subtitle">{section.blurb}</span>
                </h2>
              </div>
              {section.hosts.length === 0 ? (
                <div className="text-tertiary text-12">No hosts in this group.</div>
              ) : (
                <div className="table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th style={{ width: '32px' }}></th>
                        <th>Host</th>
                        <th>Zone</th>
                        <th>Rules</th>
                        <th>Version</th>
                        <th>Hosting</th>
                        <th>Owner</th>
                        <th>Contact</th>
                        <th>Decision</th>
                        <th>Notes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {section.hosts.map(h => {
                        const fs = findingsFor(h.host);
                        const ps = probesFor(h.host);
                        const isOpen = !!expanded[h.host];
                        return (
                          <React.Fragment key={h.host}>
                            <tr className={isOpen ? 'row-selected' : ''}>
                              <td>
                                <button className="btn-icon" onClick={() => setExpanded(e => ({ ...e, [h.host]: !isOpen }))} title="Evidence" aria-label="Toggle evidence">
                                  {isOpen ? <ChevronDown /> : <ChevronRight />}
                                </button>
                              </td>
                              <td>
                                <span className="cell-host">{h.host}</span>
                                {h.verify_error && (
                                  <div className="text-medium text-11 row" title={h.verify_error}>
                                    <AlertTriangle style={{ width: 11, height: 11 }} /> verify: {h.verify_error.slice(0, 40)}{h.verify_error.length > 40 ? '…' : ''}
                                  </div>
                                )}
                              </td>
                              <td>{h.zone_name ? <span className="badge badge-neutral">{h.zone_name}</span> : '-'}</td>
                              <td>
                                <div className="row" style={{ flexWrap: 'wrap', gap: '4px' }}>
                                  {fs.map(f => (
                                    <span key={f.id} className={`badge ${f.origin_status_trusted === false ? 'badge-medium' : 'badge-neutral'}`} title={f.detail}>{f.rule_id}</span>
                                  ))}
                                </div>
                              </td>
                              <td>{versionBadge(h.version_status, h.detected_version)}</td>
                              <td>{h.hosting_provider || (h.origin_ip ? <span className="cell-mono">{h.origin_ip}</span> : '-')}</td>
                              <td><input className="input input-inline" style={{ minWidth: '110px' }} value={hostEdit(h.host, 'owner')} onChange={e => setHostEdit(h.host, 'owner', e.target.value)} onBlur={() => saveHost(h.host, 'owner')} aria-label="Owner" /></td>
                              <td><input className="input input-inline" style={{ minWidth: '130px' }} value={hostEdit(h.host, 'contact')} onChange={e => setHostEdit(h.host, 'contact', e.target.value)} onBlur={() => saveHost(h.host, 'contact')} aria-label="Contact" /></td>
                              <td>
                                <select className="input input-inline" value={hostEdit(h.host, 'decision')} onChange={e => { setHostEdit(h.host, 'decision', e.target.value); setTimeout(() => saveHost(h.host, 'decision'), 0); }} onBlur={() => saveHost(h.host, 'decision')} aria-label="Decision">
                                  {DECISIONS.map(d => <option key={d} value={d}>{d || '—'}</option>)}
                                </select>
                              </td>
                              <td>
                                <div className="row">
                                  <input className="input input-inline" style={{ minWidth: '160px' }} value={hostEdit(h.host, 'notes')} onChange={e => setHostEdit(h.host, 'notes', e.target.value)} onBlur={() => saveHost(h.host, 'notes')} aria-label="Notes" />
                                  {saving[h.host] && <span className="spinner" />}
                                </div>
                              </td>
                            </tr>
                            {isOpen && (
                              <tr className="row-detail">
                                <td colSpan={10}>
                                  <div className="content-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
                                    <div>
                                      <div className="section-label">Findings</div>
                                      {fs.length === 0 && <div className="text-tertiary text-12">No rule fired; host seen with matching traffic only.</div>}
                                      {fs.map(f => (
                                        <div key={f.id} className="mb-3">
                                          <div className="row" style={{ flexWrap: 'wrap' }}>
                                            {verdictBadge(f.verdict)} <span className="badge badge-neutral">{f.rule_id}</span> {confidenceBadge(f.confidence)}
                                            {f.origin_status_trusted === false && <span className="badge badge-medium">origin status untrusted</span>}
                                          </div>
                                          <div className="mt-1 text-12">{f.detail}</div>
                                          <details className="mt-1 text-tertiary text-11">
                                            <summary style={{ cursor: 'pointer' }}>evidence</summary>
                                            <pre className="mono text-11" style={{ whiteSpace: 'pre-wrap', marginTop: '4px' }}>{JSON.stringify(f.evidence, null, 2)}</pre>
                                          </details>
                                        </div>
                                      ))}
                                    </div>
                                    <div>
                                      <div className="section-label">Passive stats · active probes</div>
                                      {h.summary && (
                                        <div className="text-12 mb-2 mono text-secondary">
                                          matching ≈ {formatNumber(h.summary.matching_requests)} · origin 2xx ≈ {formatNumber(h.summary.origin_2xx)} · distinct IPs {formatNumber(h.summary.distinct_ips_2xx)}
                                          {h.summary.cf_range_ips_2xx > 0 && <> (incl. {h.summary.cf_range_ips_2xx} in Cloudflare ranges)</>}
                                          {h.summary.post_requests > 0 && <> · POSTs ≈ {formatNumber(h.summary.post_requests)}</>}
                                        </div>
                                      )}
                                      {(h.resolver || h.resolved_ip) && <div className="text-12 mb-2">resolved via <span className="cell-mono">{h.resolver}</span> → <span className="cell-mono">{h.resolved_ip}</span></div>}
                                      {ps.length > 0 ? (
                                        <table className="data-table">
                                          <thead><tr><th>kind</th><th>path</th><th className="num">status</th><th className="num">size</th><th className="num">secrets</th><th className="num">debug</th><th>title</th></tr></thead>
                                          <tbody>
                                            {ps.map(p => (
                                              <tr key={p.id}>
                                                <td>{p.kind}</td>
                                                <td className="cell-mono">{p.path}</td>
                                                <td className="cell-num">{p.status || (p.error ? <span className="text-critical" title={p.error}>err</span> : '-')}</td>
                                                <td className="cell-num">{p.size ?? '-'}</td>
                                                <td className={`cell-num ${p.secret_match_count ? 'text-critical' : ''}`}>{p.secret_match_count ?? '-'}</td>
                                                <td className="cell-num">{p.debug_marker_count ?? '-'}</td>
                                                <td className="truncate" style={{ maxWidth: '200px' }}>{p.title || ''}</td>
                                              </tr>
                                            ))}
                                          </tbody>
                                        </table>
                                      ) : (
                                        <div className="text-tertiary text-12">{detail.run.verify_enabled ? 'Not probed (unresolved, blocked, or not a candidate).' : 'Active verify was off for this run.'}</div>
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
              )}
            </div>
          ))}
        </>
      )}

      <Modal isOpen={diffOpen} onClose={() => setDiffOpen(false)} title={`Run #${detail?.run?.id} vs #${previousRun?.id}`}>
        {!diff ? (
          <div className="loading-inline"><div className="spinner" /></div>
        ) : diff.error ? (
          <div className="error-message">{diff.error}</div>
        ) : (
          <div className="text-12">
            <DiffList title="New hosts" items={diff.new_hosts.map(x => `${x.host} (${x.verdict || 'none'})`)} />
            <DiffList title="Hosts no longer seen" items={diff.removed_hosts.map(x => `${x.host} (${x.verdict || 'none'})`)} />
            <DiffList title="Verdict changes" items={diff.verdict_changes.map(x => `${x.host}: ${x.from || 'none'} → ${x.to || 'none'}`)} />
            <DiffList title="Version changes" items={diff.version_changes.map(x => `${x.host}: ${x.from || '?'} (${x.from_status || '?'}) → ${x.to || '?'} (${x.to_status || '?'})`)} />
            <DiffList title="Misrouted records appeared" items={diff.misrouted_appeared} />
            <DiffList title="Misrouted records resolved" items={diff.misrouted_resolved} />
            <DiffList title="Decisions still open" items={diff.decisions_open.map(x => `${x.host} (${x.verdict})${x.owner ? ` · ${x.owner}` : ''}`)} />
          </div>
        )}
      </Modal>

      <NoticeModal state={notice} onClose={() => setNotice(null)} />
    </div>
  );
};

const DiffList = ({ title, items }) => (
  <div className="mb-3">
    <div className="section-label row">{title} <span className="badge badge-neutral">{items.length}</span></div>
    {items.length === 0 ? <div className="text-tertiary">none</div> : (
      <ul className="mono" style={{ margin: '4px 0 0 18px' }}>{items.map((it, i) => <li key={i}>{it}</li>)}</ul>
    )}
  </div>
);

export default Exposure;
