import React, { useState, useEffect } from 'react';
import { FileDown, FileSpreadsheet, FileText, Download, Save, Trash2 } from 'lucide-react';
import api, { API_BASE } from '../utils/api';
import Modal, { ConfirmModal, NoticeModal } from '../components/Modal';
import { formatDate } from '../utils/helpers';

const REPORTS = [
  {
    id: 'full',
    name: 'Full report',
    description: 'Comprehensive export with all zones, DNS records, IP addresses, reachability status, and security settings combined.',
    icon: FileSpreadsheet,
    endpoint: '/export/full',
    formats: ['csv', 'xlsx'],
    primary: true
  },
  {
    id: 'zones',
    name: 'Zones',
    description: 'All Cloudflare zones with status, type, nameservers, account info, and timestamps.',
    icon: FileSpreadsheet,
    endpoint: '/export/zones',
    formats: ['csv', 'xlsx']
  },
  {
    id: 'dns',
    name: 'DNS records',
    description: 'All DNS records including A, AAAA, CNAME, MX, TXT, etc. with zone mapping and content.',
    icon: FileSpreadsheet,
    endpoint: '/export/dns-records',
    formats: ['csv', 'xlsx']
  },
  {
    id: 'reachability',
    name: 'Reachability',
    description: 'HTTP and HTTPS reachability status for all A/AAAA/CNAME records with response codes and times.',
    icon: FileSpreadsheet,
    endpoint: '/export/reachability',
    formats: ['csv', 'xlsx']
  },
  {
    id: 'security',
    name: 'Security settings',
    description: 'All security settings per zone including SSL, WAF, TLS versions, and protection features.',
    icon: FileSpreadsheet,
    endpoint: '/export/security',
    formats: ['csv', 'xlsx']
  },
  {
    id: 'traffic',
    name: 'Traffic metrics',
    description: 'Hourly traffic analytics including requests, bandwidth, cache stats, threats, and visitor data.',
    icon: FileSpreadsheet,
    endpoint: '/export/traffic',
    formats: ['csv', 'xlsx'],
    hasHours: true
  },
  {
    id: 'summary',
    name: 'Executive summary',
    description: 'One-page PDF overview: zone inventory, 24h traffic totals, security coverage, and reachability health.',
    icon: FileText,
    endpoint: '/export/summary',
    formats: ['pdf']
  }
];

const FORMAT_LABELS = { csv: 'CSV', xlsx: 'Excel', pdf: 'PDF' };
const HOURS_OPTIONS = [{ v: 24, label: 'Last 24 hours' }, { v: 72, label: 'Last 3 days' }, { v: 168, label: 'Last 7 days' }, { v: 720, label: 'Last 30 days' }];

const Reports = () => {
  const [downloading, setDownloading] = useState({});
  const [formats, setFormats] = useState(() => Object.fromEntries(REPORTS.map(r => [r.id, r.formats[0]])));
  const [trafficHours, setTrafficHours] = useState(24);
  const [presets, setPresets] = useState([]);
  const [presetModalReport, setPresetModalReport] = useState(null);
  const [presetName, setPresetName] = useState('');
  const [presetError, setPresetError] = useState('');
  const [confirm, setConfirm] = useState(null);
  const [notice, setNotice] = useState(null);

  const loadPresets = () => api.get('/report-presets').then(setPresets).catch(console.error);
  useEffect(() => { loadPresets(); }, []);

  const buildQuery = (report, format, params = {}) => {
    const query = new URLSearchParams();
    // The PDF summary endpoint has a fixed format; tabular exports take csv|xlsx
    if (report.id !== 'summary') query.set('format', format);
    if (report.hasHours) query.set('hours', String(params.hours ?? trafficHours));
    const qs = query.toString();
    return qs ? `?${qs}` : '';
  };

  const downloadReport = async (report, format, params = {}) => {
    setDownloading(prev => ({ ...prev, [report.id]: true }));
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE}${report.endpoint}${buildQuery(report, format, params)}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!response.ok) throw new Error('Download failed');

      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = `${report.id}_report.${format}`;
      if (contentDisposition) {
        const match = contentDisposition.match(/filename="?([^";]+)"?/);
        if (match) filename = match[1];
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error('Download error:', err);
      setNotice({ title: 'Download failed', message: 'The report could not be downloaded. Please try again.' });
    } finally {
      setDownloading(prev => ({ ...prev, [report.id]: false }));
    }
  };

  const savePreset = async () => {
    setPresetError('');
    if (!presetName.trim()) { setPresetError('Name is required'); return; }
    const report = presetModalReport;
    try {
      await api.post('/report-presets', {
        name: presetName.trim(),
        report_id: report.id,
        format: formats[report.id],
        params: report.hasHours ? { hours: trafficHours } : null
      });
      setPresetModalReport(null);
      setPresetName('');
      loadPresets();
    } catch (err) {
      setPresetError(err.message || 'Failed to save preset');
    }
  };

  const downloadPreset = (preset) => {
    const report = REPORTS.find(r => r.id === preset.report_id);
    if (!report) return;
    downloadReport(report, preset.format, preset.params || {});
  };

  const deletePreset = (preset) => {
    setConfirm({
      title: 'Delete preset',
      message: `Delete "${preset.name}"?`,
      confirmLabel: 'Delete',
      destructive: true,
      onConfirm: async () => {
        try {
          await api.delete(`/report-presets/${preset.id}`);
          loadPresets();
        } catch (err) {
          console.error(err);
          setNotice({ title: 'Delete failed', message: err.message || 'The preset could not be deleted.' });
        }
      }
    });
  };

  const describePreset = (preset) => {
    const report = REPORTS.find(r => r.id === preset.report_id);
    const bits = [report?.name || preset.report_id, FORMAT_LABELS[preset.format] || preset.format];
    if (preset.params?.hours) bits.push(`${preset.params.hours}h window`);
    return bits.join(' · ');
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><FileDown className="page-title-icon" /> Reports</h1>
          <div className="page-subtitle">Export Cloudflare data as CSV or Excel, or download the PDF summary. Save frequent exports as presets for one-click downloads.</div>
        </div>
      </div>

      {presets.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title"><Save className="card-title-icon" />Saved presets<span className="card-subtitle">{presets.length} saved</span></h2>
          </div>
          <div className="table-container">
            <table className="data-table">
              <thead><tr><th>Name</th><th>Report</th><th>Created</th><th>Actions</th></tr></thead>
              <tbody>
                {presets.map(p => (
                  <tr key={p.id}>
                    <td className="cell-host">{p.name}</td>
                    <td>{describePreset(p)}</td>
                    <td className="cell-time">{formatDate(p.created_at)}</td>
                    <td>
                      <div className="row">
                        <button className="btn btn-secondary btn-small" onClick={() => downloadPreset(p)} disabled={!!downloading[p.report_id]}>
                          <Download /> Download
                        </button>
                        <button className="btn btn-danger btn-small" onClick={() => deletePreset(p)} title="Delete preset" aria-label={`Delete preset ${p.name}`}>
                          <Trash2 />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="content-grid mb-5" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))' }}>
        {REPORTS.map(report => {
          const Icon = report.icon;
          const busy = !!downloading[report.id];
          return (
            <div key={report.id} className="card mb-0" style={{ display: 'flex', flexDirection: 'column' }}>
              <div className="card-header">
                <h2 className="card-title"><Icon className="card-title-icon" />{report.name}</h2>
              </div>
              <p className="text-secondary text-12">{report.description}</p>
              {(report.formats.length > 1 || report.hasHours) && (
                <div className="row mt-3" style={{ flexWrap: 'wrap' }}>
                  {report.formats.length > 1 && (
                    <select
                      className="filter-input"
                      aria-label="Format"
                      value={formats[report.id]}
                      onChange={e => setFormats(prev => ({ ...prev, [report.id]: e.target.value }))}
                    >
                      {report.formats.map(f => <option key={f} value={f}>{FORMAT_LABELS[f]}</option>)}
                    </select>
                  )}
                  {report.hasHours && (
                    <select
                      className="filter-input"
                      aria-label="Time window"
                      value={trafficHours}
                      onChange={e => setTrafficHours(Number(e.target.value))}
                    >
                      {HOURS_OPTIONS.map(o => <option key={o.v} value={o.v}>{o.label}</option>)}
                    </select>
                  )}
                </div>
              )}
              <div className="row" style={{ marginTop: 'auto', paddingTop: 'var(--space-4)' }}>
                <button
                  className={`btn ${report.primary ? 'btn-primary' : 'btn-secondary'}`}
                  onClick={() => downloadReport(report, formats[report.id])}
                  disabled={busy}
                >
                  {busy
                    ? <><span className="spinner" /> Downloading...</>
                    : <><Download /> Download {FORMAT_LABELS[formats[report.id]]}</>}
                </button>
                <button
                  className="btn btn-secondary"
                  title="Save as preset"
                  onClick={() => { setPresetModalReport(report); setPresetName(''); setPresetError(''); }}
                >
                  <Save /> Save preset
                </button>
              </div>
            </div>
          );
        })}
      </div>

      <Modal
        isOpen={!!presetModalReport}
        onClose={() => setPresetModalReport(null)}
        title="Save preset"
        footer={(
          <>
            <button className="btn btn-secondary" onClick={() => setPresetModalReport(null)}>Cancel</button>
            <button className="btn btn-primary" onClick={savePreset}><Save /> Save preset</button>
          </>
        )}
      >
        {presetError && <div className="error-message mb-3">{presetError}</div>}
        <p className="text-secondary text-12 mb-3">
          Saves <span className="text-data">{presetModalReport?.name}</span> as {FORMAT_LABELS[formats[presetModalReport?.id] || 'csv']}
          {presetModalReport?.hasHours ? ` with a ${trafficHours}h window` : ''} for one-click downloads.
        </p>
        <div className="form-field">
          <label>Preset name</label>
          <input
            type="text"
            value={presetName}
            onChange={e => setPresetName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') savePreset(); }}
            autoFocus
          />
          <span className="form-help">For example "Weekly traffic for ops".</span>
        </div>
      </Modal>

      <ConfirmModal state={confirm} onClose={() => setConfirm(null)} />
      <NoticeModal state={notice} onClose={() => setNotice(null)} />
    </div>
  );
};

export default Reports;
