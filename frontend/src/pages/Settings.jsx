import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, KeyRound, Plus, RefreshCw, Trash2, Clock, Lock, FileText, Info, X } from 'lucide-react';
import api from '../utils/api';
import Modal, { ConfirmModal, NoticeModal } from '../components/Modal';
import Wordmark, { TAGLINE_LONG } from '../components/Wordmark';
import { formatDate } from '../utils/helpers';
import { useAuth } from '../context/AuthContext';

const TOKEN_PERMISSIONS = ['Zone · Zone · Read', 'Zone · DNS · Read', 'Zone · Zone Settings · Read', 'Zone · Analytics · Read'];

const Settings = () => {
  const { logout } = useAuth();
  const [configs, setConfigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState({ name: '', api_token: '', account_id: '' });
  const [error, setError] = useState('');
  const [syncing, setSyncing] = useState(null);
  const [syncError, setSyncError] = useState(null);
  const [pwForm, setPwForm] = useState({ old_password: '', new_password: '', confirm: '' });
  const [pwError, setPwError] = useState('');
  const [pwMessage, setPwMessage] = useState('');
  const [pwSubmitting, setPwSubmitting] = useState(false);
  const [scheduler, setScheduler] = useState(null);
  const [confirm, setConfirm] = useState(null);
  const [notice, setNotice] = useState(null);

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPwError('');
    setPwMessage('');
    if (pwForm.new_password !== pwForm.confirm) {
      setPwError('New passwords do not match');
      return;
    }
    setPwSubmitting(true);
    try {
      await api.post('/auth/change-password', {
        old_password: pwForm.old_password,
        new_password: pwForm.new_password
      });
      setPwMessage('Password changed. Logging out so you can sign in with the new password...');
      setPwForm({ old_password: '', new_password: '', confirm: '' });
      // The old JWT stays valid until expiry, so end the session explicitly
      setTimeout(logout, 2000);
    } catch (err) {
      setPwError(err.message || 'Failed to change password');
    } finally {
      setPwSubmitting(false);
    }
  };

  useEffect(() => {
    fetchConfigs();
    api.get('/sync/status').then(s => setScheduler(s.scheduler || null)).catch(console.error);
  }, []);

  const fetchConfigs = async () => { try { setConfigs(await api.get('/configs')); } finally { setLoading(false); } };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await api.post('/configs', form);
      setShowModal(false);
      setForm({ name: '', api_token: '', account_id: '' });
      fetchConfigs();
    } catch (err) { setError(err.message); }
  };

  const handleSync = async (id) => {
    setSyncing(id);
    setSyncError(null);
    try {
      await api.post(`/configs/${id}/sync`);
      // Notify Layout to immediately start polling sync progress
      window.dispatchEvent(new CustomEvent('sync-started'));
    }
    catch (e) {
      setSyncError(e.message || 'Sync failed. Check the banner for details.');
      console.error(e);
    }
    finally { setSyncing(null); }
  };

  const handleDelete = (config) => {
    setConfirm({
      title: 'Delete token',
      message: `Delete "${config.name}"?`,
      detail: 'Zones already synced from it are kept but will no longer be refreshed.',
      confirmLabel: 'Delete',
      destructive: true,
      onConfirm: async () => {
        try {
          await api.delete(`/configs/${config.id}`);
          fetchConfigs();
        } catch (err) {
          setNotice({ title: 'Delete failed', message: err.message || 'The token could not be deleted.' });
        }
      }
    });
  };

  const openAdd = () => { setError(''); setShowModal(true); };

  if (loading) return <div className="loading-inline"><div className="spinner spinner-large" /></div>;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><SettingsIcon className="page-title-icon" /> Settings</h1>
          <div className="page-subtitle">Cloudflare API tokens, scheduled jobs, and your account.</div>
        </div>
      </div>

      {syncError && (
        <div className="callout callout-critical callout-row">
          <span>{syncError}</span>
          <button className="btn-icon" onClick={() => setSyncError(null)} aria-label="Dismiss"><X /></button>
        </div>
      )}

      {configs.length > 0 ? (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title"><KeyRound className="card-title-icon" />Cloudflare API tokens<span className="card-subtitle">{configs.length} configured</span></h2>
            <button className="btn btn-primary" onClick={openAdd}><Plus /> Add token</button>
          </div>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr><th>Name</th><th>Account ID</th><th>Status</th><th>Created</th><th>Actions</th></tr>
              </thead>
              <tbody>
                {configs.map(c => (
                  <tr key={c.id}>
                    <td className="cell-host">{c.name}</td>
                    <td className="cell-mono">{c.account_id || <span className="text-tertiary">auto-detect</span>}</td>
                    <td><span className={`badge ${c.is_active ? 'badge-success' : 'badge-critical'}`}>{c.is_active ? 'Active' : 'Inactive'}</span></td>
                    <td className="cell-time">{formatDate(c.created_at)}</td>
                    <td>
                      <div className="row">
                        <button className="btn btn-secondary btn-small" onClick={() => handleSync(c.id)} disabled={syncing === c.id}>
                          {syncing === c.id ? <><span className="spinner" /> Syncing...</> : <><RefreshCw /> Sync</>}
                        </button>
                        <button className="btn btn-danger btn-small" onClick={() => handleDelete(c)} title="Delete token" aria-label={`Delete token ${c.name}`}>
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
      ) : (
        <div className="empty-state">
          <KeyRound className="empty-icon" />
          <div className="empty-title">No API tokens</div>
          <div className="empty-text">Add a Cloudflare API token to start syncing data.</div>
          <button className="btn btn-primary" onClick={openAdd}><Plus /> Add token</button>
        </div>
      )}

      <div className="card">
        <div className="card-header"><h2 className="card-title"><Clock className="card-title-icon" />Automatic sync</h2></div>
        {scheduler ? (
          <dl className="kv">
            <dt>Data sync</dt>
            <dd>
              {scheduler.sync_interval_minutes > 0 ? (
                <>
                  Every {scheduler.sync_interval_minutes} min
                  {scheduler.next_sync_at && <span className="text-tertiary"> · next <span className="mono">{formatDate(scheduler.next_sync_at)}</span></span>}
                </>
              ) : (
                <span className="row"><span className="badge badge-medium">Disabled</span><span className="text-tertiary">set <span className="mono">SYNC_INTERVAL_MINUTES</span></span></span>
              )}
            </dd>
            <dt>Reachability checks</dt>
            <dd>
              {scheduler.reachability_interval_minutes > 0 ? (
                <>
                  Every {scheduler.reachability_interval_minutes} min
                  {scheduler.next_reachability_at && <span className="text-tertiary"> · next <span className="mono">{formatDate(scheduler.next_reachability_at)}</span></span>}
                </>
              ) : (
                <span className="row"><span className="badge badge-medium">Disabled</span><span className="text-tertiary">set <span className="mono">REACHABILITY_INTERVAL_MINUTES</span></span></span>
              )}
            </dd>
          </dl>
        ) : (
          <div className="text-tertiary text-12">Scheduler status unavailable.</div>
        )}
      </div>

      <div className="card">
        <div className="card-header"><h2 className="card-title"><Lock className="card-title-icon" />Change password</h2></div>
        <form onSubmit={handleChangePassword} className="max-w-sm">
          {pwError && <div className="error-message mb-3">{pwError}</div>}
          {pwMessage && <div className="callout callout-success">{pwMessage}</div>}
          <div className="form-field">
            <label>Current password</label>
            <input type="password" value={pwForm.old_password} onChange={e => setPwForm({ ...pwForm, old_password: e.target.value })} autoComplete="current-password" required />
          </div>
          <div className="form-field">
            <label>New password</label>
            <input type="password" value={pwForm.new_password} onChange={e => setPwForm({ ...pwForm, new_password: e.target.value })} autoComplete="new-password" required />
            <span className="form-help">At least 12 characters with uppercase, lowercase, digit, and special character.</span>
          </div>
          <div className="form-field">
            <label>Confirm new password</label>
            <input type="password" value={pwForm.confirm} onChange={e => setPwForm({ ...pwForm, confirm: e.target.value })} autoComplete="new-password" required />
          </div>
          <button type="submit" className="btn btn-secondary mt-4" disabled={pwSubmitting}>
            {pwSubmitting ? <><span className="spinner" /> Saving...</> : <><Lock /> Change password</>}
          </button>
        </form>
      </div>

      <div className="card">
        <div className="card-header"><h2 className="card-title"><FileText className="card-title-icon" />Getting started</h2></div>
        <ol className="text-12 text-secondary" style={{ marginLeft: 'var(--space-5)' }}>
          <li>In the Cloudflare dashboard, go to My Profile → API Tokens.</li>
          <li className="mt-1">
            Click Create Token (not the Global API Key further down that page) and grant these permissions:
            <ul className="mt-1 mb-1" style={{ marginLeft: 'var(--space-5)' }}>
              {TOKEN_PERMISSIONS.map(p => <li key={p} className="mono text-11">{p}</li>)}
            </ul>
          </li>
          <li className="mt-1">Copy the token and add it here with Add token.</li>
          <li className="mt-1">Click Sync on the token row to pull your Cloudflare data.</li>
        </ol>
      </div>

      <div className="card">
        <div className="card-header"><h2 className="card-title"><Info className="card-title-icon" />About</h2></div>
        <div className="stack" style={{ alignItems: 'center', padding: 'var(--space-4) 0' }}>
          <Wordmark size={28} />
          <div className="text-tertiary text-12">v1.1.0 · {TAGLINE_LONG}</div>
          <div className="text-tertiary text-11">
            Free software under the GNU AGPL-3.0 ·{' '}
            <a href="https://github.com/networkitout/skylar-asi" target="_blank" rel="noreferrer">Source code</a>
          </div>
        </div>
      </div>

      <Modal
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        title="Add token"
        footer={(
          <>
            <button className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
            <button className="btn btn-primary" onClick={handleSubmit}><Plus /> Add token</button>
          </>
        )}
      >
        <form onSubmit={handleSubmit}>
          {error && <div className="error-message mb-3">{error}</div>}
          <div className="form-field">
            <label>Name</label>
            <input type="text" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
            <span className="form-help">A label to tell this token apart, for example the account it belongs to.</span>
          </div>
          <div className="form-field">
            <label>API token</label>
            <input type="password" value={form.api_token} onChange={e => setForm({ ...form, api_token: e.target.value })} autoComplete="off" required />
            <span className="form-help">A scoped API Token from My Profile → API Tokens → Create Token. The Global API Key is not supported.</span>
          </div>
          <div className="form-field">
            <label>Account ID (optional)</label>
            <input type="text" className="input-mono" value={form.account_id} onChange={e => setForm({ ...form, account_id: e.target.value })} />
            <span className="form-help">Leave empty to detect the account from the token.</span>
          </div>
        </form>
      </Modal>

      <ConfirmModal state={confirm} onClose={() => setConfirm(null)} />
      <NoticeModal state={notice} onClose={() => setNotice(null)} />
    </div>
  );
};

export default Settings;
