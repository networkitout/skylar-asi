import React, { useState, useEffect } from 'react';
import { Users, UserPlus, Pencil, KeyRound, Trash2 } from 'lucide-react';
import api from '../utils/api';
import Modal, { ConfirmModal, NoticeModal } from '../components/Modal';
import { formatDate } from '../utils/helpers';
import useSortedData from '../utils/useSortedData';

const PASSWORD_HELP = 'At least 12 characters with uppercase, lowercase, digit, and special character.';

const UserManagement = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [showResetModal, setShowResetModal] = useState(false);
  const [editUser, setEditUser] = useState(null);
  const [resetUser, setResetUser] = useState(null);
  const [form, setForm] = useState({ email: '', username: '', password: '', full_name: '', is_admin: false });
  const [resetForm, setResetForm] = useState({ new_password: '', confirm_password: '' });
  const [error, setError] = useState('');
  const [resetError, setResetError] = useState('');
  const [resetSuccess, setResetSuccess] = useState('');
  const [confirm, setConfirm] = useState(null);
  const [notice, setNotice] = useState(null);

  useEffect(() => { fetchUsers(); }, []);

  const fetchUsers = async () => { try { setUsers(await api.get('/users')); } finally { setLoading(false); } };

  const { items: sortedUsers, requestSort, getSortIndicator } = useSortedData(users, { key: 'username', direction: 'asc' });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      if (editUser) {
        await api.put(`/users/${editUser.id}`, { email: form.email, full_name: form.full_name, is_active: form.is_active, is_admin: form.is_admin });
      } else {
        await api.post('/users', form);
      }
      setShowModal(false);
      setEditUser(null);
      setForm({ email: '', username: '', password: '', full_name: '', is_admin: false });
      fetchUsers();
    } catch (err) { setError(err.message); }
  };

  const handleEdit = (user) => { setEditUser(user); setForm({ email: user.email, username: user.username, password: '', full_name: user.full_name || '', is_admin: user.is_admin, is_active: user.is_active }); setShowModal(true); };

  const handleDelete = (user) => {
    setConfirm({
      title: 'Delete user',
      message: `Delete ${user.username}?`,
      detail: 'This action cannot be undone.',
      confirmLabel: 'Delete',
      destructive: true,
      onConfirm: async () => {
        try {
          await api.delete(`/users/${user.id}`);
          fetchUsers();
        } catch (err) {
          setNotice({ title: 'Delete failed', message: `Failed to delete user: ${err.message}` });
        }
      }
    });
  };

  const handleResetPassword = (user) => {
    setResetUser(user);
    setResetForm({ new_password: '', confirm_password: '' });
    setResetError('');
    setResetSuccess('');
    setShowResetModal(true);
  };

  const handleResetSubmit = async (e) => {
    e.preventDefault();
    setResetError('');
    setResetSuccess('');

    if (resetForm.new_password !== resetForm.confirm_password) {
      setResetError('Passwords do not match');
      return;
    }

    try {
      await api.post(`/users/${resetUser.id}/reset-password`, { new_password: resetForm.new_password });
      setResetSuccess(`Password for ${resetUser.username} has been reset successfully.`);
      setResetForm({ new_password: '', confirm_password: '' });
    } catch (err) {
      setResetError(err.message);
    }
  };

  const openCreate = () => { setEditUser(null); setForm({ email: '', username: '', password: '', full_name: '', is_admin: false }); setShowModal(true); };

  if (loading) return <div className="loading-inline"><div className="spinner spinner-large" /></div>;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><Users className="page-title-icon" /> Users</h1>
          <div className="page-subtitle">Accounts that can sign in to SKYLAR and what they are allowed to do.</div>
        </div>
        <div className="page-actions">
          <button className="btn btn-primary" onClick={openCreate}><UserPlus /> Create user</button>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title"><Users className="card-title-icon" />Accounts<span className="card-subtitle">{users.length} total</span></h2>
        </div>
        {users.length === 0 ? (
          <div className="text-tertiary text-12">No user accounts.</div>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th className="sortable" onClick={() => requestSort('username')}>Username{getSortIndicator('username')}</th>
                  <th className="sortable" onClick={() => requestSort('email')}>Email{getSortIndicator('email')}</th>
                  <th className="sortable" onClick={() => requestSort('full_name')}>Name{getSortIndicator('full_name')}</th>
                  <th className="sortable" onClick={() => requestSort('is_admin')}>Role{getSortIndicator('is_admin')}</th>
                  <th className="sortable" onClick={() => requestSort('is_active')}>Status{getSortIndicator('is_active')}</th>
                  <th className="sortable" onClick={() => requestSort('last_login')}>Last login{getSortIndicator('last_login')}</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sortedUsers.map(u => (
                  <tr key={u.id}>
                    <td className="cell-mono">{u.username}</td>
                    <td className="cell-mono">{u.email}</td>
                    <td>{u.full_name || <span className="text-tertiary">-</span>}</td>
                    <td><span className={`badge ${u.is_admin ? 'badge-low' : 'badge-neutral'}`}>{u.is_admin ? 'Admin' : 'User'}</span></td>
                    <td><span className={`badge ${u.is_active ? 'badge-success' : 'badge-critical'}`}>{u.is_active ? 'Active' : 'Disabled'}</span></td>
                    <td className="cell-time">{u.last_login ? formatDate(u.last_login) : 'Never'}</td>
                    <td>
                      <div className="row">
                        <button className="btn btn-secondary btn-small" onClick={() => handleEdit(u)} title="Edit user"><Pencil /> Edit</button>
                        <button className="btn btn-secondary btn-small" onClick={() => handleResetPassword(u)} title="Reset password"><KeyRound /> Reset password</button>
                        <button className="btn btn-danger btn-small" onClick={() => handleDelete(u)} title="Delete user" aria-label={`Delete ${u.username}`}><Trash2 /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <Modal
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        title={editUser ? 'Edit user' : 'Create user'}
        footer={(
          <>
            <button className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
            <button className="btn btn-primary" onClick={handleSubmit}>{editUser ? 'Save changes' : 'Create user'}</button>
          </>
        )}
      >
        <form onSubmit={handleSubmit}>
          {error && <div className="error-message mb-3">{error}</div>}
          <div className="form-field">
            <label>Email</label>
            <input type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} autoComplete="off" required />
          </div>
          {!editUser && (
            <>
              <div className="form-field">
                <label>Username</label>
                <input type="text" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} autoComplete="off" required />
              </div>
              <div className="form-field">
                <label>Password</label>
                <input type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} autoComplete="new-password" required />
                <span className="form-help">{PASSWORD_HELP}</span>
              </div>
            </>
          )}
          <div className="form-field">
            <label>Full name (optional)</label>
            <input type="text" value={form.full_name} onChange={e => setForm({ ...form, full_name: e.target.value })} />
          </div>
          <div className="form-field">
            <label>Access</label>
            <label className="checkbox-field">
              <input type="checkbox" checked={form.is_admin} onChange={e => setForm({ ...form, is_admin: e.target.checked })} />
              Administrator
            </label>
            {editUser && (
              <label className="checkbox-field">
                <input type="checkbox" checked={!!form.is_active} onChange={e => setForm({ ...form, is_active: e.target.checked })} />
                Active
              </label>
            )}
            <span className="form-help">
              Administrators can manage users, API tokens, and settings.{editUser ? ' Disabled accounts cannot sign in.' : ''}
            </span>
          </div>
        </form>
      </Modal>

      <Modal
        isOpen={showResetModal}
        onClose={() => setShowResetModal(false)}
        title="Reset password"
        footer={(
          <>
            <button className="btn btn-secondary" onClick={() => setShowResetModal(false)}>Close</button>
            {!resetSuccess && <button className="btn btn-primary" onClick={handleResetSubmit}><KeyRound /> Reset password</button>}
          </>
        )}
      >
        <form onSubmit={handleResetSubmit}>
          {resetError && <div className="error-message mb-3">{resetError}</div>}
          {resetSuccess && <div className="callout callout-success mb-0">{resetSuccess}</div>}
          {!resetSuccess && (
            <>
              <p className="text-secondary text-12 mb-3">
                Set a new password for <span className="mono text-data">{resetUser?.username}</span>. They will need it on their next sign-in.
              </p>
              <div className="form-field">
                <label>New password</label>
                <input type="password" value={resetForm.new_password} onChange={e => setResetForm({ ...resetForm, new_password: e.target.value })} autoComplete="new-password" required />
                <span className="form-help">{PASSWORD_HELP}</span>
              </div>
              <div className="form-field">
                <label>Confirm password</label>
                <input type="password" value={resetForm.confirm_password} onChange={e => setResetForm({ ...resetForm, confirm_password: e.target.value })} autoComplete="new-password" required />
              </div>
            </>
          )}
        </form>
      </Modal>

      <ConfirmModal state={confirm} onClose={() => setConfirm(null)} />
      <NoticeModal state={notice} onClose={() => setNotice(null)} />
    </div>
  );
};

export default UserManagement;
