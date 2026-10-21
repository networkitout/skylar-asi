import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';
import Wordmark, { TAGLINE_LONG } from '../components/Wordmark';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  // null = still checking, true = show first-run setup, false = normal login
  const [needsSetup, setNeedsSetup] = useState(null);
  const [setupForm, setSetupForm] = useState({ email: '', username: '', full_name: '', password: '', confirm: '' });
  const { login, user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => { if (user) navigate('/'); }, [user, navigate]);

  useEffect(() => {
    api.get('/setup/status')
      .then(s => setNeedsSetup(!!s.needs_setup))
      .catch(() => setNeedsSetup(false));
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username, password);
      navigate('/');
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSetup = async (e) => {
    e.preventDefault();
    setError('');
    if (setupForm.password !== setupForm.confirm) {
      setError('Passwords do not match');
      return;
    }
    setLoading(true);
    try {
      await api.post('/setup/admin', {
        email: setupForm.email,
        username: setupForm.username,
        full_name: setupForm.full_name || null,
        password: setupForm.password
      });
      // Account created - sign in through the normal flow
      await login(setupForm.username, setupForm.password);
      navigate('/');
    } catch (err) {
      setError(err.message || 'Setup failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-container">
        <div className="login-header">
          <Wordmark size={28} />
          <p className="login-subtitle">{needsSetup ? 'First-run setup' : TAGLINE_LONG}</p>
        </div>

        {needsSetup === null ? (
          <div className="loading-inline"><div className="spinner" /></div>
        ) : needsSetup ? (
          <form onSubmit={handleSetup} className="login-form">
            <p className="text-secondary text-12">Create the administrator account to get started.</p>
            {error && <div className="error-message">{error}</div>}
            <div className="form-group">
              <label>Username</label>
              <input type="text" value={setupForm.username} onChange={(e) => setSetupForm({ ...setupForm, username: e.target.value })} required autoFocus autoComplete="username" />
            </div>
            <div className="form-group">
              <label>Email</label>
              <input type="email" value={setupForm.email} onChange={(e) => setSetupForm({ ...setupForm, email: e.target.value })} required autoComplete="email" />
            </div>
            <div className="form-group">
              <label>Full name (optional)</label>
              <input type="text" value={setupForm.full_name} onChange={(e) => setSetupForm({ ...setupForm, full_name: e.target.value })} autoComplete="name" />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input type="password" value={setupForm.password} onChange={(e) => setSetupForm({ ...setupForm, password: e.target.value })} required autoComplete="new-password" />
              <span className="form-help">At least 12 characters with uppercase, lowercase, digit, and special character.</span>
            </div>
            <div className="form-group">
              <label>Confirm password</label>
              <input type="password" value={setupForm.confirm} onChange={(e) => setSetupForm({ ...setupForm, confirm: e.target.value })} required autoComplete="new-password" />
            </div>
            <button type="submit" className="btn btn-primary login-button" disabled={loading}>{loading ? 'Creating account...' : 'Create admin account'}</button>
          </form>
        ) : (
          <form onSubmit={handleSubmit} className="login-form">
            {error && <div className="error-message">{error}</div>}
            <div className="form-group">
              <label>Username</label>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus autoComplete="username" />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password" />
            </div>
            <button type="submit" className="btn btn-primary login-button" disabled={loading}>{loading ? 'Signing in...' : 'Sign in'}</button>
          </form>
        )}

        <div className="login-footer">Secure access to your Cloudflare estate</div>
      </div>
    </div>
  );
};

export default Login;
