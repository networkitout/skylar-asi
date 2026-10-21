// Same-origin by default: the Vite dev server and the production nginx image
// both proxy /api to the backend, so this works wherever the app is served
// from (localhost, LAN, Cloudflare Tunnel). VITE_API_URL remains available as
// a build-time override for split deployments.
const API_BASE = import.meta.env.VITE_API_URL || '/api';

class Api {
  constructor() {
    this.token = null;
    // Registered by AuthContext; called when a request comes back 401 so the
    // app can drop the session and show the login screen instead of silently
    // failing every request after the token expires
    this.onUnauthorized = null;
  }

  setToken(token) {
    this.token = token;
  }

  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(url, {
      ...options,
      headers
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Network error' }));
      // A 401 on anything but the login attempt itself means the token is
      // expired or revoked - end the session
      if (response.status === 401 && !endpoint.startsWith('/auth/login') && this.onUnauthorized) {
        this.onUnauthorized();
      }
      throw new Error(error.detail || `HTTP ${response.status}`);
    }

    return response.json();
  }

  get(endpoint) {
    return this.request(endpoint, { method: 'GET' });
  }

  post(endpoint, data) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  put(endpoint, data) {
    return this.request(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }

  patch(endpoint, data) {
    return this.request(endpoint, {
      method: 'PATCH',
      body: JSON.stringify(data)
    });
  }

  delete(endpoint) {
    return this.request(endpoint, { method: 'DELETE' });
  }
}

const api = new Api();
export default api;
export { API_BASE };
