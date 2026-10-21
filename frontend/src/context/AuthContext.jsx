import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../utils/api';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Expired/revoked token on any request -> drop the session so the app
    // returns to the login screen instead of showing empty pages
    api.onUnauthorized = () => {
      localStorage.removeItem('token');
      api.setToken(null);
      setUser(null);
    };

    const token = localStorage.getItem('token');
    if (token) {
      api.setToken(token);
      fetchUser();
    } else {
      setLoading(false);
    }

    return () => { api.onUnauthorized = null; };
  }, []);

  const fetchUser = async () => {
    try {
      const userData = await api.get('/auth/me');
      setUser(userData);
    } catch (error) {
      localStorage.removeItem('token');
      api.setToken(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (username, password) => {
    const response = await api.post('/auth/login', { username, password });
    const { access_token } = response;
    localStorage.setItem('token', access_token);
    api.setToken(access_token);
    await fetchUser();
    return response;
  };

  const logout = () => {
    localStorage.removeItem('token');
    api.setToken(null);
    setUser(null);
  };

  const value = {
    user,
    loading,
    login,
    logout,
    refreshUser: fetchUser
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
