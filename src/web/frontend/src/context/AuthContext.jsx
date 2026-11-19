import React, { createContext, useContext, useState, useEffect } from 'react';
import { getCurrentUser, getStoredUser, isAuthenticated, logout as apiLogout } from '../api';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  // The stored user from the first render, so a page that opens at once (Account, after a reload)
  // already knows whether MFA must be set up first
  const [user, setUser] = useState(() => (isAuthenticated() ? getStoredUser() : null));
  const [loading, setLoading] = useState(true);

  // The server's view of the user: whether ROWANHOLT_REQUIRE_MFA still holds them to setting MFA up
  // (mfa_enrolment_required, which the app's pages are gated on) changes without a new sign-in
  const refresh = async () => {
    if (!isAuthenticated()) return;
    try {
      const current = await getCurrentUser();
      localStorage.setItem('user', JSON.stringify(current));
      setUser(current);
    } catch (err) {
      // A 401 signs out (api.js); anything else keeps the stored user
    }
  };

  useEffect(() => {
    setLoading(false);
    refresh();
  }, []);

  const login = (userData) => {
    setUser(userData);
  };

  const logout = async () => {
    await apiLogout();
    setUser(null);
  };

  const value = {
    user,
    login,
    logout,
    refresh,
    isAuthenticated: !!user,
    loading,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
