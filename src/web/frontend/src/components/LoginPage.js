import React, { useEffect, useState } from 'react';
import { useNavigate, Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { login as apiLogin, loginAsGuest as apiLoginAsGuest, getAuthConfig } from '../api';
import { API_BASE_URL } from '../apiBase';

const heroImage = `${process.env.PUBLIC_URL}/images/rivendell.png`;

const LoginPage = () => {
  const navigate = useNavigate();
  const { login: setUser } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [searchParams] = useSearchParams();
  const [error, setError] = useState(searchParams.get('sso_error') || '');
  const [loading, setLoading] = useState(false);
  // What this Rivendell offers: a local stack has guests and sign-up, a server may have SSO
  const [config, setConfig] = useState({ local_login: true, guest: true, register: true, sso: { enabled: false } });

  useEffect(() => {
    getAuthConfig().then(setConfig).catch(() => {});
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await apiLogin(username, password);
      setUser(response.user);
      // Redirect to jobs page on success
      navigate('/jobs');
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleGuestLogin = async () => {
    setError('');
    setLoading(true);

    try {
      const response = await apiLoginAsGuest();
      setUser(response.user);
      // Redirect to jobs page on success
      navigate('/jobs');
    } catch (err) {
      setError(err.response?.data?.detail || 'Guest login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="journey-detail">
      <section className="hero-section">
        <img
          src={heroImage}
          alt="Rivendell - The Last Homely House"
          className="hero-image"
          style={{
            transform: 'scale(0.2)',
            transformOrigin: 'center top'
          }}
        />
      </section>

      <header>
        <h2>Login</h2>
        <p>
          Access your Rivendell DF Acceleration Suite account.
        </p>
      </header>

      <div className="card" style={{ width: '800px', maxWidth: '90%', margin: '0 auto' }}>
        <h3>Sign In</h3>

        {error && (
          <div className="alert-error">
            {error}
          </div>
        )}

        {config.sso.enabled && (
          <>
            <div style={{ display: 'flex', justifyContent: 'center' }}>
              <button
                type="button"
                onClick={() => { window.location.href = `${API_BASE_URL}/api/auth/oidc/login`; }}
                disabled={loading}
                style={{ width: '100%' }}
              >
                Sign in with {config.sso.name}
              </button>
            </div>
            {config.local_login && <div className="divider" data-text="or"></div>}
          </>
        )}

        {config.local_login && (
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username or Email</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username or email"
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              required
              disabled={loading}
            />
          </div>

          <div style={{ marginTop: '0.5rem', marginBottom: '1rem' }}>
            <Link to="/forgot-password" className="text-link">
              Forgot password?
            </Link>
          </div>

          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <button type="submit" disabled={loading} style={{ width: '100%' }}>
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </div>
        </form>
        )}

        {config.guest && (
          <>
            <div className="divider" data-text="or"></div>

            <div style={{ display: 'flex', justifyContent: 'center' }}>
              <button
                onClick={handleGuestLogin}
                disabled={loading}
                className="secondary"
                style={{ width: '100%' }}
              >
                {loading ? 'Continuing...' : 'Continue as Guest'}
              </button>
            </div>
          </>
        )}

        <div className="text-center" style={{ marginTop: '1.5rem' }}>
          {config.register ? (
            <>
              Don't have an account?{' '}
              <Link to="/register" className="text-link">
                Register
              </Link>
            </>
          ) : (
            'Accounts on this server come from its administrators.'
          )}
        </div>
      </div>

    </div>
  );
};

export default LoginPage;
