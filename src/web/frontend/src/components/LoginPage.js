import React, { useEffect, useState } from 'react';
import { useNavigate, Link, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { login as apiLogin, loginAsGuest as apiLoginAsGuest, getAuthConfig, completeMfaSignIn } from '../api';
import { API_BASE_URL } from '../apiBase';

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt-tm.png`;

const LoginPage = () => {
  const navigate = useNavigate();
  const { login: setUser } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [searchParams] = useSearchParams();
  const [error, setError] = useState(searchParams.get('sso_error') || '');
  const [loading, setLoading] = useState(false);
  // The second step, when the account has MFA: the challenge the password step gave, and the code
  const [challenge, setChallenge] = useState('');
  const [code, setCode] = useState('');
  // What this Rowanholt offers: a local stack has guests and sign-up, a server may have SSO
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
      if (response.mfa_required) {
        setPassword('');
        setChallenge(response.challenge);
        return;
      }
      signedIn(response);
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const signedIn = (response) => {
    setUser(response.user);
    // A server that requires MFA lets someone without it in only to set it up
    if (response.mfa_enrolment_required) navigate('/account', { state: { tab: 'security' } });
    else navigate('/jobs');
  };

  const handleSecondFactor = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      signedIn(await completeMfaSignIn(challenge, code));
    } catch (err) {
      const detail = err.response?.data?.detail || 'That code was not accepted.';
      setCode('');
      // An expired or used challenge, or a lockout: back to the password
      if (err.response?.status !== 401 || detail !== 'Incorrect code') setChallenge('');
      setError(detail);
    } finally {
      setLoading(false);
    }
  };

  const startAgain = () => {
    setChallenge('');
    setCode('');
    setError('');
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
          alt="Rowanholt"
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
          Access your Rowanholt DF Acceleration Suite account.
        </p>
      </header>

      <div className="card" style={{ width: '800px', maxWidth: '90%', margin: '0 auto' }}>
        <h3>Sign In</h3>

        {error && (
          <div className="alert-error">
            {error}
          </div>
        )}

        {challenge && (
          <form onSubmit={handleSecondFactor} data-testid="mfa-step">
            <p style={{ marginBottom: '1rem' }}>
              Enter the code from your authenticator app, or one of your backup codes.
            </p>
            <div className="form-group">
              <label htmlFor="mfa-code">Authentication code</label>
              <input
                type="text"
                id="mfa-code"
                inputMode="text"
                autoComplete="one-time-code"
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="123456 or a backup code"
                required
                disabled={loading}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '0.5rem' }}>
              <button type="submit" disabled={loading || !code} style={{ flex: 1 }}>
                {loading ? 'Checking...' : 'Verify'}
              </button>
              <button type="button" className="secondary" onClick={startAgain} disabled={loading}>
                Start again
              </button>
            </div>
          </form>
        )}

        {!challenge && config.sso.enabled && (
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

        {!challenge && config.local_login && (
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

        {!challenge && config.guest && (
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
