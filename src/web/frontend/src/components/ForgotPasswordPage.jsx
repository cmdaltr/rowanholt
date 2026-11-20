import React, { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { getAuthConfig, requestResetLink } from '../api';
import { JOURNEYS } from './Home';

const heroImage = `/images/rowanholt-tm.webp`;

// With email set up (ROWANHOLT_SMTP_*), the address or username is sent a reset-access link, the same
// link an administrator gives; the answer reads the same whether or not an account matched. Without
// it (or without ROWANHOLT_PUBLIC_URL), ask an administrator for a link
const ForgotPasswordPage = () => {
  // The same as the sign-in page: one of the home page's figures beside the card
  const [figure] = useState(() => JOURNEYS[Math.floor(Math.random() * JOURNEYS.length)]);
  const [server, setServer] = useState(null);
  const [email, setEmail] = useState(null);
  const [address, setAddress] = useState('');
  const [sent, setSent] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    getAuthConfig()
      .then((config) => {
        setServer(Boolean(config.server_mode));
        setEmail(Boolean(config.forgot_password));
      })
      .catch(() => { setServer(false); setEmail(false); });
  }, []);

  const askForLink = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      setSent((await requestResetLink(address.trim())).message);
    } catch (err) {
      setError(err.response?.data?.detail || 'That didn\'t work; try again.');
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
        <h2>Forgot Password</h2>
        <p>
          Reset your Rowanholt account password.
        </p>
      </header>

      <div className="login-layout">
      <div className="journey-banner login-figure" aria-hidden="true">
        <img src={figure.image} alt="" style={{ '--drop': figure.drop }} />
        <span className="journey-banner__name">
          <span>{figure.name}</span>
          <span className="journey-banner__role">{figure.role}</span>
        </span>
      </div>
      <div className="card login-card">
        <h3>Reset Password</h3>

        {error && <div className="alert-error">{error}</div>}

        {email === true && (sent ? (
          <div className="alert-success" data-testid="link-sent">
            {sent}. It works once, for 24 hours; your password and authenticator keep working until you use it.
          </div>
        ) : (
          <form onSubmit={askForLink} data-testid="link-form">
            <p style={{ marginBottom: '1rem' }}>
              Enter your email or username, and we&apos;ll email you a link to choose a new password and set up
              a new authenticator.
            </p>
            <div className="form-group">
              <label htmlFor="address">Email or Username</label>
              <input id="address" name="address" type="text" value={address} onChange={(e) => setAddress(e.target.value)}
                placeholder="Enter your email or username" autoComplete="username" required disabled={loading} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'center' }}>
              <button type="submit" disabled={loading} style={{ width: '100%' }}>
                {loading ? 'Sending...' : 'Email Me a Link'}
              </button>
            </div>
          </form>
        ))}

        {email === false && (
          <p data-testid="ask-admin" style={{ marginBottom: '1rem' }}>
            This Rowanholt doesn&apos;t send email, so ask an administrator for a reset link:{' '}
            {server
              ? <code>rowanholt server users reset-access &lt;username&gt;</code>
              : <code>docker exec rowanholt-backend python -m auth.manage_users reset-access &lt;username&gt;</code>}
            {' '}gives one. It works once, for 24 hours.
          </p>
        )}

        <div className="text-center" style={{ marginTop: '1.5rem' }}>
          Remember your password?{' '}
          <Link to="/login" className="text-link">
            Sign In
          </Link>
        </div>
      </div>
      </div>
    </div>
  );
};

export default ForgotPasswordPage;
