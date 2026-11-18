import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { getAuthConfig, resetPasswordWithBackupCode } from '../api';
import { JOURNEYS } from './Home';

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt-tm.webp`;
const MIN_PASSWORD = 12;

// Rowanholt sends no email. On a server, an account with MFA resets its own password with a code
// from its authenticator app and a backup code; otherwise an administrator sets one. On your own machine it's a command in a terminal
const ForgotPasswordPage = () => {
  const navigate = useNavigate();
  // The same as the sign-in page: one of the home page's figures beside the card
  const [figure] = useState(() => JOURNEYS[Math.floor(Math.random() * JOURNEYS.length)]);
  const [server, setServer] = useState(null);
  const [form, setForm] = useState({ username: '', code: '', backupCode: '', password: '', confirm: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    getAuthConfig().then((config) => setServer(Boolean(config.server_mode))).catch(() => setServer(false));
  }, []);

  const change = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    if (form.password !== form.confirm) {
      setError('The passwords don\'t match');
      return;
    }
    if (form.password.length < MIN_PASSWORD) {
      setError(`Passwords need at least ${MIN_PASSWORD} characters`);
      return;
    }
    setLoading(true);
    try {
      await resetPasswordWithBackupCode(form.username.trim(), form.code.trim(), form.backupCode.trim(), form.password);
      navigate('/login', { state: { reset: form.username.trim() } });
    } catch (err) {
      setError(err.response?.data?.detail || 'That didn\'t work; try again.');
      setForm({ ...form, code: '', backupCode: '' });
    } finally {
      setLoading(false);
    }
  };

  const field = (name, label, type, placeholder, extra = {}) => (
    <div className="form-group">
      <label htmlFor={name}>{label}</label>
      <input id={name} name={name} type={type} value={form[name]} onChange={change} placeholder={placeholder}
        required disabled={loading} {...extra} />
    </div>
  );

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

        {server === true && (
          <>
            <form onSubmit={submit} data-testid="reset-form">
              <p style={{ marginBottom: '1rem' }}>
                With MFA on your account, a code from your authenticator app and one of your backup codes
                set a new password. The backup code is used up.
              </p>
              {field('username', 'Username or Email', 'text', 'Enter username or email', { autoComplete: 'username' })}
              {field('code', 'Authenticator Code', 'text', '6 digits from your app',
                { autoComplete: 'one-time-code', inputMode: 'numeric' })}
              {field('backupCode', 'Backup Code', 'text', 'One of your backup codes', { autoComplete: 'off' })}
              {field('password', 'New Password', 'password', `At least ${MIN_PASSWORD} characters`,
                { autoComplete: 'new-password', minLength: MIN_PASSWORD })}
              {field('confirm', 'Confirm New Password', 'password', 'Re-enter the new password',
                { autoComplete: 'new-password', minLength: MIN_PASSWORD })}
              <div style={{ display: 'flex', justifyContent: 'center' }}>
                <button type="submit" disabled={loading} style={{ width: '100%' }}>
                  {loading ? 'Setting it...' : 'Set New Password'}
                </button>
              </div>
            </form>

            <div className="divider" data-text="or"></div>

            <p data-testid="reset-server" style={{ color: '#a09580', fontSize: '0.9rem', marginBottom: 0 }}>
              No MFA, or lost your app or your backup codes? Rowanholt doesn't send email, so ask an administrator to
              run <code>rowanholt server users password &lt;username&gt;</code> on the server.
            </p>
          </>
        )}

        {server === false && (
          <div data-testid="reset-local">
            <p style={{ marginBottom: '1rem' }}>
              Rowanholt doesn't send email. On your own machine, set a new password from a terminal, with
              your username:
            </p>
            <pre style={{ marginBottom: '1.5rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}><code>docker exec -it rowanholt-backend python -m auth.manage_users password &lt;username&gt;</code></pre>
          </div>
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
