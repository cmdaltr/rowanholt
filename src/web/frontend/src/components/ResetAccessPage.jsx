import React, { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router';
import { useAuth } from '../context/AuthContext';
import {
  startAccessReset, completeAccessReset, previewInvitation, startInvitation, acceptInvitation,
} from '../api';
import { BackupCodeList } from './MfaPanels';
import { JOURNEYS } from './Home';

const heroImage = `/images/rowanholt-tm.webp`;
const MIN_PASSWORD = 12;

// An admin's reset link, /reset-access#<token> (auth/reset_access.py): a new password, a new
// authenticator (always, whether or not the server requires MFA), then the new backup codes once, and
// into the app. The token is in the fragment so it stays out of the server's logs; nothing changes
// until the authenticator's code is confirmed, so leaving half-way takes nothing away.
// mode="invite" is an invitation, /accept-invite#<token> (auth/invitations.py): the same steps with a
// username and name chosen first, and the account made only at the end.
const ResetAccessPage = ({ mode = 'reset' }) => {
  const invite = mode === 'invite';
  const navigate = useNavigate();
  const { login: setUser } = useAuth();
  const token = useLocation().hash.replace(/^#/, '');
  const [figure] = useState(() => JOURNEYS[Math.floor(Math.random() * JOURNEYS.length)]);
  // 'password' (and, for an invitation, the username and name), then 'authenticator', then 'codes'
  const [step, setStep] = useState('password');
  const [form, setForm] = useState({ username: '', fullName: '', password: '', confirm: '', code: '' });
  // An invitation's email, role and suggested username; a reset's comes with its authenticator
  const [invitation, setInvitation] = useState(null);
  const [enrolment, setEnrolment] = useState(null);
  const [done, setDone] = useState(null);
  const [error, setError] = useState(token ? '' : 'This link is incomplete: open the whole link you were given.');
  const [gone, setGone] = useState(!token);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!token) return;
    const opened = invite
      ? previewInvitation(token).then((found) => {
        setInvitation(found);
        setForm((f) => ({ ...f, username: found.username || '', fullName: found.full_name || '' }));
      })
      : startAccessReset(token).then(setEnrolment);
    opened.catch((err) => {
      setGone(true);
      setError(err.response?.data?.detail || 'This link didn\'t open; ask an administrator for a new one.');
    });
  }, [token, invite]);

  const change = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const choosePassword = async (e) => {
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
    if (invite) {
      // The username is checked (free, well formed) and labels the authenticator
      setLoading(true);
      try {
        setEnrolment(await startInvitation(token, form.username.trim()));
      } catch (err) {
        setError(err.response?.data?.detail || 'That didn\'t work; try again.');
        if (err.response?.status === 410) setGone(true);
        return;
      } finally {
        setLoading(false);
      }
    }
    setStep('authenticator');
  };

  const confirmCode = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      setDone(invite
        ? await acceptInvitation(token, form.username.trim(), form.fullName.trim(), form.password, form.code.trim())
        : await completeAccessReset(token, form.password, form.code.trim()));
      setForm({ username: '', fullName: '', password: '', confirm: '', code: '' });
      setStep('codes');
    } catch (err) {
      setError(err.response?.data?.detail || 'That code was not accepted.');
      setForm({ ...form, code: '' });
      if (err.response?.status === 410) setGone(true);
    } finally {
      setLoading(false);
    }
  };

  const finish = () => {
    setUser(done.user);
    navigate('/jobs', { replace: true });
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
        <img src={heroImage} alt="Rowanholt" className="hero-image"
          style={{ transform: 'scale(0.2)', transformOrigin: 'center top' }} />
      </section>

      <header>
        <h2>{invite ? 'Join Rowanholt' : 'Reset Access'}</h2>
        <p>{invite ? 'Make your account: a username, a password and an authenticator.'
          : 'A new password and a new authenticator for your Rowanholt account.'}</p>
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
        {error && <div className="alert-error" role="alert">{error}</div>}

        {!gone && invite && invitation && step === 'password' && (
          <form onSubmit={choosePassword} data-testid="accept-invite-details">
            <h3>Your Account</h3>
            <p style={{ marginBottom: '1rem' }}>
              For <strong data-testid="accept-invite-email">{invitation.email}</strong>, as
              {invitation.role === 'admin' ? ' an admin' : ' an analyst'}. Next you'll set up an authenticator
              app, which this account will need at every sign-in.
            </p>
            {field('username', 'Username', 'text', 'Letters, digits and . _ @ -',
              { autoComplete: 'username', minLength: 2, maxLength: 64, autoFocus: true })}
            {field('fullName', 'Full Name', 'text', 'Optional', { autoComplete: 'name', required: false })}
            {field('password', 'Password', 'password', `At least ${MIN_PASSWORD} characters`,
              { autoComplete: 'new-password', minLength: MIN_PASSWORD })}
            {field('confirm', 'Confirm Password', 'password', 'Re-enter the password',
              { autoComplete: 'new-password', minLength: MIN_PASSWORD })}
            <button type="submit" disabled={loading} style={{ width: '100%' }}>Continue</button>
          </form>
        )}

        {!gone && !invite && enrolment && step === 'password' && (
          <form onSubmit={choosePassword} data-testid="reset-access-password">
            <h3>Choose a Password</h3>
            <p style={{ marginBottom: '1rem' }}>
              For <strong data-testid="reset-access-username">{enrolment.username}</strong>. Next you'll set up an
              authenticator app, which this account will need at every sign-in.
            </p>
            {field('password', 'New Password', 'password', `At least ${MIN_PASSWORD} characters`,
              { autoComplete: 'new-password', minLength: MIN_PASSWORD, autoFocus: true })}
            {field('confirm', 'Confirm New Password', 'password', 'Re-enter the new password',
              { autoComplete: 'new-password', minLength: MIN_PASSWORD })}
            <button type="submit" style={{ width: '100%' }}>Continue</button>
          </form>
        )}

        {!gone && enrolment && step === 'authenticator' && (
          <form onSubmit={confirmCode} data-testid="reset-access-authenticator">
            <h3>Set Up Your Authenticator</h3>
            <p style={{ fontSize: '0.9rem', marginBottom: '0.75rem' }}>
              Scan this with your authenticator app (Microsoft Authenticator, Google Authenticator, 1Password,
              Authy), then enter the code it shows.{invite ? '' : ' It replaces any authenticator you had.'}
            </p>
            <img src={enrolment.qr_svg} alt="QR code for your authenticator app"
              style={{ width: '200px', height: '200px', borderRadius: '4px', display: 'block', margin: '0 auto 0.75rem' }} />
            <p style={{ fontSize: '0.85rem', color: '#a09580', marginBottom: '1rem', wordBreak: 'break-all' }}>
              Can't scan it? Enter this key instead: <code data-testid="mfa-secret">{enrolment.secret}</code>
            </p>
            {field('code', 'Code from the app', 'text', '6 digits',
              { autoComplete: 'one-time-code', inputMode: 'numeric', autoFocus: true })}
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button type="submit" disabled={loading || !form.code} style={{ flex: 1 }}>
                {loading ? 'Checking...' : invite ? 'Create Account' : 'Reset Access'}
              </button>
              <button type="button" className="secondary" disabled={loading}
                onClick={() => { setError(''); setStep('password'); }}>Back</button>
            </div>
          </form>
        )}

        {step === 'codes' && done && (
          <>
            <h3>Save Your Backup Codes</h3>
            <p style={{ marginBottom: '1rem' }}>
              {invite ? 'Your account is ready. Each of these signs in once if you lose your authenticator.'
                : 'Your password and authenticator are set, and your old backup codes no longer work.'}
            </p>
            <BackupCodeList codes={done.backup_codes} onDone={finish} confirm />
          </>
        )}

        {step !== 'codes' && (
          <div className="text-center" style={{ marginTop: '1.5rem' }}>
            <Link to="/login" className="text-link">Sign In</Link>
          </div>
        )}
      </div>
      </div>
    </div>
  );
};

export default ResetAccessPage;
