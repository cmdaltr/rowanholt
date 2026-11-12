import React, { useEffect, useState } from 'react';
import {
  getMfaStatus, startMfaSetup, enableMfa, disableMfa, regenerateBackupCodes,
} from '../api';

// The Account page's Multi-Factor Authentication and Backup Codes panels, over auth/mfa.py. MFA here is
// for a team server's password accounts: single sign-on accounts have their identity provider's, and on
// an analyst's own machine there's no sign-in for it to protect, so both say so instead.

const detail = (error, fallback) => error.response?.data?.detail || fallback;

const BackupCodeList = ({ codes, onDone }) => {
  const [copied, setCopied] = useState('');
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      setCopied('Copied.');
    } catch {
      setCopied('Copy them from the list: the browser refused the clipboard.');
    }
  };
  return (
    <div data-testid="backup-codes" style={{ marginBottom: '1.5rem', padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px' }}>
      <p style={{ color: '#f0dba5', fontSize: '0.9rem', marginBottom: '0.75rem' }}>
        Keep these somewhere safe, away from your phone. Each signs in once in place of a code, and they
        aren't shown again.
      </p>
      <ul style={{ columns: 2, listStyle: 'none', padding: 0, fontFamily: 'monospace', fontSize: '1rem' }}>
        {codes.map((code) => <li key={code}>{code}</li>)}
      </ul>
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
        <button type="button" className="secondary" onClick={copy}>Copy</button>
        <button type="button" onClick={onDone}>I've saved them</button>
        {copied && <span style={{ fontSize: '0.85rem', color: '#a09580' }}>{copied}</span>}
      </div>
    </div>
  );
};

const MfaPanels = () => {
  const [status, setStatus] = useState(null);
  const [message, setMessage] = useState({ type: '', text: '' });
  // What's open: null, 'reauth' (a current code before a new authenticator), 'setup', 'disable', 'regenerate'
  const [step, setStep] = useState(null);
  const [setup, setSetup] = useState(null);
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [shownCodes, setShownCodes] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      setStatus(await getMfaStatus());
    } catch (error) {
      setMessage({ type: 'error', text: detail(error, 'Could not read your MFA settings.') });
    }
  };

  useEffect(() => { load(); }, []);

  const close = () => { setStep(null); setSetup(null); setCode(''); setPassword(''); };

  const run = async (action) => {
    setMessage({ type: '', text: '' });
    setBusy(true);
    try {
      await action();
    } catch (error) {
      setMessage({ type: 'error', text: detail(error, 'That did not work; try again.') });
    } finally {
      setBusy(false);
    }
  };

  const beginSetup = (currentCode = '') => run(async () => {
    setSetup(await startMfaSetup(currentCode));
    setCode('');
    setStep('setup');
  });

  const confirmSetup = (e) => {
    e.preventDefault();
    run(async () => {
      const done = await enableMfa(code);
      const again = status?.enabled;
      close();
      if (done.backup_codes) setShownCodes(done.backup_codes);
      setMessage({ type: 'success', text: again ? 'Your new authenticator is set up.' : 'MFA is on.' });
      await load();
    });
  };

  const confirmDisable = (e) => {
    e.preventDefault();
    run(async () => {
      await disableMfa(password, code);
      close();
      setShownCodes(null);
      setMessage({ type: 'success', text: 'MFA is off.' });
      await load();
    });
  };

  const confirmRegenerate = (e) => {
    e.preventDefault();
    run(async () => {
      const made = await regenerateBackupCodes(code);
      close();
      setShownCodes(made.backup_codes);
      setMessage({ type: 'success', text: 'New backup codes: the old ones no longer work.' });
      await load();
    });
  };

  const alert = message.text && (
    <div className={`alert-${message.type}`} role={message.type === 'error' ? 'alert' : 'status'}>{message.text}</div>
  );
  const intro = (
    <p style={{ marginBottom: '1rem', color: '#a09580', fontSize: '0.9rem' }}>
      A code from an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, Authy) as
      well as your password when you sign in.
    </p>
  );

  if (!status) {
    return (
      <div>
        <h3 style={{ marginBottom: '1.5rem' }}>Multi-Factor Authentication</h3>
        {alert}
      </div>
    );
  }

  if (!status.available) {
    return (
      <div>
        <h3 style={{ marginBottom: '1.5rem' }}>Multi-Factor Authentication</h3>
        {alert}
        {intro}
        <p data-testid="mfa-unavailable" style={{ color: '#66d9ef', fontSize: '0.9rem' }}>{status.message}</p>
        <h4 style={{ color: '#f0dba5', marginBottom: '1rem', marginTop: '3rem', paddingTop: '3rem', borderTop: '1px solid #3f4b2a' }}>Backup Codes</h4>
        <p style={{ color: '#a09580', fontSize: '0.9rem' }}>
          {status.reason === 'sso'
            ? 'Your identity provider handles recovery if you lose your device.'
            : 'Backup codes come with MFA on a team server.'}
        </p>
      </div>
    );
  }

  const codeInput = (label, hint) => (
    <div className="form-group">
      <label htmlFor="mfa-code">{label}</label>
      <input id="mfa-code" type="text" inputMode="text" autoComplete="one-time-code" value={code}
        onChange={(e) => setCode(e.target.value)} placeholder={hint} required disabled={busy} />
    </div>
  );

  return (
    <div>
      <h3 style={{ marginBottom: '1.5rem' }}>Multi-Factor Authentication</h3>
      {alert}
      {status.required && !status.enabled && (
        <div className="alert-info" data-testid="mfa-required">
          This server requires MFA: set it up to start using Rowanholt.
        </div>
      )}
      {intro}

      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
        <span>Status:</span>
        <span className={status.enabled ? 'status-badge status-completed' : 'status-badge status-pending'}>
          {status.enabled ? 'Enabled' : 'Disabled'}
        </span>
        {!step && !status.enabled && (
          <button onClick={() => beginSetup()} disabled={busy} style={{ marginLeft: 'auto' }}>Enable MFA</button>
        )}
        {!step && status.enabled && (
          <span style={{ marginLeft: 'auto', display: 'flex', gap: '0.5rem' }}>
            <button className="secondary" onClick={() => { setCode(''); setStep('reauth'); }} disabled={busy}>
              New authenticator
            </button>
            {!status.required && (
              <button className="secondary" onClick={() => { setCode(''); setStep('disable'); }} disabled={busy}>
                Disable MFA
              </button>
            )}
          </span>
        )}
      </div>

      {step === 'reauth' && (
        <form onSubmit={(e) => { e.preventDefault(); beginSetup(code); }} style={{ marginBottom: '1.5rem' }}>
          {codeInput('Current code', 'From your current app, or a backup code')}
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button type="submit" disabled={busy || !code}>Continue</button>
            <button type="button" className="secondary" onClick={close}>Cancel</button>
          </div>
        </form>
      )}

      {step === 'setup' && setup && (
        <form onSubmit={confirmSetup} style={{ marginBottom: '1.5rem', padding: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px' }}>
          <p style={{ fontSize: '0.9rem', marginBottom: '0.75rem' }}>
            Scan this with your authenticator app, then enter the code it shows.
          </p>
          <img src={setup.qr_svg} alt="QR code for your authenticator app"
            style={{ width: '200px', height: '200px', background: '#fff', borderRadius: '4px', display: 'block', marginBottom: '0.75rem' }} />
          <p style={{ fontSize: '0.85rem', color: '#a09580', marginBottom: '1rem' }}>
            Can't scan it? Enter this key instead: <code data-testid="mfa-secret">{setup.secret}</code>
          </p>
          {codeInput('Code from the app', '6 digits')}
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button type="submit" disabled={busy || !code}>{status.enabled ? 'Use this authenticator' : 'Turn on MFA'}</button>
            <button type="button" className="secondary" onClick={close}>Cancel</button>
          </div>
        </form>
      )}

      {step === 'disable' && (
        <form onSubmit={confirmDisable} style={{ marginBottom: '1.5rem' }}>
          <div className="form-group">
            <label htmlFor="mfa-password">Password</label>
            <input id="mfa-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              required disabled={busy} />
          </div>
          {codeInput('Code', 'From your app, or a backup code')}
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button type="submit" disabled={busy || !password || !code}>Turn off MFA</button>
            <button type="button" className="secondary" onClick={close}>Cancel</button>
          </div>
        </form>
      )}

      <h4 style={{ color: '#f0dba5', marginBottom: '1rem', marginTop: '3rem', paddingTop: '3rem', borderTop: '1px solid #3f4b2a' }}>Backup Codes</h4>

      <p style={{ marginBottom: '1rem', color: '#a09580', fontSize: '0.9rem' }}>
        Each signs in once if you lose your authenticator. Making new ones replaces them all.
      </p>

      {shownCodes && <BackupCodeList codes={shownCodes} onDone={() => setShownCodes(null)} />}

      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <span>Remaining codes:</span>
        <span data-testid="backup-codes-left"
          className={status.enabled && status.backup_codes_left > 2 ? 'status-badge status-completed' : 'status-badge status-pending'}>
          {status.backup_codes_left} / {status.backup_codes_total}
        </span>
        {step !== 'regenerate' && (
          <button onClick={() => { setCode(''); setStep('regenerate'); }} disabled={!status.enabled || busy || !!step}
            style={{ marginLeft: 'auto' }}>
            Generate
          </button>
        )}
      </div>

      {step === 'regenerate' && (
        <form onSubmit={confirmRegenerate} style={{ marginTop: '1rem' }}>
          {codeInput('Code from your app', '6 digits (not a backup code)')}
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button type="submit" disabled={busy || !code}>Make new codes</button>
            <button type="button" className="secondary" onClick={close}>Cancel</button>
          </div>
        </form>
      )}
    </div>
  );
};

export default MfaPanels;
