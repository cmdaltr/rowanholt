import React, { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { checkLicence, getLicence, getLicenceTerms, installLicence, removeLicence } from '../api';

// A team server's licence (docs/LICENSING_MODEL.md): admins see the edition and places taken, and
// install a licence only after checking it and accepting the commercial terms for the licensee.
// Local mode is one analyst and needs no licence: the API answers 404 and nothing here shows.

const errorText = (err) => {
  const detail = err.response?.data?.detail;
  if (!detail) return err.message;
  return typeof detail === 'string' ? detail : detail.message || JSON.stringify(detail);
};

const EDITIONS = { free: 'Free', pro: 'Pro', services: 'Services' };
const day = (value) => (value ? new Date(value).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) : '');

function Standing({ licence }) {
  const seats = licence.seats === null ? 'unlimited' : licence.seats;
  return (
    <div className="card" data-testid="licence-standing">
      <h2>{EDITIONS[licence.edition]} edition</h2>
      {licence.licensee && <p>Licensed to <strong>{licence.licensee}</strong> ({licence.licence_id}), runs to {licence.expires ? day(licence.expires) : 'no end date'}.</p>}
      <p>Places taken: <strong>{licence.places_held}</strong> of {seats}. Only adding someone past that is refused; nobody already here is ever signed out.</p>
      {licence.state === 'pending' && <p className="licence-notice">This licence starts on {day(licence.not_before)}. Until then the server runs as the Free edition.</p>}
      {licence.state === 'grace' && <p className="licence-notice">This licence ran out on {day(licence.expires)}. It keeps working until {day(licence.grace_ends)}, then the server is Free again. Install a renewed licence before then.</p>}
      {licence.state === 'lapsed' && <p className="licence-notice">The licence ran out on {day(licence.expires)}: the server is on the Free edition.</p>}
      {licence.accepted && <p>Commercial licence v{licence.accepted.terms_version} accepted by {licence.accepted.by} on {day(licence.accepted.at)}.</p>}
    </div>
  );
}

function Install({ onInstalled }) {
  const [text, setText] = useState('');
  const [preview, setPreview] = useState(null);
  const [terms, setTerms] = useState(null);
  const [accepted, setAccepted] = useState(false);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const check = async () => {
    setError(null);
    setBusy(true);
    try {
      const [found, current] = await Promise.all([checkLicence(text), getLicenceTerms()]);
      setPreview(found);
      setTerms(current);
      setAccepted(false);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const install = async () => {
    setError(null);
    setBusy(true);
    try {
      onInstalled(await installLicence(text, terms.version));
      setText('');
      setPreview(null);
      setTerms(null);
    } catch (err) {
      // 409: the terms changed since they were shown; show the new ones to accept
      if (err.response?.status === 409) {
        setTerms(await getLicenceTerms());
        setAccepted(false);
      }
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <h2>Install a licence</h2>
      <textarea
        aria-label="Licence"
        rows={3}
        placeholder="rowanholt-licence-1.…"
        value={text}
        onChange={(e) => { setText(e.target.value); setPreview(null); }}
        style={{ width: '100%', fontFamily: 'monospace' }}
      />
      <button onClick={check} disabled={!text.trim() || busy}>Check</button>
      {error && <div className="error">{error}</div>}
      {preview && terms && (
        <div data-testid="licence-preview">
          <p>
            <strong>{preview.licensee}</strong>: {EDITIONS[preview.edition]}, {preview.seats === null ? 'unlimited' : preview.seats} seats,
            {preview.not_before ? ` from ${day(preview.not_before)}` : ''} to {preview.expires ? day(preview.expires) : 'no end date'}.
          </p>
          <h3>Rowanholt Commercial Licence, version {terms.version}</h3>
          <pre className="licence-terms" style={{ maxHeight: '20rem', overflow: 'auto', whiteSpace: 'pre-wrap' }}>{terms.text}</pre>
          <label>
            <input type="checkbox" checked={accepted} onChange={(e) => setAccepted(e.target.checked)} />
            {' '}I accept the Rowanholt Commercial Licence, version {terms.version}, on behalf of {preview.licensee}, and I have authority to do so
          </label>
          <div>
            <button onClick={install} disabled={!accepted || busy}>Install</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Licence() {
  const { user } = useAuth();
  const [licence, setLicence] = useState(null);
  const [error, setError] = useState(null);
  const [local, setLocal] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const isAdmin = user?.role === 'admin';

  const load = useCallback(async () => {
    try {
      setLicence(await getLicence());
    } catch (err) {
      if (err.response?.status === 404) setLocal(true);
      else setError(errorText(err));
    }
  }, []);

  useEffect(() => { if (isAdmin) load(); }, [isAdmin, load]);

  if (!isAdmin) {
    return <div className="card"><h2>Licence</h2><p>The licence is managed by Rowanholt administrators.</p></div>;
  }
  if (local) {
    return <div className="card"><h2>Licence</h2><p>Local mode is one analyst and needs no licence. Licences are for a team server.</p></div>;
  }
  if (error) return <div className="card"><div className="error">{error}</div></div>;
  if (!licence) return <div className="loading">Checking the licence…</div>;

  const remove = async () => {
    setConfirming(false);
    try {
      setLicence(await removeLicence());
    } catch (err) {
      setError(errorText(err));
    }
  };

  return (
    <div className="licence">
      <Standing licence={licence} />
      <Install onInstalled={setLicence} />
      {licence.licensee && (
        <div className="card">
          <h2>Remove the licence</h2>
          <p>The server goes back to the Free edition. Nobody is deactivated; past the free edition's {licence.free_seats} accounts, nobody new can be added.</p>
          {confirming
            ? <><button onClick={remove}>Remove it</button> <button className="secondary" onClick={() => setConfirming(false)}>Keep it</button></>
            : <button className="secondary" onClick={() => setConfirming(true)}>Remove…</button>}
        </div>
      )}
    </div>
  );
}

// Shown to admins on every page while a licence is in its grace period
export function LicenceNotice({ serverMode }) {
  const { user } = useAuth();
  const [licence, setLicence] = useState(null);
  const isAdmin = user?.role === 'admin';

  useEffect(() => {
    if (!serverMode || !isAdmin) return undefined;
    let cancelled = false;
    getLicence().then((found) => { if (!cancelled) setLicence(found); }).catch(() => {});
    return () => { cancelled = true; };
  }, [serverMode, isAdmin]);

  if (!licence || licence.state !== 'grace') return null;
  return (
    <div className="licence-banner" role="alert">
      The Rowanholt licence for {licence.licensee} ran out on {day(licence.expires)} and stops on {day(licence.grace_ends)}.
      {' '}Install a renewed licence from the Licence page.
    </div>
  );
}
