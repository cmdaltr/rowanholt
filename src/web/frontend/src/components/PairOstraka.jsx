import React, { useCallback, useEffect, useState } from 'react';
import { getPairingCodes, makePairingLink, withdrawPairingCode } from '../api';

// Pair with Ostraka (docs/suite/INTEGRATION.md): an admin makes a link, shown this once, and pastes it into
// Ostraka (Settings, Integrations). Ostraka's claim makes its token and webhook here. Codes last ten minutes
// and work once; an open one can be withdrawn. Revoking the token or deleting the webhook undoes a pairing.

const errorText = (err) => {
  const detail = err.response?.data?.detail;
  if (!detail) return err.message;
  return typeof detail === 'string' ? detail : detail.message || JSON.stringify(detail);
};

const when = (iso) => new Date(iso).toLocaleString('en-GB', {
  day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
});

const isOpen = (code, now) => !code.claimed_at && new Date(code.expires_at) > now;

export default function PairOstraka() {
  const [codes, setCodes] = useState(null);
  const [note, setNote] = useState('');
  const [made, setMade] = useState(null); // the new link, shown once
  const [copied, setCopied] = useState('');
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      setCodes(await getPairingCodes());
    } catch (err) {
      setError(errorText(err));
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const make = async (e) => {
    e.preventDefault();
    setError(null);
    setCopied('');
    try {
      setMade(await makePairingLink(note.trim()));
      setNote('');
      load();
    } catch (err) {
      setError(errorText(err));
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(made.link);
      setCopied('Copied.');
    } catch {
      setCopied('Copy it from the box: the browser refused the clipboard.');
    }
  };

  const withdraw = async (id) => {
    setError(null);
    try {
      await withdrawPairingCode(id);
      load();
    } catch (err) {
      setError(errorText(err));
    }
  };

  const now = new Date();
  const open = (codes || []).filter((code) => isOpen(code, now));
  const claimed = (codes || []).filter((code) => code.claimed_at);

  return (
    <div className="card" data-testid="pair-ostraka">
      <h2>Pair with Ostraka</h2>
      <p>
        Make a pairing link and paste it into Ostraka (Settings, Integrations). Ostraka's claim gives it a token
        that reads cases and starts jobs, and a webhook for job.completed, job.failed and finding.confirmed. A link
        works once, within 10 minutes. To undo a pairing, revoke its token (Ostraka (paired)) or delete its webhook.
      </p>
      <form onSubmit={make}>
        <div className="form-group">
          <label htmlFor="pairing-note">Note</label>
          <input id="pairing-note" type="text" aria-label="Pairing note" value={note} maxLength={200}
            onChange={(e) => setNote(e.target.value)} placeholder="Ostraka on the homelab" />
        </div>
        <button type="submit">Make a pairing link</button>
      </form>
      {made && (
        <div data-testid="pairing-link">
          <p>The link, shown this once. It expires at {when(made.expires_at)}.</p>
          <pre style={{ userSelect: 'all', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{made.link}</pre>
          <button className="secondary" onClick={copy}>Copy</button>{' '}
          <button className="secondary" onClick={() => setMade(null)}>Done</button>
          {copied && <p role="status">{copied}</p>}
        </div>
      )}
      {error && <div className="error">{error}</div>}
      {open.length > 0 && (
        <>
          <h3>Open codes</h3>
          <table>
            <thead><tr><th>Note</th><th>Made by</th><th>Expires</th><th /></tr></thead>
            <tbody>
              {open.map((code) => (
                <tr key={code.id} data-testid={`pairing-${code.id}`}>
                  <td>{code.note || '(no note)'}</td>
                  <td>{code.created_by}</td>
                  <td>{when(code.expires_at)}</td>
                  <td><button className="secondary" onClick={() => withdraw(code.id)}>Withdraw</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {claimed.length > 0 && (
        <>
          <h3>Paired</h3>
          <table>
            <thead><tr><th>Note</th><th>Made by</th><th>Claimed by</th><th>When</th></tr></thead>
            <tbody>
              {claimed.map((code) => (
                <tr key={code.id}>
                  <td>{code.note || '(no note)'}</td>
                  <td>{code.created_by}</td>
                  <td>{code.claimed_by_name}</td>
                  <td>{when(code.claimed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

// What /pair shows: the link is for Ostraka, which reads the code after the #; nothing happens here
export function PairPage() {
  return (
    <div className="card">
      <h2>Pairing link</h2>
      <p>This link is for Ostraka: paste the whole link into Ostraka (Settings, Integrations) to pair it with Rowanholt.</p>
    </div>
  );
}
