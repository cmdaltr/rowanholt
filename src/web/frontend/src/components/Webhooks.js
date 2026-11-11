import React, { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { addWebhook, deleteWebhook, editWebhook, getWebhooks, testWebhook } from '../api';
import { managesLicence } from './Licence';

// Webhooks (the automation feature, docs/LICENSING_MODEL.md): admins register a URL and the events it
// wants. Registering stays open on every edition, so nothing is lost when a licence lapses; sending is
// Pro and Services, and when webhooks aren't being sent the page says why instead of hiding them.

const errorText = (err) => {
  const detail = err.response?.data?.detail;
  if (!detail) return err.message;
  return typeof detail === 'string' ? detail : detail.message || JSON.stringify(detail);
};

const when = (seconds) => new Date(seconds * 1000).toLocaleString('en-GB', {
  day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit',
});

function AddWebhook({ events, onAdded }) {
  const [url, setUrl] = useState('');
  const [chosen, setChosen] = useState([]);
  const [description, setDescription] = useState('');
  const [error, setError] = useState(null);

  const toggle = (event) => setChosen((now) => (now.includes(event) ? now.filter((e) => e !== event) : [...now, event]));

  const add = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      onAdded(await addWebhook({ url: url.trim(), events: chosen, description }));
      setUrl('');
      setChosen([]);
      setDescription('');
    } catch (err) {
      setError(errorText(err));
    }
  };

  return (
    <form className="card" onSubmit={add}>
      <h2>Add a webhook</h2>
      <label>URL <input aria-label="Webhook URL" value={url} onChange={(e) => setUrl(e.target.value)}
        placeholder="https://soar.example.org/rowanholt" style={{ width: '100%' }} /></label>
      <p style={{ color: '#888' }}>https:// only; http:// is allowed for localhost and private 10/172.16/192.168 addresses.</p>
      <label>Description <input aria-label="Description" value={description}
        onChange={(e) => setDescription(e.target.value)} style={{ width: '100%' }} /></label>
      <fieldset>
        <legend>Events</legend>
        {events.map((event) => (
          <label key={event} style={{ marginRight: '1rem' }}>
            <input type="checkbox" checked={chosen.includes(event)} onChange={() => toggle(event)} /> {event}
          </label>
        ))}
      </fieldset>
      <button type="submit" disabled={!url.trim() || !chosen.length}>Add</button>
      {error && <div className="error">{error}</div>}
    </form>
  );
}

function Webhook({ hook, sending, onChanged, onDeleted }) {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);

  const run = async (work) => {
    setError(null);
    setBusy(true);
    try {
      await work();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const test = () => run(async () => {
    setResult(await testWebhook(hook.id));
    onChanged(); // the test is a delivery, listed with the others
  });

  return (
    <div className="card" data-testid={`webhook-${hook.id}`}>
      <h3 style={{ wordBreak: 'break-all' }}>{hook.url}</h3>
      {hook.description && <p>{hook.description}</p>}
      <p>
        {hook.events.join(', ')} · {hook.enabled ? 'enabled' : 'disabled'} · {hook.has_secret ? 'signed' : 'not signed'}
      </p>
      <button disabled={busy || !sending} onClick={test}
        title={sending ? 'Send a job.completed for a made-up job now' : 'Webhooks aren\'t being sent on this edition'}>
        Send a test
      </button>{' '}
      <button className="secondary" disabled={busy}
        onClick={() => run(async () => { await editWebhook(hook.id, { enabled: !hook.enabled }); onChanged(); })}>
        {hook.enabled ? 'Disable' : 'Enable'}
      </button>{' '}
      {confirming
        ? <><button disabled={busy} onClick={() => run(async () => { await deleteWebhook(hook.id); onDeleted(hook.id); })}>Delete it</button>{' '}
          <button className="secondary" onClick={() => setConfirming(false)}>Keep it</button></>
        : <button className="secondary" onClick={() => setConfirming(true)}>Delete…</button>}
      {result && <p data-testid="webhook-test-result">{result.ok ? `Delivered (HTTP ${result.status}).` : `Not delivered: ${result.error}`}</p>}
      {error && <div className="error">{error}</div>}
      {hook.deliveries?.length > 0 && (
        <table>
          <thead><tr><th>When</th><th>Event</th><th>Result</th><th>Tries</th></tr></thead>
          <tbody>
            {hook.deliveries.map((d) => (
              <tr key={`${d.at}-${d.event}`}>
                <td>{when(d.at)}</td>
                <td>{d.event}</td>
                <td style={{ color: d.ok ? '#8cc152' : '#ed5565' }}>{d.ok ? `HTTP ${d.status}` : d.error}</td>
                <td>{d.tries}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function Webhooks({ serverMode = true }) {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [secret, setSecret] = useState(null); // the new webhook's, shown once
  const [error, setError] = useState(null);
  const isAdmin = managesLicence(user, serverMode);

  const load = useCallback(async () => {
    try {
      setData(await getWebhooks());
    } catch (err) {
      setError(errorText(err));
    }
  }, []);

  useEffect(() => { if (isAdmin && serverMode != null) load(); }, [isAdmin, serverMode, load]);

  if (serverMode == null) return <div className="loading">Loading the webhooks…</div>;
  if (!isAdmin) {
    return <div className="card"><h2>Webhooks</h2><p>Webhooks are managed by Rowanholt administrators.</p></div>;
  }
  if (error && !data) return <div className="card"><div className="error">{error}</div></div>;
  if (!data) return <div className="loading">Loading the webhooks…</div>;

  const added = (hook) => {
    setSecret({ url: hook.url, value: hook.secret });
    load();
  };

  return (
    <div className="webhooks">
      <div className="card">
        <h2>Webhooks</h2>
        <p>
          Rowanholt POSTs JSON to each URL when one of its events happens: {data.events.join(', ')}. Bodies carry
          ids, the case number, a host and counts, never artefact contents. Each is signed with the webhook's
          secret: <code>X-Rowanholt-Signature: sha256=&lt;HMAC-SHA256 of the body&gt;</code>.
        </p>
        {!data.sending && <p className="licence-notice" role="status">{data.reason}</p>}
      </div>
      {secret && (
        <div className="card" data-testid="webhook-secret">
          <p>The secret for {secret.url}, shown this once. Keep it with the receiver to check signatures.</p>
          <pre style={{ userSelect: 'all' }}>{secret.value}</pre>
          <button className="secondary" onClick={() => setSecret(null)}>I've kept it</button>
        </div>
      )}
      {data.webhooks.map((hook) => (
        <Webhook key={hook.id} hook={hook} sending={data.sending} onChanged={load} onDeleted={load} />
      ))}
      <AddWebhook events={data.events} onAdded={added} />
    </div>
  );
}
