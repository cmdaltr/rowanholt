import React, { useEffect, useState } from 'react';
import { getSmithModel, resetSmithModel, saveSmithModel, testSmithModel } from '../api';

const KINDS = [
  ['ollama', 'Ollama', 'http://192.168.1.20:11434'],
  ['openai', 'OpenAI-compatible: LM Studio, vLLM, llama.cpp, LocalAI', 'http://192.168.1.20:1234'],
];

const errorText = (err) => err.response?.data?.detail || err.message || 'Something went wrong';

// Where Smith's free-text answers come from (admins): Ollama or an OpenAI-compatible server on this
// machine, the local network or the tailnet. The backend refuses anything on a public address.
export default function SmithModel() {
  const [setting, setSetting] = useState(null);
  const [fields, setFields] = useState({ provider: 'ollama', url: '', model: '' });
  const [apiKey, setApiKey] = useState('');
  const [dropKey, setDropKey] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState('');
  const [busy, setBusy] = useState(false);

  const show = (s) => {
    setSetting(s);
    setFields({ provider: s.provider, url: s.url, model: s.model });
    setApiKey('');
    setDropKey(false);
  };

  useEffect(() => {
    getSmithModel().then(show).catch((err) => setError(errorText(err)));
  }, []);

  const set = (name) => (e) => {
    setFields({ ...fields, [name]: e.target.value });
    setResult(null);
    setSaved('');
  };

  // The key as the API takes it: null keeps the saved one, '' removes it
  const body = () => ({ ...fields, api_key: apiKey ? apiKey : dropKey ? '' : null });

  const run = async (action) => {
    setBusy(true);
    setError(null);
    setSaved('');
    try {
      await action();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const test = () => run(async () => setResult(await testSmithModel(body())));
  const save = () => run(async () => {
    show(await saveSmithModel(body()));
    setSaved('Saved: Ask Smith uses it from the next question.');
  });
  const reset = () => run(async () => {
    show(await resetSmithModel());
    setResult(null);
    setSaved('Back to the default: Ollama on this machine, unless .env sets OLLAMA_HOST.');
  });

  if (error && !setting) return <div className="card"><div className="error">{error}</div></div>;
  if (!setting) return <div className="loading">Loading Smith's model…</div>;

  const kind = KINDS.find(([k]) => k === fields.provider) || KINDS[0];
  return (
    <div className="card smith-model">
      <h3>Smith's model</h3>
      <p>
        Where Smith's free-text answers come from. If this machine can't run a language model, point Smith at
        one on another machine: a GPU box on your network or across the tailnet. Only private addresses are
        allowed (loopback, 10/8, 172.16/12, 192.168/16, Tailscale's 100.64/10), so a case is never sent to a
        cloud service{setting.public_allowed ? ' — except that ROWANHOLT_ALLOW_PUBLIC_MODEL in .env lifts that here' : ''}.
      </p>
      <div className="form-group">
        <label htmlFor="smith-provider">Kind of server</label>
        <select id="smith-provider" value={fields.provider} onChange={set('provider')}>
          {KINDS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
        </select>
      </div>
      <div className="form-group">
        <label htmlFor="smith-url">URL</label>
        <input id="smith-url" type="url" value={fields.url} onChange={set('url')} placeholder={kind[2]} />
        <p className="field-hint">
          {fields.provider === 'ollama'
            ? "Ollama's address, usually port 11434. On another machine, start it with OLLAMA_HOST=0.0.0.0 so it listens beyond itself."
            : 'The server address without /v1, such as LM Studio on 1234 or vLLM on 8000.'}
        </p>
      </div>
      <div className="form-group">
        <label htmlFor="smith-model">Model</label>
        <input id="smith-model" type="text" list="smith-models" value={fields.model} onChange={set('model')} />
        <datalist id="smith-models">
          {(result?.models || []).map((m) => <option key={m} value={m} />)}
        </datalist>
        <p className="field-hint">Test lists the models the server has.</p>
      </div>
      {fields.provider === 'openai' && (
        <div className="form-group">
          <label htmlFor="smith-key">API key</label>
          <input id="smith-key" type="password" value={apiKey} autoComplete="off"
                 onChange={(e) => { setApiKey(e.target.value); setResult(null); }}
                 placeholder={setting.has_api_key && !dropKey ? 'Saved: leave empty to keep it' : 'Only if the server asks for one'} />
          {setting.has_api_key && (
            <label className="checkbox-inline">
              <input type="checkbox" checked={dropKey} onChange={(e) => setDropKey(e.target.checked)} /> Remove the saved key
            </label>
          )}
        </div>
      )}
      <div className="smith-model__actions">
        <button type="button" className="secondary" onClick={test} disabled={busy || !fields.url || !fields.model}>Test</button>{' '}
        <button type="button" onClick={save} disabled={busy || !fields.url || !fields.model}>Save</button>{' '}
        {setting.saved && <button type="button" className="secondary" onClick={reset} disabled={busy}>Use the default</button>}
      </div>
      {result && (
        <p className={result.ok ? 'smith-model__ok' : 'licence-notice'} role="status">
          {result.ok ? `It answers, and has ${fields.model}.` : result.reason}
        </p>
      )}
      {saved && <p className="smith-model__ok" role="status">{saved}</p>}
      {error && <div className="error">{error}</div>}
    </div>
  );
}
