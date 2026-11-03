import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  getAuthConfig,
  getThreatIntelSummary,
  searchThreatIntel,
  importThreatIntel,
  importTaxii,
  deleteThreatIntelSource,
  setThreatIntelValidity,
  enrichValue,
} from '../api';
import { useAuth } from '../context/AuthContext';
import PageHero from './PageHero';

const PAGE = 50;
const ACCEPT = '.xlsx,.xlsm,.csv,.json,.txt';

const detail = (err, fallback) => err.response?.data?.detail || err.message || fallback;
const EXTEND_DAYS = 90;
const day = (iso) => (iso ? iso.slice(0, 10) : '');
const inDays = (days) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);

// The indicators Elrond matches a case against (Threat intelligence on Elrond's page, or
// --threatIntel) and Eru enriches single values with. On a team server only admins add or
// remove them (auth/access.py), so the import controls are hidden from everyone else.
function ThreatIntel() {
  const { user } = useAuth();
  const [canEdit, setCanEdit] = useState(true);
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [file, setFile] = useState(null);
  const picker = useRef(null);
  const [taxii, setTaxii] = useState({ url: '', username: '', password: '', added_after: '' });
  const [query, setQuery] = useState('');
  const [source, setSource] = useState('');
  const [offset, setOffset] = useState(0);
  const [results, setResults] = useState({ total: 0, indicators: [] });
  const [value, setValue] = useState('');
  const [enriched, setEnriched] = useState(null);

  useEffect(() => {
    getAuthConfig()
      .then((config) => setCanEdit(!config.server_mode || user?.role === 'admin'))
      .catch(() => {});
  }, [user]);

  const loadSummary = useCallback(async () => {
    try {
      setSummary(await getThreatIntelSummary());
    } catch (err) {
      setError(detail(err, 'Failed to load threat intelligence'));
    }
  }, []);

  const loadIndicators = useCallback(async () => {
    try {
      setResults(await searchThreatIntel({ q: query, source, limit: PAGE, offset }));
    } catch (err) {
      setError(detail(err, 'Search failed'));
    }
  }, [query, source, offset]);

  useEffect(() => { loadSummary(); }, [loadSummary]);
  useEffect(() => { loadIndicators(); }, [loadIndicators]);

  const refresh = async () => {
    await loadSummary();
    await loadIndicators();
  };

  const run = async (action) => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await action();
      await refresh();
    } catch (err) {
      setError(detail(err, 'Request failed'));
    } finally {
      setBusy(false);
    }
  };

  const upload = () => run(async () => {
    const result = await importThreatIntel(file);
    setNotice(`${result.file}: ${result.added} indicators added, ${result.duplicates} already there.`);
    setFile(null);
    if (picker.current) picker.current.value = '';
  });

  const pull = () => run(async () => {
    const result = await importTaxii(taxii);
    setNotice(`${result.read} indicators read from the collection: ${result.added} added, ${result.duplicates} already there.`);
  });

  const remove = (name) => {
    if (!window.confirm(`Remove every indicator from "${name}"?`)) return;
    run(async () => {
      const result = await deleteThreatIntelSource(name);
      setNotice(`${result.removed} indicators removed.`);
      if (source === name) setSource('');
    });
  };

  const extend = (indicator) => run(async () => {
    await setThreatIntelValidity(indicator.id, inDays(EXTEND_DAYS));
    setNotice(`${indicator.evidential_element} now holds until ${inDays(EXTEND_DAYS)}.`);
  });

  const clearExpiry = (indicator) => run(async () => {
    await setThreatIntelValidity(indicator.id, null);
    setNotice(`${indicator.evidential_element} no longer expires.`);
  });

  const enrich = async (event) => {
    event.preventDefault();
    setError('');
    try {
      setEnriched(await enrichValue(value));
    } catch (err) {
      setError(detail(err, 'Enrichment failed'));
    }
  };

  return (
    <div className="job-list journey-detail">
      <PageHero title="Pippin">
        Threat intelligence: the indicators that Elrond matches cases against and Eru checks single values with: the Iran APT
        workbook, STIX 2.1 bundles, TAXII 2.1 collections, MITRESaw procedures or a watchlist.
      </PageHero>

      {error && <div className="error">{error}</div>}
      {notice && <div className="card" style={{ color: '#a7db6c' }}>{notice}</div>}

      <div data-guide="intel.sources" className="card">
        <h3>Sources</h3>
        {!summary ? <p>Loading…</p> : summary.total === 0 ? (
          <p>No indicators yet.{canEdit ? ' Import a file or pull a TAXII collection below.' : ' An administrator imports them.'}</p>
        ) : (
          <>
            <p>
              {summary.total.toLocaleString()} indicators about {summary.groups} groups.
              {summary.expired > 0 && ` ${summary.expired.toLocaleString()} have expired: they stay listed but cases aren't matched against them, and Eru doesn't check values with them, until a fresh import of their source or an administrator extends them.`}
            </p>
            <div className="table-container">
              <table>
                <thead><tr><th>Source</th><th>Indicators</th><th /></tr></thead>
                <tbody>
                  {summary.sources.map((s) => (
                    <tr key={s.source}>
                      <td><button type="button" style={{ background: 'none', border: 'none', padding: 0, color: '#f0dba5', cursor: 'pointer', textDecoration: 'underline' }} onClick={() => { setSource(s.source); setOffset(0); }}>{s.source || '(none)'}</button></td>
                      <td>{s.count.toLocaleString()}</td>
                      <td>{canEdit && <button type="button" disabled={busy} onClick={() => remove(s.source)}>Remove</button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>

      {canEdit && (
        <div data-guide="intel.import" className="card">
          <h3>Import</h3>
          <p>
            XLSX (the Iran APT workbook's ten columns), CSV (Dernvale's columns or MITRESaw's procedures),
            JSON (a STIX 2.1 bundle) or a .txt watchlist with one value per line.
            Indicators already stored are skipped.
          </p>
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
            {/* The browser's own file picker hidden behind a button in the app's style */}
            <input ref={picker} type="file" accept={ACCEPT} style={{ display: 'none' }}
              onChange={(e) => setFile(e.target.files[0] || null)} />
            <button type="button" className="secondary" onClick={() => picker.current?.click()}>Choose file</button>
            <span style={{ color: file ? '#a7db6c' : '#999' }}>{file ? file.name : 'No file chosen'}</span>
            <button type="button" disabled={!file || busy} onClick={upload}>{busy ? 'Working…' : 'Import'}</button>
          </div>
          <h4 style={{ marginTop: '1.5rem' }}>TAXII 2.1 collection</h4>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14rem, 1fr))', gap: '0.5rem' }}>
            <input type="text" placeholder="https://taxii.example/api/collections/<id>/" value={taxii.url}
              onChange={(e) => setTaxii({ ...taxii, url: e.target.value })} />
            <input type="text" placeholder="Username (optional)" value={taxii.username} autoComplete="off"
              onChange={(e) => setTaxii({ ...taxii, username: e.target.value })} />
            <input placeholder="Password (optional)" type="password" value={taxii.password} autoComplete="new-password"
              onChange={(e) => setTaxii({ ...taxii, password: e.target.value })} />
            <input type="text" placeholder="Added after (2026-01-01T00:00:00Z)" value={taxii.added_after}
              onChange={(e) => setTaxii({ ...taxii, added_after: e.target.value })} />
          </div>
          <button type="button" style={{ marginTop: '0.5rem' }} disabled={!taxii.url || busy} onClick={pull}>Pull collection</button>
        </div>
      )}

      <div data-guide="intel.enrich" className="card">
        <h3>Check a value</h3>
        <p>A process name, command line, path, IP, domain or hash: which indicators it matches, and how many groups share each one.</p>
        <form onSubmit={enrich} style={{ display: 'flex', gap: '0.5rem' }}>
          <input type="text" style={{ flex: 1 }} value={value} onChange={(e) => setValue(e.target.value)}
            placeholder="powershell.exe -nop -w hidden -enc ..." />
          <button type="submit" disabled={value.length < 3}>Check</button>
        </form>
        {enriched && (enriched.matches.length === 0 ? <p>No indicators match.</p> : (
          <div className="table-container" style={{ marginTop: '1rem' }}>
            <table>
              <thead><tr><th>Element</th><th>Kind</th><th>Groups</th><th>Techniques</th><th>Sources</th></tr></thead>
              <tbody>
                {enriched.matches.map((m) => (
                  <tr key={m.element}>
                    <td><code>{m.element}</code>{m.common && <div style={{ fontSize: '0.8rem', color: '#888' }}>common: {m.breadth} groups use it</div>}</td>
                    <td>{m.kind}</td>
                    <td>{m.groups.slice(0, 8).join(', ')}{m.groups.length > 8 ? ` +${m.groups.length - 8}` : ''}</td>
                    <td>{m.techniques.join(', ')}</td>
                    <td>{m.sources.join('; ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>

      <div data-guide="intel.browse" className="card">
        <h3>Indicators{source ? `: ${source}` : ''}</h3>
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
          <input type="text" style={{ flex: 1 }} placeholder="Search elements, groups or technique IDs" value={query}
            onChange={(e) => { setQuery(e.target.value); setOffset(0); }} />
          {source && <button type="button" onClick={() => { setSource(''); setOffset(0); }}>All sources</button>}
        </div>
        <div className="table-container">
          <table>
            <thead><tr><th>Evidential Element</th><th>Threat Group</th><th>Technique</th><th>Tactic</th><th>Source</th><th>Expires</th></tr></thead>
            <tbody>
              {results.indicators.map((i) => (
                <tr key={i.id}>
                  <td title={i.procedure_example}><code>{i.evidential_element}</code></td>
                  <td>{i.threat_group}</td>
                  <td>{i.reference_url ? <a href={i.reference_url} target="_blank" rel="noopener noreferrer">{i.technique_id}</a> : i.technique_id} {i.technique_name}</td>
                  <td>{i.tactic}</td>
                  <td>{i.source_type}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {i.valid_until
                      ? <span style={i.expired ? { color: '#ed5565' } : undefined} title={i.first_seen ? `first seen ${day(i.first_seen)}` : undefined}>
                          {i.expired ? 'expired ' : ''}{day(i.valid_until)}
                        </span>
                      : 'never'}
                    {i.confidence !== null && i.confidence !== undefined && <div style={{ fontSize: '0.8rem', color: '#888' }}>confidence {i.confidence}</div>}
                    {canEdit && (
                      <div style={{ display: 'flex', gap: '0.25rem', marginTop: '0.25rem' }}>
                        <button type="button" disabled={busy} style={{ padding: '0.1rem 0.4rem' }} title={`Hold until ${inDays(EXTEND_DAYS)}`}
                          onClick={() => extend(i)}>+{EXTEND_DAYS} days</button>
                        {i.valid_until && <button type="button" className="secondary" disabled={busy} style={{ padding: '0.1rem 0.4rem' }}
                          onClick={() => clearExpiry(i)}>No expiry</button>}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {results.total > PAGE && (
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginTop: '0.5rem' }}>
            <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
            <span>{offset + 1}–{Math.min(offset + PAGE, results.total)} of {results.total.toLocaleString()}</span>
            <button type="button" disabled={offset + PAGE >= results.total} onClick={() => setOffset(offset + PAGE)}>Next</button>
          </div>
        )}
      </div>
    </div>
  );
}

export default ThreatIntel;
