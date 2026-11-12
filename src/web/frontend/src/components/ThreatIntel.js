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
  getLookupStatus,
  lookupValue,
} from '../api';
import { useAuth } from '../context/AuthContext';
import PageHero from './PageHero';
import './ThreatIntel.css';

const PAGE = 50;
const ACCEPT = '.xlsx,.xlsm,.csv,.json,.txt';

const detail = (err, fallback) => err.response?.data?.detail || err.message || fallback;
const EXTEND_DAYS = 90;
const day = (iso) => (iso ? iso.slice(0, 10) : '');
const inDays = (days) => new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);
const tactics = (text) => (text || '').split(/[,;]\s*/).map((t) => t.trim()).filter(Boolean);

// The technique ID as a pill (a link when the row has a reference), its name beneath
function Technique({ id, name, url }) {
  if (!id && !name) return null;
  return (
    <>
      {id && (url
        ? <a className="pippin-tid" href={url} target="_blank" rel="noopener noreferrer">{id}</a>
        : <span className="pippin-tid">{id}</span>)}
      {name && <span className="pippin-tname">{name}</span>}
    </>
  );
}

function Tactics({ text }) {
  const list = tactics(text);
  return list.length ? <div className="pippin-tactics">{list.map((t) => <span key={t} className="pippin-tactic">{t}</span>)}</div> : null;
}

// The indicators Elrond matches a case against (Threat intelligence on Elrond's page, or
// --threatIntel) and Smith enriches single values with. On a team server only admins add or
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
  const [lookupOn, setLookupOn] = useState(null);
  const [looked, setLooked] = useState(null);
  const [looking, setLooking] = useState(false);

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
  useEffect(() => { getLookupStatus().then(setLookupOn).catch(() => setLookupOn(null)); }, []);
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

  const lookUp = async () => {
    setError('');
    setLooked(null);
    setLooking(true);
    try {
      setLooked(await lookupValue(value.trim()));
    } catch (err) {
      setError(detail(err, 'Lookup failed'));
    } finally {
      setLooking(false);
    }
  };

  const sourcesCard = (
    <section data-guide="intel.sources" className="card">
      <div className="pippin-head">
        <h3>Sources</h3>
        {summary && summary.total > 0 && (
          <span className="pippin-meta">
            <strong>{summary.total.toLocaleString()}</strong> indicators · <strong>{summary.groups}</strong> groups
          </span>
        )}
      </div>
      {!summary ? <p className="pippin-muted">Loading…</p> : summary.total === 0 ? (
        <p className="pippin-muted">No indicators yet.{canEdit ? ' Import a file or pull a TAXII collection.' : ' An administrator imports them.'}</p>
      ) : (
        <>
          <ul className="pippin-sources">
            {summary.sources.map((s) => (
              <li key={s.source} className={source === s.source ? 'is-current' : undefined}>
                <button type="button" className="pippin-source-name" title="Show only this source's indicators"
                  onClick={() => { setSource(s.source); setOffset(0); }}>{s.source || '(none)'}</button>
                <span className="pippin-count">{s.count.toLocaleString()}</span>
                {canEdit && (
                  <button type="button" className="pippin-small pippin-danger" disabled={busy}
                    onClick={() => remove(s.source)}>Remove</button>
                )}
              </li>
            ))}
          </ul>
          {summary.expired > 0 && (
            <p className="pippin-muted pippin-expired-note">
              {summary.expired.toLocaleString()} expired: still listed, but cases aren't matched against them and Smith
              doesn't check values with them until their source is imported again or an administrator extends them.
            </p>
          )}
        </>
      )}
    </section>
  );

  const importCard = canEdit && (
    <section data-guide="intel.import" className="card">
      <div className="pippin-head">
        <h3>Import</h3>
        <span className="pippin-meta">up to 200 MB</span>
      </div>
      <dl className="pippin-formats">
        <dt><code>.xlsx</code> <code>.xlsm</code></dt>
        <dd>A sheet with the ten threat intelligence columns as headers (Evidential Element … Source Type).</dd>
        <dt><code>.csv</code></dt>
        <dd>The same ten columns, as Rowanholt exports them, or a MITRESaw procedures export (<code>group_sw_name</code> and <code>evidence</code> columns).</dd>
        <dt><code>.json</code></dt>
        <dd>A STIX 2.1 bundle; each indicator's own expiry and confidence are kept.</dd>
        <dt><code>.txt</code></dt>
        <dd>A watchlist: one value per line, <code>#</code> for comments.</dd>
      </dl>
      <p className="pippin-muted" style={{ margin: '0 0 1rem' }}>Indicators already stored are skipped and their expiry renewed.</p>
      <div className="pippin-file">
        {/* The browser's own file picker hidden behind a button in the app's style */}
        <input ref={picker} type="file" accept={ACCEPT} style={{ display: 'none' }}
          onChange={(e) => setFile(e.target.files[0] || null)} />
        <button type="button" className="secondary" onClick={() => picker.current?.click()}>Choose file</button>
        <span className={`pippin-file-name${file ? ' is-chosen' : ''}`}>{file ? file.name : 'No file chosen'}</span>
        <button type="button" disabled={!file || busy} onClick={upload}>{busy ? 'Working…' : 'Import'}</button>
      </div>

      <div className="pippin-subsection">
        <h4>TAXII 2.1 collection</h4>
        <div className="pippin-taxii">
          <div className="is-wide">
            <label htmlFor="taxii-url">Collection URL</label>
            <input id="taxii-url" type="text" placeholder="https://taxii.example/api/collections/<id>/" value={taxii.url}
              onChange={(e) => setTaxii({ ...taxii, url: e.target.value })} />
          </div>
          <div>
            <label htmlFor="taxii-user">Username <span>(optional)</span></label>
            <input id="taxii-user" type="text" value={taxii.username} autoComplete="off"
              onChange={(e) => setTaxii({ ...taxii, username: e.target.value })} />
          </div>
          <div>
            <label htmlFor="taxii-password">Password <span>(optional)</span></label>
            <input id="taxii-password" type="password" value={taxii.password} autoComplete="new-password"
              onChange={(e) => setTaxii({ ...taxii, password: e.target.value })} />
          </div>
          <div>
            <label htmlFor="taxii-after">Added after <span>(optional)</span></label>
            <input id="taxii-after" type="text" placeholder="2026-01-01T00:00:00Z" value={taxii.added_after}
              onChange={(e) => setTaxii({ ...taxii, added_after: e.target.value })} />
          </div>
        </div>
        <div className="pippin-actions">
          <button type="button" disabled={!taxii.url || busy} onClick={pull}>Pull collection</button>
          <span className="pippin-muted">Up to 5,000 objects per pull.</span>
        </div>
      </div>
    </section>
  );

  return (
    <div className="job-list journey-detail pippin">
      <PageHero title="Pippin">
        Threat intelligence: the indicators Elrond matches cases against and Smith checks single values with,
        from STIX 2.1 bundles, TAXII 2.1 collections, MITRESaw procedures or a watchlist.
      </PageHero>

      {error && <div className="error">{error}</div>}
      {notice && <div className="card pippin-notice">{notice}</div>}

      {canEdit ? <div className="pippin-pair">{sourcesCard}{importCard}</div> : sourcesCard}

      <section data-guide="intel.enrich" className="card">
        <div className="pippin-head">
          <h3>Check a value</h3>
          <span className="pippin-meta">one value against every indicator</span>
        </div>
        <p className="pippin-lede">
          Paste one value from a case: a command line, path, process name, IP, domain or hash. Pippin finds the
          indicators that occur in it, matched as Elrond matches (IPs and hashes exactly, tools as whole words,
          commands as phrases), and how many groups share each. Expired indicators are left out.
        </p>
        <form onSubmit={enrich} className="pippin-check">
          <input type="text" className="pippin-value" value={value} onChange={(e) => setValue(e.target.value)}
            placeholder="powershell.exe -nop -w hidden -enc ..." aria-label="Value to check" />
          <button type="submit" disabled={value.length < 3}>Check</button>
          {lookupOn?.enabled && (
            <button type="button" className="secondary" disabled={value.trim().length < 3 || looking} onClick={lookUp}
              title="Sends this one value to VirusTotal">{looking ? 'Looking up…' : 'Look up on VirusTotal'}</button>
          )}
        </form>
        {lookupOn?.enabled && (
          <p className="pippin-muted" style={{ marginTop: '0.5rem' }}>
            Looking up sends the value to VirusTotal: an IP, domain or hash only, never a private address or internal name.
          </p>
        )}
        {looked && (
          <div data-testid="lookup-result" className="pippin-result">
            {!looked.found ? <p>VirusTotal has nothing on <code>{looked.value}</code>.</p> : (
              <p>
                VirusTotal on <code>{looked.value}</code>: <strong style={{ color: looked.malicious ? '#e06c6c' : '#a7db6c' }}>
                {looked.malicious} malicious</strong>, {looked.suspicious} suspicious, {looked.harmless} harmless,
                {' '}{looked.undetected} undetected
                {looked.last_analysis && ` (last analysed ${day(looked.last_analysis)})`}
                {looked.tags?.length > 0 && `; tags: ${looked.tags.join(', ')}`}.
              </p>
            )}
            <a href={looked.link} target="_blank" rel="noopener noreferrer">Open on VirusTotal</a>
            {looked.cached && <span className="pippin-muted"> · from the last hour's answer</span>}
          </div>
        )}
        {enriched && (
          <div className="pippin-result">
            {enriched.matches.length === 0 ? <p className="pippin-muted">No indicators occur in that value.</p> : (
              <div className="table-container">
                <table className="pippin-table">
                  <colgroup>
                    <col style={{ width: '28%' }} /><col style={{ width: '8%' }} /><col style={{ width: '27%' }} />
                    <col style={{ width: '25%' }} /><col style={{ width: '12%' }} />
                  </colgroup>
                  <thead><tr><th>Matched element</th><th>Kind</th><th>Threat groups</th><th>Technique IDs</th><th>Sources</th></tr></thead>
                  <tbody>
                    {enriched.matches.map((m) => (
                      <tr key={m.element}>
                        <td data-label="Matched element">
                          <code className="pippin-element">{m.element}</code>
                          {m.common && <div className="pippin-muted">common: {m.breadth} groups use it</div>}
                        </td>
                        <td data-label="Kind">{m.kind}</td>
                        <td data-label="Threat groups">{m.groups.slice(0, 8).join(', ')}{m.groups.length > 8 ? ` +${m.groups.length - 8}` : ''}</td>
                        <td data-label="Technique IDs">
                          <div className="pippin-tids">{m.techniques.map((t) => <span key={t} className="pippin-tid">{t}</span>)}</div>
                        </td>
                        <td data-label="Sources">{m.sources.join('; ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </section>

      <section data-guide="intel.browse" className="card">
        <div className="pippin-head">
          <h3>Indicators</h3>
          <span className="pippin-meta"><strong>{results.total.toLocaleString()}</strong> {query || source ? 'shown by the filter' : 'stored'}</span>
        </div>
        <div className="pippin-filter">
          <label htmlFor="pippin-filter">Filter</label>
          <input id="pippin-filter" type="text" placeholder="Element, threat group or technique ID (e.g. mimikatz, APT29, T1105)" value={query}
            onChange={(e) => { setQuery(e.target.value); setOffset(0); }} />
          {source && (
            <span className="pippin-chip">Source: {source}
              <button type="button" aria-label="Show every source" title="Show every source"
                onClick={() => { setSource(''); setOffset(0); }}>×</button>
            </span>
          )}
        </div>
        <p className="pippin-muted" style={{ margin: '0.35rem 0 0.75rem' }}>
          Narrows this list to rows whose element, group or technique ID contains the text; expired rows included.
          To test a value from a case against the indicators, use Check a value.
        </p>
        <div className="table-container">
          <table className="pippin-table">
            <colgroup>
              <col style={{ width: '29%' }} /><col style={{ width: '13%' }} /><col style={{ width: '20%' }} />
              <col style={{ width: '16%' }} /><col style={{ width: '10%' }} /><col style={{ width: '12%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>Evidential element</th><th>Threat group</th><th>Technique (ID and name)</th>
                <th>Tactic</th><th>Source</th><th>Expires</th>
              </tr>
            </thead>
            <tbody>
              {results.indicators.map((i) => (
                <tr key={i.id}>
                  <td data-label="Evidential element" title={i.procedure_example || undefined}>
                    <code className="pippin-element">{i.evidential_element}</code>
                  </td>
                  <td data-label="Threat group">{i.threat_group}</td>
                  <td data-label="Technique"><Technique id={i.technique_id} name={i.technique_name} url={i.reference_url} /></td>
                  <td data-label="Tactic"><Tactics text={i.tactic} /></td>
                  <td data-label="Source">{i.source_type}</td>
                  <td data-label="Expires" className="pippin-expiry">
                    {i.valid_until
                      ? <span className={i.expired ? 'is-expired' : undefined} title={i.first_seen ? `first seen ${day(i.first_seen)}` : undefined}>
                          {i.expired ? 'expired ' : ''}{day(i.valid_until)}
                        </span>
                      : 'never'}
                    {i.confidence !== null && i.confidence !== undefined && <div className="pippin-muted">confidence {i.confidence}</div>}
                    {canEdit && (
                      <div className="pippin-expiry-actions">
                        <button type="button" className="pippin-small pippin-quiet" disabled={busy} title={`Hold until ${inDays(EXTEND_DAYS)}`}
                          onClick={() => extend(i)}>+{EXTEND_DAYS} days</button>
                        {i.valid_until && <button type="button" className="pippin-small pippin-quiet" disabled={busy}
                          onClick={() => clearExpiry(i)}>No expiry</button>}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {results.indicators.length === 0 && <p className="pippin-empty">No indicators match the filter.</p>}
        </div>
        {results.total > PAGE && (
          <div className="pippin-pager">
            <button type="button" className="pippin-small pippin-quiet" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
            <span>{offset + 1}–{Math.min(offset + PAGE, results.total)} of {results.total.toLocaleString()}</span>
            <button type="button" className="pippin-small pippin-quiet" disabled={offset + PAGE >= results.total} onClick={() => setOffset(offset + PAGE)}>Next</button>
          </div>
        )}
      </section>
    </div>
  );
}

export default ThreatIntel;
