import React, { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  getJob,
  getCase,
  getCaseRows,
  getCaseRowsCsv,
  getFindings,
  flagFinding,
  updateFinding,
  deleteFinding,
  getCaseNotes,
  addCaseNote,
  assignHost,
  getCaseActivity,
  caseLiveUrl,
  getCaseReport,
  getCaseFullReport,
  getConfirmedLayer,
  getAuthConfig,
  getUserDirectory,
  getCaseBrand,
  chooseCaseBrand,
} from '../api';
import PageHero from './PageHero';

const PAGE = 100;
const POLL_MS = 15000;
const CASE_HOST = '(case)';
const STATUS_COLOURS = { lead: '#ffce54', confirmed: '#ed5565', benign: '#888' };
const HOST_STATUSES = ['to do', 'in progress', 'done'];

const detail = (err, fallback) => err.response?.data?.detail || err.message || fallback;

const download = (name, text, type) => {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
};

const when = (iso) => (iso ? iso.slice(0, 16).replace('T', ' ') : '');

// The envelope's host, artefact and source path are the same on every row of a table: the heading says them once
const ENVELOPE = new Set(['host', 'artefact', 'source_path']);

// A cooked table's name as people read it: no folder, no extension, Windows' %4 back to a slash
const tableName = (path) => path.split('/').pop().replace(/\.(jsonl|csv|json)$/, '').replace(/%4/g, '/').replace(/^gandalf\+/, '');

// A host's tables by folder (evt, tasks, registry…), the loose ones first
const byFolder = (files) => {
  const groups = {};
  files.forEach((file) => {
    const parts = file.path.replace(/^artefacts\/cooked\//, '').split('/');
    const folder = parts.length > 1 ? parts[0] : '';
    (groups[folder] = groups[folder] || []).push(file);
  });
  return Object.entries(groups).sort(([a], [b]) => (a === '' ? -1 : b === '' ? 1 : a.localeCompare(b)));
};

// A cell holding JSON, laid out; anything else as it is
const pretty = (value) => {
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === 'object' && parsed !== null ? JSON.stringify(parsed, null, 2) : String(value);
  } catch {
    return value;
  }
};

const techniqueList = (value) => {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

// A case's tables, read-only, with findings flagged on their rows, notes, who has which host,
// and what everyone has done. Live over a websocket, polling while that's down.
function CaseBrowser() {
  const { jobId } = useParams();
  const [job, setJob] = useState(null);
  const [overview, setOverview] = useState(null);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(null); // {host, path}
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [table, setTable] = useState(null);
  const [flagging, setFlagging] = useState(null); // {ref, title, technique, status}
  const [findings, setFindings] = useState([]);
  const [notes, setNotes] = useState([]);
  const [activity, setActivity] = useState([]);
  const [caseNote, setCaseNote] = useState('');
  const [findingNote, setFindingNote] = useState({});
  const [people, setPeople] = useState([]);
  const [building, setBuilding] = useState(''); // the case report's format while it's being built
  const [expanded, setExpanded] = useState(null); // the row ref opened to show its whole record
  const [caseBrand, setCaseBrand] = useState(null); // admins only: the brand the case names, and what's used

  const loadOverview = useCallback(async () => {
    try {
      setOverview(await getCase(jobId));
    } catch (err) {
      setError(detail(err, 'Failed to load the case'));
    }
  }, [jobId]);

  const loadShared = useCallback(async () => {
    try {
      const [f, n, a] = await Promise.all([getFindings(jobId, true), getCaseNotes(jobId), getCaseActivity(jobId)]);
      setFindings(f);
      setNotes(n);
      setActivity(a);
    } catch (err) {
      setError(detail(err, 'Failed to load findings'));
    }
  }, [jobId]);

  useEffect(() => {
    getJob(jobId).then(setJob).catch(() => {});
    getCaseBrand(jobId).then(setCaseBrand).catch(() => {}); // 403 for analysts: no picker
    loadOverview();
    loadShared();
    getAuthConfig()
      .then((config) => (config.server_mode ? getUserDirectory().then(setPeople) : null))
      .catch(() => {});
    // The live socket says when anything changes; polling stands in while it's down
    let socket = null;
    let live = false;
    let retry = null;
    let wait = 2000;
    let closed = false;
    let initial = true; // the first message is the state just loaded; after a reconnect it isn't
    const connect = () => {
      socket = new WebSocket(caseLiveUrl(jobId));
      socket.onopen = () => { live = true; wait = 2000; };
      socket.onmessage = () => {
        if (!initial) { loadShared(); loadOverview(); }
        initial = false;
      };
      socket.onclose = () => {
        live = false;
        if (!closed) retry = setTimeout(connect, wait);
        wait = Math.min(wait * 2, 60000);
      };
    };
    connect();
    const timer = setInterval(() => { if (!live) { loadShared(); loadOverview(); } }, POLL_MS);
    return () => {
      closed = true;
      clearInterval(timer);
      clearTimeout(retry);
      socket.close();
    };
  }, [jobId, loadOverview, loadShared]);

  useEffect(() => {
    if (!selected) return;
    getCaseRows(jobId, { host: selected.host, path: selected.path, q: query, offset, limit: PAGE })
      .then((rows) => { setTable(rows); setError(''); })
      .catch((err) => setError(detail(err, 'Failed to read the table')));
  }, [jobId, selected, query, offset]);

  const act = async (action) => {
    try {
      await action();
      await loadShared();
      await loadOverview();
    } catch (err) {
      setError(detail(err, 'Request failed'));
      // A 409 means a colleague got there first: show what they did
      if (err.response?.status === 409) await loadShared();
    }
  };

  const open = (host, path) => {
    setSelected({ host, path });
    setOffset(0);
    setTable(null);
    setFlagging(null);
    setExpanded(null);
  };

  const submitFlag = (event) => {
    event.preventDefault();
    act(async () => {
      await flagFinding(jobId, { host: selected.host, artefact: selected.path, row_ref: flagging.ref,
        title: flagging.title, technique: flagging.technique, status: flagging.status });
      setFlagging(null);
    });
  };

  const caseReport = async (format) => {
    setBuilding(format);
    try {
      download(`${job?.case_number || jobId}_report.${format === 'docx' ? 'docx' : 'md'}`,
        await getCaseFullReport(jobId, format),
        format === 'docx' ? 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' : 'text/markdown');
      await loadShared(); // the export is in the activity feed
    } catch (err) {
      // The response was asked for as a blob, so an error's detail is in one too
      let message = err.message || 'The report failed';
      try { message = JSON.parse(await err.response.data.text()).detail || message; } catch { /* not JSON */ }
      setError(message);
    } finally {
      setBuilding('');
    }
  };

  const flaggedRefs = new Set(findings.filter((f) => selected && f.host === selected.host && f.artefact === selected.path)
    .map((f) => f.row_ref));
  const caseNotes = notes.filter((n) => n.finding_id === null);
  const columns = table ? table.columns.filter((c) => !ENVELOPE.has(c)) : [];
  const title = job ? `Case ${job.case_number}` : 'Case';

  return (
    <div className="job-list journey-detail">
      <PageHero title={title}>
        The case's cooked artefacts and analysis, read-only. Flag rows as findings, confirm or dismiss them,
        and keep notes; Findings and the Navigator layer are built from confirmed findings only. The case
        report (DOCX or Markdown) puts confirmed findings first, then Elrond's own report of the case:
        techniques with the rows behind them, indicators, Gandalf's integrity check and the method.
      </PageHero>

      <div className="card" style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <Link to={`/jobs/${jobId}`}><button>← Back to Job</button></Link>
        <span style={{ flex: 1 }} />
        {overview && Object.entries(overview.findings).map(([status, count]) => (
          <span key={status} style={{ color: STATUS_COLOURS[status] }}>{count} {status}</span>
        ))}
        <button type="button" onClick={() => act(async () => download(`${job?.case_number || jobId}-findings.md`,
          await getCaseReport(jobId), 'text/markdown'))}>Findings</button>
        <span style={{ display: 'inline-flex', gap: '0.25rem', alignItems: 'center' }}>
          {building && <span style={{ color: '#888' }}>Building the report…</span>}
          <button type="button" disabled={!!building} title="Confirmed findings first, then Elrond's report of the case"
            onClick={() => caseReport('docx')}>Report (DOCX)</button>
          <button type="button" disabled={!!building} onClick={() => caseReport('markdown')}>Report (Markdown)</button>
        </span>
        {caseBrand && caseBrand.brands.length > 0 && (
          <label title={caseBrand.brand_library ? 'The Word report uses this brand'
            : 'Kept for the case; a brand per case is used on the Services edition'}>
            Brand{' '}
            <select aria-label="The case's brand" value={caseBrand.brand_id || ''}
              onChange={(e) => act(async () => setCaseBrand(await chooseCaseBrand(jobId, e.target.value || null)))}>
              <option value="">The installation's</option>
              {caseBrand.brands.map((b) => <option key={b.id} value={b.id}>{b.name}</option>)}
            </select>
            {!caseBrand.brand_library && <span style={{ color: '#888' }}> (not used on this edition)</span>}
          </label>
        )}
        <button type="button" onClick={() => act(async () => download(`${job?.case_number || jobId}-confirmed-layer.json`,
          JSON.stringify(await getConfirmedLayer(jobId), null, 2), 'application/json'))}>Navigator layer</button>
      </div>

      {error && <div className="error">{error}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(16rem, 1fr) 3fr', gap: '1rem', alignItems: 'start' }}>
        <div data-guide="case.hosts" className="card case-browser" style={{ maxHeight: '80vh', overflowY: 'auto' }}>
          <h3>Hosts</h3>
          {!overview ? <p>Loading…</p> : overview.hosts.map((host) => (
            <details key={host.host} open={overview.hosts.length === 1}>
              <summary><strong>{host.host}</strong> <span style={{ color: '#888' }}>{host.assignee ? `· ${host.assignee}` : ''} · {host.status}</span></summary>
              <div className="case-host-controls">
                <input type="text" list="case-people" placeholder="Assigned to" aria-label="Assigned to" defaultValue={host.assignee}
                  onBlur={(e) => e.target.value !== host.assignee && act(() => assignHost(jobId, host.host, { assignee: e.target.value }))} />
                <select aria-label="Status" value={host.status} onChange={(e) => act(() => assignHost(jobId, host.host, { status: e.target.value }))}>
                  {HOST_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              {byFolder(host.files).map(([folder, files]) => {
                const links = files.map((file) => (
                  <button key={file.path} type="button" title={file.path} onClick={() => open(host.host, file.path)}
                    className={`case-table-link${selected?.host === host.host && selected?.path === file.path ? ' selected' : ''}`}>
                    {tableName(file.path)}
                  </button>
                ));
                return folder ? (
                  <details key={folder} className="case-folder" open={files.some((f) => selected?.host === host.host && selected?.path === f.path)}>
                    <summary>{folder} <span className="case-count">{files.length}</span></summary>
                    {links}
                  </details>
                ) : <div key="(loose)">{links}</div>;
              })}
            </details>
          ))}
          {overview?.case_files.length > 0 && (
            <details>
              <summary><strong>Case files</strong></summary>
              {overview.case_files.map((file) => (
                <div key={file.path}>
                  <button type="button" title={file.path} onClick={() => open(CASE_HOST, file.path)}
                    className={`case-table-link${selected?.host === CASE_HOST && selected?.path === file.path ? ' selected' : ''}`}>
                    {tableName(file.path)}
                  </button>
                </div>
              ))}
            </details>
          )}
          <datalist id="case-people">{people.map((p) => <option key={p.username} value={p.username} />)}</datalist>
        </div>

        <div data-guide="case.table" className="card case-browser" style={{ minWidth: 0 }}>
          {!selected ? <p>Pick a table on the left.</p> : (
            <>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'baseline' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <h3 style={{ margin: 0 }}>{selected.host === CASE_HOST ? '' : `${selected.host}: `}{tableName(selected.path)}</h3>
                  <div className="case-source">
                    {selected.path}{table?.rows[0]?.cells.source_path ? ` · from ${table.rows[0].cells.source_path}` : ''}
                  </div>
                </div>
                <button type="button" title={query ? 'The rows matching the filter' : 'Every row'}
                  onClick={() => act(async () => download(
                    `${selected.host === CASE_HOST ? '' : `${selected.host}_`}${selected.path.split('/').pop().replace(/\.[^.]+$/, '')}.csv`,
                    await getCaseRowsCsv(jobId, { host: selected.host, path: selected.path, q: query }), 'text/csv'))}>
                  Download as CSV
                </button>
              </div>
              <input type="text" style={{ width: '100%', marginBottom: '0.5rem' }} placeholder="Filter rows (any field)" value={query}
                onChange={(e) => { setQuery(e.target.value); setOffset(0); }} />
              {table && (
                <>
                  <div className="table-container" style={{ overflowX: 'auto', maxHeight: '60vh' }}>
                    <table className="case-rows">
                      <thead>
                        <tr><th>Row</th>{columns.map((c) => <th key={c}>{c.replace(/_/g, ' ')}</th>)}</tr>
                      </thead>
                      <tbody>
                        {table.rows.map((row) => (
                          <React.Fragment key={row.ref}>
                            <tr className={`${flaggedRefs.has(row.ref) ? 'flagged' : ''}${expanded === row.ref ? ' open' : ''}`}
                              onClick={() => setExpanded(expanded === row.ref ? null : row.ref)} title="Show the whole row">
                              <td className="case-row-ref">
                                {selected.host !== CASE_HOST && (
                                  <button type="button" title="Flag as finding" className="case-flag"
                                    onClick={(e) => { e.stopPropagation(); setFlagging({ ref: row.ref, title: '', technique: '', status: 'lead' }); }}>⚑</button>
                                )}
                                {row.ref}
                              </td>
                              {columns.map((c) => (
                                <td key={c}>
                                  {c === 'techniques'
                                    ? techniqueList(row.cells[c]).map((t) => <span key={t} className="case-technique">{t}</span>)
                                    : row.cells[c]}
                                </td>
                              ))}
                            </tr>
                            {expanded === row.ref && (
                              <tr className="case-row-detail">
                                <td colSpan={columns.length + 1}>
                                  <dl>
                                    {table.columns.filter((c) => row.cells[c] !== '' && row.cells[c] !== 'null' && row.cells[c] !== '[]').map((c) => (
                                      <React.Fragment key={c}>
                                        <dt>{c.replace(/_/g, ' ')}</dt>
                                        <dd><pre>{pretty(row.cells[c])}</pre></dd>
                                      </React.Fragment>
                                    ))}
                                  </dl>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginTop: '0.5rem' }}>
                    <button type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
                    <span>{table.total ? `${offset + 1}–${offset + table.rows.length} of ${table.total.toLocaleString()}${table.exact ? '' : '+'}` : 'No rows'}</span>
                    <button type="button" disabled={table.exact && offset + PAGE >= table.total} onClick={() => setOffset(offset + PAGE)}>Next</button>
                  </div>
                </>
              )}
              {flagging && (
                <form onSubmit={submitFlag} style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '1rem' }}>
                  <strong style={{ alignSelf: 'center' }}>Flag row {flagging.ref}</strong>
                  <input type="text" required autoFocus placeholder="What it is" value={flagging.title} style={{ flex: 2, minWidth: '12rem' }}
                    onChange={(e) => setFlagging({ ...flagging, title: e.target.value })} />
                  <input type="text" placeholder="T1053.003" value={flagging.technique} style={{ width: '8rem' }}
                    onChange={(e) => setFlagging({ ...flagging, technique: e.target.value })} />
                  <select value={flagging.status} onChange={(e) => setFlagging({ ...flagging, status: e.target.value })}>
                    <option value="lead">lead</option><option value="confirmed">confirmed</option>
                  </select>
                  <button type="submit">Flag</button>
                  <button type="button" className="secondary" onClick={() => setFlagging(null)}>Cancel</button>
                </form>
              )}
            </>
          )}
        </div>
      </div>

      <div data-guide="case.findings" className="card">
        <h3>Findings</h3>
        {findings.length === 0 ? <p>None yet: flag a row with ⚑.</p> : findings.map((f) => (
          <div key={f.id} style={{ borderLeft: `3px solid ${STATUS_COLOURS[f.status]}`, padding: '0.25rem 0.75rem', marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <strong>#{f.id} {f.title}</strong>
              {f.technique && <span style={{ color: '#66d9ef' }}>{f.technique}</span>}
              <select value={f.status} onChange={(e) => act(() => updateFinding(jobId, f.id, { status: e.target.value, updated_at: f.updated_at }))}>
                <option value="lead">lead</option><option value="confirmed">confirmed</option><option value="benign">benign</option>
              </select>
              <button type="button" className="link" style={{ background: 'none', border: 'none', color: '#f0dba5', cursor: 'pointer', textDecoration: 'underline' }}
                onClick={() => open(f.host, f.artefact)}>{f.host}: {f.artefact} row {f.row_ref}</button>
              {f.intact === false && <span style={{ color: '#ed5565' }} title="The row no longer reads as it did when flagged: the case was re-run or the file changed">row changed</span>}
              <span style={{ color: '#888' }}>{f.author}, {when(f.created_at)}</span>
              <span style={{ flex: 1 }} />
              <button type="button" className="secondary" onClick={() => window.confirm(`Remove finding #${f.id}?`) && act(() => deleteFinding(jobId, f.id))}>Remove</button>
            </div>
            <div style={{ fontSize: '0.8rem', color: '#bbb', margin: '0.25rem 0', wordBreak: 'break-all' }}>{f.excerpt}</div>
            {notes.filter((n) => n.finding_id === f.id).map((n) => (
              <div key={n.id} style={{ fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}><em>{n.author}:</em> {n.body}</div>
            ))}
            <form style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }} onSubmit={(e) => {
              e.preventDefault();
              act(async () => { await addCaseNote(jobId, findingNote[f.id], f.id); setFindingNote({ ...findingNote, [f.id]: '' }); });
            }}>
              <input type="text" style={{ flex: 1 }} placeholder="Add a note" value={findingNote[f.id] || ''}
                onChange={(e) => setFindingNote({ ...findingNote, [f.id]: e.target.value })} />
              <button type="submit" disabled={!findingNote[f.id]}>Note</button>
            </form>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(20rem, 1fr))', gap: '1rem' }}>
        <div data-guide="case.notes" className="card">
          <h3>Case notes</h3>
          {caseNotes.map((n) => (
            <div key={n.id} style={{ marginBottom: '0.75rem' }}>
              <div style={{ color: '#888', fontSize: '0.8rem' }}>{n.author}, {when(n.created_at)}</div>
              <div style={{ whiteSpace: 'pre-wrap' }}>{n.body}</div>
            </div>
          ))}
          <textarea rows={4} style={{ width: '100%' }} placeholder="Markdown: scope, hand-over, what's left" value={caseNote}
            onChange={(e) => setCaseNote(e.target.value)} />
          <button type="button" disabled={!caseNote.trim()} onClick={() => act(async () => { await addCaseNote(jobId, caseNote); setCaseNote(''); })}>Add note</button>
        </div>
        <div data-guide="case.activity" className="card" style={{ maxHeight: '30rem', overflowY: 'auto' }}>
          <h3>Activity</h3>
          {activity.length === 0 ? <p>Nothing yet.</p> : activity.map((a) => (
            <div key={a.id} style={{ fontSize: '0.85rem', marginBottom: '0.35rem' }}>
              <span style={{ color: '#888' }}>{when(a.created_at)}</span> <strong>{a.actor}</strong> {a.action} {a.detail}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default CaseBrowser;
