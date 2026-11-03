import React, { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  getJob,
  getCase,
  getCaseRows,
  getFindings,
  flagFinding,
  updateFinding,
  deleteFinding,
  getCaseNotes,
  addCaseNote,
  assignHost,
  getCaseActivity,
  getCaseReport,
  getConfirmedLayer,
  getAuthConfig,
  getUserDirectory,
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

// A case's tables, read-only, with findings flagged on their rows, notes, who has which host,
// and what everyone has done. Polls, which is enough for a team of this size.
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
    loadOverview();
    loadShared();
    getAuthConfig()
      .then((config) => (config.server_mode ? getUserDirectory().then(setPeople) : null))
      .catch(() => {});
    const timer = setInterval(() => { loadShared(); loadOverview(); }, POLL_MS);
    return () => clearInterval(timer);
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
  };

  const submitFlag = (event) => {
    event.preventDefault();
    act(async () => {
      await flagFinding(jobId, { host: selected.host, artefact: selected.path, row_ref: flagging.ref,
        title: flagging.title, technique: flagging.technique, status: flagging.status });
      setFlagging(null);
    });
  };

  const flaggedRefs = new Set(findings.filter((f) => selected && f.host === selected.host && f.artefact === selected.path)
    .map((f) => f.row_ref));
  const caseNotes = notes.filter((n) => n.finding_id === null);
  const title = job ? `Case ${job.case_number}` : 'Case';

  return (
    <div className="job-list journey-detail">
      <PageHero title={title}>
        The case's cooked artefacts and analysis, read-only. Flag rows as findings, confirm or dismiss them,
        and keep notes; the report and Navigator layer are built from confirmed findings only.
      </PageHero>

      <div className="card" style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <Link to={`/jobs/${jobId}`}><button>← Back to Job</button></Link>
        <span style={{ flex: 1 }} />
        {overview && Object.entries(overview.findings).map(([status, count]) => (
          <span key={status} style={{ color: STATUS_COLOURS[status] }}>{count} {status}</span>
        ))}
        <button type="button" onClick={() => act(async () => download(`${job?.case_number || jobId}-findings.md`,
          await getCaseReport(jobId), 'text/markdown'))}>Report</button>
        <button type="button" onClick={() => act(async () => download(`${job?.case_number || jobId}-confirmed-layer.json`,
          JSON.stringify(await getConfirmedLayer(jobId), null, 2), 'application/json'))}>Navigator layer</button>
      </div>

      {error && <div className="error">{error}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(16rem, 1fr) 3fr', gap: '1rem', alignItems: 'start' }}>
        <div data-guide="case.hosts" className="card" style={{ maxHeight: '80vh', overflowY: 'auto' }}>
          <h3>Hosts</h3>
          {!overview ? <p>Loading…</p> : overview.hosts.map((host) => (
            <details key={host.host} open={overview.hosts.length === 1}>
              <summary><strong>{host.host}</strong> <span style={{ color: '#888' }}>{host.assignee ? `· ${host.assignee}` : ''} · {host.status}</span></summary>
              <div style={{ display: 'flex', gap: '0.25rem', margin: '0.5rem 0' }}>
                <input type="text" list="case-people" placeholder="Assignee" defaultValue={host.assignee} style={{ flex: 1, minWidth: 0 }}
                  onBlur={(e) => e.target.value !== host.assignee && act(() => assignHost(jobId, host.host, { assignee: e.target.value }))} />
                <select value={host.status} onChange={(e) => act(() => assignHost(jobId, host.host, { status: e.target.value }))}>
                  {HOST_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              {host.files.map((file) => (
                <div key={file.path}>
                  <button type="button" onClick={() => open(host.host, file.path)}
                    style={{ background: 'none', border: 'none', padding: '0.1rem 0', cursor: 'pointer', textAlign: 'left',
                      color: selected?.host === host.host && selected?.path === file.path ? '#66d9ef' : '#f0dba5' }}>
                    {file.path.replace(/^artefacts\/cooked\//, '')}
                  </button>
                </div>
              ))}
            </details>
          ))}
          {overview?.case_files.length > 0 && (
            <details>
              <summary><strong>Case files</strong></summary>
              {overview.case_files.map((file) => (
                <div key={file.path}>
                  <button type="button" onClick={() => open(CASE_HOST, file.path)}
                    style={{ background: 'none', border: 'none', padding: '0.1rem 0', cursor: 'pointer', color: '#f0dba5' }}>
                    {file.path}
                  </button>
                </div>
              ))}
            </details>
          )}
          <datalist id="case-people">{people.map((p) => <option key={p.username} value={p.username} />)}</datalist>
        </div>

        <div data-guide="case.table" className="card" style={{ minWidth: 0 }}>
          {!selected ? <p>Pick a table on the left.</p> : (
            <>
              <h3 style={{ wordBreak: 'break-all' }}>{selected.host === CASE_HOST ? '' : `${selected.host}: `}{selected.path}</h3>
              <input type="text" style={{ width: '100%', marginBottom: '0.5rem' }} placeholder="Filter rows (any field)" value={query}
                onChange={(e) => { setQuery(e.target.value); setOffset(0); }} />
              {table && (
                <>
                  <div className="table-container" style={{ overflowX: 'auto', maxHeight: '60vh' }}>
                    <table style={{ fontSize: '0.8rem' }}>
                      <thead>
                        <tr><th>Row</th>{selected.host !== CASE_HOST && <th />}{table.columns.map((c) => <th key={c}>{c}</th>)}</tr>
                      </thead>
                      <tbody>
                        {table.rows.map((row) => (
                          <tr key={row.ref} style={flaggedRefs.has(row.ref) ? { background: 'rgba(237, 85, 101, 0.12)' } : undefined}>
                            <td>{row.ref}</td>
                            {selected.host !== CASE_HOST && (
                              <td>
                                <button type="button" title="Flag as finding" style={{ padding: '0.1rem 0.4rem' }}
                                  onClick={() => setFlagging({ ref: row.ref, title: '', technique: '', status: 'lead' })}>⚑</button>
                              </td>
                            )}
                            {table.columns.map((c) => (
                              <td key={c} style={{ maxWidth: '28rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                                title={row.cells[c]}>{row.cells[c]}</td>
                            ))}
                          </tr>
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
