// Mordor → Recorded telemetry: where attack telemetry comes from (public datasets and the lab's
// own recordings), the lab that records it, and which logs record each technique. Ported from
// Archer's Emulate page (templates/emulate.html, static/js/lab.js, emulate.js); the engine is
// src/mordor/telemetry and the lab src/mordor/lab, driven on the host by the lab agent.
import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import MordorDatasets from './MordorLanding';
import {
  getTelemetryStatus,
  getTelemetryTechniques,
  getTelemetryTechnique,
  searchTelemetry,
  updateTelemetry,
  getLocalMordorDatasets,
  downloadMordorDataset,
} from '../api';

const IMG = `${process.env.PUBLIC_URL}/images/mordor`;
const errorText = (err) => {
  const d = err.response?.data?.detail;
  if (!d) return err.message;
  return typeof d === 'string' ? d : JSON.stringify(d);
};

// The public datasets, in the order the cards show them; counts and notes come from the API
const SOURCES = [
  { key: 'splunk', img: 'splunk.png', badge: 'Maintained' },
  { key: 'otrf', img: 'otrf.png', badge: 'Updated Mar 2024' },
  { key: 'evtx', img: 'evtx.png', badge: 'Maintained' },
  { key: 'macos', img: 'attack.png', badge: 'Local only' },
];
const PAGE = 50;


// ---------------------------------------------------------------- diagram

function Pipeline() {
  const node = (x, y, w, h, cls, icon, title, sub, iconCls) => (
    <g>
      <rect x={x} y={y} width={w} height={h} rx="8" className={cls} />
      <use href={`#mt-ic-${icon}`} x={x + 10} y={y + h / 2 - 9} width="18" height="18" className={`mt-dg-ic ${iconCls}`} />
      <text x={x + 34} y={sub ? y + h / 2 - 3 : y + h / 2 + 5} className="mt-dg-t">{title}</text>
      {sub && <text x={x + 34} y={y + h / 2 + 13} className="mt-dg-s">{sub}</text>}
    </g>
  );
  const arrow = (d) => <path d={d} className="mt-dg-link" markerEnd="url(#mt-dg-arrow)" />;
  return (
    <div className="mt-dg">
      <svg viewBox="0 0 960 250" role="img" aria-label="Your lab's recordings and the public datasets are mapped to ATT&CK, checked against detections' indicators, and shown as recorded telemetry">
        <defs>
          <marker id="mt-dg-arrow" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" className="mt-dg-head" />
          </marker>
          <symbol id="mt-ic-flask" viewBox="0 0 16 16"><path d="M6.5 2.5h3M7 2.5V6.5L4 12.2a1 1 0 0 0 .9 1.5h6.2a1 1 0 0 0 .9-1.5L9 6.5V2.5" /></symbol>
          <symbol id="mt-ic-db" viewBox="0 0 16 16"><ellipse cx="8" cy="4" rx="4.8" ry="1.9" /><path d="M3.2 4v8a4.8 1.9 0 0 0 9.6 0V4" /></symbol>
          <symbol id="mt-ic-doc" viewBox="0 0 16 16"><path d="M4 2.5h5l3 3v8H4z" /><path d="M6 8h4M6 10.5h4" /></symbol>
          <symbol id="mt-ic-target" viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.2" /><circle cx="8" cy="8" r="2" /></symbol>
          <symbol id="mt-ic-search" viewBox="0 0 16 16"><circle cx="7" cy="7" r="4" /><path d="M10 10l3.5 3.5" /></symbol>
          <symbol id="mt-ic-chart" viewBox="0 0 16 16"><path d="M3 13h10" /><path d="M5 12V8.5M8 12V5.5M11 12V7" /></symbol>
          <symbol id="mt-ic-create" viewBox="0 0 16 16"><rect x="2.5" y="3.5" width="11" height="8" rx="1.2" /><path d="M5.5 13.5h5M8 6v3.5M6.25 7.75h3.5" /></symbol>
          <symbol id="mt-ic-camera" viewBox="0 0 16 16"><rect x="2.3" y="4.8" width="11.4" height="7.4" rx="1.6" /><circle cx="8" cy="8.5" r="2.1" /><path d="M6.1 4.8l1-1.5h1.8l1 1.5" /></symbol>
          <symbol id="mt-ic-gear" viewBox="0 0 16 16"><circle cx="8" cy="8" r="2" /><path d="M8 2.6v2.1M8 11.3v2.1M2.6 8h2.1M11.3 8h2.1M4.2 4.2l1.5 1.5M10.3 10.3l1.5 1.5M11.8 4.2l-1.5 1.5M5.7 10.3l-1.5 1.5" /></symbol>
          <symbol id="mt-ic-play" viewBox="0 0 16 16"><circle cx="8" cy="8" r="5.3" /><path d="M6.6 5.5l4 2.5-4 2.5z" /></symbol>
        </defs>

        {/* The lab lane is the "Your lab" source, expanded */}
        <polygon points="16,120 196,20 760,92 176,168" className="mt-dg-expand" />
        <path d="M16,120 L196,20" className="mt-dg-expand-edge" />
        <path d="M176,168 L760,92" className="mt-dg-expand-edge" />
        <rect x="196" y="20" width="564" height="72" rx="12" className="mt-dg-lane-box" />
        <text x="208" y="38" className="mt-dg-lane">LAB — BUILD &amp; RECORD A MACHINE</text>
        {node(212, 48, 120, 40, 'mt-dg-loop', 'create', 'Create', null, 'is-lab')}
        {node(350, 48, 120, 40, 'mt-dg-loop', 'camera', 'Snapshot', null, 'is-lab')}
        {node(488, 48, 120, 40, 'mt-dg-loop', 'gear', 'Set up', 'logs & atomics', 'is-lab')}
        {node(626, 48, 120, 40, 'mt-dg-loop', 'play', 'Record', 'run atomics', 'is-lab')}
        {arrow('M332,68 L348,68')}{arrow('M470,68 L486,68')}{arrow('M608,68 L624,68')}

        {node(16, 120, 160, 48, 'mt-dg-origin', 'flask', 'Your lab', 'runs you record', 'is-lab')}
        {node(16, 182, 160, 48, 'mt-dg-pub', 'db', 'Public datasets', 'shipped with Rivendell', 'is-pub')}
        {arrow('M176,144 C194,144 192,170 206,172')}
        {arrow('M176,206 C194,206 192,180 206,178')}

        {node(208, 147, 168, 56, 'mt-dg-node', 'doc', 'Recordings', 'one tool run, logging on', 'is-blue')}
        {node(400, 147, 168, 56, 'mt-dg-node', 'target', 'Mapped to ATT&CK', 'technique · source', 'is-blue')}
        {node(592, 147, 168, 56, 'mt-dg-node', 'search', 'Indicator check', 'detections vs events', 'is-blue')}
        {node(784, 147, 160, 56, 'mt-dg-end', 'chart', 'Recorded telemetry', 'the views below', 'is-green')}
        {arrow('M376,175 L398,175')}{arrow('M568,175 L590,175')}{arrow('M760,175 L782,175')}
      </svg>
    </div>
  );
}

// ---------------------------------------------------------------- sources

function Sources({ status, isAdmin, onUpdate }) {
  if (!status) return <p className="lab-note">Loading…</p>;
  const info = status.sources || {};
  const count = status.per_source || {};
  const runs = status.lab_runs || [];
  const building = status.build?.state === 'running';
  return (
    <>
      <div className="mt-sources-head">
        <h3>Public datasets</h3>
        {isAdmin && (
          <button onClick={onUpdate} disabled={building} title="Fetch what the sources changed since the last build">
            {building ? 'Updating…' : 'Update'}
          </button>
        )}
      </div>
      <ul className="mt-sources">
        <li className="mt-source is-lab">
          <span className="mt-source-logo"><svg viewBox="0 0 16 16"><use href="#mt-ic-flask" /></svg></span>
          <div>
            <div className="mt-source-top"><strong>Your lab</strong><span className="mt-badge">{runs.length ? `${runs.length} run${runs.length === 1 ? '' : 's'}` : 'No runs yet'}</span></div>
            <div className="mt-source-meta">{count.lab || 0} recordings · yours, never committed</div>
            <div className="mt-source-note">Atomic Red Team on the lab's own machines, each test's logs kept apart (Aragorn → Deploy)</div>
          </div>
        </li>
        {SOURCES.filter(s => info[s.key]).map(s => (
          <li key={s.key} className="mt-source">
            <img className="mt-source-logo" src={`${IMG}/${s.img}`} alt="" />
            <div>
              <div className="mt-source-top">
                <a href={info[s.key].url} target="_blank" rel="noopener noreferrer">{info[s.key].name}</a>
                <span className="mt-badge">{s.badge}</span>
              </div>
              <div className="mt-source-meta">{(count[s.key] || 0).toLocaleString()} recordings · {info[s.key].licence}</div>
              <div className="mt-source-note">{info[s.key].note}</div>
            </div>
          </li>
        ))}
        {status.guide && (
          <li className="mt-source">
            <img className="mt-source-logo" src={`${IMG}/microsoft.png`} alt="" />
            <div>
              <div className="mt-source-top">
                <a href={status.guide.url} target="_blank" rel="noopener noreferrer">{status.guide.name}</a>
                <span className="mt-badge">Alerts, not logs</span>
              </div>
              <div className="mt-source-meta">{status.guide.techniques} techniques · {status.guide.licence}</div>
              <div className="mt-source-note">{status.guide.note}</div>
            </div>
          </li>
        )}
      </ul>
      <p className="lab-note">
        Each recording is one tool run in a lab with logging on (Sysmon, Windows auditing, PowerShell, cloud audit logs),
        mapped to ATT&amp;CK by the people who recorded it. It shows that a technique can be recorded and by which log,
        for that tool in that lab; not every way the technique can be done. The recordings ship with Rivendell;
        {' '}<strong>Update</strong> (or <code>python3 -m src.mordor.telemetry --build</code>) fetches what the sources have changed since.
      </p>
      {status.build && status.build.state !== 'idle' && (
        <pre className="lab-output">{(status.build.log || []).join('\n') || status.build.state}</pre>
      )}
    </>
  );
}

// ---------------------------------------------------------------- recorded telemetry

// An OTRF recording is a Security-Datasets dataset (otrf:SDWIN-… is catalogue SDWIN-…), so its raw
// events can be downloaded for Elrond to analyse (--Mordor), as the Downloadable datasets tab does
function DownloadButton({ id, local, onDone }) {
  const [state, setState] = useState(local.has(id) ? 'done' : 'idle');
  useEffect(() => { if (local.has(id)) setState('done'); }, [local, id]);
  const go = async () => {
    setState('busy');
    try { await downloadMordorDataset(id); setState('done'); onDone(); } catch (err) { setState('failed'); }
  };
  if (state === 'done') return <span className="mt-seen"> · downloaded for Elrond</span>;
  return (
    <button className="mt-pill mt-inline" disabled={state === 'busy'} onClick={go} title="Download the raw events so Elrond can analyse them (--Mordor)">
      {state === 'busy' ? 'Downloading…' : state === 'failed' ? 'Retry download' : 'Download for Elrond'}
    </button>
  );
}

function TechniqueDetail({ tid, local, onDownloaded }) {
  const [t, setT] = useState(null);
  useEffect(() => { getTelemetryTechnique(tid).then(setT).catch(() => setT({ error: true })); }, [tid]);
  if (!t) return <p className="lab-note">Loading…</p>;
  if (t.error) return <p className="lab-note mt-bad">Couldn't load {tid}</p>;
  const g = t.defender;
  return (
    <div className="mt-detail">
      {!t.exact && <p className="lab-note">No recording is mapped to {tid} itself; these are its {tid.includes('.') ? 'parent' : 'sub-techniques'}'.</p>}
      <p className="mt-dim">
        Logs most recordings hold: Defender XDR {(t.need?.mde || []).map((n) => n.name).join(', ') || '—'} ·
        Chronicle UDM {(t.need?.udm || []).map((n) => n.name).join(', ') || '—'}
      </p>
      {g ? (
        <p className="mt-dim"><img className="mt-icon" src={`${IMG}/microsoft.png`} alt="" /> Defender XDR alerting (Microsoft GUIDE): {g.alerts} alerts across {g.orgs} organisations, {Math.round((g.tp_rate || 0) * 100)}% true positives.</p>
      ) : (
        <p className="mt-dim">No Defender XDR alert in Microsoft GUIDE maps to this technique: a custom detection is where coverage comes from.</p>
      )}
      <table className="lab-table">
        <thead><tr><th>Log</th><th>Collection</th><th>Recordings</th><th>Events</th><th>Defender XDR</th><th>UDM</th></tr></thead>
        <tbody>
          {(t.event_types || []).slice(0, 25).map((r) => (
            <tr key={r.event} className={r.common ? 'mt-common' : ''} title={r.common ? 'Also in most recordings of other techniques (lab background)' : ''}>
              <td>{r.label}</td><td>{r.collection}</td><td>{r.recordings}</td><td>{r.events.toLocaleString()}</td><td>{r.mde}</td><td>{r.udm}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <ul className="mt-recordings">
        {(t.recordings || []).slice(0, 30).map((d) => (
          <li key={d.id}>
            <img className="mt-icon" src={`${IMG}/${(SOURCES.find((s) => s.key === d.source) || {}).img || 'tux.svg'}`} alt="" />
            {d.url ? <a href={d.url} target="_blank" rel="noopener noreferrer">{d.title}</a> : d.title}
            <span className="mt-dim"> · {d.platforms.join(', ')} · {d.events.toLocaleString()} events</span>
            {d.source === 'otrf' && <DownloadButton id={d.id.split(':')[1]} local={local} onDone={onDownloaded} />}
          </li>
        ))}
      </ul>
    </div>
  );
}

function TelemetryViews({ refreshKey }) {
  const [rows, setRows] = useState([]);
  const [local, setLocal] = useState(new Set());
  const loadLocal = useCallback(() => {
    getLocalMordorDatasets({ limit: 200 }).then((r) => setLocal(new Set((r.datasets || []).map((d) => d.dataset_id)))).catch(() => {});
  }, []);
  useEffect(() => { loadLocal(); }, [loadLocal]);
  const [platform, setPlatform] = useState('');
  const [collection, setCollection] = useState('');
  const [q, setQ] = useState('');
  const [found, setFound] = useState(null);
  const [page, setPage] = useState(0);
  const [open, setOpen] = useState(null);
  const [meta, setMeta] = useState({ collections: {}, platforms: {} });

  useEffect(() => {
    getTelemetryTechniques({ platforms: platform, collections: collection })
      .then((r) => { setRows(r.techniques || []); setMeta({ collections: r.collections || {}, platforms: r.platforms || {} }); setPage(0); })
      .catch(() => setRows([]));
  }, [platform, collection, refreshKey]);

  useEffect(() => {
    if (q.trim().length < 3) { setFound(null); return undefined; }
    const timer = setTimeout(() => searchTelemetry(q.trim()).then((r) => setFound(r.techniques || {})).catch(() => setFound({})), 400);
    return () => clearTimeout(timer);
  }, [q]);

  const shown = found ? rows.filter((r) => found[r.technique] || Object.keys(found).some((t) => t.startsWith(`${r.technique}.`))) : rows;
  const pageRows = shown.slice(page * PAGE, (page + 1) * PAGE);
  return (
    <>
      <div className="mt-filters">
        <input type="text" value={q} maxLength={200} onChange={(e) => setQ(e.target.value)}
               placeholder="Search recorded events (comsvcs, lsass.dmp, vssadmin…)" />
        <select className="large-select" value={platform} onChange={(e) => setPlatform(e.target.value)}>
          <option value="">All platforms</option>
          {Object.entries(meta.platforms).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select className="large-select" value={collection} onChange={(e) => setCollection(e.target.value)}>
          <option value="">All logging</option>
          {Object.entries(meta.collections).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
      </div>
      <p className="mt-dim mt-count">Showing {shown.length} of {rows.length} techniques</p>
      <table className="mt-techniques">
        <colgroup><col style={{ width: '13%' }} /><col style={{ width: '17%' }} /><col style={{ width: '36%' }} /><col style={{ width: '20%' }} /><col style={{ width: '14%' }} /></colgroup>
        <thead><tr><th>Technique</th><th>Recordings</th><th>Logs most recordings hold</th><th>Defender XDR</th><th>Platforms</th></tr></thead>
        <tbody>
          {pageRows.map((r) => (
            <React.Fragment key={r.technique}>
              <tr className="mt-click" onClick={() => setOpen(open === r.technique ? null : r.technique)}>
                <td><a href={`https://attack.mitre.org/techniques/${r.technique.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()}>{r.technique}</a></td>
                <td>{Object.entries(r.sources).map(([k, n]) => `${n} ${k}`).join(', ')}</td>
                <td>{found && found[r.technique] ? <span className="mt-seen">seen in {found[r.technique].slice(0, 3).join(', ')}</span> : r.logs.slice(0, 3).join(', ')}</td>
                <td>{r.mde.join(', ')}</td>
                <td>{r.platforms.join(', ')}</td>
              </tr>
              {open === r.technique && <tr><td colSpan="5"><TechniqueDetail tid={r.technique} local={local} onDownloaded={loadLocal} /></td></tr>}
            </React.Fragment>
          ))}
        </tbody>
      </table>
      {shown.length > PAGE && (
        <div className="mt-row mt-pager">
          <button className="mt-pill" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <span className="mt-dim">{page + 1} / {Math.ceil(shown.length / PAGE)}</span>
          <button className="mt-pill" disabled={(page + 1) * PAGE >= shown.length} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------- page

function MordorTelemetry() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [status, setStatus] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [error, setError] = useState(null);

  const loadStatus = useCallback(async () => {
    try { setStatus(await getTelemetryStatus()); } catch (err) { setError(errorText(err)); }
  }, []);
  useEffect(() => { loadStatus(); }, [loadStatus]);

  // Follow an Update until it's done, then reload everything that reads the data
  useEffect(() => {
    if (status?.build?.state !== 'running') return undefined;
    const timer = setTimeout(async () => {
      const s = await getTelemetryStatus().catch(() => null);
      if (s) {
        setStatus(s);
        if (s.build.state !== 'running') setRefreshKey((k) => k + 1);
      }
    }, 2000);
    return () => clearTimeout(timer);
  }, [status]);

  const update = async () => {
    try { await updateTelemetry(); loadStatus(); } catch (err) { setError(errorText(err)); }
  };

  return (
    <div className="journey-detail mt-page">
      <section className="hero-section">
        <img src={`${process.env.PUBLIC_URL}/images/rivendell.png`} alt="Mordor Recordings" className="hero-image"
             style={{ transform: 'scale(0.2)', transformOrigin: 'center top' }} />
      </section>
      <header>
        <h2>Mordor Recordings</h2>
        <p>Which logs record each ATT&amp;CK technique, from attacks emulated and recorded in labs, the lab that records your own, and the raw events to download for Elrond.</p>
      </header>
      {error && <div className="card lab-error">{error}</div>}

      <div data-guide="mordor.tiles" className="mt-tiles">
        <div className="mt-tile is-recordings"><div className="mt-num">{status ? status.datasets.toLocaleString() : '–'}</div><div>Recordings</div></div>
        <div className="mt-tile is-techniques"><div className="mt-num">{status ? status.techniques : '–'}</div><div>Techniques</div></div>
        <div className="mt-tile is-check"><div className="mt-num">{status ? (status.values ? 'Ready' : 'No values') : '–'}</div><div>Indicator check</div></div>
      </div>

      <div data-guide="mordor.generate" className="card">
        <h2>Generating telemetry</h2>
        <Pipeline />
        <p className="lab-note">
          Recordings are real attacks run in a lab with logging on: the public datasets that ship with Rivendell, plus any you
          record yourself in the lab (Aragorn → Deploy). Each is mapped to ATT&amp;CK, then Rivendell checks whether the
          indicators a detection matches actually appear in the recorded events. The result is the <strong>Recorded telemetry</strong>
          {' '}view below. No AI is involved.
        </p>
        <Sources status={status} isAdmin={isAdmin} onUpdate={update} />

        <h3 className="mt-labhead">Your lab</h3>
        <p className="lab-note">
          Record your own: the lab creates disposable containers and VMs, turns logging on, runs Atomic Red Team and brings
          each test's logs back here as <strong>Your lab</strong>. The machines are managed in Aragorn, with the rest of what
          Rivendell runs on this host.
        </p>
        <a className="mt-pill-link" href="/aragorn#deploy">Record in the lab →</a>
      </div>

      <div data-guide="mordor.recorded" className="card">
        <h2>Recorded telemetry</h2>
        <p className="lab-note">Every recorded technique and the logs most of its recordings hold. Open one for its recordings, the event types they hold and Defender XDR's alerting on it; an OTRF recording can be downloaded for Elrond to analyse. Search finds the techniques whose recorded events contain a value. Datasets that span several techniques (APT29's days, for example) are in <a href="#datasets">Downloadable datasets</a> below, with bulk download.</p>
        <TelemetryViews refreshKey={refreshKey} />
      </div>

      <MordorDatasets />
    </div>
  );
}

export default MordorTelemetry;
