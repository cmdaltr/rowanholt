// The lab's machines (src/mordor/lab, ported from Archer's Emulate page): this host's engines,
// the machines it can create, and every machine with its lifecycle, set-up and recording. Shown
// on Aragorn → Lab; driven on the host by the lab agent (lab/agent/mordor_api.py).
import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  getMordorLab,
  getMordorLabLogs,
  getMordorLabSteps,
  postMordorLab,
  getLabStatus,
  getLabRun,
  runLabCommand,
} from '../api';

const IMG = `${process.env.PUBLIC_URL}/images/mordor`;
const errorText = (err) => {
  const d = err.response?.data?.detail;
  if (!d) return err.message;
  return typeof d === 'string' ? d : JSON.stringify(d);
};
const OS_ICON = { windows: 'windows.svg', macos: 'macos.png', linux: 'tux.svg' };
const ENGINE_ICON = { docker: 'docker.png', tart: 'tart.png', utm: 'utm.svg' };
const ENGINE_NAME = { docker: 'Docker', tart: 'Tart', utm: 'UTM' };

const OsIcon = ({ os, name = '' }) => {
  let f = OS_ICON[os];
  if (os === 'linux' && /ubuntu/i.test(name)) f = 'ubuntu.png';
  if (os === 'linux' && /rocky/i.test(name)) f = 'rocky.svg';
  return f ? <img className="mt-icon" src={`${IMG}/${f}`} alt={os} /> : null;
};
const EngineIcon = ({ engine }) =>
  ENGINE_ICON[engine] ? <img className="mt-icon" src={`${IMG}/${ENGINE_ICON[engine]}`} alt={engine} /> : null;
function Modal({ title, onClose, children }) {
  useEffect(() => {
    const esc = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', esc);
    return () => document.removeEventListener('keydown', esc);
  }, [onClose]);
  return (
    <div className="mt-modal" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="mt-modal-box" role="dialog" aria-modal="true">
        <div className="mt-modal-head"><strong>{title}</strong><button className="mt-close" onClick={onClose} aria-label="Close">×</button></div>
        <div className="mt-modal-body">{children}</div>
      </div>
    </div>
  );
}

function NameDialog({ title, label, initial, hint, action, danger, onCancel, onGo }) {
  const [value, setValue] = useState(initial);
  const go = () => value.trim() && onGo(value.trim());
  return (
    <Modal title={title} onClose={onCancel}>
      <label className="mt-field">{label}
        <input type="text" value={value} autoFocus onChange={(e) => setValue(e.target.value)}
               onKeyDown={(e) => { if (e.key === 'Enter') go(); }} />
      </label>
      {hint && <p className="lab-note">{hint}</p>}
      <div className="mt-modal-actions">
        <button className="mt-pill" onClick={onCancel}>Cancel</button>
        <button className={danger ? 'secondary' : ''} onClick={go}>{action}</button>
      </div>
    </Modal>
  );
}

function RecordDialog({ machine, labWindows, onCancel, onRun }) {
  const [techs, setTechs] = useState('');
  const [revert, setRevert] = useState('clean');
  const [snapped, setSnapped] = useState(false);
  const [preview, setPreview] = useState(null);
  const body = { engine: machine.engine, name: machine.name, os: machine.os };
  const doPreview = async () => {
    try { setPreview(await postMordorLab('record', { ...body, techniques: techs, execute: false })); }
    catch (err) { setPreview({ error: errorText(err) }); }
  };
  return (
    <Modal title={`Record on ${machine.name}`} onClose={onCancel}>
      <label className="mt-field">ATT&amp;CK techniques
        <input type="text" value={techs} autoFocus placeholder="T1059.001, T1053.005" onChange={(e) => setTechs(e.target.value)} />
      </label>
      <p className="lab-note">
        Atomic Red Team runs every test of these in the machine and the logs land in <strong>Your lab</strong>.
        The tests change the machine: snapshot it first and revert after.
        {labWindows && ' This is the lab\'s Windows VM, so it records over SSH with ./lab.sh mordor-record.'}
      </p>
      <label className="mt-field">Revert to snapshot afterwards (optional)
        <input type="text" value={revert} onChange={(e) => setRevert(e.target.value)} />
      </label>
      {preview && (
        <div className="mt-preview">
          {preview.error && <div className="mt-warn">{preview.error}</div>}
          {(preview.warnings || []).length > 0 && <div className="mt-warn">Not ready: {preview.warnings.join('; ')}</div>}
          {preview.plan && <ol>{preview.plan.map((s, i) => <li key={i}>{s}</li>)}</ol>}
        </div>
      )}
      <label className="mt-confirm"><input type="checkbox" checked={snapped} onChange={(e) => setSnapped(e.target.checked)} /> I've snapshotted this machine and it's disposable</label>
      <div className="mt-modal-actions">
        <button className="mt-pill" onClick={doPreview} disabled={!techs.trim()}>Preview</button>
        <button className="secondary" disabled={!(snapped && techs.trim())}
                onClick={() => onRun({ ...body, techniques: techs, revert_to: labWindows ? '' : revert, execute: true })}>Run atomics</button>
      </div>
    </Modal>
  );
}

function IsoDialog({ hasLabWindows, onClose, onBuild }) {
  const [path, setPath] = useState('');
  const [result, setResult] = useState(null);
  const verify = async () => {
    if (!path.trim()) { setResult({ bad: true, text: 'Give the path first.' }); return; }
    setResult({ text: 'Checking…' });
    try {
      const r = await postMordorLab('verify-iso', { path });
      setResult({ bad: !r.ok_arm64, text: r.detail || r.error || '' });
    } catch (err) { setResult({ bad: true, text: errorText(err) }); }
  };
  return (
    <Modal title="Build a Windows VM from an ISO" onClose={onClose}>
      <ol className="mt-steps">
        <li>Download the official <strong>Windows 11 Arm64</strong> ISO from{' '}
          <a href="https://www.microsoft.com/software-download/windows11arm64" target="_blank" rel="noopener noreferrer">Microsoft</a> (~5 GB)
          into the lab's <code>isos</code> folder.</li>
        <li>Check it's the right installer:
          <label className="mt-field">Path to the .iso
            <input type="text" value={path} placeholder="/Volumes/…/lab/isos/Win11_arm64.iso" onChange={(e) => setPath(e.target.value)} />
          </label>
          <button className="mt-pill" onClick={verify}>Verify ISO</button>{' '}
          {result && <span className={result.bad ? 'mt-bad' : 'mt-good'}>{result.text}</span>}
        </li>
        <li>
          {hasLabWindows
            ? <>The lab's Windows VM already exists. For another, use <strong>Clone</strong> on it: no reinstall.</>
            : <>Let the lab build it unattended (<code>./lab.sh windows-vm create</code>: installs Windows, OpenSSH and the Gandalf target, about an hour), or build it yourself in UTM and use <strong>Set OS</strong> on it.</>}
        </li>
      </ol>
      <div className="mt-modal-actions">
        {!hasLabWindows && <button className="mt-pill" onClick={onBuild}>Build the lab's Windows VM</button>}
        <button onClick={onClose}>Done</button>
      </div>
    </Modal>
  );
}

function LabMachines({ onRecorded = () => {} }) {
  const [available, setAvailable] = useState(null);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [run, setRun] = useState(null);
  const [dialog, setDialog] = useState(null);
  const offsetRef = useRef(0);
  const pollRef = useRef(null);

  const refresh = useCallback(async () => {
    try {
      const s = await getLabStatus();
      setAvailable(s);
      if (!s.available) return;
      const d = await getMordorLab();
      setData(d);
      setError(null);
      if (d.busy && d.busy.status === 'running') setRun((r) => (r && r.id === d.busy.id ? r : { ...d.busy, output: '' }));
    } catch (err) { setError(errorText(err)); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Follow the running job's log until it finishes, then reload the machines
  useEffect(() => {
    if (!run || run.status !== 'running') return undefined;
    offsetRef.current = run.offset || 0;
    pollRef.current = setInterval(async () => {
      try {
        const r = await getLabRun(run.id, offsetRef.current);
        offsetRef.current = r.offset;
        setRun((prev) => ({ ...r, output: (prev?.output || '') + (r.output || '') }));
        if (r.status !== 'running') {
          clearInterval(pollRef.current);
          refresh();
          if (/record/.test(r.label)) onRecorded();
        }
      } catch (err) { clearInterval(pollRef.current); setError(errorText(err)); }
    }, 1500);
    return () => clearInterval(pollRef.current);
  }, [run?.id, run?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const post = async (verb, body) => {
    setDialog(null);
    try {
      const r = await postMordorLab(verb, body);
      if (r && r.id && r.status === 'running') setRun({ ...r, output: '' });
      else refresh();
      return r;
    } catch (err) { setError(errorText(err)); return null; }
  };

  if (available && !available.available) {
    // The lab panel below explains how to start the agent; one notice is enough
    return <p className="lab-note">The machines appear here once the lab agent is running (see below).</p>;
  }
  if (!data) return error ? <p className="lab-note mt-bad">{error}</p> : <p className="lab-note">Loading the lab…</p>;

  const taken = new Set(data.taken || []);
  const free = (stem) => { for (let n = 1; ; n += 1) { const c = `${stem}-${n}`; if (!taken.has(c)) return c; } };
  const byOs = new Map();
  (data.templates || []).forEach((t) => { if (!byOs.has(t.os)) byOs.set(t.os, []); byOs.get(t.os).push(t); });
  const utm = (data.host.engines || []).find((e) => e.key === 'utm');
  const utmVms = (data.machines || []).filter((m) => m.engine === 'utm');
  const hasLabWindows = utmVms.some((m) => m.name === data.lab_windows_vm);
  const busy = run && run.status === 'running';

  const act = (m, action) => {
    const base = { engine: m.engine, name: m.name };
    if (action === 'start' || action === 'stop') post('action', { ...base, action });
    else if (action === 'delete') {
      if (window.confirm(`Delete ${m.name}? This removes the machine and its snapshots for good.`)) post('action', { ...base, action });
    } else if (action === 'logs') {
      getMordorLabLogs(m.engine, m.name).then((r) => setDialog({ kind: 'logs', m, text: r.logs }))
        .catch((err) => setDialog({ kind: 'logs', m, text: errorText(err) }));
    } else if (action === 'provision') {
      if (m.name === data.lab_windows_vm) setDialog({ kind: 'provision', m, steps: [{ step: 'sensor', label: 'Sysmon, audit logging and Atomic Red Team (./lab.sh mordor-sensor)' }] });
      else getMordorLabSteps(m.os).then((r) => setDialog({ kind: 'provision', m, steps: r.steps || [] }));
    } else setDialog({ kind: action, m });
  };

  return (
    <>
      <div className="mt-host">
        <div>This host: <strong>{data.host.label}</strong> <span className="mt-dim">{data.host.os} · {data.host.arch}</span></div>
        <details>
          <summary>{data.host.label} supports the following platforms</summary>
          <ul className="mt-engines">
            {data.host.engines.map((e) => {
              const state = !e.supported ? 'not on this host' : e.running ? `ready · ${e.version}` : e.installed ? 'installed, not running' : 'not installed';
              const cls = !e.supported ? 'is-na' : e.running ? 'is-ready' : 'is-warn';
              return (
                <li key={e.key} className={`mt-engine ${cls}`}>
                  <div><EngineIcon engine={e.key} /><strong>{e.name}</strong> <span className="mt-dim">{state}</span></div>
                  <div className="mt-dim">{e.blurb || e.runs}</div>
                  {e.note && e.installed && !e.running && <div className="lab-note">{e.note}</div>}
                  {e.install && <code>{e.install}</code>}
                </li>
              );
            })}
          </ul>
        </details>
      </div>

      <div className="mt-cols">
        <div>
          <h3 className="mt-colhead">Create a machine</h3>
          {[...byOs].map(([os, group]) => (
            <div key={os} className="mt-template">
              <div className="mt-template-name"><OsIcon os={os} name={group[0].os_name} /><strong>{group[0].os_name}</strong></div>
              <p>{group[0].os_about}</p>
              <p className="mt-dim"><span>Records:</span> {group[0].os_records}</p>
              <div className="mt-row">
                {group.map((t) => (
                  <button key={t.id} className="mt-pill" disabled={!t.ready || busy} title={t.ready ? `Create with ${ENGINE_NAME[t.engine]}` : t.reason}
                          onClick={() => setDialog({ kind: 'create', t, name: free(`rowanholt-${t.id.replace(/-(vm|container)$/, '')}`) })}>
                    <EngineIcon engine={t.engine} /> Create
                  </button>
                ))}
              </div>
            </div>
          ))}
          {utm && utm.supported && (
            <div className="mt-template">
              <div className="mt-template-name"><EngineIcon engine="utm" /><strong>Windows &amp; others, via UTM</strong></div>
              {utm.running ? (
                <>
                  <p>Two ways to a Windows machine: clone one already built, or build one from Microsoft's ISO.</p>
                  <div className="mt-row">
                    <button className="mt-pill" disabled={busy} onClick={() => setDialog({ kind: 'clone-pick' })}><EngineIcon engine="utm" /> Clone existing</button>
                    <button className="mt-pill" disabled={busy} onClick={() => setDialog({ kind: 'iso' })}><OsIcon os="windows" /> From ISO</button>
                  </div>
                </>
              ) : (
                <p className="mt-dim">{utm.installed ? utm.note : 'Install UTM to run Windows 11 on ARM.'} {utm.install && <code>{utm.install}</code>}</p>
              )}
            </div>
          )}
        </div>

        <div>
          <h3 className="mt-colhead">Your machines</h3>
          {(data.machines || []).length === 0 && <p className="lab-note">No machines yet. Create one on the left.</p>}
          <ul className="mt-machines">
            {(data.machines || []).map((m) => (
              <li key={`${m.engine}/${m.name}`} className="mt-machine">
                <div className="mt-machine-head">
                  <span className={`mt-dot is-${m.state}`} title={m.state} />
                  <OsIcon os={m.os} name={m.name} /><strong>{m.name}</strong>
                  {m.lab && <span className="mt-badge" title="Built and deleted by ./lab.sh">lab</span>}
                </div>
                <div className="mt-dim"><EngineIcon engine={m.engine} /> {[m.engine, m.state, m.records && `records ${m.records}`].filter(Boolean).join(' · ')}</div>
                {(m.provisioned || []).length > 0 && <div className="mt-dim">set up: {m.provisioned.join(', ')}</div>}
                <div className="mt-row">
                  <button className="mt-pill" disabled={busy} onClick={() => act(m, m.state === 'running' ? 'stop' : 'start')}>{m.state === 'running' ? 'Stop' : 'Start'}</button>
                  <button className="mt-pill" disabled={busy} onClick={() => act(m, 'snapshot')}>Snapshot</button>
                  <button className="mt-pill" disabled={busy} onClick={() => act(m, 'revert')}>Revert</button>
                  {m.engine === 'utm' && <button className="mt-pill" disabled={busy} onClick={() => act(m, 'clone')}>Clone</button>}
                  {m.engine === 'utm' && !m.os && <button className="mt-pill" onClick={() => act(m, 'adopt')}>Set OS</button>}
                  {m.os && <button className="mt-pill" disabled={busy} onClick={() => act(m, 'provision')}>Set up</button>}
                  {m.os && <button className="mt-pill" disabled={busy} onClick={() => act(m, 'record')}>Record</button>}
                  <button className="mt-pill" onClick={() => act(m, 'logs')}>Logs</button>
                  {m.deletable && <button className="mt-pill mt-danger" disabled={busy} onClick={() => act(m, 'delete')}>Delete</button>}
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {error && <p className="lab-note mt-bad">{error}</p>}
      {run && (
        <div className="mt-job">
          <div className="lab-run-head">
            <h3>{run.label} <span className={`lab-status lab-status-${run.status}`}>{run.status}</span></h3>
            {run.status !== 'running' && <button className="mt-pill" onClick={() => setRun(null)}>Close</button>}
          </div>
          <pre className="lab-output">{run.output || 'Starting…'}</pre>
        </div>
      )}

      {dialog?.kind === 'create' && (
        <NameDialog title="Create a machine" label="Name" initial={dialog.name} action="Create"
                    hint="Letters, digits, dot, dash or underscore. Pulling the image can take a while."
                    onCancel={() => setDialog(null)} onGo={(name) => post('create', { template: dialog.t.id, name })} />
      )}
      {dialog?.kind === 'snapshot' && (
        <NameDialog title={`Snapshot ${dialog.m.name}`} label="Snapshot name" initial="clean" action="Snapshot"
                    hint={dialog.m.engine === 'tart' ? 'A Tart snapshot is a clone of the VM: instant on APFS until it diverges.' : ''}
                    onCancel={() => setDialog(null)} onGo={(snapshot) => post('action', { engine: dialog.m.engine, name: dialog.m.name, action: 'snapshot', snapshot })} />
      )}
      {dialog?.kind === 'revert' && (
        <NameDialog title={`Revert ${dialog.m.name}`} label="Snapshot to revert to" initial="clean" action="Revert" danger
                    hint="Everything since that snapshot is discarded."
                    onCancel={() => setDialog(null)} onGo={(snapshot) => post('action', { engine: dialog.m.engine, name: dialog.m.name, action: 'revert', snapshot })} />
      )}
      {dialog?.kind === 'clone' && (
        <NameDialog title={`Clone ${dialog.m.name}`} label="New machine name" initial={free(dialog.m.name.replace(/-\d+$/, ''))} action="Clone"
                    hint={`Copies the VM and its disk: a few minutes. The clone inherits ${dialog.m.name}'s OS and set-up; snapshot it before recording.`}
                    onCancel={() => setDialog(null)} onGo={(newName) => post('clone', { engine: 'utm', name: dialog.m.name, new_name: newName })} />
      )}
      {dialog?.kind === 'clone-pick' && (
        utmVms.length === 0 ? (
          <Modal title="Clone a Windows VM" onClose={() => setDialog(null)}>
            <p className="lab-note">No UTM VM to clone yet. Build one from an ISO first.</p>
            <div className="mt-modal-actions"><button onClick={() => setDialog(null)}>OK</button></div>
          </Modal>
        ) : (
          <Modal title="Clone a Windows VM" onClose={() => setDialog(null)}>
            <label className="mt-field">Clone from
              <select value={dialog.src || utmVms[0].name} onChange={(e) => setDialog({ ...dialog, src: e.target.value })}>
                {utmVms.map((m) => <option key={m.name} value={m.name}>{m.name}{m.os ? ` (${m.os})` : ''}</option>)}
              </select>
            </label>
            <p className="lab-note">Copies the VM. The clone inherits the source's OS and set-up; snapshot it before recording.</p>
            <div className="mt-modal-actions">
              <button className="mt-pill" onClick={() => setDialog(null)}>Cancel</button>
              <button onClick={() => { const src = dialog.src || utmVms[0].name; setDialog({ kind: 'clone', m: { engine: 'utm', name: src } }); }}>Next</button>
            </div>
          </Modal>
        )
      )}
      {dialog?.kind === 'iso' && (
        <IsoDialog hasLabWindows={hasLabWindows} onClose={() => setDialog(null)}
                   onBuild={async () => {
                     setDialog(null);
                     try { const r = await runLabCommand('windows-vm', ['create']); setRun({ ...r, output: '' }); }
                     catch (err) { setError(errorText(err)); }
                   }} />
      )}
      {dialog?.kind === 'adopt' && (
        <Modal title={`Set the OS for ${dialog.m.name}`} onClose={() => setDialog(null)}>
          <label className="mt-field">Operating system
            <select value={dialog.os || 'windows'} onChange={(e) => setDialog({ ...dialog, os: e.target.value })}>
              <option value="windows">Windows</option><option value="linux">Linux</option><option value="macos">macOS</option>
            </select>
          </label>
          <p className="lab-note">So Rowanholt knows how to turn on logging, install Atomic Red Team and record on it.</p>
          <div className="mt-modal-actions">
            <button className="mt-pill" onClick={() => setDialog(null)}>Cancel</button>
            <button onClick={() => post('adopt', { engine: dialog.m.engine, name: dialog.m.name, os: dialog.os || 'windows' })}>Save</button>
          </div>
        </Modal>
      )}
      {dialog?.kind === 'provision' && (
        <Modal title={`Set up ${dialog.m.name}`} onClose={() => setDialog(null)}>
          <p className="lab-note">Each step changes the machine. Snapshot it first.</p>
          <div className="mt-row">
            {dialog.steps.map((s) => (
              <button key={s.step} className="mt-pill" onClick={() => post('provision', { engine: dialog.m.engine, name: dialog.m.name, os: dialog.m.os, step: s.step })}>{s.label}</button>
            ))}
          </div>
        </Modal>
      )}
      {dialog?.kind === 'record' && (
        <RecordDialog machine={dialog.m} labWindows={dialog.m.name === data.lab_windows_vm}
                      onCancel={() => setDialog(null)} onRun={(body) => post('record', body)} />
      )}
      {dialog?.kind === 'logs' && (
        <Modal title={`Logs — ${dialog.m.name}`} onClose={() => setDialog(null)}>
          <pre className="lab-output">{dialog.text || 'No output'}</pre>
        </Modal>
      )}
    </>
  );
}

export default LabMachines;
