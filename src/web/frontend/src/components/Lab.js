import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  getLabStatus,
  getLabState,
  saveLabConfig,
  setLabPassword,
  runLabCommand,
  listLabRuns,
  getLabRun,
  cancelLabRun,
} from '../api';

const errorText = (err) => {
  const detail = err.response?.data?.detail;
  if (!detail) return err.message;
  return typeof detail === 'string' ? detail : JSON.stringify(detail);
};

const SETTINGS = [
  ['LAB_DATA_DIR', 'Lab data directory', 'Collected acquisitions and Mordor datasets go here.'],
  ['TEST_IMAGES_PATH', 'Test images root', "Dernvale's test root; the lab writes gandalf/ and mordor/ under it when set."],
  ['LAB_VM_DIR', 'VM directory', 'Vagrant boxes, VirtualBox and Tart VMs.'],
  ['WINDOWS_VM_CPUS', 'Windows VM CPUs', ''],
  ['WINDOWS_VM_MEMORY_MB', 'Windows VM memory (MB)', ''],
  ['LINUX_VM_MEMORY_MB', 'Linux VM memory (MB)', ''],
  ['LAB_HIDDEN_MACHINES', 'Hidden machines', "VMs on this host the lab doesn't show, e.g. another project's (space-separated)."],
];

const DIR_KEYS = ['LAB_DATA_DIR', 'TEST_IMAGES_PATH', 'LAB_VM_DIR', 'LAB_HIDDEN_MACHINES'];  // the first row
const IMG = `${process.env.PUBLIC_URL}/images/mordor`;
const STATUS_ICON = { succeeded: '✅', failed: '❌', cancelled: '⏹️', running: '⏳' };
const formatTime = (t) => (t ? new Date(t * 1000).toLocaleString() : '—');

function AgentPanel({ status, onRecheck }) {
  return (
    <div className="card">
      <h2>Lab agent not running</h2>
      <p>
        The lab's containers and VMs run on this machine, outside Dernvale's containers, so the web UI drives
        them through a small agent on the host. Start it from the repository on the machine running Dernvale:
      </p>
      <div className="lab-command"><code>cd lab && {status?.start_command || './lab.sh agent start'}</code></div>
      <p className="lab-note">
        It listens on loopback only and accepts nothing but the lab commands. First time? Run <code>./lab.sh</code>{' '}
        in a terminal and choose <em>Install prerequisites</em>, since that step needs your password.
      </p>
      {status?.detail && <p className="lab-note">Last error: {status.detail}</p>}
      <button onClick={onRecheck}>Check again</button>
    </div>
  );
}

function RunOutput({ run, onCancel, onClose }) {
  const preRef = useRef(null);
  useEffect(() => {
    if (preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight;
  }, [run?.output]);
  if (!run) return null;
  return (
    <div className="card">
      <div className="lab-run-head">
        <h3>
          <code>./lab.sh {run.label}</code> <span className={`lab-status lab-status-${run.status}`}>{run.status}</span>
        </h3>
        <div className="lab-actions">
          {run.status === 'running'
            ? <button className="secondary" onClick={onCancel}>Cancel</button>
            : <button className="secondary" onClick={onClose}>Close</button>}
        </div>
      </div>
      <pre ref={preRef} className="lab-output">{run.output || 'Starting…'}</pre>
    </div>
  );
}

// Recent runs, as tall as the Targets column beside it, paged by however many rows fit
function RecentRuns({ runs, onOpen }) {
  const bodyRef = useRef(null);
  const [perPage, setPerPage] = useState(8);
  const [page, setPage] = useState(0);
  useEffect(() => {
    const el = bodyRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return undefined;
    const fit = () => {
      const head = el.querySelector('thead')?.offsetHeight || 36;
      const row = el.querySelector('tbody tr')?.offsetHeight || 44;
      setPerPage(Math.max(1, Math.floor((el.clientHeight - head) / row)));
    };
    const ro = new ResizeObserver(fit);
    ro.observe(el);
    fit();
    return () => ro.disconnect();
  }, [runs.length]);
  const pages = Math.max(1, Math.ceil(runs.length / perPage));
  const current = Math.min(page, pages - 1);
  const shown = runs.slice(current * perPage, (current + 1) * perPage);
  return (
    <div className="card lab-runs">
      <h2>Recent runs</h2>
      <div className="lab-runs-body" ref={bodyRef}>
        {runs.length ? (
          <table className="lab-table">
            <thead><tr><th>Command</th><th>Status</th><th>Started</th><th /></tr></thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.id}>
                  <td><code>{r.label}</code></td>
                  <td className="lab-status-icon" title={r.status}>{STATUS_ICON[r.status] || r.status}</td>
                  <td>{formatTime(r.started)}</td>
                  <td><button className="secondary" onClick={() => onOpen(r.id)}>Output</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="lab-note">No runs yet. Commands from this page and Deploy show here.</p>}
      </div>
      {pages > 1 && (
        <div className="lab-pager">
          <button className="secondary" disabled={current === 0} onClick={() => setPage(current - 1)}>‹</button>
          <span>{current + 1} / {pages}</span>
          <button className="secondary" disabled={current >= pages - 1} onClick={() => setPage(current + 1)}>›</button>
        </div>
      )}
    </div>
  );
}

// section: 'settings' (host, settings, password) or 'lab' (targets, maintenance, runs)
function LabManage({ section = 'lab', children = null }) {
  const { user } = useAuth();
  const [status, setStatus] = useState(null);
  const [state, setState] = useState(null);
  const [settings, setSettings] = useState({});
  const [password, setPassword] = useState('');
  const [runs, setRuns] = useState([]);
  const [run, setRun] = useState(null);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);
  const offsetRef = useRef(0);
  const queueRef = useRef([]);      // further lab.sh commands to run once the current one succeeds
  const [unpicked, setUnpicked] = useState({});  // VMs deselected on a shared engine row

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const s = await getLabStatus();
      setStatus(s);
      if (!s.available) return;
      const st = await getLabState();
      setState(st);
      setSettings(st.config || {});
      setRuns(await listLabRuns());
      if (st.busy && !run) {
        offsetRef.current = 0;
        setRun({ ...st.busy, output: '' });
      }
    } catch (err) {
      setError(errorText(err));
    }
  }, [run]);

  useEffect(() => { refresh(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Follow the current run's output.
  useEffect(() => {
    if (!run || run.status !== 'running') return undefined;
    const timer = setInterval(async () => {
      try {
        const r = await getLabRun(run.id, offsetRef.current);
        offsetRef.current = r.offset;
        setRun((prev) => ({ ...r, output: (prev?.id === r.id ? prev.output || '' : '') + r.output }));
        if (r.status !== 'running') {
          setRuns(await listLabRuns());
          getLabState().then(setState).catch(() => {});
          const next = r.status === 'succeeded' ? queueRef.current.shift() : null;
          if (!next) queueRef.current = [];
          else start(next.command, next.args); // eslint-disable-line no-use-before-define
        }
      } catch (err) {
        setError(errorText(err));
      }
    }, 1500);
    return () => clearInterval(timer);
  }, [run?.id, run?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const start = async (command, args = [], confirmText = null) => {
    if (confirmText && !window.confirm(confirmText)) return;
    setError(null);
    try {
      const r = await runLabCommand(command, args);
      offsetRef.current = 0;
      setRun({ ...r, output: '' });
    } catch (err) {
      setError(errorText(err));
    }
  };

  const openRun = async (id) => {
    try {
      const r = await getLabRun(id, 0);
      offsetRef.current = r.offset;
      setRun(r);
    } catch (err) {
      setError(errorText(err));
    }
  };

  const saveSettings = async () => {
    setError(null);
    setMessage(null);
    const changed = Object.fromEntries(
      Object.entries(settings).filter(([k, v]) => String(v ?? '') !== String(state.config?.[k] ?? '')),
    );
    if (!Object.keys(changed).length) { setMessage('Nothing changed.'); return; }
    try {
      await saveLabConfig(changed);
      setMessage('Settings saved.');
      setState(await getLabState());
    } catch (err) {
      setError(errorText(err));
    }
  };

  const savePassword = async (value) => {
    setError(null);
    setMessage(null);
    try {
      await setLabPassword(value);
      setPassword('');
      setMessage(value ? 'Lab password stored in the host keyring.' : `Using the default lab password '${state.default_password}'.`);
      setState(await getLabState());
    } catch (err) {
      setError(errorText(err));
    }
  };

  if (user && user.role !== 'admin') {
    return <div className="lab"><div className="card"><h2>Lab</h2><p>Only admins can run the test lab.</p></div></div>;
  }
  if (!status) return <div className="lab"><div className="card">Checking the lab agent…</div></div>;
  if (!status.available) return <div className="lab"><AgentPanel status={status} onRecheck={refresh} /></div>;
  if (!state) return <div className="lab"><div className="card">{error || 'Loading…'}</div></div>;

  const host = state.host || {};
  const busy = run?.status === 'running';
  const vagrant = ['macos-x86_64', 'linux-x86_64'].includes(host.profile);
  const tart = host.profile === 'macos-arm64';
  const noPassword = !state.password_set;

  // A row per engine: its logo, then the machines on it. Where an engine runs more than one VM, each
  // OS logo toggles whether the row's buttons act on it; with several picked they run one after another.
  const img = (f, alt) => (f.includes('.')
    ? <img className="lab-logo" src={`${IMG}/${f}`} alt={alt} />
    : <span className="lab-logo-text">{f}</span>);
  const field = ([key, label, help]) => (
    <label key={key} className={`lab-field${DIR_KEYS.includes(key) ? '' : ' lab-field-narrow'}${key === 'WINDOWS_VM_MEMORY_MB' ? ' lab-field-winmem' : ''}`} title={help}>
      <span>{label}</span>
      <input type="text" value={settings[key] ?? ''} placeholder={help}
             onChange={(e) => setSettings({ ...settings, [key]: e.target.value })} />
    </label>
  );
  // Buttons line up in shared columns: up, down and reset take start, stop and delete's columns on the containers; buttons
  // only some rows have go on the left, the ones every row has on the right, status last.
  const slotOf = (a) => ({ up: 'start', down: 'stop', reset: 'delete' }[a] || a);
  const SLOT_ORDER = ['adopt', 'provision', 'create', 'delete', 'start', 'stop', 'status'];
  const slotsFor = (defs) => {
    const count = {};
    defs.forEach(([, , items, fixed]) => {
      new Set((fixed || items.flatMap((it) => it.actions)).map(slotOf)).forEach((sl) => { count[sl] = (count[sl] || 0) + 1; });
    });
    const rank = (sl) => (sl === 'status' ? Infinity : count[sl] * 100 + SLOT_ORDER.indexOf(sl));
    return Object.keys(count).sort((x, y) => rank(x) - rank(y));
  };
  const engineRow = ([key, engine, items, fixedActions = null], slots) => {
    const picked = items.filter((it) => !unpicked[it.id]);
    const actions = fixedActions || [...new Set(items.flatMap((it) => it.actions))];
    const run = (a) => {
      if (fixedActions) { start(items[0].command, [a], items[0].confirm?.[a]); return; }
      const todo = picked.filter((it) => it.actions.includes(a));
      if (a === 'delete' && !window.confirm(`Destroy ${todo.map((it) => it.name).join(' and ')}? The disk is deleted.`)) return;
      queueRef.current = todo.slice(1).map((it) => ({ command: it.command, args: [a] }));
      start(todo[0].command, [a]);
    };
    return (
      <tr key={key}>
        <td className="lab-target">
          <span title={engine[2]}>{img(engine[0], engine[1])}</span>
          <span className="lab-logo-sep" />
          {items.map((it) => (fixedActions || items.length === 1 ? (
            <span key={it.id} title={it.tip} className="lab-logo-toggle is-static">{img(it.logo, it.name)}</span>
          ) : (
            <button key={it.id} type="button" title={`${it.tip}${unpicked[it.id] ? ' (not selected)' : ''}`}
                    className={`lab-logo-toggle${unpicked[it.id] ? ' is-off' : ''}`}
                    onClick={() => setUnpicked({ ...unpicked, [it.id]: !unpicked[it.id] })}>
              {img(it.logo, it.name)}
            </button>
          )))}
        </td>
        {slots.map((slot) => {
          const a = actions.find((x) => slotOf(x) === slot);
          if (!a) return <td key={slot} className="lab-slot" />;
          const able = fixedActions || picked.some((it) => it.actions.includes(a));
          return (
            <td key={slot} className="lab-slot">
              <button className="secondary" onClick={() => run(a)}
                      disabled={busy || !able || (noPassword && ['create', 'adopt', 'up', 'reset'].includes(a))}>
                {a}
              </button>
            </td>
          );
        })}
      </tr>
    );
  };
  const vmActions = ['create', 'start', 'stop', 'delete', 'status'];
  const ubuntuVm = { id: 'linux-vm', command: 'linux-vm', logo: 'ubuntu.png', name: 'the Linux VM', actions: vmActions,
    tip: `Linux VM: Ubuntu with a real kernel (${tart ? 'Tart' : 'Vagrant'}), SSH on 127.0.0.1:2230. For memory acquisition and Mordor recording.` };
  const macosVm = { id: 'macos-vm', command: 'macos-vm', logo: 'macos.png', name: 'the macOS VM', actions: vmActions,
    tip: 'macOS VM: Sequoia (Tart), SSH on 127.0.0.1:2231' };
  const windowsVm = tart
    ? { id: 'windows-vm', command: 'windows-vm', logo: 'windows.svg', name: 'the Windows VM', actions: ['create', 'adopt', 'start', 'stop', 'delete', 'status'],
      tip: "Windows 11 ARM VM (UTM), SSH on 127.0.0.1:2232. create installs it unattended from the ARM64 ISO in the lab's isos/ folder (Microsoft's download is manual); adopt takes an installed VM from utm/ that has OpenSSH and provisions it." }
    : { id: 'windows-vm', command: 'windows-vm', logo: 'windows.svg', name: 'the Windows VM', actions: ['create', 'start', 'stop', 'provision', 'delete', 'status'],
      tip: 'Windows 11 VM (Vagrant)' };

  const targetRows = [
    ['docker', ['docker.png', 'Docker', 'Docker containers: quick to rebuild, no real kernel'], [
      { id: 'lab-ubuntu', logo: 'ubuntu.png', name: 'Ubuntu', command: 'linux-targets',
        tip: 'lab-ubuntu: Ubuntu 24.04 (Debian family, apt), SSH on 127.0.0.1:2221',
        confirm: { reset: 'Rebuild and re-seed all Linux containers?' } },
      { id: 'lab-rocky', logo: 'rocky.svg', name: 'Rocky', tip: 'lab-rocky: Rocky 9 (RHEL family, dnf), SSH on 127.0.0.1:2222' },
    ], ['up', 'down', 'reset', 'status']],
    ...(tart ? [['tart', ['tart.png', 'Tart', 'Tart VMs (Apple silicon)'], [ubuntuVm, macosVm]],
      ['utm', ['utm.svg', 'UTM', 'UTM (Windows on Apple silicon)'], [windowsVm]]] : []),
    ...(vagrant ? [['vagrant', ['Vagrant', 'Vagrant', 'Vagrant VMs'], [ubuntuVm, windowsVm]]] : []),
  ];
  const targetSlots = slotsFor(targetRows);

  return (
    <div className="lab">

      {error && <div className="card lab-error">{error} <button className="secondary" onClick={() => setError(null)}>Dismiss</button></div>}
      {message && <div className="card lab-message">{message}</div>}

      {section === 'settings' && (
        <div className="card">
          <h2>Lab host and settings</h2>
          <div className="lab-facts">
            <span><em>Profile</em>{host.label} <code>{host.profile}</code></span>
            <span><em>System</em>{host.os_version}, {host.ram_gb} GB RAM</span>
            <span><em>Docker</em>{host.docker === 'yes' ? 'running' : 'not running'}</span>
            <span><em>VMs</em>{host.vm_tool === 'none' ? 'not installed (./lab.sh install)' : host.vm_tool}</span>
            <span><em>Password</em>{state.password_default ? <>default <code>{state.default_password}</code></> : 'custom, in the keyring'}</span>
          </div>
          <div className="lab-actions">
            <button className="secondary" disabled={busy} onClick={() => start('check')}>Check prerequisites</button>
            <button className="secondary" disabled={busy} onClick={() => start('status')}>Status</button>
            <button className="secondary" onClick={refresh}>Refresh</button>
          </div>
          <div className="lab-fields lab-fields-dirs">
            {SETTINGS.filter(([key]) => DIR_KEYS.includes(key)).map(field)}
          </div>
          <div className="lab-fields-row">
            {SETTINGS.filter(([key]) => !DIR_KEYS.includes(key)).map(field)}
            <label className="lab-field lab-field-password" title="For the gandalf user on every target; a custom one goes in the host keyring. No quotes, backslashes or spaces. Targets created before a change keep their old password until they're re-created.">
              <span>Lab password</span>
              <div className="lab-inline">
                <input type="password" value={password} autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} />
                <button onClick={() => savePassword(password)} disabled={!password}>Set custom password</button>
                {!state.password_default && <button className="secondary" onClick={() => savePassword('')}>Use the default</button>}
              </div>
            </label>
            <button className="lab-save" onClick={saveSettings}>Save settings</button>
          </div>
        </div>
      )}

      <RunOutput
        run={run}
        onCancel={async () => { queueRef.current = []; try { setRun(await cancelLabRun(run.id).then((r) => ({ ...run, ...r }))); } catch (err) { setError(errorText(err)); } }}
        onClose={() => setRun(null)}
      />

      {section === 'lab' && (
      <>
      <div className="lab-split">
      <div className="lab-col">
      <div className="card">
        <h2>Targets</h2>
        <table className="lab-table lab-targets">
          <tbody>
            {targetRows.map((d) => engineRow(d, targetSlots))}
          </tbody>
        </table>
        <p className="lab-note">Hover over a logo for what it is and its SSH port. Click a VM's logo to leave it out of that row's commands.{noPassword && ' Set the lab password before creating targets.'}</p>
      </div>

            <div className="card">
        <h2>Maintenance</h2>
        <div>
          <div className="lab-actions">
            <button className="secondary" disabled={busy} onClick={() => start('dernvale-env')}>Dernvale test settings</button>
            <button className="secondary" disabled={busy} onClick={() => start('teardown', [], 'Remove all lab containers and VMs? Collected data and the lab password are kept.')}>Tear down lab</button>
          </div>
          <p className="lab-note">
            Test settings writes the paths <code>tests/scripts/run_test.py</code> needs and checks Dernvale's worker can
            read the lab's data directory. Teardown removes every target; collected data and the password are kept.
          </p>
        </div>
      </div>
      </div>
      <RecentRuns runs={runs} onOpen={openRun} />
      </div>

      {children}
      </>
      )}
    </div>
  );
}

// Aragorn → Settings (host, settings, password) and Aragorn → Lab (targets, maintenance, runs)
export default LabManage;
