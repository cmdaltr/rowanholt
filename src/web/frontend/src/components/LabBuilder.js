// Aragorn → Deploy: build a lab run step by step (Gandalf, Elrond or Mordor), review the plan, then
// Deploy. Each step is a lab agent run (lab.sh or src/mordor/lab) or an Elrond job; they run in
// order, each waiting for the one before, with the current one's log underneath.
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import {
  getLabStatus,
  getLabState,
  getLabRun,
  runLabCommand,
  getMordorLab,
  getMordorLabSteps,
  postMordorLab,
  createJob,
  getTelemetryStatus,
  updateTelemetry,
} from '../api';

const IMG = `${process.env.PUBLIC_URL}/images`;
const errorText = (err) => {
  const d = err.response?.data?.detail;
  if (!d) return err.message;
  return typeof d === 'string' ? d : JSON.stringify(d);
};

const TOOLS = [
  { key: 'gandalf', name: 'Gandalf', img: 'gandalf.png', blurb: 'Collect from lab targets: deploy a collector and bring the acquisition back.' },
  { key: 'elrond', name: 'Elrond', img: 'elrond.png', blurb: "Analyse what the lab collected: process, analyse and map it to ATT&CK." },
  { key: 'mordor', name: 'Mordor', img: 'middle_earth.png', blurb: 'Record attacks with Atomic Red Team on a lab machine, or fetch and update public datasets.' },
];
const PRESETS = {
  persistence: 'T1547.001,T1053.005,T1543.003',
  credential_access: 'T1003.001,T1552.001',
  defense_evasion: 'T1070.001,T1562.001,T1218.011',
  discovery: 'T1082,T1087.001,T1016',
};
const OTRF_GROUPS = {
  'APT29 days 1 and 2': ['apt29/day1', 'apt29/day2'],
  'Atomic sets (credential access, evasion, lateral movement, persistence)': [
    'atomic/credential_access', 'atomic/defense_evasion', 'atomic/lateral_movement', 'atomic/persistence'],
  'Every dataset the tests use': [],
};
const ELROND_PROFILES = {
  standard: { label: 'Process, analyse, extract IOCs', options: { analysis: true, extract_iocs: true } },
  brisk: { label: 'Brisk (adds Navigator and user profiles)', options: { brisk: true } },
  timeline: { label: 'Process, analyse, IOCs and a timeline', options: { analysis: true, extract_iocs: true, timeline: true } },
};

const OS_LOGO = { windows: 'windows.svg', macos: 'macos.png', linux: 'tux.svg' };
const osLogo = (m) => {
  let f = OS_LOGO[m.os] || 'tux.svg';
  if (m.os === 'linux' && /ubuntu/i.test(m.name)) f = 'ubuntu.png';
  if (m.os === 'linux' && /rocky/i.test(m.name)) f = 'rocky.svg';
  return `${IMG}/mordor/${f}`;
};

const Step = ({ n, title, children }) => (
  <div className="lb-step">
    <div className="lb-step-head"><span className="lb-step-n">{n}</span><h3>{title}</h3></div>
    <div className="lb-step-body">{children}</div>
  </div>
);

const Choice = ({ active, onClick, children, disabled, title }) => (
  <button type="button" className={`lb-choice${active ? ' is-active' : ''}`} onClick={onClick} disabled={disabled} title={title}>{children}</button>
);

function LabBuilder() {
  const [status, setStatus] = useState(null);
  const [state, setState] = useState(null);
  const [lab, setLab] = useState(null);
  const [error, setError] = useState(null);
  const [tool, setTool] = useState('gandalf');

  // Gandalf
  const [targets, setTargets] = useState([]);
  const [collector, setCollector] = useState('bash');
  const [thenElrond, setThenElrond] = useState(true);
  // Elrond
  const [source, setSource] = useState('bash');
  const [customPath, setCustomPath] = useState('');
  const [caseId, setCaseId] = useState('');
  const [profile, setProfile] = useState('standard');
  // Mordor
  const [mode, setMode] = useState('record');
  const [machine, setMachine] = useState('');
  const [preset, setPreset] = useState('persistence');
  const [custom, setCustom] = useState('');
  const [setUp, setSetUp] = useState(false);
  const [revertTo, setRevertTo] = useState('');
  const [snapped, setSnapped] = useState(false);
  const [group, setGroup] = useState(Object.keys(OTRF_GROUPS)[0]);
  const [mordorElrond, setMordorElrond] = useState(false);

  // Deploy
  const [steps, setSteps] = useState(null);   // [{label, status, run?, job?}]
  const [output, setOutput] = useState('');
  const cancelled = useRef(false);

  const load = useCallback(async () => {
    try {
      const s = await getLabStatus();
      setStatus(s);
      if (!s.available) return;
      setState(await getLabState());
      setLab(await getMordorLab());
    } catch (err) { setError(errorText(err)); }
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => () => { cancelled.current = true; }, []);

  if (status && !status.available) {
    return (
      <div className="card">
        <h2>Start the lab agent</h2>
        <p className="lab-note">The lab's machines run on the host, outside Dernvale's containers, so the lab drives them through a small agent there:</p>
        <div className="lab-command"><code>cd lab && {status.start_command || './lab.sh agent start'}</code></div>
        <button className="mt-pill" onClick={load}>Check again</button>
      </div>
    );
  }
  if (!state || !lab) return <div className="card">{error || 'Loading the lab…'}</div>;

  const cfg = state.config || {};
  const acqRoot = `${cfg.TEST_IMAGES_PATH || cfg.LAB_DATA_DIR}/gandalf`;
  const mordorRoot = `${cfg.TEST_IMAGES_PATH || cfg.LAB_DATA_DIR}/mordor`;
  const tart = state.host?.profile === 'macos-arm64';
  const machines = lab.machines || [];
  const running = (name) => machines.some((m) => m.name === name && m.state === 'running');
  const windowsVm = machines.find((m) => m.name === lab.lab_windows_vm);
  // Gandalf targets: the Linux containers and the lab VMs; Windows is PowerShell's, on its own
  const gandalfTargets = [
    ...(state.linux_containers || []).map((t) => ({ name: t, os: 'linux', up: running(t) })),
    ...(tart ? [{ name: 'lab-macos', os: 'macos', up: running('dernvale-lab-macos') },
      { name: 'lab-linuxvm', os: 'linux', up: running('dernvale-lab-linux') }] : []),
  ];
  const recordable = machines.filter((m) => m.os);
  const picked = recordable.find((m) => `${m.engine}/${m.name}` === machine) || recordable[0];
  const techniques = (custom.trim() || PRESETS[preset] || '').replace(/\s+/g, '');
  const elrondPath = source === 'custom' ? customPath.trim() : `${acqRoot}/${source}_collection/acquisitions/`;
  const busy = steps && steps.some((s) => s.status === 'running' || s.status === 'waiting');

  // The plan: what Deploy will do, step by step
  const plan = [];
  let blocker = null;
  if (tool === 'gandalf') {
    if (collector === 'powershell') {
      if (!windowsVm) blocker = "The lab's Windows VM doesn't exist yet (Lab → Lab machines, or From ISO).";
      plan.push({ label: `Run Invoke-Gandalf in ${lab.lab_windows_vm} and copy the archive out`, kind: 'lab', command: 'gandalf-collect', args: ['powershell'] });
    } else {
      if (!targets.length) blocker = 'Pick at least one target.';
      plan.push({ label: `Deploy gandalf.${collector === 'bash' ? 'sh' : 'py'} to ${targets.join(', ') || '…'} over SSH and collect`, kind: 'lab', command: 'gandalf-collect', args: [collector, ...targets] });
    }
    if (thenElrond) {
      if (!caseId.trim()) blocker = blocker || 'Give the case ID Elrond should file the analysis under.';
      plan.push({ label: `Elrond: ${ELROND_PROFILES[profile].label.toLowerCase()} on ${acqRoot}/${collector}_collection/acquisitions/ as ${caseId || '…'}`, kind: 'elrond', paths: [`${acqRoot}/${collector}_collection/acquisitions/`] });
    }
  } else if (tool === 'elrond') {
    if (!caseId.trim()) blocker = 'Give a case ID.';
    if (!elrondPath) blocker = 'Give the acquisitions folder.';
    plan.push({ label: `Elrond: ${ELROND_PROFILES[profile].label.toLowerCase()} on ${elrondPath || '…'} as ${caseId || '…'}`, kind: 'elrond', paths: [elrondPath] });
  } else if (mode === 'record') {
    if (!picked) blocker = 'No machine with a known OS yet (Lab → Lab machines).';
    else {
      if (!techniques || !/^T\d{4}(\.\d{3})?(,T\d{4}(\.\d{3})?)*$/i.test(techniques)) blocker = 'Techniques look like T1059.001,T1053.005.';
      if (!snapped) blocker = blocker || "Confirm the machine is snapshotted and disposable.";
      const labWin = picked.name === lab.lab_windows_vm;
      if (setUp) plan.push({ label: labWin ? `Set up ${picked.name}: Sysmon, audit logging, Atomic Red Team` : `Set up ${picked.name}: audit logging, then Atomic Red Team`, kind: 'setup', machine: picked });
      plan.push({ label: `Run Atomic Red Team ${techniques} in ${picked.name}, each test's logs kept apart, and bring them back as Your lab`, kind: 'record', machine: picked });
      if (revertTo && !labWin) plan.push({ label: `Revert ${picked.name} to ${revertTo}`, kind: 'none' });
      if (revertTo && labWin) plan.push({ label: `Revert ${picked.name} to ${revertTo} (UTM snapshot)`, kind: 'revert', machine: picked });
      if (mordorElrond) {
        if (!caseId.trim()) blocker = blocker || 'Give the case ID Elrond should file the analysis under.';
        plan.push({ label: `Turn the recording into a dataset Elrond reads: ${mordorRoot}/lab/<run>/acquisitions/`, kind: 'lab', command: 'mordor-dataset', run: true });
        plan.push({ label: `Elrond: ${ELROND_PROFILES[profile].label.toLowerCase()} on the recording as ${caseId || '…'}`, kind: 'elrond', run: true });
      }
    }
  } else if (mode === 'setup') {
    if (!picked) blocker = 'No machine with a known OS yet (Lab → Lab machines).';
    else {
      if (!snapped) blocker = 'Confirm the machine is snapshotted and disposable.';
      const labWin = picked.name === lab.lab_windows_vm;
      plan.push({ label: labWin ? `Set up ${picked.name}: Sysmon, audit logging, Atomic Red Team` : `Set up ${picked.name}: audit logging, then Atomic Red Team`, kind: 'setup', machine: picked });
    }
  } else if (mode === 'update') {
    plan.push({ label: 'Fetch what OTRF, Splunk attack_data and EVTX-ATTACK-SAMPLES changed since the last build, and rebuild the technique index', kind: 'build' });
  } else {
    let paths = [];
    if (mode === 'capture') {
      if (tart) blocker = "On Apple silicon, capture runs inside the VM (./lab.sh mordor-capture prints the command); use Record instead.";
      plan.push({ label: `Run the ${preset} Atomic tests in the Windows VM and export one OTRF-style dataset for Elrond`, kind: 'lab', command: 'mordor-capture', args: [preset] });
      paths = [`${mordorRoot}/lab/lab_${preset}/acquisitions/`];
    } else {
      plan.push({ label: `Download ${group} from OTRF Security-Datasets`, kind: 'lab', command: 'mordor-download', args: OTRF_GROUPS[group] });
      paths = OTRF_GROUPS[group].map((g) => `${mordorRoot}/${g}/acquisitions/`);
    }
    if (mordorElrond && paths.length) {
      if (!caseId.trim()) blocker = blocker || 'Give the case ID Elrond should file the analysis under.';
      plan.push({ label: `Elrond: ${ELROND_PROFILES[profile].label.toLowerCase()} on ${paths.length === 1 ? paths[0] : `${paths.length} datasets under ${mordorRoot}`} as ${caseId || '…'}`, kind: 'elrond', paths });
    }
  }

  // Run one lab agent job to the end, streaming its log
  const follow = async (run) => {
    let offset = 0;
    while (!cancelled.current) {
      // eslint-disable-next-line no-await-in-loop
      const r = await getLabRun(run.id, offset);
      const chunk = r.output;
      offset = r.offset;
      if (chunk) setOutput((o) => o + chunk);
      if (r.status !== 'running') return r.status;
      // eslint-disable-next-line no-await-in-loop
      await new Promise((res) => setTimeout(res, 1500));
    }
    return 'cancelled';
  };

  // The telemetry rebuild runs in the backend, not the agent: poll its status and print new log lines
  const followBuild = async () => {
    let seen = [];
    while (!cancelled.current) {
      // eslint-disable-next-line no-await-in-loop
      const { build = {} } = await getTelemetryStatus();
      const log = build.log || [];
      const from = seen.length ? log.lastIndexOf(seen[seen.length - 1]) + 1 : 0;
      const fresh = log.slice(from);
      if (fresh.length) setOutput((o) => `${o}${fresh.join('\n')}\n`);
      seen = log;
      if (build.state !== 'running') return build.state === 'error' ? 'failed' : 'succeeded';
      // eslint-disable-next-line no-await-in-loop
      await new Promise((res) => setTimeout(res, 3000));
    }
    return 'cancelled';
  };

  const deploy = async () => {
    setError(null);
    setOutput('');
    // Deploy names the recording, so the steps after it know where it is
    const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
    const runName = picked ? `deploy-${picked.name}-${stamp}`.slice(0, 64) : '';
    const todo = plan.filter((p) => p.kind !== 'none').map((p) => {
      if (!p.run) return p;
      return p.kind === 'elrond' ? { ...p, paths: [`${mordorRoot}/lab/${runName}/acquisitions/`] } : { ...p, args: [runName] };
    });
    setSteps(todo.map((p) => ({ label: p.label, status: 'waiting' })));
    const mark = (i, patch) => setSteps((prev) => prev.map((s, j) => (j === i ? { ...s, ...patch } : s)));
    for (let i = 0; i < todo.length; i += 1) {
      const p = todo[i];
      mark(i, { status: 'running' });
      setOutput((o) => `${o}${o ? '\n' : ''}== ${p.label}\n`);
      try {
        let result = 'succeeded';
        if (p.kind === 'lab') {
          // eslint-disable-next-line no-await-in-loop
          result = await follow(await runLabCommand(p.command, p.args));
        } else if (p.kind === 'setup' || p.kind === 'record' || p.kind === 'revert') {
          const m = p.machine;
          const body = { engine: m.engine, name: m.name, os: m.os };
          let req;
          if (p.kind === 'setup' && m.name !== lab.lab_windows_vm) {
            // each of the OS's setup steps in order (audit logging, PowerShell 7, Atomic Red Team)
            // eslint-disable-next-line no-await-in-loop
            const { steps: setupSteps = [] } = await getMordorLabSteps(m.os);
            for (const st of setupSteps) {
              if (result !== 'succeeded') break;
              setOutput((o) => `${o}-- ${st.label}\n`);
              // eslint-disable-next-line no-await-in-loop
              result = await follow(await postMordorLab('provision', { ...body, step: st.step }));
            }
          } else if (p.kind === 'setup') req = postMordorLab('provision', { ...body, step: 'sensor' });
          else if (p.kind === 'record') req = postMordorLab('record', { ...body, techniques, run_name: runName, revert_to: m.name === lab.lab_windows_vm ? '' : revertTo, execute: true });
          else req = postMordorLab('action', { ...body, action: 'revert', snapshot: revertTo });
          if (req) {
            // eslint-disable-next-line no-await-in-loop
            const run = await req;
            // eslint-disable-next-line no-await-in-loop
            result = run.id ? await follow(run) : 'succeeded';
          }
        } else if (p.kind === 'build') {
          // eslint-disable-next-line no-await-in-loop
          await updateTelemetry();
          // eslint-disable-next-line no-await-in-loop
          result = await followBuild();
        } else if (p.kind === 'elrond') {
          // eslint-disable-next-line no-await-in-loop
          const job = await createJob({
            case_number: caseId.trim(), source_paths: p.paths, destination_path: null,
            options: { local: false, gandalf: true, ...ELROND_PROFILES[profile].options },
          });
          mark(i, { job: job.id });
          setOutput((o) => `${o}Elrond job ${job.id} started; follow it in Jobs.\n`);
        }
        mark(i, { status: result });
        if (result !== 'succeeded') {
          setSteps((prev) => prev.map((s, j) => (j > i ? { ...s, status: 'skipped' } : s)));
          break;
        }
      } catch (err) {
        mark(i, { status: 'failed' });
        setOutput((o) => `${o}Failed: ${errorText(err)}\n`);
        setSteps((prev) => prev.map((s, j) => (j > i ? { ...s, status: 'skipped' } : s)));
        break;
      }
    }
    load();
  };

  return (
    <div className="lb">
      {error && <div className="card lab-error">{error}</div>}

      <div className="lb-tools">
        {TOOLS.map((t) => (
          <button key={t.key} type="button" className={`lb-tool${tool === t.key ? ' is-active' : ''}`} disabled={busy} onClick={() => { setTool(t.key); setSteps(null); }}>
            <img src={`${IMG}/${t.img}`} alt="" />
            <strong>{t.name}</strong>
            <span>{t.blurb}</span>
          </button>
        ))}
      </div>

      <div className="card lb-builder">
        {tool === 'gandalf' && (
          <>
            <div className="lb-pair">
            <Step n="1" title="Collector">
              <div className="lb-row">
                <Choice active={collector === 'bash'} onClick={() => setCollector('bash')}>Bash · gandalf.sh</Choice>
                <Choice active={collector === 'python'} onClick={() => setCollector('python')}>Python · gandalf.py</Choice>
                <Choice active={collector === 'powershell'} onClick={() => setCollector('powershell')}>PowerShell · Invoke-Gandalf</Choice>
              </div>
            </Step>
            <Step n="2" title="Deploy to">
              {collector === 'powershell' ? (
                <p className="lab-note">The lab's Windows VM, <strong>{lab.lab_windows_vm}</strong> ({windowsVm ? windowsVm.state : 'not created'}), over SSH. Gandalf runs locally in it and the archive is copied out.</p>
              ) : (
                <div className="lb-row">
                  {gandalfTargets.map((t) => (
                    <Choice key={t.name} active={targets.includes(t.name)} title={t.up ? 'running' : 'not running: it is started as part of the collection when it can be'}
                            onClick={() => setTargets(targets.includes(t.name) ? targets.filter((x) => x !== t.name) : [...targets, t.name])}>
                      <span className={`mt-dot is-${t.up ? 'running' : 'stopped'}`} />{t.name}
                    </Choice>
                  ))}
                </div>
              )}
            </Step>
            </div>
            <Step n="3" title="Acquire to">
              <p className="lab-note"><code>{acqRoot}/{collector}_collection/acquisitions/&lt;host&gt;/</code>, each target with its <code>expected.json</code> (the lab's seeded attacks).</p>
              <div className="lb-thirds">
                <input type="text" className="lb-input" placeholder="Case ID, e.g. LAB-2026-001" value={caseId} disabled={!thenElrond} onChange={(e) => setCaseId(e.target.value)} />
                <select className="large-select lb-select" value={profile} disabled={!thenElrond} onChange={(e) => setProfile(e.target.value)}>
                  {Object.entries(ELROND_PROFILES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                </select>
                <label className="lb-check"><input type="checkbox" checked={thenElrond} onChange={(e) => setThenElrond(e.target.checked)} /> Then analyse it with Elrond</label>
              </div>
            </Step>
          </>
        )}

        {tool === 'elrond' && (
          <>
            <Step n="1" title="Analyse">
              <div className="lb-row">
                {['bash', 'python', 'powershell'].map((c) => <Choice key={c} active={source === c} onClick={() => setSource(c)}>{c} collection</Choice>)}
                <Choice active={source === 'custom'} onClick={() => setSource('custom')}>Another folder</Choice>
              </div>
              {source === 'custom'
                ? <input type="text" className="lb-input lb-wide" placeholder="/Volumes/…/acquisitions/" value={customPath} onChange={(e) => setCustomPath(e.target.value)} />
                : <p className="lab-note"><code>{elrondPath}</code>: the lab's latest {source} acquisitions.</p>}
            </Step>
            <Step n="2" title="Case and depth">
              <div className="lb-row">
                <input type="text" className="lb-input" placeholder="Case ID, e.g. LAB-2026-001" value={caseId} onChange={(e) => setCaseId(e.target.value)} />
                <select className="large-select lb-select" value={profile} onChange={(e) => setProfile(e.target.value)}>
                  {Object.entries(ELROND_PROFILES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                </select>
              </div>
              <p className="lab-note">For every other option (memory, keywords, YARA, SIEM export), use the <Link to="/elrond">Elrond</Link> page.</p>
            </Step>
          </>
        )}

        {tool === 'mordor' && (
          <>
            <div className="lb-pair lb-pair-even">
              <Step n="1" title="What">
                <div className="lb-row">
                  <Choice active={mode === 'record'} onClick={() => setMode('record')}>Record telemetry</Choice>
                  <Choice active={mode === 'setup'} onClick={() => setMode('setup')}>Set up a machine</Choice>
                  <Choice active={mode === 'capture'} onClick={() => setMode('capture')}>Capture dataset for Elrond</Choice>
                  <Choice active={mode === 'download'} onClick={() => setMode('download')}>Download OTRF datasets</Choice>
                  <Choice active={mode === 'update'} onClick={() => setMode('update')}>Update telemetry sources</Choice>
                </div>
              </Step>
              {(mode === 'record' || mode === 'setup') && (
                <Step n="2" title="On">
                  <div className="lb-row">
                    {recordable.map((m) => (
                      <Choice key={`${m.engine}/${m.name}`} active={picked && picked.name === m.name} onClick={() => setMachine(`${m.engine}/${m.name}`)}>
                        <span className={`mt-dot is-${m.state}`} /><img className="lb-os" src={osLogo(m)} alt={m.os} title={m.os} />{m.name}
                      </Choice>
                    ))}
                    {mode === 'record' && <label className="lb-check lb-inline-check"><input type="checkbox" checked={setUp} onChange={(e) => setSetUp(e.target.checked)} /> Set it up first (logging and Atomic Red Team)</label>}
                  </div>
                  {mode === 'setup' && <label className="lb-check lb-warn"><input type="checkbox" checked={snapped} onChange={(e) => setSnapped(e.target.checked)} /> The machine is snapshotted and disposable: set-up changes it</label>}
                </Step>
              )}
              {mode === 'capture' && (
                <Step n="2" title="Techniques">
                  <div className="lb-row">
                    {Object.keys(PRESETS).map((k) => <Choice key={k} active={preset === k} onClick={() => setPreset(k)}>{k.replace('_', ' ')}</Choice>)}
                  </div>
                </Step>
              )}
              {mode === 'download' && (
                <Step n="2" title="Which">
                  <div className="lb-row">
                    {Object.keys(OTRF_GROUPS).map((g) => <Choice key={g} active={group === g} onClick={() => setGroup(g)}>{g}</Choice>)}
                  </div>
                </Step>
              )}
              {mode === 'update' && (
                <Step n="2" title="Sources">
                  <p className="lab-note">OTRF Security-Datasets, Splunk attack_data and EVTX-ATTACK-SAMPLES: only what changed since the last build is fetched. The Mordor page shows the result.</p>
                </Step>
              )}
            </div>
            {(mode === 'record' || mode === 'capture' || mode === 'download') && (
              <Step n={mode === 'record' ? '5' : '3'} title="Then">
                {mode === 'download' && !OTRF_GROUPS[group].length ? (
                  <p className="lab-note">Pick APT29 or the Atomic sets to analyse them here; for every dataset, use the <Link to="/elrond">Elrond</Link> page per dataset.</p>
                ) : (
                  <div className="lb-thirds">
                    <input type="text" className="lb-input" placeholder="Case ID, e.g. LAB-2026-001" value={caseId} disabled={!mordorElrond} onChange={(e) => setCaseId(e.target.value)} />
                    <select className="large-select lb-select" value={profile} disabled={!mordorElrond} onChange={(e) => setProfile(e.target.value)}>
                      {Object.entries(ELROND_PROFILES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                    </select>
                    <label className="lb-check"><input type="checkbox" checked={mordorElrond} onChange={(e) => setMordorElrond(e.target.checked)} /> Then analyse it with Elrond</label>
                  </div>
                )}
              </Step>
            )}
            {mode === 'record' && (
              <div className="lb-pair lb-pair-even">
                <Step n="3" title="Techniques">
                  <div className="lb-row">
                    {Object.keys(PRESETS).map((k) => <Choice key={k} active={!custom && preset === k} onClick={() => { setPreset(k); setCustom(''); }}>{k.replace('_', ' ')}</Choice>)}
                  </div>
                  <input type="text" className="lb-input lb-wide" placeholder={`Or your own: ${PRESETS[preset]}`} value={custom} onChange={(e) => setCustom(e.target.value)} />
                </Step>
                <Step n="4" title="Afterwards">
                  <input type="text" className="lb-input lb-wide" placeholder="Snapshot to revert to (blank: don't)" value={revertTo} onChange={(e) => setRevertTo(e.target.value)} />
                  <label className="lb-check lb-warn"><input type="checkbox" checked={snapped} onChange={(e) => setSnapped(e.target.checked)} /> The machine is snapshotted and disposable: the tests change it</label>
                </Step>
              </div>
            )}
          </>
        )}

        <div className="lb-plan">
          <h3>Plan</h3>
          <ol>
            {plan.map((p, i) => {
              const s = steps && steps[plan.filter((q, j) => j < i && q.kind !== 'none').length];
              return (
                <li key={p.label} className={s && p.kind !== 'none' ? `is-${s.status}` : ''}>
                  {p.label}
                  {s && p.kind !== 'none' && <span className={`lab-status lab-status-${s.status}`}>{s.status}</span>}
                  {s?.job && <> · <Link to={`/jobs/${s.job}`}>open the job</Link></>}
                </li>
              );
            })}
          </ol>
          {blocker && <p className="lb-blocker">{blocker}</p>}
          <button className="lb-deploy" disabled={!!blocker || busy} onClick={deploy}>{busy ? 'Deploying…' : 'Deploy'}</button>
        </div>
      </div>

      {output && <pre className="lab-output lb-output">{output}</pre>}
    </div>
  );
}

export default LabBuilder;
