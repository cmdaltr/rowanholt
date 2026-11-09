import React, { useState, useEffect, useCallback } from 'react';
import { listSymbolTables, addSymbolTable, getSymbolTask } from '../api';

const KINDS = {
  table: 'A symbol table (.json or .json.xz)',
  vmlinux: "A Linux kernel's vmlinux (with System.map if you have it)",
  kdk: "A macOS kernel and its dSYM DWARF file, from Apple's Kernel Debug Kit",
};

const sizeOf = (n) => (n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${Math.ceil(n / 1024)} KB`);

// Aragorn's Settings: the Volatility symbol tables Linux and macOS memory images need. Elrond
// fetches a kernel's table itself when downloads are on (ROWANHOLT_SYMBOL_DOWNLOADS); the rest
// are added here, built by the worker with dwarf2json.
function SymbolTables() {
  const [state, setState] = useState(null);
  const [error, setError] = useState('');
  const [kind, setKind] = useState('table');
  const [files, setFiles] = useState({});
  const [busy, setBusy] = useState('');

  const load = useCallback(async () => {
    try {
      setState(await listSymbolTables());
      setError('');
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const add = async (e) => {
    e.preventDefault();
    setBusy('Uploading…');
    try {
      const { task_id: taskId } = await addSymbolTable(kind, files.file,
        { system_map: files.system_map, dwarf: files.dwarf });
      setBusy('Building the table in the worker…');
      for (;;) {
        // eslint-disable-next-line no-await-in-loop
        await new Promise((r) => setTimeout(r, 3000));
        // eslint-disable-next-line no-await-in-loop
        const task = await getSymbolTask(taskId);
        if (task.state === 'done') {
          setBusy('');
          if (!task.ok) setError(task.output || 'The table could not be added');
          break;
        }
      }
      setFiles({});
      e.target.reset();
      load();
    } catch (err) {
      setBusy('');
      setError(err.response?.data?.detail || err.message);
    }
  };

  const pick = (name) => (e) => setFiles({ ...files, [name]: e.target.files[0] });

  return (
    <div data-guide="aragorn.symbols" className="card">
      <h3>Memory symbol tables</h3>
      <p className="lab-note">
        Volatility needs a symbol table for each Linux and macOS kernel it reads. Elrond finds one by the image's kernel
        banner: a prebuilt table, or one built from the distribution's debug package, each checked against its
        publisher's hash. {state && (state.downloads
          ? 'Downloads are on.'
          : <>Downloads are off (ROWANHOLT_SYMBOL_DOWNLOADS), so a job that needs one names the command instead: <code>{state.fetch_command}</code>.</>)}
        {' '}Windows tables come from Microsoft's symbol server, under the same switch.
      </p>
      {error && <div className="error-message">{error}</div>}
      {state && (
        <table className="aragorn-table">
          <thead>
            <tr><th>Table</th><th>Kernel</th><th>Source</th><th>Size</th></tr>
          </thead>
          <tbody>
            {state.tables.length === 0 && <tr><td colSpan={4}>None yet.</td></tr>}
            {state.tables.map((t) => (
              <tr key={`${t.os}/${t.file}`}>
                <td>{t.os}/{t.file}</td>
                <td>{t.banner || <span className="aragorn-note">not indexed yet (on the next job that uses it)</span>}</td>
                <td>{t.source || '—'}{t.added && <div className="aragorn-note">{t.added}</div>}</td>
                <td>{sizeOf(t.size)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form onSubmit={add}>
        <h4>Add a table</h4>
        <select value={kind} onChange={(e) => { setKind(e.target.value); setFiles({}); }} disabled={!!busy}>
          {Object.entries(KINDS).map(([k, label]) => <option key={k} value={k}>{label}</option>)}
        </select>
        <div>
          <label>{kind === 'kdk' ? 'Kernel (System/Library/Kernels/kernel…)' : kind === 'vmlinux' ? 'vmlinux' : 'Table'}{' '}
            <input type="file" onChange={pick('file')} required disabled={!!busy} />
          </label>
        </div>
        {kind === 'vmlinux' && (
          <div><label>System.map (optional) <input type="file" onChange={pick('system_map')} disabled={!!busy} /></label></div>
        )}
        {kind === 'kdk' && (
          <div><label>DWARF (kernel….dSYM/Contents/Resources/DWARF/…) <input type="file" onChange={pick('dwarf')} required disabled={!!busy} /></label></div>
        )}
        <button type="submit" disabled={!!busy || !files.file}>{busy || 'Add'}</button>
      </form>
      {state?.log?.length > 0 && (
        <details>
          <summary>Downloads and builds</summary>
          <pre>{state.log.join('\n')}</pre>
        </details>
      )}
    </div>
  );
}

export default SymbolTables;
