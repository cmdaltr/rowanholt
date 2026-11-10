import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { listSamples, fetchSample, getSampleTask, sampleJobRequest, createJob } from '../api';

const sizeOf = (n) => (n >= 1 << 30 ? `${(n / (1 << 30)).toFixed(1)} GB` : `${Math.round(n / (1 << 20))} MB`);

// Aragorn's Settings: public forensic images as ready cases (rowanholt samples). Fetch downloads
// in the worker, checking each file's published hash; Import starts the case as an ordinary job.
function SampleData() {
  const navigate = useNavigate();
  const [state, setState] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState({});

  const load = useCallback(async () => {
    try {
      setState(await listSamples());
      setError('');
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const fetchOne = async (id) => {
    setBusy((b) => ({ ...b, [id]: 'Starting…' }));
    try {
      const { task_id: taskId } = await fetchSample(id);
      for (;;) {
        // eslint-disable-next-line no-await-in-loop
        await new Promise((r) => setTimeout(r, 5000));
        // eslint-disable-next-line no-await-in-loop
        const task = await getSampleTask(taskId);
        if (task.state === 'done') {
          if (!task.ok) setError(`${id}: ${task.output}`);
          break;
        }
        const progress = task.bytes ? `${task.file}: ${sizeOf(task.bytes)}${task.total ? ` of ${sizeOf(task.total)}` : ''}` : 'Working…';
        setBusy((b) => ({ ...b, [id]: progress }));
      }
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
    setBusy((b) => ({ ...b, [id]: '' }));
    load();
  };

  const importOne = async (id) => {
    setBusy((b) => ({ ...b, [id]: 'Starting the job…' }));
    try {
      const job = await createJob(await sampleJobRequest(id));
      navigate(`/jobs/${job.id}`);
    } catch (e) {
      setError(`${id}: ${e.response?.data?.detail || e.message}`);
      setBusy((b) => ({ ...b, [id]: '' }));
    }
  };

  return (
    <div data-guide="aragorn.samples" className="card">
      <h3>Sample data</h3>
      <p className="lab-note">
        Public forensic images, each a ready case: a Windows disk and memory, Linux disk and memory, a Mac, an Android
        phone and an iPhone. Fetch downloads one into {state ? <code>{state.dir}</code> : 'the samples folder'}{' '}
        (ROWANHOLT_SAMPLES_DIR), checking it against its publisher&apos;s hash; Import starts it as a job. Tens of
        gigabytes each; <code>rowanholt samples fetch</code> does the same from a terminal. The lab&apos;s own
        samples (Windows 11, and macOS, whose licence rules out sharing one) are built rather than fetched, by the
        command shown; once built they import the same way.
      </p>
      {error && <div className="error-message">{error}</div>}
      {state && (
        <table className="aragorn-table">
          <thead>
            <tr><th>Sample</th><th>Covers</th><th>Files</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {state.samples.map((s) => (
              <tr key={s.id}>
                <td>
                  <a href={s.page} target="_blank" rel="noreferrer">{s.title}</a>
                  <div className="aragorn-note">
                    {s.os}; {s.publisher}
                    {s.answers && !s.build && <> · <a href={s.answers} target="_blank" rel="noreferrer">answers</a></>}
                    {s.answers && s.build && <> · answers: <code>{s.answers}</code></>}
                  </div>
                  {s.catches && <div className="aragorn-note">{s.catches}</div>}
                </td>
                <td>{s.covers.join(', ')}</td>
                <td>
                  {s.images.length > 0 && 'ready'}
                  {s.images.length === 0 && s.build && (
                    <div className="aragorn-note">
                      Not built. On {s.build.host} (takes {s.build.takes}), from the repo:{' '}
                      <code>{s.build.command}</code>; built elsewhere, copy the folder there.
                      Makes {s.build.produces.join(', ')}.
                    </div>
                  )}
                  {s.images.length === 0 && !s.build && s.files.map((f) => (
                    <div key={f.name}>{f.name}: {f.state}{f.bytes > 0 && f.state !== 'ready' ? ` (${sizeOf(f.bytes)})` : ''}</div>
                  ))}
                </td>
                <td className="aragorn-actions">
                  {busy[s.id] ? <span className="aragorn-note">{busy[s.id]}</span> : (
                    <>
                      {s.images.length === 0 && !s.build && <button className="secondary" onClick={() => fetchOne(s.id)}>Fetch</button>}
                      {s.images.length > 0 && <button onClick={() => importOne(s.id)}>Import</button>}
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default SampleData;
