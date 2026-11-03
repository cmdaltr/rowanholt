import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  getAndurilStatus,
  listAndurilContainers,
  listAndurilImages,
  getAndurilLogs,
  getAndurilStats,
  andurilContainerAction,
  andurilPullImage,
  andurilRemoveImage,
  andurilPruneImages,
  getAndurilOp,
  listAndurilOps,
} from '../api';
import { useLocation, useNavigate } from 'react-router-dom';
import PageHero from './PageHero';
import LabMachines from './LabMachines';
import LabManage from './Lab';
import LabBuilder from './LabBuilder';

const formatBytes = (n) => {
  if (!n && n !== 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
};

const errorText = (err) => {
  const detail = err.response?.data?.detail;
  if (!detail) return err.message;
  return typeof detail === 'string' ? detail : detail.message || JSON.stringify(detail);
};

const isBusy = (err) => {
  const detail = err.response?.data?.detail;
  return err.response?.status === 409 && (err.response?.data?.busy || detail?.busy || /running/i.test(errorText(err)));
};

function EnablePanel({ status, onRecheck }) {
  const [copied, setCopied] = useState(false);
  const command = status?.enable_command || 'rivendell anduril enable';

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      setCopied(false);
    }
  };

  return (
    <div data-guide="aragorn.anduril" className="card aragorn-enable">
      <h2>Anduril is not enabled</h2>
      {status?.reason === 'secret_key' ? (
        <p>
          The backend is still signing logins with the default JWT secret, so anyone could forge an admin
          token. Anduril stays off until <code>SECRET_KEY</code> is set for the backend (in your shell or a
          <code> .env</code> file next to <code>docker-compose.yml</code>). Then run the command below on the host.
        </p>
      ) : (
        <p>
          Anduril, Rivendell's Docker manager, needs access to the Docker socket to manage Rivendell's containers and images. Only the host
          can grant that, so run this on the machine running Docker Desktop or OrbStack. It explains what it
          grants and asks before changing anything.
        </p>
      )}
      <div className="aragorn-command">
        <code>{command}</code>
        <button className="secondary" onClick={copy}>{copied ? 'Copied' : 'Copy'}</button>
        <button className="aragorn-recheck" onClick={onRecheck}>Check again</button>
      </div>
      <p className="aragorn-note">
        Anduril only sees containers labelled with the <code>rivendell</code> compose project and named
        <code> rivendell-*</code>. Other containers and images on the same engine are never listed or touched.
      </p>
      {status?.detail && <p className="aragorn-note">Last error: {status.detail}</p>}
    </div>
  );
}

function AndurilPanel() {
  const { user } = useAuth();
  const [status, setStatus] = useState(null);
  const [containers, setContainers] = useState([]);
  const [images, setImages] = useState([]);
  const [ops, setOps] = useState([]);
  const [stats, setStats] = useState({});
  const [logs, setLogs] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const pollRef = useRef(null);

  const isAdmin = user?.role === 'admin';

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await getAndurilStatus());
    } catch (err) {
      setStatus({ enabled: false, reason: 'error', detail: errorText(err) });
    } finally {
      setLoading(false);
    }
  }, []);

  const loadData = useCallback(async () => {
    try {
      const [c, i, o] = await Promise.all([listAndurilContainers(), listAndurilImages(), listAndurilOps()]);
      setContainers(c);
      setImages(i);
      setOps(o);
      setError(null);
    } catch (err) {
      setError(errorText(err));
    }
  }, []);

  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  useEffect(() => {
    if (!status?.enabled || !isAdmin) return undefined;
    loadData();
    pollRef.current = setInterval(loadData, 5000);
    return () => clearInterval(pollRef.current);
  }, [status, isAdmin, loadData]);

  const waitForOp = async (op) => {
    let current = op;
    while (current.state === 'queued' || current.state === 'running') {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, 1500));
      // eslint-disable-next-line no-await-in-loop
      current = await getAndurilOp(op.id);
      setOps((prev) => [current, ...prev.filter((p) => p.id !== current.id)]);
    }
    if (current.state === 'failed') setError(`${current.action} ${current.target}: ${current.error}`);
    loadData();
  };

  const runAction = async (container, action) => {
    const warnings = {
      stop: container.service === 'backend'
        ? 'Stopping the backend takes this web UI offline. You will need the host CLI to start it again.'
        : `Stop ${container.name}?`,
      restart: `Restart ${container.name}?`,
      update: `Pull the latest ${container.image} and recreate ${container.name} if it changed?`,
    };
    if (warnings[action] && !window.confirm(warnings[action])) return;
    try {
      await waitForOp(await andurilContainerAction(container.name, action));
    } catch (err) {
      if (isBusy(err)) {
        const force = window.confirm(
          `${errorText(err)}\n\nForcing this will orphan or kill the running job. Continue anyway?`
        );
        if (force) {
          try {
            await waitForOp(await andurilContainerAction(container.name, action, true));
          } catch (err2) {
            setError(errorText(err2));
          }
        }
        return;
      }
      setError(errorText(err));
    }
  };

  const showStats = async (container) => {
    try {
      const s = await getAndurilStats(container.name);
      setStats((prev) => ({ ...prev, [container.name]: s }));
    } catch (err) {
      setError(errorText(err));
    }
  };

  const showLogs = async (name, tail = 200) => {
    try {
      const data = await getAndurilLogs(name, tail);
      setLogs({ name, tail, text: data.logs });
    } catch (err) {
      setError(errorText(err));
    }
  };

  const pull = async (ref) => {
    try {
      await waitForOp(await andurilPullImage(ref));
    } catch (err) {
      setError(errorText(err));
    }
  };

  const removeImage = async (image) => {
    if (!window.confirm(`Remove image ${image.tags.join(', ') || image.short_id}?`)) return;
    try {
      await waitForOp(await andurilRemoveImage(image.id));
    } catch (err) {
      setError(errorText(err));
    }
  };

  const prune = async () => {
    if (!window.confirm('Remove dangling images built for Rivendell?')) return;
    try {
      await waitForOp(await andurilPruneImages());
    } catch (err) {
      setError(errorText(err));
    }
  };

  if (loading) return <div className="loading">Checking Anduril…</div>;

  if (!isAdmin) {
    return (
      <div className="aragorn">
        <div className="card">
          <h2>Containers and images</h2>
          <p>Docker administration is limited to Rivendell administrators. Sign in with an admin account.</p>
        </div>
      </div>
    );
  }

  if (!status?.enabled) {
    return (
      <div className="aragorn">
        <EnablePanel status={status} onRecheck={loadStatus} />
      </div>
    );
  }

  const builtImageIds = new Set(images.filter((i) => i.built).map((i) => i.id));
  const activeOps = ops.filter((o) => o.state === 'queued' || o.state === 'running');

  return (
    <div className="aragorn">
      <div data-guide="aragorn.anduril" className="card">
        <h2>Containers and images</h2>
        <p className="aragorn-note">
          Rivendell containers and images on <code>{status.socket}</code> (compose project <code>{status.project}</code>).
          Rebuilding Rivendell's own images runs on the host: <code>rivendell anduril rebuild &lt;service&gt;</code>.
        </p>
        {error && (
          <div className="error">
            {error} <button className="secondary" onClick={() => setError(null)}>Dismiss</button>
          </div>
        )}
        {activeOps.map((o) => (
          <div key={o.id} className="aragorn-op">
            {o.action} {o.target}: {o.state}{o.log.length ? ` — ${o.log[o.log.length - 1]}` : ''}
          </div>
        ))}
      </div>

      <div className="card">
        <h3>Containers</h3>
        <table className="aragorn-table">
          <thead>
            <tr><th>Container</th><th>State</th><th>Status</th><th>Ports</th><th>Usage</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {containers.map((c) => {
              const s = stats[c.name];
              const running = c.state === 'running';
              const upstream = !builtImageIds.has(c.image_id);
              return (
                <tr key={c.id}>
                  <td>
                    {c.name}
                    {c.job_processes.length > 0 && <span className="status-badge status-running aragorn-flag">Elrond running</span>}
                  </td>
                  <td><span className={`status-badge ${running ? 'status-completed' : 'status-cancelled'}`}>{c.state}</span></td>
                  <td>{c.status}</td>
                  <td>{c.ports.join(', ') || '—'}</td>
                  <td>
                    {s ? (s.running ? `${s.cpu_percent}% CPU, ${formatBytes(s.memory_bytes)} / ${formatBytes(s.memory_limit)}` : '—')
                      : running && <button className="secondary" onClick={() => showStats(c)}>Stats</button>}
                  </td>
                  <td className="aragorn-actions">
                    {c.protected ? (
                      <span className="aragorn-note">managed from the host CLI</span>
                    ) : (
                      <>
                        {!running && <button onClick={() => runAction(c, 'start')}>Start</button>}
                        {running && <button className="secondary" onClick={() => runAction(c, 'restart')}>Restart</button>}
                        {running && <button className="secondary" onClick={() => runAction(c, 'stop')}>Stop</button>}
                        {upstream && <button className="secondary" onClick={() => runAction(c, 'update')}>Update</button>}
                        <button className="secondary" onClick={() => showLogs(c.name)}>Logs</button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>Images</h3>
        <button className="secondary" onClick={prune}>Prune dangling Rivendell images</button>
        <table className="aragorn-table">
          <thead>
            <tr><th>Image</th><th>Size</th><th>Source</th><th>Used by</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {images.map((i) => (
              <tr key={i.id}>
                <td>{i.tags.join(', ') || `<none> ${i.short_id}`}</td>
                <td>{formatBytes(i.size)}</td>
                <td>{i.built ? 'built' : 'upstream'}</td>
                <td>
                  {i.used_by.join(', ') || '—'}
                  {i.shared_with.length > 0 && <div className="aragorn-note">also used outside Rivendell: {i.shared_with.join(', ')}</div>}
                </td>
                <td className="aragorn-actions">
                  {!i.built && i.tags[0] && <button className="secondary" onClick={() => pull(i.tags[0])}>Pull</button>}
                  {i.used_by.length === 0 && i.shared_with.length === 0 && (
                    <button className="secondary" onClick={() => removeImage(i)}>Remove</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {ops.length > 0 && (
        <div className="card">
          <h3>Recent operations</h3>
          <table className="aragorn-table">
            <tbody>
              {ops.slice(0, 10).map((o) => (
                <tr key={o.id}>
                  <td>{new Date(o.created * 1000).toLocaleString()}</td>
                  <td>{o.action} {o.target}</td>
                  <td><span className={`status-badge status-${o.state === 'done' ? 'completed' : o.state === 'failed' ? 'failed' : 'pending'}`}>{o.state}</span></td>
                  <td>{o.error || (typeof o.result === 'string' ? o.result : '')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {logs && (
        <div className="aragorn-modal-overlay" onClick={() => setLogs(null)}>
          <div className="aragorn-modal" onClick={(e) => e.stopPropagation()}>
            <h3>{logs.name}: last {logs.tail} lines</h3>
            <pre>{logs.text || '(no output)'}</pre>
            <div className="aragorn-actions">
              <button className="secondary" onClick={() => showLogs(logs.name, logs.tail)}>Refresh</button>
              <button className="secondary" onClick={() => showLogs(logs.name, logs.tail * 5)}>More</button>
              <button onClick={() => setLogs(null)}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Aragorn: everything Rivendell runs on this host. Lab is the lab's targets and machines (the lab
// agent); Deploy builds and runs a Gandalf, Elrond or Mordor run; Settings is Rivendell's containers
// and images (Anduril, the aragorn service) and the lab's host, settings and password.
const TABS = [['lab', 'Lab'], ['deploy', 'Deploy'], ['settings', 'Settings']];

function Aragorn() {
  const { user } = useAuth();
  const { hash } = useLocation();
  const navigate = useNavigate();
  const tab = TABS.some(([k]) => `#${k}` === hash) ? hash.slice(1) : 'lab';
  const admin = user?.role === 'admin';
  const adminOnly = <div className="card"><p>The lab is limited to Rivendell administrators. Sign in with an admin account.</p></div>;
  return (
    <div className="journey-detail">
      <PageHero title="Aragorn">
        Everything Rivendell runs on this machine: the lab's targets and machines, runs that deploy Gandalf, Elrond
        or Mordor against them, and Rivendell's own containers and settings.
      </PageHero>
      <div data-guide="aragorn.tabs" className="aragorn-tabs" role="tablist">
        {TABS.map(([key, label]) => (
          <button key={key} type="button" role="tab" aria-selected={tab === key}
                  className={`aragorn-tab${tab === key ? ' is-active' : ''}`}
                  onClick={() => navigate({ hash: key }, { replace: true })}>
            {label}
          </button>
        ))}
      </div>
      {tab === 'lab' && (admin ? (
        <LabManage section="lab">
          <div data-guide="aragorn.lab" className="card">
            <h2>Lab machines</h2>
            <p className="lab-note">
              Create and manage the containers and VMs Gandalf collects from and Mordor records on. Rivendell drives Docker
              and Tart for Linux and macOS, and UTM for Windows. The machines are disposable: snapshot one before you turn
              logging on or run atomics, and revert when you're done. Recordings appear on the Mordor page as Your lab.
            </p>
            <LabMachines />
          </div>
        </LabManage>
      ) : adminOnly)}
      {tab === 'deploy' && (admin ? <LabBuilder /> : adminOnly)}
      {tab === 'settings' && (
        <>
          <AndurilPanel />
          {admin ? <LabManage section="settings" /> : adminOnly}
        </>
      )}
    </div>
  );
}

export default Aragorn;
