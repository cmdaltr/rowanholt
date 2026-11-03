import React, { useEffect, useState } from 'react';
import { getAuthConfig, getJobSharing, setJobSharing, getUserDirectory } from '../api';

// Who owns a job and who it's shared with. Shown on a server only: on an analyst's own
// machine every job is theirs.
function JobSharing({ jobId }) {
  const [serverMode, setServerMode] = useState(false);
  const [sharing, setSharing] = useState(null);
  const [directory, setDirectory] = useState([]);
  const [adding, setAdding] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    getAuthConfig()
      .then(async (config) => {
        if (cancelled || !config.server_mode) return;
        setServerMode(true);
        const [current, people] = await Promise.all([getJobSharing(jobId), getUserDirectory()]);
        if (!cancelled) {
          setSharing(current);
          setDirectory(people);
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [jobId]);

  if (!serverMode || !sharing) return null;

  const save = async (usernames) => {
    setError('');
    try {
      setSharing(await setJobSharing(jobId, usernames));
      setAdding('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not update sharing');
    }
  };

  const candidates = directory.filter(
    (person) => person.username !== sharing.owner && !sharing.shared_with.includes(person.username)
  );

  return (
    <div data-guide="job.sharing" className="card" style={{ marginBottom: '1.5rem' }}>
      <h3>Access</h3>
      <p style={{ margin: '0.25rem 0 0.75rem' }}>
        Owner: <strong>{sharing.owner || 'none (created before sharing; admins only)'}</strong>
      </p>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
        <span>Shared with:</span>
        {sharing.shared_with.length === 0 && <span style={{ opacity: 0.7 }}>nobody</span>}
        {sharing.shared_with.map((name) => (
          <span key={name} className="options-tag" style={{ display: 'inline-flex', gap: '0.4rem', alignItems: 'center' }}>
            {name}
            {sharing.can_manage && (
              <button
                className="secondary"
                style={{ padding: '0 0.4rem', lineHeight: 1.4 }}
                title={`Stop sharing with ${name}`}
                onClick={() => save(sharing.shared_with.filter((n) => n !== name))}
              >
                ×
              </button>
            )}
          </span>
        ))}
      </div>
      {sharing.can_manage && candidates.length > 0 && (
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem' }}>
          <select value={adding} onChange={(e) => setAdding(e.target.value)} style={{ flex: 1 }}>
            <option value="">Share with…</option>
            {candidates.map((person) => (
              <option key={person.username} value={person.username}>
                {person.full_name ? `${person.full_name} (${person.username})` : person.username}
              </option>
            ))}
          </select>
          <button disabled={!adding} onClick={() => save([...sharing.shared_with, adding])}>
            Share
          </button>
        </div>
      )}
      {error && <div className="alert-error" style={{ marginTop: '0.75rem' }}>{error}</div>}
    </div>
  );
}

export default JobSharing;
