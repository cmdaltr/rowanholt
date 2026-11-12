import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { listJobs, bulkUnarchiveJobs, bulkDeleteJobs } from '../api';
import { bulkOffered, bulkPlan, canManage, skippedNote } from '../jobActions';

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt-tm.png`;

// Where a job wrote, as the backend records it (output_removal.recorded_output)
const outputFolder = (job) => job.destination_path || job.result?.output_directory || null;

// What DELETE /api/jobs/{id} (and bulk/delete) actually removes: the job's row and its owner and
// sharing row (storage.delete_job). Nothing on disk, and not the case's findings, notes or host
// assignments, which are keyed by job and left behind. The wording mustn't promise more.
export const deleteConfirmation = (jobs, plan) => {
  const n = jobs.length;
  const folders = jobs.map((job) => `  ${job.case_number}: ${outputFolder(job) || 'no output folder recorded'}`);
  return [
    `Permanently delete ${n} archived job${n === 1 ? '' : 's'}? This can't be undone.`,
    "Rowanholt deletes each job's record (its settings, status, log, owner and sharing), so the job "
      + 'and its case pages are gone from Rowanholt.',
    'Nothing on disk is removed. The evidence and the output stay where they are, and the output has '
      + 'to be removed by hand if it should go:',
    folders.join('\n'),
    "The findings, notes and host assignments made on its case stay in Rowanholt's database, but nothing "
      + `shows them any more.${skippedNote(plan, 'delete')}`,
  ].join('\n\n');
};

// "3 jobs", or "1 job"
const jobsCount = (n) => `${n} job${n === 1 ? '' : 's'}`;

function Archive() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedJobs, setSelectedJobs] = useState([]);
  const [notice, setNotice] = useState(null);
  const [working, setWorking] = useState(false);

  useEffect(() => {
    loadArchivedJobs();
  }, []);

  const loadArchivedJobs = async () => {
    try {
      const data = await listJobs('archived');
      setJobs(data.jobs);
      // A job restored or deleted elsewhere drops out of the selection with the list
      const listed = new Set(data.jobs.map((job) => job.id));
      setSelectedJobs((prev) => prev.filter((id) => listed.has(id)));
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load archived jobs');
    } finally {
      setLoading(false);
    }
  };

  const getStatusClass = (status) => {
    return `status-badge status-${status.toLowerCase()}`;
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const handleSelectJob = (jobId) => {
    setSelectedJobs(prev =>
      prev.includes(jobId)
        ? prev.filter(id => id !== jobId)
        : [...prev, jobId]
    );
  };

  // Restore and delete are all this page does, and both are the owner's or an admin's: a job
  // someone else owns can't be selected at all (the server refuses it anyway)
  const manageable = jobs.filter(canManage);
  const selectedJobData = jobs.filter((job) => selectedJobs.includes(job.id));

  const handleSelectAll = () => {
    if (selectedJobs.length === manageable.length) {
      setSelectedJobs([]);
    } else {
      setSelectedJobs(manageable.map(job => job.id));
    }
  };

  // Sends the eligible jobs, then says how many it did and why any weren't, in the page's own
  // messages; the list is reloaded either way, so it shows what the server now holds
  const runBulk = async (plan, send, done, verb) => {
    const byId = Object.fromEntries(jobs.map((job) => [job.id, job]));
    setWorking(true);
    setError(null);
    setNotice(null);
    try {
      const response = await send(plan.eligible.map((job) => job.id));
      const results = response.results || [];
      const succeeded = results.filter((r) => r.success).length;
      const failed = results.filter((r) => !r.success);
      if (succeeded) setNotice(`${done} ${jobsCount(succeeded)}.${skippedNote(plan, verb)}`);
      else if (plan.notYours.length) setNotice(skippedNote(plan, verb).trim());
      if (failed.length) {
        setError(`Couldn't ${verb} ${jobsCount(failed.length)}: `
          + failed.map((r) => `${byId[r.job_id]?.case_number || r.job_id} (${r.error})`).join('; '));
      }
    } catch (err) {
      setError(err.response?.data?.detail || `Failed to ${verb} the selected jobs`);
    } finally {
      await loadArchivedJobs();
      setWorking(false);
    }
  };

  const handleBulkRestore = async () => {
    const plan = bulkPlan(selectedJobData, 'restore');
    if (!plan.eligible.length) {
      setError(`None of the selected jobs can be restored.${skippedNote(plan, 'restore')}`);
      return;
    }
    await runBulk(plan, bulkUnarchiveJobs, 'Restored to Jobs:', 'restore');
  };

  const handleBulkDelete = async () => {
    const plan = bulkPlan(selectedJobData, 'delete');
    if (!plan.eligible.length) {
      setError(`None of the selected jobs can be deleted.${skippedNote(plan, 'delete')}`);
      return;
    }
    if (!window.confirm(deleteConfirmation(plan.eligible, plan))) {
      return;
    }
    await runBulk(plan, bulkDeleteJobs, 'Deleted the records of', 'delete');
  };

  if (loading) {
    return <div className="loading">Loading archived jobs...</div>;
  }

  return (
    <div className="job-list journey-detail">
      <section className="hero-section">
        <img
          src={heroImage}
          alt="Rowanholt"
          className="hero-image"
          style={{
            transform: 'scale(0.2)',
            transformOrigin: 'center top'
          }}
        />
      </section>

      <header>
        <h2>Archived Jobs</h2>
        <p>View and manage archived forensic analysis jobs.</p>
      </header>

      <div data-guide="archive.list" className="card">
        <div className="list-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <Link to="/jobs">
            <button>← Back to Jobs</button>
          </Link>
          {(bulkOffered(selectedJobData, 'restore') || bulkOffered(selectedJobData, 'delete')) && (
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => handleBulkRestore()}
                disabled={working}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'rgba(107, 142, 63, 0.3)',
                  color: '#a7db6c',
                  border: '1px solid #6b8e3f',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Restore ({selectedJobs.length})
              </button>
              <button
                onClick={() => handleBulkDelete()}
                disabled={working}
                style={{
                  padding: '0.5rem 1rem',
                  background: '#8b4513',
                  color: '#f0dba5',
                  border: '1px solid #654321',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Delete Permanently ({selectedJobs.length})
              </button>
            </div>
          )}
        </div>

        {error && <div className="error" role="alert">{error}</div>}
        {notice && <div className="success" role="status">{notice}</div>}

        {jobs.length === 0 ? (
          <div className="empty-state">
            <p>No archived jobs found.</p>
            <Link to="/jobs">
              <button>Back to Jobs</button>
            </Link>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th style={{ width: '5%' }}>
                    {manageable.length > 0 && (
                      <input
                        type="checkbox"
                        aria-label="Select all"
                        checked={selectedJobs.length === manageable.length}
                        onChange={handleSelectAll}
                        style={{ cursor: 'pointer' }}
                      />
                    )}
                  </th>
                  <th style={{ width: '25%' }}>Case Number</th>
                  <th style={{ width: '15%' }}>Status</th>
                  <th style={{ width: '22%' }}>Created</th>
                  <th style={{ width: '22%' }}>Archived</th>
                  <th style={{ width: '11%' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map(job => (
                  <tr key={job.id}>
                    <td>
                      {canManage(job) && (
                        <input
                          type="checkbox"
                          aria-label={`Select ${job.case_number}`}
                          checked={selectedJobs.includes(job.id)}
                          onChange={() => handleSelectJob(job.id)}
                          style={{ cursor: 'pointer' }}
                        />
                      )}
                    </td>
                    <td>
                      <Link to={`/jobs/${job.id}`}>
                        <strong>{job.case_number}</strong>
                      </Link>
                      <div style={{ fontSize: '0.875rem', color: '#888' }}>
                        {job.source_paths.length} image(s)
                      </div>
                    </td>
                    <td>
                      <span className={getStatusClass(job.status)}>
                        {job.status}
                      </span>
                    </td>
                    <td>{formatDate(job.created_at)}</td>
                    <td>{formatDate(job.archived_at)}</td>
                    <td>
                      <Link to={`/jobs/${job.id}`}>
                        <button className="view-button">View Details</button>
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default Archive;
