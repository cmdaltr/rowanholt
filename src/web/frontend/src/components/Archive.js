import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { listJobs } from '../api';

const heroImage = `${process.env.PUBLIC_URL}/images/rivendell.png`;

function Archive() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedJobs, setSelectedJobs] = useState([]);

  useEffect(() => {
    loadArchivedJobs();
  }, []);

  const loadArchivedJobs = async () => {
    try {
      // TODO: Update API to support archived status
      const data = await listJobs('archived');
      setJobs(data.jobs);
      setError(null);
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

  const handleSelectAll = () => {
    if (selectedJobs.length === jobs.length) {
      setSelectedJobs([]);
    } else {
      setSelectedJobs(jobs.map(job => job.id));
    }
  };

  const handleBulkRestore = () => {
    alert('Restore functionality will be implemented');
  };

  const handleBulkDelete = async () => {
    if (!window.confirm(`Are you sure you want to permanently delete ${selectedJobs.length} archived job(s)?`)) {
      return;
    }
    alert('Permanent delete functionality will be implemented');
    setSelectedJobs([]);
  };

  if (loading) {
    return <div className="loading">Loading archived jobs...</div>;
  }

  return (
    <div className="job-list journey-detail">
      <section className="hero-section">
        <img
          src={heroImage}
          alt="Rivendell - The Last Homely House"
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
          {selectedJobs.length > 0 && (
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => handleBulkRestore()}
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

        {error && <div className="error">{error}</div>}

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
                    <input
                      type="checkbox"
                      checked={selectedJobs.length === jobs.length && jobs.length > 0}
                      onChange={handleSelectAll}
                      style={{ cursor: 'pointer' }}
                    />
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
                      <input
                        type="checkbox"
                        checked={selectedJobs.includes(job.id)}
                        onChange={() => handleSelectJob(job.id)}
                        style={{ cursor: 'pointer' }}
                      />
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
