import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { listJobs, bulkDeleteJobs, bulkArchiveJobs, bulkRestartJobs, bulkCancelJobs, countFindings } from '../api';

const heroImage = `${process.env.PUBLIC_URL}/images/dernvale.png`;

function JobList() {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState(null);
  const [selectedJobs, setSelectedJobs] = useState([]);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [confirmModalData, setConfirmModalData] = useState({ title: '', message: '', action: null, actionType: '' });
  const [showErrorModal, setShowErrorModal] = useState(false);
  const [errorModalData, setErrorModalData] = useState({ title: '', message: '' });

  useEffect(() => {
    loadJobs();
    // Auto-refresh every 5 seconds
    const interval = setInterval(loadJobs, 5000);
    return () => clearInterval(interval);
  }, [statusFilter]);

  // Status priority for sorting (lower number = higher priority)
  const statusPriority = {
    'awaiting_confirmation': 0,
    'running': 1,
    'paused': 1,
    'failed': 2,
    'pending': 3,
    'cancelled': 4,
    'completed': 5,
    'archived': 6
  };

  const sortJobsByStatus = (jobsToSort) => {
    return [...jobsToSort].sort((a, b) => {
      const priorityA = statusPriority[a.status.toLowerCase()] ?? 99;
      const priorityB = statusPriority[b.status.toLowerCase()] ?? 99;
      if (priorityA !== priorityB) {
        return priorityA - priorityB;
      }
      // Secondary sort by created_at (newest first) for same status
      return new Date(b.created_at) - new Date(a.created_at);
    });
  };

  const loadJobs = async () => {
    try {
      const data = await listJobs(statusFilter);
      setJobs(sortJobsByStatus(data.jobs));
      setError(null);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load jobs');
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

  const formatDuration = (start, end) => {
    if (!start) return 'N/A';
    const startDate = new Date(start);
    const endDate = end ? new Date(end) : new Date();
    const duration = Math.floor((endDate - startDate) / 1000);

    if (duration < 60) return `${duration}s`;
    if (duration < 3600) return `${Math.floor(duration / 60)}m`;
    return `${Math.floor(duration / 3600)}h ${Math.floor((duration % 3600) / 60)}m`;
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

  const handleConfirmAction = async () => {
    setShowConfirmModal(false);
    if (confirmModalData.action) {
      await confirmModalData.action();
    }
  };

  const handleCancelAction = () => {
    setShowConfirmModal(false);
  };

  const handleBulkDelete = async () => {
    // Check if any selected jobs can actually be deleted
    const selectedJobData = jobs.filter(job => selectedJobs.includes(job.id));
    const deletableJobs = selectedJobData.filter(job => job.status !== 'pending' && job.status !== 'running' && job.status !== 'paused');

    if (deletableJobs.length === 0) {
      setErrorModalData({
        title: 'Cannot Delete Jobs',
        message: 'None of the selected jobs can be deleted. Cannot delete PENDING or RUNNING jobs. Please stop them first.'
      });
      setShowErrorModal(true);
      return;
    }

    setConfirmModalData({
      title: '⚠️ Delete Confirmation',
      message: `Are you sure you want to delete ${deletableJobs.length} job(s)? This action cannot be undone.`,
      actionType: 'delete',
      action: async () => {
        try {
          // Only send deletable job IDs
          const deletableJobIds = deletableJobs.map(job => job.id);
          const response = await bulkDeleteJobs(deletableJobIds);

          // Check results and show feedback
          const successful = response.results.filter(r => r.success).length;
          const failed = response.results.filter(r => !r.success).length;

          if (failed > 0) {
            const failedJobs = response.results.filter(r => !r.success);
            const errorMessages = failedJobs.map(r => `${r.job_id}: ${r.error}`).join('\n');
            alert(`Deleted ${successful} job(s). Failed to delete ${failed} job(s):\n\n${errorMessages}`);
          } else {
            // Success message could be shown in a better way (toast notification)
            console.log(`Successfully deleted ${successful} job(s)`);
          }

          // Refresh job list
          await loadJobs();
          setSelectedJobs([]);

        } catch (err) {
          setError(err.response?.data?.detail || 'Failed to delete jobs');
          alert('Error deleting jobs: ' + (err.response?.data?.detail || err.message));
        }
      }
    });
    setShowConfirmModal(true);
  };

  const handleBulkExport = () => {
    if (selectedJobs.length === 0) {
      alert('No jobs selected for export');
      return;
    }

    try {
      // Get selected job data
      const selectedJobData = jobs.filter(job => selectedJobs.includes(job.id));

      // Create JSON export
      const exportData = {
        exported_at: new Date().toISOString(),
        job_count: selectedJobData.length,
        jobs: selectedJobData.map(job => ({
          id: job.id,
          case_number: job.case_number,
          status: job.status,
          progress: job.progress,
          source_paths: job.source_paths,
          destination_path: job.destination_path,
          created_at: job.created_at,
          started_at: job.started_at,
          completed_at: job.completed_at,
          options: job.options,
          error: job.error,
          result: job.result
        }))
      };

      // Create and download file
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dernvale-jobs-export-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      console.log(`Successfully exported ${selectedJobData.length} job(s)`);
    } catch (err) {
      setError('Failed to export jobs');
      alert('Error exporting jobs: ' + err.message);
    }
  };

  const handleBulkArchive = async () => {
    // Check if any selected jobs can actually be archived
    const selectedJobData = jobs.filter(job => selectedJobs.includes(job.id));
    const archivableJobs = selectedJobData.filter(job => job.status !== 'pending' && job.status !== 'running' && job.status !== 'paused' && job.status !== 'archived');

    if (archivableJobs.length === 0) {
      setErrorModalData({
        title: 'Cannot Archive Jobs',
        message: 'None of the selected jobs can be archived. Cannot archive PENDING, RUNNING, or already ARCHIVED jobs.'
      });
      setShowErrorModal(true);
      return;
    }

    setConfirmModalData({
      title: '📦 Archive Confirmation',
      message: `Are you sure you want to archive ${archivableJobs.length} job(s)?`,
      actionType: 'archive',
      action: async () => {
        try {
          // Only send archivable job IDs
          const archivableJobIds = archivableJobs.map(job => job.id);
          const response = await bulkArchiveJobs(archivableJobIds);

          // Check results and show feedback
          const successful = response.results.filter(r => r.success).length;
          const failed = response.results.filter(r => !r.success).length;

          if (failed > 0) {
            const failedJobs = response.results.filter(r => !r.success);
            const errorMessages = failedJobs.map(r => `${r.job_id}: ${r.error}`).join('\n');
            alert(`Archived ${successful} job(s). Failed to archive ${failed} job(s):\n\n${errorMessages}`);
          } else {
            // Success message
            console.log(`Successfully archived ${successful} job(s)`);
          }

          // Refresh job list
          await loadJobs();
          setSelectedJobs([]);

        } catch (err) {
          setError(err.response?.data?.detail || 'Failed to archive jobs');
          alert('Error archiving jobs: ' + (err.response?.data?.detail || err.message));
        }
      }
    });
    setShowConfirmModal(true);
  };

  const handleBulkRestart = async () => {
    // Check if any selected jobs can actually be restarted
    const selectedJobData = jobs.filter(job => selectedJobs.includes(job.id));
    const restartableJobs = selectedJobData.filter(job => job.status === 'failed' || job.status === 'cancelled' || job.status === 'completed');

    if (restartableJobs.length === 0) {
      setErrorModalData({
        title: 'Cannot Restart Jobs',
        message: 'None of the selected jobs can be restarted. Only FAILED, CANCELLED, or COMPLETED jobs can be restarted.'
      });
      setShowErrorModal(true);
      return;
    }

    const counts = await Promise.all(restartableJobs.map(job => countFindings(job.id)));
    const withFindings = counts.filter(Boolean).length;
    const findingsNote = withFindings
      ? ` ${withFindings} of them ha${withFindings === 1 ? 's' : 've'} findings (${counts.reduce((a, b) => a + b, 0)} in all): `
        + 'restarting rewrites their output, so changed rows will show "row changed" in the case browser.'
      : '';

    setConfirmModalData({
      title: '🔄 Restart Confirmation',
      message: `Are you sure you want to restart ${restartableJobs.length} job(s)?${findingsNote}`,
      actionType: 'restart',
      action: async () => {
        try {
          // Only send restartable job IDs
          const restartableJobIds = restartableJobs.map(job => job.id);
          // The message above already warned about any findings
          const response = await bulkRestartJobs(restartableJobIds, true);

          // Check results and show feedback
          const successful = response.results.filter(r => r.success).length;
          const failed = response.results.filter(r => !r.success).length;

          if (failed > 0) {
            const failedJobs = response.results.filter(r => !r.success);
            const errorMessages = failedJobs.map(r => `${r.job_id}: ${r.error}`).join('\n');
            alert(`Restarted ${successful} job(s). Failed to restart ${failed} job(s):\n\n${errorMessages}`);
          } else {
            // Success message
            console.log(`Successfully restarted ${successful} job(s)`);
          }

          // Refresh job list
          await loadJobs();
          setSelectedJobs([]);

        } catch (err) {
          setError(err.response?.data?.detail || 'Failed to restart jobs');
          alert('Error restarting jobs: ' + (err.response?.data?.detail || err.message));
        }
      }
    });
    setShowConfirmModal(true);
  };

  const handleBulkStop = async () => {
    // Check if any selected jobs can actually be stopped
    const selectedJobData = jobs.filter(job => selectedJobs.includes(job.id));
    const stoppableJobs = selectedJobData.filter(job => job.status === 'pending' || job.status === 'running' || job.status === 'paused');

    if (stoppableJobs.length === 0) {
      setErrorModalData({
        title: 'Cannot Stop Jobs',
        message: 'None of the selected jobs can be stopped. Only PENDING or RUNNING jobs can be stopped.'
      });
      setShowErrorModal(true);
      return;
    }

    setConfirmModalData({
      title: '⛔ Stop Confirmation',
      message: `Are you sure you want to stop ${stoppableJobs.length} job(s)?`,
      actionType: 'stop',
      action: async () => {
        try {
          // Only send stoppable job IDs
          const stoppableJobIds = stoppableJobs.map(job => job.id);
          const response = await bulkCancelJobs(stoppableJobIds);

          // Check results and show feedback
          const successful = response.results.filter(r => r.success).length;
          const failed = response.results.filter(r => !r.success).length;

          if (failed > 0) {
            const failedJobs = response.results.filter(r => !r.success);
            const errorMessages = failedJobs.map(r => `Job: ${r.error}`).join('\n');
            alert(`Stopped ${successful} job(s). Failed to stop ${failed} job(s):\n\n${errorMessages}`);
          } else {
            // Success message
            console.log(`Successfully stopped ${successful} job(s)`);
          }

          // Clear any previous errors
          setError(null);

          // Refresh job list
          await loadJobs();
          setSelectedJobs([]);

        } catch (err) {
          setError(err.response?.data?.detail || 'Failed to stop jobs');
          setErrorModalData({
            title: 'Error Stopping Jobs',
            message: 'Error stopping jobs: ' + (err.response?.data?.detail || err.message)
          });
          setShowErrorModal(true);
        }
      }
    });
    setShowConfirmModal(true);
  };

  if (loading) {
    return <div className="loading">Loading jobs...</div>;
  }

  return (
    <div className="job-list journey-detail">
      {/* Confirmation Modal */}
      {showConfirmModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999
        }}>
          <div style={{
            background: 'linear-gradient(135deg, rgba(15, 15, 35, 0.98) 0%, rgba(25, 25, 45, 0.98) 100%)',
            border: '2px solid rgba(240, 219, 165, 0.5)',
            borderRadius: '8px',
            padding: '2rem',
            maxWidth: '600px',
            width: '100%',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.7)'
          }}>
            <h3 style={{
              color: confirmModalData.actionType === 'delete' ? '#f44336' : confirmModalData.actionType === 'stop' ? '#f44336' : '#ffc107',
              marginBottom: '1rem',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1.5rem',
              textAlign: 'center'
            }}>
              {confirmModalData.title}
            </h3>
            <p style={{
              color: '#f0dba5',
              lineHeight: '1.8',
              marginBottom: '2rem',
              fontSize: '1.1rem',
              textAlign: 'center'
            }}>
              {confirmModalData.message}
            </p>
            <div style={{
              display: 'flex',
              gap: '1rem',
              justifyContent: 'center'
            }}>
              <button
                onClick={handleCancelAction}
                style={{
                  padding: '0.75rem 1.5rem',
                  minWidth: '140px',
                  height: '48px',
                  background: 'rgba(240, 219, 165, 0.1)',
                  border: '1px solid rgba(240, 219, 165, 0.3)',
                  borderRadius: '4px',
                  color: '#f0dba5',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => {
                  e.target.style.background = 'rgba(240, 219, 165, 0.2)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(240, 219, 165, 0.1)';
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmAction}
                style={{
                  padding: '0.75rem 1.5rem',
                  minWidth: '140px',
                  height: '48px',
                  background: confirmModalData.actionType === 'delete' ? 'rgba(244, 67, 54, 0.3)' :
                              confirmModalData.actionType === 'stop' ? 'rgba(244, 67, 54, 0.3)' :
                              confirmModalData.actionType === 'restart' ? 'rgba(102, 217, 239, 0.3)' :
                              confirmModalData.actionType === 'archive' ? 'rgba(240, 219, 165, 0.2)' : 'rgba(102, 217, 239, 0.3)',
                  border: confirmModalData.actionType === 'delete' ? '1px solid rgba(244, 67, 54, 0.5)' :
                          confirmModalData.actionType === 'stop' ? '1px solid rgba(244, 67, 54, 0.5)' :
                          confirmModalData.actionType === 'restart' ? '1px solid rgba(102, 217, 239, 0.5)' :
                          confirmModalData.actionType === 'archive' ? '1px solid rgba(240, 219, 165, 0.4)' : '1px solid rgba(102, 217, 239, 0.5)',
                  borderRadius: '4px',
                  color: confirmModalData.actionType === 'delete' ? '#f44336' :
                         confirmModalData.actionType === 'stop' ? '#f44336' :
                         confirmModalData.actionType === 'restart' ? '#66d9ef' :
                         confirmModalData.actionType === 'archive' ? '#f0dba5' : '#66d9ef',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => {
                  if (confirmModalData.actionType === 'delete' || confirmModalData.actionType === 'stop') {
                    e.target.style.background = 'rgba(244, 67, 54, 0.4)';
                  } else if (confirmModalData.actionType === 'restart') {
                    e.target.style.background = 'rgba(102, 217, 239, 0.4)';
                  } else if (confirmModalData.actionType === 'archive') {
                    e.target.style.background = 'rgba(240, 219, 165, 0.3)';
                  } else {
                    e.target.style.background = 'rgba(102, 217, 239, 0.4)';
                  }
                }}
                onMouseOut={(e) => {
                  if (confirmModalData.actionType === 'delete' || confirmModalData.actionType === 'stop') {
                    e.target.style.background = 'rgba(244, 67, 54, 0.3)';
                  } else if (confirmModalData.actionType === 'restart') {
                    e.target.style.background = 'rgba(102, 217, 239, 0.3)';
                  } else if (confirmModalData.actionType === 'archive') {
                    e.target.style.background = 'rgba(240, 219, 165, 0.2)';
                  } else {
                    e.target.style.background = 'rgba(102, 217, 239, 0.3)';
                  }
                }}
              >
                {confirmModalData.actionType === 'delete' ? 'Delete' :
                 confirmModalData.actionType === 'stop' ? 'Stop' :
                 confirmModalData.actionType === 'restart' ? 'Restart' :
                 confirmModalData.actionType === 'archive' ? 'Archive' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Error Modal */}
      {showErrorModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999
        }}>
          <div style={{
            background: 'linear-gradient(135deg, rgba(15, 15, 35, 0.98) 0%, rgba(25, 25, 45, 0.98) 100%)',
            border: '2px solid rgba(240, 219, 165, 0.5)',
            borderRadius: '8px',
            padding: '2rem',
            maxWidth: '600px',
            width: '100%',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.7)'
          }}>
            <h3 style={{
              color: '#f44336',
              marginBottom: '1rem',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1.5rem',
              textAlign: 'center'
            }}>
              {errorModalData.title}
            </h3>
            <p style={{
              color: '#f0dba5',
              lineHeight: '1.8',
              marginBottom: '2rem',
              fontSize: '1.1rem',
              textAlign: 'center'
            }}>
              {errorModalData.message}
            </p>
            <div style={{
              display: 'flex',
              gap: '1rem',
              justifyContent: 'center'
            }}>
              <button
                onClick={() => setShowErrorModal(false)}
                style={{
                  padding: '0.75rem 1.5rem',
                  minWidth: '140px',
                  height: '48px',
                  background: 'rgba(102, 217, 239, 0.3)',
                  border: '1px solid rgba(102, 217, 239, 0.5)',
                  borderRadius: '4px',
                  color: '#66d9ef',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => {
                  e.target.style.background = 'rgba(102, 217, 239, 0.4)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(102, 217, 239, 0.3)';
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      <section className="hero-section">
        <img
          src={heroImage}
          alt="Dernvale"
          className="hero-image"
          style={{
            transform: 'scale(0.2)',
            transformOrigin: 'center top'
          }}
        />
      </section>

      <header>
        <h2>Analysis Jobs</h2>
        <p>Monitor and manage all forensic analysis and artifact processing jobs.</p>
      </header>

      <div className="card">
        <div className="list-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div data-guide="jobs.filters" className="filter-controls">
            <label>Filter by status:</label>
            <select
              value={statusFilter || ''}
              onChange={(e) => setStatusFilter(e.target.value || null)}
            >
              <option value="">All</option>
              <option value="pending">Pending</option>
              <option value="running">Running</option>
              <option value="paused">Paused</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </select>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          {selectedJobs.length > 0 && (
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={() => handleBulkStop()}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'rgba(244, 67, 54, 0.3)',
                  color: '#f44336',
                  border: '1px solid #e53935',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  minWidth: '140px'
                }}
              >
                Stop ({selectedJobs.length})
              </button>
              <button
                onClick={() => handleBulkRestart()}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'rgba(102, 217, 239, 0.3)',
                  color: '#66d9ef',
                  border: '1px solid #5ac8d8',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  minWidth: '140px'
                }}
              >
                Restart ({selectedJobs.length})
              </button>
              <button
                onClick={() => handleBulkExport()}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'rgba(107, 142, 63, 0.3)',
                  color: '#a7db6c',
                  border: '1px solid #6b8e3f',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  minWidth: '140px'
                }}
              >
                Export ({selectedJobs.length})
              </button>
              <button
                onClick={() => handleBulkArchive()}
                style={{
                  padding: '0.5rem 1rem',
                  background: 'rgba(240, 219, 165, 0.1)',
                  color: '#f0dba5',
                  border: '1px solid #8a7a5a',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  minWidth: '140px'
                }}
              >
                Archive ({selectedJobs.length})
              </button>
              <button
                onClick={() => handleBulkDelete()}
                style={{
                  padding: '0.5rem 1rem',
                  background: '#8b4513',
                  color: '#f0dba5',
                  border: '1px solid #654321',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  minWidth: '140px'
                }}
              >
                Delete ({selectedJobs.length})
              </button>
            </div>
          )}
            <Link to="/archive">
              <button
                style={{
                  padding: '0.5rem 1rem',
                  background: 'rgba(107, 142, 63, 0.3)',
                  color: '#a7db6c',
                  border: '1px solid #6b8e3f',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  minWidth: '140px',
                  boxSizing: 'border-box'
                }}
              >
                <span style={{ fontSize: '0.6rem' }}>📦</span> Archived Jobs
              </button>
            </Link>
          </div>
        </div>

        {error && <div className="error">{error}</div>}

        {jobs.length === 0 ? (
          <div className="empty-state">
            <p>No jobs found.</p>
            <Link to="/">
              <button>Start New Analysis</button>
            </Link>
          </div>
        ) : (
          <div data-guide="jobs.table" className="table-container">
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
                  <th style={{ width: '22%' }}>Case ID</th>
                  <th style={{ width: '14%' }}>Status</th>
                  <th style={{ width: '16%' }}>Progress</th>
                  <th style={{ width: '16%', paddingLeft: '2rem' }}>Created</th>
                  <th style={{ width: '16%', paddingLeft: '2rem' }}>Duration</th>
                  <th style={{ width: '9%' }}>Actions</th>
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
                      <div style={{ fontSize: '0.875rem', color: '#888', display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.25rem' }}>
                        <span>{job.source_paths.length} image(s)</span>
                        {(job.options?.splunk || job.options?.elastic || job.options?.navigator) && (
                          <div style={{ display: 'flex', gap: '0.25rem', alignItems: 'center' }}>
                            {job.options.splunk && (
                              <span title="Splunk Export Enabled" style={{ display: 'inline-flex', alignItems: 'center' }}>
                                <svg width="16" height="16" viewBox="0 0 100 100" fill="none">
                                  <defs>
                                    <radialGradient id="splunkGradientList" cx="30%" cy="30%">
                                      <stop offset="0%" style={{ stopColor: '#FF6B9D', stopOpacity: 1 }} />
                                      <stop offset="50%" style={{ stopColor: '#E91E8C', stopOpacity: 1 }} />
                                      <stop offset="100%" style={{ stopColor: '#C4166C', stopOpacity: 1 }} />
                                    </radialGradient>
                                  </defs>
                                  <circle cx="50" cy="50" r="48" fill="url(#splunkGradientList)"/>
                                  <path d="M45 35 L60 50 L45 65" stroke="white" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
                                </svg>
                              </span>
                            )}
                            {job.options.elastic && (
                              <span title="Elasticsearch Export Enabled" style={{ display: 'inline-flex', alignItems: 'center' }}>
                                <svg width="16" height="16" viewBox="0 0 100 100" fill="none">
                                  <defs>
                                    <linearGradient id="elasticYellowList" x1="0%" y1="0%" x2="100%" y2="0%">
                                      <stop offset="0%" style={{ stopColor: '#FED10A', stopOpacity: 1 }} />
                                      <stop offset="100%" style={{ stopColor: '#FDB42F', stopOpacity: 1 }} />
                                    </linearGradient>
                                    <linearGradient id="elasticTealList" x1="0%" y1="0%" x2="100%" y2="0%">
                                      <stop offset="0%" style={{ stopColor: '#00BFB3', stopOpacity: 1 }} />
                                      <stop offset="100%" style={{ stopColor: '#00A9A5', stopOpacity: 1 }} />
                                    </linearGradient>
                                    <linearGradient id="elasticBlueList" x1="0%" y1="0%" x2="100%" y2="0%">
                                      <stop offset="0%" style={{ stopColor: '#24BBB1', stopOpacity: 1 }} />
                                      <stop offset="100%" style={{ stopColor: '#0077CC', stopOpacity: 1 }} />
                                    </linearGradient>
                                  </defs>
                                  <rect x="10" y="20" width="70" height="12" rx="6" fill="url(#elasticYellowList)"/>
                                  <rect x="15" y="44" width="70" height="12" rx="6" fill="url(#elasticTealList)"/>
                                  <rect x="20" y="68" width="70" height="12" rx="6" fill="url(#elasticBlueList)"/>
                                </svg>
                              </span>
                            )}
                            {job.options.navigator && (
                              <span title="MITRE ATT&CK Navigator Enabled" style={{ display: 'inline-flex', alignItems: 'center' }}>
                                <svg width="16" height="16" viewBox="0 0 100 100" fill="none">
                                  <defs>
                                    <linearGradient id="mitreGradientList" x1="0%" y1="0%" x2="100%" y2="100%">
                                      <stop offset="0%" style={{ stopColor: '#FFD700', stopOpacity: 1 }} />
                                      <stop offset="50%" style={{ stopColor: '#FFC107', stopOpacity: 1 }} />
                                      <stop offset="100%" style={{ stopColor: '#FF9800', stopOpacity: 1 }} />
                                    </linearGradient>
                                  </defs>
                                  <path d="M50 10 L85 25 L85 50 Q85 75 50 90 Q15 75 15 50 L15 25 Z" fill="url(#mitreGradientList)"/>
                                  <circle cx="50" cy="50" r="22" fill="none" stroke="white" strokeWidth="3"/>
                                  <circle cx="50" cy="50" r="14" fill="none" stroke="white" strokeWidth="3"/>
                                  <circle cx="50" cy="50" r="6" fill="white"/>
                                  <line x1="50" y1="28" x2="50" y2="38" stroke="white" strokeWidth="2"/>
                                  <line x1="50" y1="62" x2="50" y2="72" stroke="white" strokeWidth="2"/>
                                  <line x1="28" y1="50" x2="38" y2="50" stroke="white" strokeWidth="2"/>
                                  <line x1="62" y1="50" x2="72" y2="50" stroke="white" strokeWidth="2"/>
                                </svg>
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className={getStatusClass(job.status)}>
                        {job.status.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td>
                      <div className="progress-bar">
                        <div
                          className="progress-fill"
                          style={{ width: `${job.progress}%` }}
                        >
                        </div>
                        {job.progress > 0 && <span className="progress-text">{job.progress}%</span>}
                      </div>
                    </td>
                    <td style={{ paddingLeft: '2rem' }}>{formatDate(job.created_at)}</td>
                    <td style={{ paddingLeft: '2rem' }}>{formatDuration(job.started_at, job.completed_at)}</td>
                    <td>
                      <Link to={`/jobs/${job.id}`}>
                        <button>Details</button>
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

export default JobList;
