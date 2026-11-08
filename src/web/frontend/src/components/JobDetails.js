import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { getJob, cancelJob, pauseJob, resumeJob, deleteJob, restartJob, exportSiem, confirmSudo, cancelSudo } from '../api';
import { serviceUrl } from '../apiBase';
import JobSharing from './JobSharing';

const heroImage = `${process.env.PUBLIC_URL}/images/rowanholt.png`;

function JobDetails() {
  const { jobId } = useParams();
  const navigate = useNavigate();
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  const logEndRef = useRef(null);
  const [showCancelModal, setShowCancelModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showSudoModal, setShowSudoModal] = useState(false);

  // Auto-show sudo modal when job is awaiting confirmation
  useEffect(() => {
    if (job?.status === 'awaiting_confirmation' && job?.pending_action) {
      setShowSudoModal(true);
    } else {
      setShowSudoModal(false);
    }
  }, [job?.status, job?.pending_action]);

  useEffect(() => {
    loadJob();
    // Auto-refresh every 3 seconds
    const interval = setInterval(loadJob, 3000);
    return () => clearInterval(interval);
  }, [jobId]);

  // Auto-scroll to bottom of log when it updates
  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollTop = logEndRef.current.scrollHeight;
    }
  }, [job?.log]);

  const loadJob = async () => {
    try {
      const data = await getJob(jobId);
      setJob(data);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load job');
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = () => {
    setShowCancelModal(true);
  };

  const handleCancelConfirm = async () => {
    setShowCancelModal(false);
    setActionLoading(true);
    try {
      await cancelJob(jobId);
      await loadJob();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to cancel job');
    } finally {
      setActionLoading(false);
    }
  };

  const handleDelete = () => {
    setShowDeleteModal(true);
  };

  const handleDeleteConfirm = async () => {
    setShowDeleteModal(false);
    setActionLoading(true);
    try {
      await deleteJob(jobId);
      navigate('/jobs');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to delete job');
      setActionLoading(false);
    }
  };

  const handlePauseResume = async () => {
    setActionLoading(true);
    try {
      if (job.status === 'paused') {
        await resumeJob(jobId);
      } else {
        await pauseJob(jobId);
      }
      await loadJob();
    } catch (err) {
      setError(err.response?.data?.detail || `Failed to ${job.status === 'paused' ? 'resume' : 'pause'} job`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRestart = async () => {
    setActionLoading(true);
    try {
      try {
        await restartJob(jobId);
      } catch (err) {
        // The case has findings: the backend says how many, and the restart waits for a yes
        if (err.response?.status !== 409) throw err;
        const { findings } = err.response.data.detail;
        if (!window.confirm(
          `This case has ${findings} finding${findings === 1 ? '' : 's'}. Restarting rewrites the case's output, so any `
          + 'row that changes will show "row changed" in the case browser. Restart anyway?')) {
          return;
        }
        await restartJob(jobId, true);
      }
      await loadJob();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to restart job');
    } finally {
      setActionLoading(false);
    }
  };

  const handleSudoConfirm = async () => {
    setShowSudoModal(false);
    setActionLoading(true);
    try {
      await confirmSudo(jobId);
      await loadJob();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to confirm sudo action');
    } finally {
      setActionLoading(false);
    }
  };

  const handleSudoCancel = async () => {
    setShowSudoModal(false);
    setActionLoading(true);
    try {
      await cancelSudo(jobId);
      await loadJob();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to cancel sudo action');
    } finally {
      setActionLoading(false);
    }
  };

  const handleExportSiem = async () => {
    setActionLoading(true);
    try {
      await exportSiem(jobId);
      // Reload job to get updated logs
      await loadJob();
      alert('SIEM export started! Check the job log for progress.');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to export SIEM data');
      alert('SIEM export failed: ' + (err.response?.data?.detail || 'Unknown error'));
    } finally {
      setActionLoading(false);
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
    if (duration < 3600) return `${Math.floor(duration / 60)}m ${duration % 60}s`;
    const hours = Math.floor(duration / 3600);
    const minutes = Math.floor((duration % 3600) / 60);
    return `${hours}h ${minutes}m`;
  };

  const downloadLog = () => {
    if (!job || !job.log || job.log.length === 0) return;

    const logText = job.log.join('\n');
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `job-${job.id}-log.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getEnabledOptions = () => {
    if (!job) return [];
    const enabled = [];
    // Internal options to exclude from display
    const internalOptions = ['collect', 'process', 'local', 'gandalf', 'brisk', 'force_overwrite', 'save_template'];

    // Special formatting for specific options
    const specialFormatting = {
      'vss': 'VSS',
      'userprofiles': 'User Profiles',
      'nsrl': 'NSRL',
      'extract_iocs': 'Extract IOCs',
      'threat_intel': 'Threat Intelligence',
      'splunk': 'Splunk',
      'elastic': 'Elastic',
      'opensearch': 'OpenSearch',
      'timesketch': 'Timesketch',
      'navigator': 'Navigator'
    };

    // SIEM options that get special treatment with logos and links
    const siemOptions = ['splunk', 'elastic', 'navigator'];

    Object.entries(job.options).forEach(([key, value]) => {
      // Use case-insensitive comparison for internal options
      const keyLower = key.toLowerCase();
      if (value === true && !internalOptions.includes(keyLower)) {
        // Check if there's special formatting for this key (case-insensitive)
        const displayName = specialFormatting[keyLower] || key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        enabled.push({
          name: displayName,
          key: keyLower,
          isSiem: siemOptions.includes(keyLower)
        });
      }
    });
    return enabled;
  };

  const getSiemLink = (optionKey) => {
    if (!job) return null;
    switch (optionKey) {
      case 'splunk':
        return serviceUrl(7755, '/en-GB/app/elrond/mitre');
      case 'elastic':
        return `${serviceUrl(5601)}/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-20y,to:now))&_a=(columns:!(),filters:!(),index:${job.case_number},interval:auto,query:(language:kuery,query:''),sort:!(!('@timestamp',desc)))`;
      case 'navigator':
        const layerUrl = serviceUrl(5602, `/assets/${job.case_number}.json`);
        return `${serviceUrl(5602)}/#layerURL=${encodeURIComponent(layerUrl)}`;
      default:
        return null;
    }
  };

  const renderSiemIcon = (optionKey) => {
    switch (optionKey) {
      case 'splunk':
        return (
          <svg width="16" height="16" viewBox="0 0 100 100" fill="none" style={{ marginRight: '6px', verticalAlign: 'middle' }}>
            <defs>
              <radialGradient id="splunkGradientBadge" cx="30%" cy="30%">
                <stop offset="0%" style={{ stopColor: '#FF6B9D', stopOpacity: 1 }} />
                <stop offset="50%" style={{ stopColor: '#E91E8C', stopOpacity: 1 }} />
                <stop offset="100%" style={{ stopColor: '#C4166C', stopOpacity: 1 }} />
              </radialGradient>
            </defs>
            <circle cx="50" cy="50" r="48" fill="url(#splunkGradientBadge)"/>
            <path d="M45 35 L60 50 L45 65" stroke="white" strokeWidth="6" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
          </svg>
        );
      case 'elastic':
        return (
          <svg width="16" height="16" viewBox="0 0 100 100" fill="none" style={{ marginRight: '6px', verticalAlign: 'middle' }}>
            <defs>
              <linearGradient id="elasticYellowBadge" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" style={{ stopColor: '#FED10A', stopOpacity: 1 }} />
                <stop offset="100%" style={{ stopColor: '#FDB42F', stopOpacity: 1 }} />
              </linearGradient>
              <linearGradient id="elasticTealBadge" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" style={{ stopColor: '#00BFB3', stopOpacity: 1 }} />
                <stop offset="100%" style={{ stopColor: '#00A9A5', stopOpacity: 1 }} />
              </linearGradient>
              <linearGradient id="elasticBlueBadge" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" style={{ stopColor: '#24BBB1', stopOpacity: 1 }} />
                <stop offset="100%" style={{ stopColor: '#0077CC', stopOpacity: 1 }} />
              </linearGradient>
            </defs>
            <rect x="10" y="20" width="70" height="12" rx="6" fill="url(#elasticYellowBadge)"/>
            <rect x="15" y="44" width="70" height="12" rx="6" fill="url(#elasticTealBadge)"/>
            <rect x="20" y="68" width="70" height="12" rx="6" fill="url(#elasticBlueBadge)"/>
          </svg>
        );
      case 'navigator':
        return (
          <svg width="16" height="16" viewBox="0 0 100 100" fill="none" style={{ marginRight: '6px', verticalAlign: 'middle' }}>
            <defs>
              <linearGradient id="mitreGradientBadge" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style={{ stopColor: '#FFD700', stopOpacity: 1 }} />
                <stop offset="50%" style={{ stopColor: '#FFC107', stopOpacity: 1 }} />
                <stop offset="100%" style={{ stopColor: '#FF9800', stopOpacity: 1 }} />
              </linearGradient>
            </defs>
            <path d="M50 10 L85 25 L85 50 Q85 75 50 90 Q15 75 15 50 L15 25 Z" fill="url(#mitreGradientBadge)"/>
            <circle cx="50" cy="50" r="22" fill="none" stroke="white" strokeWidth="3"/>
            <circle cx="50" cy="50" r="14" fill="none" stroke="white" strokeWidth="3"/>
            <circle cx="50" cy="50" r="6" fill="white"/>
          </svg>
        );
      default:
        return null;
    }
  };

  if (loading) {
    return <div className="loading">Loading job details...</div>;
  }

  if (error && !job) {
    // Select a random 404 image
    const notFoundImages = [
      'boromir404.png',
      'frodo1404.png',
      'frodo2404.png',
      'gandalf404.png',
      'gollum404.png'
    ];
    const randomImage = notFoundImages[Math.floor(Math.random() * notFoundImages.length)];
    const notFoundImageUrl = `${process.env.PUBLIC_URL}/images/404/${randomImage}`;

    return (
      <div className="job-details journey-detail">
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
          <h2>Job Not Found</h2>
          <p>The requested job could not be found. It may have been deleted or the ID is incorrect.</p>
        </header>

        <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
          <img
            src={notFoundImageUrl}
            alt="Job Not Found"
            style={{
              maxWidth: '900px',
              width: '100%',
              height: 'auto',
              marginBottom: '2rem',
              borderRadius: '8px'
            }}
          />
          <p style={{ marginBottom: '2rem', color: '#a7db6c' }}>{error}</p>
          <Link to="/jobs">
            <button>Back to Jobs</button>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="job-details journey-detail">
      {/* Cancel Job Modal */}
      {showCancelModal && (
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
            maxWidth: '500px',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.7)'
          }}>
            <h3 style={{
              color: '#ffc107',
              marginBottom: '1rem',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1.5rem',
              textAlign: 'center'
            }}>
              ⚠️ Cancel Job
            </h3>
            <p style={{
              color: '#f0dba5',
              lineHeight: '1.8',
              marginBottom: '2rem',
              fontSize: '1rem',
              textAlign: 'center'
            }}>
              Are you sure you want to cancel this job?
            </p>
            <div style={{
              display: 'flex',
              gap: '1rem',
              justifyContent: 'center'
            }}>
              <button
                onClick={() => setShowCancelModal(false)}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'rgba(107, 142, 63, 0.3)',
                  border: '1px solid rgba(107, 142, 63, 0.5)',
                  borderRadius: '4px',
                  color: '#a7db6c',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => {
                  e.target.style.background = 'rgba(107, 142, 63, 0.4)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(107, 142, 63, 0.3)';
                }}
              >
                No, Keep Job
              </button>
              <button
                onClick={handleCancelConfirm}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'rgba(244, 67, 54, 0.3)',
                  border: '1px solid rgba(244, 67, 54, 0.5)',
                  borderRadius: '4px',
                  color: '#f44336',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => {
                  e.target.style.background = 'rgba(244, 67, 54, 0.4)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(244, 67, 54, 0.3)';
                }}
              >
                Yes, Cancel Job
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Job Modal */}
      {showDeleteModal && (
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
            maxWidth: '500px',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.7)'
          }}>
            <h3 style={{
              color: '#ffc107',
              marginBottom: '1rem',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1.5rem',
              textAlign: 'center'
            }}>
              ⚠️ Delete Job
            </h3>
            <p style={{
              color: '#f0dba5',
              lineHeight: '1.8',
              marginBottom: '1rem',
              fontSize: '1rem',
              textAlign: 'center'
            }}>
              Are you sure you want to delete this job?
            </p>
            <p style={{
              color: '#f44336',
              lineHeight: '1.8',
              marginBottom: '2rem',
              fontSize: '0.9rem',
              textAlign: 'center',
              fontWeight: 'bold'
            }}>
              This action cannot be undone.
            </p>
            <div style={{
              display: 'flex',
              gap: '1rem',
              justifyContent: 'center'
            }}>
              <button
                onClick={() => setShowDeleteModal(false)}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'rgba(107, 142, 63, 0.3)',
                  border: '1px solid rgba(107, 142, 63, 0.5)',
                  borderRadius: '4px',
                  color: '#a7db6c',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => {
                  e.target.style.background = 'rgba(107, 142, 63, 0.4)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(107, 142, 63, 0.3)';
                }}
              >
                No, Keep Job
              </button>
              <button
                onClick={handleDeleteConfirm}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'rgba(244, 67, 54, 0.3)',
                  border: '1px solid rgba(244, 67, 54, 0.5)',
                  borderRadius: '4px',
                  color: '#f44336',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => {
                  e.target.style.background = 'rgba(244, 67, 54, 0.4)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(244, 67, 54, 0.3)';
                }}
              >
                Yes, Delete Job
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Sudo Confirmation Modal */}
      {showSudoModal && job?.pending_action && (
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
            border: '2px solid rgba(255, 152, 0, 0.7)',
            borderRadius: '8px',
            padding: '2rem',
            maxWidth: '600px',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.7)'
          }}>
            <h3 style={{
              color: '#ff9800',
              marginBottom: '1rem',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1.5rem',
              textAlign: 'center'
            }}>
              🔐 Elevated Permissions Required
            </h3>
            <p style={{
              color: '#f0dba5',
              lineHeight: '1.8',
              marginBottom: '1rem',
              fontSize: '1rem',
              textAlign: 'center'
            }}>
              {job.pending_action.message}
            </p>
            <p style={{
              color: '#ff9800',
              lineHeight: '1.6',
              marginBottom: '1rem',
              fontSize: '0.9rem',
              textAlign: 'center',
              fontFamily: 'monospace',
              background: 'rgba(0,0,0,0.3)',
              padding: '0.5rem',
              borderRadius: '4px',
              wordBreak: 'break-all'
            }}>
              {job.pending_action.target_path}
            </p>
            <p style={{
              color: '#f44336',
              lineHeight: '1.6',
              marginBottom: '2rem',
              fontSize: '0.85rem',
              textAlign: 'center',
              fontWeight: 'bold'
            }}>
              ⚠️ This will run: sudo rm -rf on the above path
            </p>
            <div style={{
              display: 'flex',
              gap: '1rem',
              justifyContent: 'center'
            }}>
              <button
                onClick={handleSudoCancel}
                disabled={actionLoading}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'rgba(107, 142, 63, 0.3)',
                  border: '1px solid rgba(107, 142, 63, 0.5)',
                  borderRadius: '4px',
                  color: '#a7db6c',
                  cursor: actionLoading ? 'not-allowed' : 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease',
                  opacity: actionLoading ? 0.5 : 1
                }}
                onMouseOver={(e) => {
                  if (!actionLoading) e.target.style.background = 'rgba(107, 142, 63, 0.4)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(107, 142, 63, 0.3)';
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleSudoConfirm}
                disabled={actionLoading}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'rgba(255, 152, 0, 0.3)',
                  border: '1px solid rgba(255, 152, 0, 0.5)',
                  borderRadius: '4px',
                  color: '#ff9800',
                  cursor: actionLoading ? 'not-allowed' : 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease',
                  opacity: actionLoading ? 0.5 : 1
                }}
                onMouseOver={(e) => {
                  if (!actionLoading) e.target.style.background = 'rgba(255, 152, 0, 0.4)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(255, 152, 0, 0.3)';
                }}
              >
                {actionLoading ? 'Processing...' : 'Confirm Sudo'}
              </button>
            </div>
          </div>
        </div>
      )}

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
        <h2>Job Monitoring</h2>
        <p>Real-time monitoring of forensic analysis and artifact processing jobs.</p>
      </header>

      <div className="card">
        <div className="job-header">
          <div>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              Job Details
              <span style={{ fontSize: '0.9rem', fontWeight: 'normal', color: '#8a9ba8' }}>{formatDate(job.started_at)}</span>
            </h2>
            <div className="job-id">ID: {job.id}</div>
          </div>
          <div data-guide="job.actions" className="job-actions">
            {(job.status === 'running' || job.status === 'paused') && (
              <button
                className="secondary"
                onClick={handlePauseResume}
                disabled={actionLoading}
                title="Paused jobs keep their image mounted and locked"
              >
                {job.status === 'paused' ? 'Resume Job' : 'Pause Job'}
              </button>
            )}
            {(job.status === 'pending' || job.status === 'running' || job.status === 'paused') && (
              <button
                className="secondary"
                onClick={handleCancel}
                disabled={actionLoading}
              >
                Cancel Job
              </button>
            )}
            {(job.status === 'failed' || job.status === 'cancelled' || job.status === 'completed') && (
              <>
                <button
                  onClick={handleRestart}
                  disabled={actionLoading}
                  style={{
                    background: 'rgba(107, 142, 63, 0.3)',
                    border: '1px solid rgba(107, 142, 63, 0.5)',
                    color: '#a7db6c'
                  }}
                >
                  Restart Job
                </button>
                <button
                  className="secondary"
                  onClick={handleDelete}
                  disabled={actionLoading}
                >
                  Delete Job
                </button>
              </>
            )}
            {job.status === 'completed' && (
              <Link to={`/jobs/${job.id}/case`}>
                <button data-guide="job.case">Browse Case</button>
              </Link>
            )}
            <Link to="/jobs">
              <button>Back to Jobs</button>
            </Link>
          </div>
        </div>

        {error && <div className="error">{error}</div>}

        {/* Row 1: Case # | Duration | Destination */}
        <div data-guide="job.info" className="job-info-grid" style={{ display: 'grid', gridTemplateColumns: '0.5fr 0.5fr 2fr', gap: '1rem', marginBottom: '1rem' }}>
          <div className="info-item">
            <strong>Case #:</strong>
            <span>{job.case_number}</span>
          </div>
          <div className="info-item">
            <strong>Duration:</strong>
            <span>{formatDuration(job.started_at, job.completed_at)}</span>
          </div>
          <div className="info-item">
            <strong>Destination:</strong>
            <span>{job.destination_path ? job.destination_path.replace(/\/[^/]+$/, '') : 'Default location'}</span>
          </div>
        </div>
        {/* Row 3: Progress bar */}
        <div data-guide="job.progress" className="job-info-grid" style={{ marginBottom: '0.5rem' }}>
          <div className="progress-bar" style={{ width: '100%' }}>
            <div
              className="progress-fill"
              style={{ width: `${job.progress}%` }}
            >
            </div>
            {job.progress > 0 && <span className="progress-text">{job.progress}%</span>}
          </div>
        </div>

        {job.error && (
          <div className="error-section">
            <h3>Error</h3>
            <div className="error">{job.error}</div>
          </div>
        )}

        <JobSharing jobId={job.id} />

        <div style={{ display: 'flex', gap: '1.5rem', marginBottom: '2rem' }}>
          <div data-guide="job.sources" className="source-paths-section" style={{ flex: '1', minWidth: '0' }}>
            <h3>Source Images ({job.source_paths.length})</h3>
            <ul>
              {job.source_paths.map((path, index) => (
                <li key={index}>{path}</li>
              ))}
            </ul>
          </div>

          <div data-guide="job.options" className="options-section" style={{ flex: '1', minWidth: '0' }}>
            <h3>Enabled Options</h3>
            {getEnabledOptions().length > 0 ? (
              <div className="options-tags">
                {getEnabledOptions().map((option, index) => {
                  // For SIEM options (when job is completed), render as clickable links with icons
                  if (option.isSiem && job.status === 'completed') {
                    const link = getSiemLink(option.key);
                    return (
                      <a
                        key={index}
                        href={link}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={`option-tag option-tag-siem option-tag-${option.key}`}
                        title={`Open ${option.name}`}
                      >
                        {renderSiemIcon(option.key)}
                        {option.name}
                      </a>
                    );
                  }
                  // Regular options
                  return (
                    <span key={index} className="option-tag">{option.name}</span>
                  );
                })}
              </div>
            ) : (
              <p>No options enabled (default configuration)</p>
            )}
            {job.options?.save_template && (
              <div className="template-save-indicator">
                {job.status === 'completed' ? (
                  <span className="template-saved">Template saved to output directory</span>
                ) : (
                  <span className="template-pending">Template will be saved on completion</span>
                )}
              </div>
            )}
          </div>
        </div>

        <div data-guide="job.log" className="log-section">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <button
                onClick={job.log.length > 0 ? downloadLog : undefined}
                disabled={job.log.length === 0}
                style={{
                  padding: '0.5rem 1rem',
                  background: job.log.length > 0 ? 'rgba(107, 142, 63, 0.3)' : 'rgba(80, 80, 80, 0.3)',
                  border: job.log.length > 0 ? '1px solid rgba(107, 142, 63, 0.5)' : '1px solid rgba(80, 80, 80, 0.5)',
                  borderRadius: '4px',
                  color: job.log.length > 0 ? '#a7db6c' : '#666',
                  cursor: job.log.length > 0 ? 'pointer' : 'not-allowed',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '0.9rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease',
                  opacity: job.log.length > 0 ? 1 : 0.5
                }}
                onMouseOver={(e) => {
                  if (job.log.length > 0) e.target.style.background = 'rgba(107, 142, 63, 0.4)';
                }}
                onMouseOut={(e) => {
                  if (job.log.length > 0) e.target.style.background = 'rgba(107, 142, 63, 0.3)';
                }}
              >
                Download Log
              </button>
              <span
                className={getStatusClass(job.status)}
                style={{
                  textAlign: 'center',
                  padding: '0.5rem 1rem',
                  borderRadius: '4px',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '0.9rem',
                  fontWeight: 600
                }}
              >
                {job.status}
              </span>
            </div>
            <h3 style={{ margin: 0 }}>Job Log ({job.log.length} entries)</h3>
          </div>
          <div className="log-viewer" ref={logEndRef}>
            <pre>
              {job.log.length > 0
                ? job.log.join('\n')
                : 'No log entries yet...'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

export default JobDetails;
