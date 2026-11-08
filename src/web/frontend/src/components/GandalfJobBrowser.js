import React, { useState, useEffect } from 'react';
import { browsePath } from '../api';
import { browseRoots } from './FileBrowser';

function GandalfJobBrowser({ onSelectJobs, selectedJobs, disabled = false }) {
  // /evidence first, then the folders the Local browser offers: the lab's archives are on /Volumes
  const roots = ['/evidence', ...browseRoots()];
  const [rootPath, setRootPath] = useState(roots[0]);
  const [currentPath, setCurrentPath] = useState(roots[0]);
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!disabled) {
      loadJobs(currentPath);
    }
  }, [currentPath, disabled]);

  const loadJobs = async (path) => {
    setLoading(true);
    setError(null);

    try {
      const data = await browsePath(path);
      const items = Array.isArray(data) ? data : data.items || [];

      // Filter to show only directories (Gandalf acquisitions are directories)
      const directories = items.filter(item => item.is_directory && item.name !== '..' && !item.name.startsWith('.'));

      setJobs(directories);
    } catch (err) {
      // Check if it's a "path not found" or "access denied" error
      const errorMsg = err.response?.data?.detail || 'Failed to load Gandalf acquisitions';

      // If the directory doesn't exist, don't show it as an error
      if (errorMsg.includes('Path not found') || errorMsg.includes('not found')) {
        setJobs([]);
        setError(null);
      } else {
        setError(errorMsg);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSelectJob = (jobPath) => {
    if (disabled) return;

    if (selectedJobs.includes(jobPath)) {
      // Deselect
      onSelectJobs(selectedJobs.filter(p => p !== jobPath));
    } else {
      // Select
      onSelectJobs([...selectedJobs, jobPath]);
    }
  };

  const parentPath = currentPath !== rootPath ? currentPath.replace(/[\\/][^\\/]+[\\/]?$/, '') || rootPath : null;

  const handleRootChange = (newRoot) => {
    setRootPath(newRoot);
    setCurrentPath(newRoot);
  };

  const handleClearSelection = () => {
    onSelectJobs([]);
  };

  const formatDate = (dateString) => {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  if (loading) {
    return <div className="loading">Loading Gandalf acquisition jobs...</div>;
  }

  return (
    <div className={`gandalf-job-browser ${disabled ? 'disabled' : ''}`}>
      <div className="path-selector">
        <label htmlFor="gandalfRootSelect">Select Root Directory:</label>
        <select
          id="gandalfRootSelect"
          value={rootPath}
          onChange={(e) => handleRootChange(e.target.value)}
          disabled={disabled}
        >
          {roots.map((path) => (
            <option key={path} value={path}>{path}</option>
          ))}
        </select>
      </div>
      <div className="browser-header">
        <div className="current-location">
          <strong>Location:</strong> {currentPath}
        </div>
        {selectedJobs.length > 0 && (
          <div className="selection-info">
            <span>{selectedJobs.length} job(s) selected</span>
            <button
              type="button"
              onClick={handleClearSelection}
              className="secondary"
              disabled={disabled}
            >
              Clear Selection
            </button>
          </div>
        )}
      </div>

      {parentPath && (
        <button
          type="button"
          className="secondary"
          onClick={() => !disabled && setCurrentPath(parentPath)}
          disabled={disabled}
          style={{ marginBottom: '0.5rem' }}
        >
          ⬆ Up to {parentPath}
        </button>
      )}

      {jobs.length === 0 ? (
        <div className="empty-state">
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📁</div>
          <p style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>No Gandalf acquisition jobs found</p>
          <p style={{ fontSize: '0.9rem', color: '#888', marginTop: '0.5rem' }}>
            Gandalf acquisitions should be stored in {currentPath}
          </p>
        </div>
      ) : (
        <div className="jobs-list">
          <table>
            <thead>
              <tr>
                <th style={{ width: '5%' }}></th>
                <th style={{ width: '40%' }}>Folder (its name opens it)</th>
                <th style={{ width: '30%' }}>Modified</th>
                <th style={{ width: '25%' }}>Path</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr
                  key={job.path}
                  onClick={() => handleSelectJob(job.path)}
                  className={selectedJobs.includes(job.path) ? 'selected' : ''}
                  style={{ cursor: disabled ? 'not-allowed' : 'pointer' }}
                >
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedJobs.includes(job.path)}
                      onChange={() => handleSelectJob(job.path)}
                      disabled={disabled}
                      style={{ cursor: disabled ? 'not-allowed' : 'pointer' }}
                    />
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center' }}>
                      <span style={{ marginRight: '0.5rem', fontSize: '1.2rem' }}>📁</span>
                      <strong
                        onClick={(e) => { e.stopPropagation(); if (!disabled) setCurrentPath(job.path); }}
                        title="Open this folder"
                        style={{ textDecoration: 'underline', cursor: disabled ? 'not-allowed' : 'pointer' }}
                      >
                        {job.name}
                      </strong>
                    </div>
                  </td>
                  <td>{formatDate(job.modified)}</td>
                  <td style={{ fontSize: '0.85rem', color: '#888' }}>
                    {job.path}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedJobs.length > 0 && (
        <div className="selected-jobs">
          <h4>Selected Gandalf Acquisitions ({selectedJobs.length}):</h4>
          <ul>
            {selectedJobs.map((jobPath) => (
              <li key={jobPath}>
                {jobPath}
                <button
                  type="button"
                  onClick={() => handleSelectJob(jobPath)}
                  className="remove-button"
                  disabled={disabled}
                >
                  ✕
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default GandalfJobBrowser;
