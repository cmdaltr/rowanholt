import React, { useState, useEffect } from 'react';
import { browsePath } from '../api';

// The folders evidence is browsed from, by the browser's OS
export function browseRoots() {
  const isWindows = navigator.platform.toLowerCase().includes('win');
  const isMac = navigator.platform.toLowerCase().includes('mac');
  if (isWindows) {
    return ['C:\\Temp\\rowanholt', 'D:\\Temp\\rowanholt', 'E:\\Temp\\rowanholt', 'F:\\Temp\\rowanholt'];
  }
  if (isMac) {
    // Mac: /host/tmp/rowanholt for host /tmp access, /Volumes for external drives
    return ['/host/tmp/rowanholt', '/Volumes'];
  }
  // Linux: native uses /tmp/rowanholt, Docker uses /host/tmp (for Docker on Mac)
  return ['/Volumes', '/mnt', '/media', '/tmp/rowanholt'];
}

// allowFolders: a folder can be selected too (Mobile: an iTunes/Finder backup or an extraction is a folder)
function FileBrowser({ onSelectFiles, selectedFiles = [], disabled = false, allowFolders = false }) {
  const [currentPath, setCurrentPath] = useState(null);
  const [rootPath, setRootPath] = useState(null);  // Separate state for dropdown selection
  const [allowedPaths, setAllowedPaths] = useState([]);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [permissionWarning, setPermissionWarning] = useState(null);

  // Fetch allowed paths on mount
  useEffect(() => {
    fetchAllowedPaths();
  }, []);

  useEffect(() => {
    if (currentPath) {
      loadPath(currentPath);
    }
  }, [currentPath]);

  // Handle root path changes from dropdown
  const handleRootChange = (newRoot) => {
    setRootPath(newRoot);
    setCurrentPath(newRoot);
  };

  const fetchAllowedPaths = async () => {
    try {
      const paths = browseRoots();
      setAllowedPaths(paths);

      // Set first available path as default
      if (paths.length > 0) {
        setRootPath(paths[0]);
        setCurrentPath(paths[0]);
      }
    } catch (err) {
      setError('Failed to initialize file browser');
    }
  };

  const loadPath = async (path) => {
    setLoading(true);
    setError(null);
    setPermissionWarning(null);

    try {
      const data = await browsePath(path);
      // Handle new response format (object with items) or old format (array)
      const responseItems = Array.isArray(data) ? data : data.items || [];
      // Filter out hidden files (starting with .) except for ".." navigation
      const filteredData = responseItems.filter(item =>
        item.name === '..' || !item.name.startsWith('.')
      );
      setItems(filteredData);

      // Set permission warning if present
      if (data.permission_warning) {
        setPermissionWarning(data.permission_warning);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load directory');
    } finally {
      setLoading(false);
    }
  };

  // Check if a path is within or is the jobs directory
  const isJobsPath = (path) => {
    if (!path) return false;
    // Normalize path separators and check if path contains /jobs or ends with /jobs
    const normalizedPath = path.replace(/\\/g, '/');
    return normalizedPath.includes('/rowanholt/jobs/') || normalizedPath.endsWith('/rowanholt/jobs');
  };

  const handleItemClick = (item) => {
    if (disabled) return;

    // Prevent navigation into or selection within jobs directory
    if (isJobsPath(item.path) && item.name !== '..') {
      return;
    }

    if (item.is_directory) {
      setCurrentPath(item.path);
    } else {
      // Toggle file selection
      const isSelected = selectedFiles.includes(item.path);
      if (isSelected) {
        onSelectFiles(selectedFiles.filter(p => p !== item.path));
      } else {
        onSelectFiles([...selectedFiles, item.path]);
      }
    }
  };

  const formatSize = (bytes) => {
    if (!bytes) return '';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = bytes;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    return `${size.toFixed(2)} ${units[unitIndex]}`;
  };

  const formatDate = (dateString) => {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  return (
    <div className={`file-browser-container ${disabled ? 'disabled' : ''}`}>
      {allowedPaths.length > 1 && (
        <div className="path-selector">
          <label htmlFor="pathSelect">Select Root Directory:</label>
          <select
            id="pathSelect"
            value={rootPath || ''}
            onChange={(e) => handleRootChange(e.target.value)}
            disabled={disabled}
          >
            {allowedPaths.map((path) => (
              <option key={path} value={path}>
                {path}
              </option>
            ))}
          </select>
        </div>
      )}

      <div className="current-path" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <strong>Current Path:</strong> {currentPath || 'Loading...'}
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
        {allowFolders && currentPath && (
          <button
            type="button"
            onClick={() => {
              if (disabled || isJobsPath(currentPath)) return;
              onSelectFiles(selectedFiles.includes(currentPath)
                ? selectedFiles.filter(p => p !== currentPath)
                : [...selectedFiles, currentPath]);
            }}
            disabled={disabled || loading || isJobsPath(currentPath)}
            title="Select the folder you're in (a backup or an extraction folder)"
            style={{
              padding: '0.5rem 1rem',
              borderRadius: '4px',
              border: '1px solid #3f4b2a',
              background: selectedFiles.includes(currentPath) ? 'rgba(167, 219, 108, 0.2)' : 'rgba(240, 219, 165, 0.1)',
              color: '#f0dba5',
              cursor: disabled || loading ? 'not-allowed' : 'pointer',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '0.9rem'
            }}
          >
            {selectedFiles.includes(currentPath) ? 'Folder selected' : 'Select this folder'}
          </button>
        )}
        <button
          onClick={() => currentPath && loadPath(currentPath)}
          disabled={disabled || loading}
          style={{
            padding: '0.5rem 1rem',
            borderRadius: '4px',
            border: '1px solid #3f4b2a',
            background: 'rgba(240, 219, 165, 0.1)',
            color: '#f0dba5',
            cursor: disabled || loading ? 'not-allowed' : 'pointer',
            fontFamily: "'Cinzel', 'Times New Roman', serif",
            fontSize: '0.9rem',
            transition: 'all 0.3s ease'
          }}
          onMouseOver={(e) => !disabled && !loading && (e.target.style.background = 'rgba(240, 219, 165, 0.2)')}
          onMouseOut={(e) => (e.target.style.background = 'rgba(240, 219, 165, 0.1)')}
        >
          Refresh
        </button>
        </div>
      </div>

      {error && <div className="error">{error}</div>}

      {permissionWarning && (
        <div className="permission-warning" style={{
          backgroundColor: 'rgba(255, 193, 7, 0.15)',
          border: '1px solid rgba(255, 193, 7, 0.5)',
          borderRadius: '4px',
          padding: '0.75rem 1rem',
          marginBottom: '1rem',
          color: '#ffc107',
          fontSize: '0.9rem'
        }}>
          ⚠️ {permissionWarning}
        </div>
      )}

      {loading ? (
        <div className="loading">Loading...</div>
      ) : (
        <div className="file-browser">
          {items.map((item, index) => {
            const isRestricted = isJobsPath(item.path) && item.name !== '..';
            return (
            <div
              key={index}
              className={`file-item ${
                selectedFiles.includes(item.path) ? 'selected' : ''
              } ${item.is_image ? 'image' : ''} ${isRestricted ? 'restricted' : ''}`}
              onClick={() => handleItemClick(item)}
              style={isRestricted ? { opacity: 0.5, cursor: 'not-allowed' } : {}}
            >
              <span className="file-icon">
                {item.name === '..' ? '⬆️' : item.is_directory ? '📁' : item.is_image ? '💿' : '📄'}
              </span>
              <div className="file-info">
                <div className="file-name">{item.name}</div>
                {!item.is_directory && item.size && (
                  <div className="file-details">
                    {formatSize(item.size)} • {formatDate(item.modified)}
                  </div>
                )}
              </div>
              {item.is_image && (
                <span className="image-badge">IMAGE</span>
              )}
            </div>
          );
          })}
        </div>
      )}

      {selectedFiles.length > 0 && (
        <div className="selected-files">
          <h4>Selected Files ({selectedFiles.length}):</h4>
          <ul>
            {selectedFiles.map((path, index) => (
              <li key={index}>{path}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default FileBrowser;
