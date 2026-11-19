import React, { useState, useEffect } from 'react';
import { getMordorCatalog, downloadMordorDataset } from '../api';

// Platform icons
import windowsIcon from '../static/images/windows.png';
import linuxIcon from '../static/images/linux.png';
import macosIcon from '../static/images/macos.png';
import awsIcon from '../static/images/aws.png';
import azureIcon from '../static/images/azure.png';

const MordorCatalog = ({ onDownloadComplete, search = '', showDownloadedOnly = false, platform = '', tactic = '', technique = '', selectedDatasets = [], setSelectedDatasets }) => {
  const [datasets, setDatasets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [total, setTotal] = useState(0);
  const [downloading, setDownloading] = useState({});

  useEffect(() => {
    loadCatalog();
  }, [platform, tactic, technique, search]);

  const loadCatalog = async () => {
    try {
      setLoading(true);
      const params = {};
      if (platform) params.platform = platform;
      if (tactic) params.tactic = tactic;
      if (technique) params.technique = technique;
      if (search) params.search = search;

      params.limit = 200; // Request all datasets
      const result = await getMordorCatalog(params);
      setDatasets(result.datasets);
      setTotal(result.total);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load catalog');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (datasetId) => {
    try {
      setDownloading(prev => ({ ...prev, [datasetId]: true }));
      await downloadMordorDataset(datasetId);

      // Refresh to show updated status
      await loadCatalog();
      onDownloadComplete?.();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to start download');
    } finally {
      setDownloading(prev => ({ ...prev, [datasetId]: false }));
    }
  };

  const toggleSelect = (datasetId) => {
    setSelectedDatasets(prev =>
      prev.includes(datasetId)
        ? prev.filter(id => id !== datasetId)
        : [...prev, datasetId]
    );
  };

  const getPlatformIcon = (platformName) => {
    const platformImages = {
      'windows': windowsIcon,
      'linux': linuxIcon,
      'macos': macosIcon,
      'aws': awsIcon,
      'azure': azureIcon,
    };

    const key = platformName?.toLowerCase();
    const imageSrc = platformImages[key];

    if (imageSrc) {
      return (
        <img
          src={imageSrc}
          alt={platformName}
          title={platformName}
          style={{ height: '36px', width: 'auto' }}
        />
      );
    }
    return platformName;
  };

  const getStatusBadge = (status) => {
    const styles = {
      available: { background: 'rgba(240, 219, 165, 0.2)', color: '#f0dba5' },
      downloading: { background: 'rgba(102, 217, 239, 0.2)', color: '#66d9ef' },
      downloaded: { background: 'rgba(167, 219, 108, 0.2)', color: '#a7db6c' },
      failed: { background: 'rgba(244, 67, 54, 0.2)', color: '#f44336' }
    };

    return (
      <span style={{
        ...styles[status] || styles.available,
        padding: '0.25rem 0.5rem',
        borderRadius: '4px',
        fontSize: '0.8rem',
        textTransform: 'uppercase'
      }}>
        {status}
      </span>
    );
  };

  if (loading && datasets.length === 0) {
    return <div className="loading">Loading catalog...</div>;
  }

  // Filter datasets based on showDownloadedOnly toggle
  const filteredDatasets = showDownloadedOnly
    ? datasets.filter(ds => ds.status === 'downloaded')
    : datasets;

  return (
    <div>
      {error && <div className="error" style={{ marginBottom: '1rem' }}>{error}</div>}

      {/* Results */}
      <div style={{ marginBottom: '0.5rem', color: '#888' }}>
        Showing {filteredDatasets.length} of {total} datasets
        {showDownloadedOnly && ' (downloaded only)'}
      </div>

      <div className="table-container" style={{ fontSize: '1.1rem' }}>
        <table>
          <thead>
            <tr>
              <th style={{ width: '5%' }}>
                <input
                  type="checkbox"
                  checked={selectedDatasets.length === filteredDatasets.length && filteredDatasets.length > 0}
                  onChange={() => {
                    if (selectedDatasets.length === filteredDatasets.length) {
                      setSelectedDatasets([]);
                    } else {
                      setSelectedDatasets(filteredDatasets.map(d => d.dataset_id));
                    }
                  }}
                />
              </th>
              <th style={{ width: '15%' }}>ID</th>
              <th style={{ width: '35%' }}>Title</th>
              <th style={{ width: '10%' }}>Platform</th>
              <th style={{ width: '15%' }}>Tactics</th>
              <th style={{ width: '15%' }}>Status</th>
              <th style={{ width: '15%' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredDatasets.map(ds => (
              <tr key={ds.dataset_id}>
                <td>
                  <input
                    type="checkbox"
                    checked={selectedDatasets.includes(ds.dataset_id)}
                    onChange={() => toggleSelect(ds.dataset_id)}
                  />
                </td>
                <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                  {ds.dataset_id}
                </td>
                <td>
                  <strong>{ds.title}</strong>
                  {ds.techniques && ds.techniques.length > 0 && (
                    <div style={{ fontSize: '1rem', color: '#888', marginTop: '0.25rem' }}>
                      {ds.techniques.slice(0, 3).join(', ')}
                      {ds.techniques.length > 3 && ` +${ds.techniques.length - 3} more`}
                    </div>
                  )}
                </td>
                <td style={{ textAlign: 'center' }}>{getPlatformIcon(ds.platform)}</td>
                <td style={{ fontSize: '1rem' }}>
                  {ds.tactics && ds.tactics.slice(0, 2).join(', ')}
                  {ds.tactics && ds.tactics.length > 2 && '...'}
                </td>
                <td>{getStatusBadge(ds.status)}</td>
                <td>
                  {ds.status === 'available' && (
                    <button
                      onClick={() => handleDownload(ds.dataset_id)}
                      disabled={downloading[ds.dataset_id]}
                      style={{
                        padding: '0.4rem 0.8rem',
                        fontSize: '0.85rem'
                      }}
                    >
                      {downloading[ds.dataset_id] ? 'Starting...' : 'Download'}
                    </button>
                  )}
                  {ds.status === 'downloading' && (
                    <span style={{ color: '#66d9ef' }}>
                      {ds.download_progress || 0}%
                    </span>
                  )}
                  {ds.status === 'downloaded' && (
                    <span style={{ color: '#a7db6c' }}>Ready</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filteredDatasets.length === 0 && !loading && (
        <div className="empty-state">
          <p>No datasets found matching your criteria.</p>
          <p style={{ color: '#888' }}>
            {showDownloadedOnly
              ? 'No downloaded datasets yet. Download some from the catalog.'
              : 'Try adjusting your filters or refresh the catalog.'}
          </p>
        </div>
      )}
    </div>
  );
};

export default MordorCatalog;
