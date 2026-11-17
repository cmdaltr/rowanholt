import React, { useState, useEffect } from 'react';
import {
  getLocalMordorDatasets,
  deleteMordorDataset,
  verifyMordorDataset
} from '../api';

const MordorDatasets = ({ onDelete }) => {
  const [datasets, setDatasets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedDatasets, setSelectedDatasets] = useState([]);
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [confirmAction, setConfirmAction] = useState(null);
  const [verifying, setVerifying] = useState({});

  useEffect(() => {
    loadDatasets();
    const interval = setInterval(loadDatasets, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadDatasets = async () => {
    try {
      const result = await getLocalMordorDatasets();
      setDatasets(result.datasets);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load datasets');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (datasetId) => {
    setConfirmAction({
      type: 'delete',
      datasetId,
      title: 'Delete Dataset',
      message: `Are you sure you want to delete dataset ${datasetId}? This will remove all downloaded files.`
    });
    setShowConfirmModal(true);
  };

  const handleVerify = async (datasetId) => {
    try {
      setVerifying(prev => ({ ...prev, [datasetId]: true }));
      const result = await verifyMordorDataset(datasetId);
      if (result.valid) {
        alert(`Dataset verified successfully.\n${result.files_checked} files checked.`);
      } else {
        alert(`Verification failed:\n${result.errors.join('\n')}`);
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Verification failed');
    } finally {
      setVerifying(prev => ({ ...prev, [datasetId]: false }));
    }
  };

  const handleBulkDelete = () => {
    if (selectedDatasets.length === 0) return;

    setConfirmAction({
      type: 'bulk_delete',
      datasetIds: selectedDatasets,
      title: 'Delete Multiple Datasets',
      message: `Are you sure you want to delete ${selectedDatasets.length} dataset(s)?`
    });
    setShowConfirmModal(true);
  };

  const executeConfirmAction = async () => {
    try {
      if (confirmAction.type === 'delete') {
        await deleteMordorDataset(confirmAction.datasetId);
      } else if (confirmAction.type === 'bulk_delete') {
        for (const id of confirmAction.datasetIds) {
          await deleteMordorDataset(id);
        }
        setSelectedDatasets([]);
      }

      await loadDatasets();
      onDelete?.();
    } catch (err) {
      setError(err.response?.data?.detail || 'Operation failed');
    } finally {
      setShowConfirmModal(false);
      setConfirmAction(null);
    }
  };

  const formatSize = (bytes) => {
    if (!bytes) return 'N/A';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }
    return `${size.toFixed(1)} ${units[unitIndex]}`;
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    try {
      return new Date(dateString).toLocaleDateString();
    } catch (e) {
      return dateString.substring(0, 10);
    }
  };

  if (loading) {
    return <div className="loading">Loading downloaded datasets...</div>;
  }

  return (
    <div>
      {/* Confirmation Modal */}
      {showConfirmModal && confirmAction && (
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
            background: 'linear-gradient(135deg, rgba(30, 33, 18, 0.98) 0%, rgba(42, 45, 25, 0.98) 100%)',
            border: '2px solid rgba(240, 219, 165, 0.5)',
            borderRadius: '8px',
            padding: '2rem',
            maxWidth: '500px',
            width: '100%'
          }}>
            <h3 style={{ color: '#ffc107', marginBottom: '1rem' }}>
              {confirmAction.title}
            </h3>
            <p style={{ color: '#f0dba5', marginBottom: '2rem' }}>
              {confirmAction.message}
            </p>
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
              <button
                onClick={() => setShowConfirmModal(false)}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'rgba(240, 219, 165, 0.1)',
                  border: '1px solid rgba(240, 219, 165, 0.3)',
                  borderRadius: '4px',
                  color: '#f0dba5',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                onClick={executeConfirmAction}
                style={{
                  padding: '0.75rem 1.5rem',
                  background: 'rgba(244, 67, 54, 0.3)',
                  border: '1px solid rgba(244, 67, 54, 0.5)',
                  borderRadius: '4px',
                  color: '#f44336',
                  cursor: 'pointer'
                }}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Actions */}
      {selectedDatasets.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <button
            onClick={handleBulkDelete}
            style={{
              padding: '0.5rem 1rem',
              background: 'rgba(244, 67, 54, 0.3)',
              color: '#f44336',
              border: '1px solid #e53935',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Delete Selected ({selectedDatasets.length})
          </button>
        </div>
      )}

      {error && <div className="error" style={{ marginBottom: '1rem' }}>{error}</div>}

      {datasets.length === 0 ? (
        <div className="empty-state">
          <p>No datasets downloaded yet.</p>
          <p style={{ color: '#888' }}>
            Browse the catalog to download security datasets.
          </p>
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th style={{ width: '5%' }}>
                  <input
                    type="checkbox"
                    checked={selectedDatasets.length === datasets.length}
                    onChange={() => {
                      if (selectedDatasets.length === datasets.length) {
                        setSelectedDatasets([]);
                      } else {
                        setSelectedDatasets(datasets.map(d => d.dataset_id));
                      }
                    }}
                  />
                </th>
                <th style={{ width: '15%' }}>ID</th>
                <th style={{ width: '28%' }}>Title</th>
                <th style={{ width: '10%' }}>Platform</th>
                <th style={{ width: '10%' }}>Size</th>
                <th style={{ width: '12%' }}>Downloaded</th>
                <th style={{ width: '20%' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {datasets.map(ds => (
                <tr key={ds.dataset_id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedDatasets.includes(ds.dataset_id)}
                      onChange={() => {
                        setSelectedDatasets(prev =>
                          prev.includes(ds.dataset_id)
                            ? prev.filter(id => id !== ds.dataset_id)
                            : [...prev, ds.dataset_id]
                        );
                      }}
                    />
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                    {ds.dataset_id}
                  </td>
                  <td>
                    <strong>{ds.title}</strong>
                    {ds.local_path && (
                      <div style={{ fontSize: '0.75rem', color: '#666', marginTop: '0.25rem' }}>
                        {ds.local_path}
                      </div>
                    )}
                  </td>
                  <td>{ds.platform}</td>
                  <td>{formatSize(ds.total_size)}</td>
                  <td>{formatDate(ds.downloaded_at)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        onClick={() => handleVerify(ds.dataset_id)}
                        disabled={verifying[ds.dataset_id]}
                        style={{
                          padding: '0.3rem 0.6rem',
                          fontSize: '0.8rem'
                        }}
                      >
                        {verifying[ds.dataset_id] ? 'Checking...' : 'Verify'}
                      </button>
                      <button
                        onClick={() => handleDelete(ds.dataset_id)}
                        style={{
                          padding: '0.3rem 0.6rem',
                          fontSize: '0.8rem',
                          background: 'rgba(244, 67, 54, 0.2)',
                          color: '#f44336',
                          border: '1px solid rgba(244, 67, 54, 0.3)'
                        }}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default MordorDatasets;
