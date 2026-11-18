import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import FileBrowser from './FileBrowser';
import OptionsPanel from './OptionsPanel';
import { createJob } from '../api';

function NewAnalysis() {
  const navigate = useNavigate();
  const [caseNumber, setCaseNumber] = useState('');
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [destinationPath, setDestinationPath] = useState('');
  const [options, setOptions] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!caseNumber.trim()) {
      setError('Please enter a case number');
      return;
    }

    if (selectedFiles.length === 0) {
      setError('Please select at least one disk or memory image');
      return;
    }

    // Check operation mode is selected
    if (!options.collect && !options.gandalf && !options.reorganise) {
      setError('Please select an operation mode (Collect, Custodian, or Reorganise)');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const job = await createJob({
        case_number: caseNumber,
        source_paths: selectedFiles,
        destination_path: destinationPath || null,
        options: options,
      });

      // Redirect to job details page
      navigate(`/jobs/${job.id}`);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create analysis job');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="new-analysis">
      <div className="card">
        <h2>New Forensic Analysis</h2>

        {error && <div className="error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="caseNumber">
              Case Number / Investigation ID *
            </label>
            <input
              type="text"
              id="caseNumber"
              value={caseNumber}
              onChange={(e) => setCaseNumber(e.target.value)}
              placeholder="e.g., INC-2025-001"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="destinationPath">
              Destination Directory (optional)
            </label>
            <input
              type="text"
              id="destinationPath"
              value={destinationPath}
              onChange={(e) => setDestinationPath(e.target.value)}
              placeholder="Leave empty to use default location (same as input)"
            />
          </div>

          <div className="form-group">
            <label>Select Disk/Memory Images *</label>
            <FileBrowser
              onSelectFiles={setSelectedFiles}
              selectedFiles={selectedFiles}
            />
          </div>

          <div className="form-group">
            <label>Analysis Options</label>
            <OptionsPanel options={options} onChange={setOptions} />
          </div>

          <div className="form-actions">
            <button type="submit" disabled={loading}>
              {loading ? 'Starting Analysis...' : 'Start Analysis'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default NewAnalysis;
