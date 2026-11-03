import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import FileBrowser from './FileBrowser';
import GandalfJobBrowser from './GandalfJobBrowser';
import OptionsPanel from './OptionsPanel';
import { createJob, getLocalMordorDatasets } from '../api';
import axios from 'axios';
import { API_BASE_URL } from '../apiBase';

// File requirements for certain options
const FILE_REQUIREMENTS = {
  keywords: { filename: 'keywords.txt', label: 'Keywords Search', description: 'Text file with one keyword per line' },
  yara: { filename: 'yara.yar', label: 'YARA Rules', description: 'YARA rules file (.yar or .yara)' },
  collectFiles: { filename: 'files.txt', label: 'Collect Specific Files', description: 'Text file with file paths/patterns to collect' },
};

function NewAnalysis() {
  const navigate = useNavigate();
  const [caseNumber, setCaseNumber] = useState('');
  const [analysisMode, setAnalysisMode] = useState(''); // '', 'local', 'gandalf', 'cloud', 'mordor', or 'json'
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [destinationPath, setDestinationPath] = useState('');
  const [options, setOptions] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showAvWarning, setShowAvWarning] = useState(false);
  const [showOverwriteModal, setShowOverwriteModal] = useState(false);
  const [overwriteModalData, setOverwriteModalData] = useState({ type: '', message: '', path: '' });
  const [caseIdExists, setCaseIdExists] = useState(false);
  const [checkingCaseId, setCheckingCaseId] = useState(false);
  const [showFileUploadModal, setShowFileUploadModal] = useState(false);
  const [missingFiles, setMissingFiles] = useState([]);
  const [uploadedFiles, setUploadedFiles] = useState({});
  const fileInputRefs = useRef({});
  const jsonFileInputRef = useRef(null);
  const [loadedConfigName, setLoadedConfigName] = useState(null);
  // Mordor-specific state
  const [mordorDatasets, setMordorDatasets] = useState([]);
  const [selectedMordorDataset, setSelectedMordorDataset] = useState('');
  const [loadingMordorDatasets, setLoadingMordorDatasets] = useState(false);
  // Cloud-specific state
  const [cloudUrl, setCloudUrl] = useState('');

  // Clear error when options change
  const handleOptionsChange = (newOptions) => {
    setOptions(newOptions);
    if (error) {
      setError(null);
    }
  };

  // Check if case ID exists in Rivendell (debounced)
  useEffect(() => {
    const timeoutId = setTimeout(async () => {
      if (caseNumber.length >= 6) {  // Only check if case number is valid length
        setCheckingCaseId(true);
        try {
          const response = await axios.get(`${API_BASE_URL}/api/validate/case-id/${encodeURIComponent(caseNumber)}`);
          setCaseIdExists(response.data.exists);
        } catch (err) {
          console.error('Error checking case ID:', err);
          setCaseIdExists(false);
        } finally {
          setCheckingCaseId(false);
        }
      } else {
        setCaseIdExists(false);
      }
    }, 500); // 500ms debounce

    return () => clearTimeout(timeoutId);
  }, [caseNumber]);

  // Auto-enable mordor options when Mordor mode is selected
  useEffect(() => {
    if (analysisMode === 'mordor') {
      setOptions(prev => ({
        ...prev,
        mordor: true,
        analysis: true,
        extract_iocs: true,
        memory: true,
        userprofiles: true,
        navigator: true,
        splunk: true,
        elastic: true,
      }));
    }
  }, [analysisMode]);

  // Load Mordor datasets when mode is 'mordor'
  useEffect(() => {
    if (analysisMode === 'mordor') {
      const loadMordorDatasets = async () => {
        setLoadingMordorDatasets(true);
        try {
          const result = await getLocalMordorDatasets({ limit: 200 });
          // Filter to only show downloaded datasets
          const downloaded = (result.datasets || []).filter(ds => ds.status === 'downloaded');
          setMordorDatasets(downloaded);
        } catch (err) {
          console.error('Failed to load Mordor datasets:', err);
          setMordorDatasets([]);
        } finally {
          setLoadingMordorDatasets(false);
        }
      };
      loadMordorDatasets();
    }
  }, [analysisMode]);

  // Update selectedFiles when Mordor dataset is selected
  useEffect(() => {
    if (analysisMode === 'mordor' && selectedMordorDataset) {
      const dataset = mordorDatasets.find(ds => ds.dataset_id === selectedMordorDataset);
      if (dataset && dataset.local_path) {
        setSelectedFiles([dataset.local_path]);
      }
    }
  }, [selectedMordorDataset, mordorDatasets, analysisMode]);

  // Update selectedFiles when cloud URL changes
  useEffect(() => {
    if (analysisMode === 'cloud' && cloudUrl) {
      setSelectedFiles([cloudUrl]);
    }
  }, [cloudUrl, analysisMode]);

  // Clear selections when mode changes
  useEffect(() => {
    setSelectedFiles([]);
    setSelectedMordorDataset('');
    setCloudUrl('');
  }, [analysisMode]);

  // Validate case number and get validation message
  const getCaseNumberValidation = (value) => {
    if (value.length === 0) {
      return { valid: false, message: '' };
    }

    if (value.length < 6) {
      return { valid: false, message: `Case number must be at least 6 characters (currently ${value.length})` };
    }

    if (value.length > 30) {
      return { valid: false, message: `Case number must be no longer than 30 characters (currently ${value.length})` };
    }

    const startsValid = /^[a-zA-Z0-9]/.test(value);
    if (!startsValid) {
      return { valid: false, message: 'Case number must start with a letter or number' };
    }

    const endsValid = /[a-zA-Z0-9]$/.test(value);
    if (!endsValid) {
      return { valid: false, message: 'Case number must end with a letter or number' };
    }

    const validChars = /^[a-zA-Z0-9\-._]+$/.test(value);
    if (!validChars) {
      const invalidChar = value.match(/[^a-zA-Z0-9\-._]/);
      return { valid: false, message: `Invalid character '${invalidChar ? invalidChar[0] : ''}' - only letters, numbers, hyphens, periods, and underscores allowed` };
    }

    // Check if case ID already exists in Rivendell
    if (caseIdExists) {
      return { valid: false, message: `Case ID "${value}" already exists in Rivendell. Please use a different case ID or delete the existing job.` };
    }

    return { valid: true, message: '' };
  };

  const caseNumberValidation = getCaseNumberValidation(caseNumber);
  const isCaseNumberValid = caseNumberValidation.valid;

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!caseNumber.trim()) {
      setError('Please enter a case number');
      return;
    }

    if (!isCaseNumberValid) {
      setError('Case number must be at least 6 characters, start/end with a letter or number, and only contain letters, numbers, hyphens, periods, and underscores');
      return;
    }

    if (!analysisMode) {
      setError('Please select an evidence source');
      return;
    }

    if (selectedFiles.length === 0) {
      if (analysisMode === 'mordor') {
        setError('Please select a Mordor dataset');
      } else if (analysisMode === 'cloud') {
        setError('Please enter a cloud storage URL');
      } else {
        setError('Please select at least one disk or memory image');
      }
      return;
    }

    // Show AV warning modal before proceeding
    setShowAvWarning(true);
  };

  const handleAvWarningConfirm = async () => {
    setShowAvWarning(false);
    setError(null);

    // Check if any file-requiring options are selected
    const requiredOptions = Object.keys(FILE_REQUIREMENTS).filter(key => options[key]);

    if (requiredOptions.length > 0) {
      // Check which files exist on the server
      try {
        const response = await axios.post(
          `${API_BASE_URL}/api/check-required-files`,
          { options: requiredOptions }
        );

        const missing = response.data.missing || [];

        if (missing.length > 0) {
          setMissingFiles(missing);
          setUploadedFiles({});
          setShowFileUploadModal(true);
          return;
        }
      } catch (err) {
        console.error('Error checking required files:', err);
        // If we can't check, assume files are missing and prompt
        setMissingFiles(requiredOptions);
        setUploadedFiles({});
        setShowFileUploadModal(true);
        return;
      }
    }

    await startJobCreation(false);
  };

  const handleAvWarningCancel = () => {
    setShowAvWarning(false);
  };

  const handleFileUpload = (optionKey, event) => {
    const file = event.target.files[0];
    if (file) {
      setUploadedFiles(prev => ({ ...prev, [optionKey]: file }));
    }
  };

  const handleFileUploadConfirm = async () => {
    // Check all required files are uploaded
    const allUploaded = missingFiles.every(key => uploadedFiles[key]);

    if (!allUploaded) {
      setError('Please upload all required files');
      return;
    }

    // Upload the files to the server
    try {
      const formData = new FormData();
      missingFiles.forEach(key => {
        formData.append(key, uploadedFiles[key]);
      });

      await axios.post(
        `${API_BASE_URL}/api/upload-required-files`,
        formData,
        { headers: { 'Content-Type': 'multipart/form-data' } }
      );

      setShowFileUploadModal(false);
      await startJobCreation(false);
    } catch (err) {
      setError('Failed to upload files: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleFileUploadCancel = () => {
    setShowFileUploadModal(false);
    setMissingFiles([]);
    setUploadedFiles({});
  };

  const handleFileUploadSkip = async () => {
    // Deselect the options that require files and continue
    const newOptions = { ...options };
    missingFiles.forEach(key => {
      newOptions[key] = false;
    });
    setOptions(newOptions);
    setShowFileUploadModal(false);
    setMissingFiles([]);
    setUploadedFiles({});

    // Continue with job creation
    await startJobCreation(false);
  };

  const handleJsonFileLoad = (event) => {
    const file = event.target.files[0];
    if (!file) {
      setAnalysisMode('local');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const config = JSON.parse(e.target.result);

        // Validate required fields
        if (!config.case_number && !config.caseNumber) {
          setError('JSON file missing required field: case_number');
          setAnalysisMode('local');
          return;
        }

        // Set case number
        setCaseNumber(config.case_number || config.caseNumber || '');

        // Set source paths/files
        if (config.source_paths && Array.isArray(config.source_paths)) {
          setSelectedFiles(config.source_paths);
        } else if (config.sourcePaths && Array.isArray(config.sourcePaths)) {
          setSelectedFiles(config.sourcePaths);
        }

        // Set destination path
        if (config.destination_path || config.destinationPath) {
          setDestinationPath(config.destination_path || config.destinationPath);
        }

        // Set options
        if (config.options && typeof config.options === 'object') {
          // Map the options from the JSON to the format expected by the UI
          const opts = config.options;
          setOptions({
            collect: opts.local !== false,  // Default to true unless explicitly false
            analysis: opts.analysis || false,
            extractiocs: opts.extract_iocs || opts.extractiocs || false,
            threat_intel: opts.threat_intel || false,
            timeline: opts.timeline || false,
            memory: opts.memory || false,
            memory_timeline: opts.memory_timeline || false,
            keywords: opts.keywords || false,
            keywords_file: opts.keywords_file || '',
            yara: opts.yara || false,
            yara_dir: opts.yara_dir || '',
            collectFiles: opts.collectFiles || opts.collect_files || false,
            collectFiles_filter: opts.collectFiles_filter || opts.collect_files_filter || '',
            brisk: opts.brisk || false,
            vss: opts.vss || false,
            symlinks: opts.symlinks || false,
            userprofiles: opts.userprofiles || false,
            nsrl: opts.nsrl || false,
            hash_collected: opts.hash_collected || false,
            hash_all: opts.hash_all || false,
            splunk: opts.splunk || false,
            elastic: opts.elastic || false,
            navigator: opts.navigator || false,
            gandalf: opts.gandalf || false,
          });

          // Set analysis mode based on options
          if (opts.gandalf) {
            setAnalysisMode('gandalf');
          } else {
            setAnalysisMode('local');
          }
        } else {
          setAnalysisMode('local');
        }

        // Set loaded config name for display
        setLoadedConfigName(file.name);
        setError(null);

        // Show success message briefly
        console.log('Loaded configuration from:', file.name);

      } catch (err) {
        setError(`Failed to parse JSON file: ${err.message}`);
        setAnalysisMode('local');
        setLoadedConfigName(null);
      }
    };

    reader.onerror = () => {
      setError('Failed to read JSON file');
      setAnalysisMode('local');
      setLoadedConfigName(null);
    };

    reader.readAsText(file);

    // Reset the file input so the same file can be selected again
    event.target.value = '';
  };

  const handleOverwriteConfirm = async () => {
    setShowOverwriteModal(false);
    setError(null);

    await startJobCreation(true);
  };

  const handleOverwriteCancel = () => {
    setShowOverwriteModal(false);
    setLoading(false);
  };

  const startJobCreation = async (forceOverwrite = false) => {
    setLoading(true);
    setError(null);
    try {
      // Determine the actual mode - 'json' mode uses whatever was loaded from the file
      // 'mordor' mode is treated like 'local' for file selection but enables mordor processing
      const effectiveMode = analysisMode === 'json' ? (options.gandalf ? 'gandalf' : 'local') : analysisMode;

      const jobData = {
        case_number: caseNumber,
        source_paths: selectedFiles,
        destination_path: destinationPath || null,
        options: {
          ...options,
          local: effectiveMode === 'local' || effectiveMode === 'cloud' || effectiveMode === 'mordor',
          gandalf: effectiveMode === 'gandalf',
          mordor: effectiveMode === 'mordor',
          force_overwrite: forceOverwrite,
        },
      };

      const job = await createJob(jobData);
      navigate(`/jobs/${job.id}`);
    } catch (err) {
      const errorDetail = err.response?.data?.detail || err.message || 'Failed to create analysis job';

      // Only check for output directory conflicts now (case ID validation happens in real-time)
      if (errorDetail.includes('[Errno 17]') || errorDetail.includes('File exists')) {
        const pathMatch = errorDetail.match(/'([^']+)'/);
        const existingPath = pathMatch ? pathMatch[1] : (destinationPath || selectedFiles[0]);

        setOverwriteModalData({
          type: 'directory',
          message: 'The output directory already exists:',
          path: existingPath
        });
        setShowOverwriteModal(true);
        return;
      } else {
        setError(errorDetail);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="new-analysis">
      {/* AV Warning Modal */}
      {showAvWarning && (
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
            maxWidth: '680px',
            width: '100%',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.7)'
          }}>
            <h3 style={{
              color: '#ffc107',
              marginBottom: '1rem',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1.5rem',
              textAlign: 'center'
            }}>
              ⚠️ Antivirus Warning
            </h3>
            <p style={{
              color: '#f0dba5',
              lineHeight: '1.8',
              marginBottom: '1.5rem',
              fontSize: '1rem'
            }}>
              During forensic analysis, malware or suspicious files may be identified and extracted.
              Your antivirus software may interfere with the analysis process by quarantining or deleting evidence.
            </p>
            <p style={{
              color: '#f0dba5',
              lineHeight: '1.8',
              marginBottom: '2rem',
              fontSize: '1rem',
              fontWeight: 'bold'
            }}>
              Consider temporarily disabling antivirus protection or adding exclusions for the output directory before proceeding.
            </p>
            <div style={{
              display: 'flex',
              gap: '1rem',
              justifyContent: 'center'
            }}>
              <button
                onClick={handleAvWarningCancel}
                style={{
                  padding: '0.75rem 1.5rem',
                  minWidth: '140px',
                  height: '48px',
                  background: 'rgba(244, 67, 54, 0.2)',
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
                  e.target.style.background = 'rgba(244, 67, 54, 0.3)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(244, 67, 54, 0.2)';
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleAvWarningConfirm}
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
                Continue with Processing
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Overwrite Confirmation Modal */}
      {showOverwriteModal && (
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
            maxWidth: '680px',
            width: '100%',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.7)'
          }}>
            <h3 style={{
              color: '#ffc107',
              marginBottom: '1rem',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1.5rem',
              textAlign: 'center'
            }}>
              ⚠️ Overwrite Confirmation
            </h3>
            <p style={{
              color: '#f0dba5',
              lineHeight: '1.8',
              marginBottom: '1rem',
              fontSize: '1rem'
            }}>
              {overwriteModalData.message}
            </p>
            <div style={{
              background: 'rgba(240, 219, 165, 0.1)',
              border: '1px solid rgba(240, 219, 165, 0.3)',
              borderRadius: '4px',
              padding: '0.75rem 1rem',
              marginBottom: '1.5rem',
              fontFamily: 'monospace',
              color: '#66d9ef',
              wordBreak: 'break-all'
            }}>
              {overwriteModalData.path}
            </div>
            <p style={{
              color: '#f0dba5',
              lineHeight: '1.8',
              marginBottom: '2rem',
              fontSize: '1rem',
              fontWeight: 'bold'
            }}>
              {overwriteModalData.type === 'case_id'
                ? 'Do you want to overwrite the existing job and continue?'
                : 'Do you want to delete the existing directory and continue?'}
            </p>
            <div style={{
              display: 'flex',
              gap: '1rem',
              justifyContent: 'center'
            }}>
              <button
                onClick={handleOverwriteCancel}
                style={{
                  padding: '0.75rem 1.5rem',
                  minWidth: '140px',
                  height: '48px',
                  background: 'rgba(244, 67, 54, 0.2)',
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
                  e.target.style.background = 'rgba(244, 67, 54, 0.3)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(244, 67, 54, 0.2)';
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleOverwriteConfirm}
                style={{
                  padding: '0.75rem 1.5rem',
                  minWidth: '140px',
                  height: '48px',
                  background: 'rgba(255, 152, 0, 0.3)',
                  border: '1px solid rgba(255, 152, 0, 0.5)',
                  borderRadius: '4px',
                  color: '#ff9800',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => {
                  e.target.style.background = 'rgba(255, 152, 0, 0.4)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(255, 152, 0, 0.3)';
                }}
              >
                Overwrite and Continue
              </button>
            </div>
          </div>
        </div>
      )}

      {/* File Upload Modal */}
      {showFileUploadModal && (
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
            maxWidth: '680px',
            width: '100%',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.7)'
          }}>
            <h3 style={{
              color: '#66d9ef',
              marginBottom: '1rem',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1.5rem',
              textAlign: 'center'
            }}>
              Required Files
            </h3>
            <p style={{
              color: '#f0dba5',
              lineHeight: '1.8',
              marginBottom: '1.5rem',
              fontSize: '1rem',
              textAlign: 'center'
            }}>
              The following files are required but were not found in <code style={{ background: 'rgba(102, 217, 239, 0.2)', padding: '2px 6px', borderRadius: '3px' }}>/tmp/rivendell</code>
            </p>

            <div style={{ marginBottom: '1.5rem' }}>
              {missingFiles.map(key => {
                const req = FILE_REQUIREMENTS[key];
                const uploaded = uploadedFiles[key];
                return (
                  <div key={key} style={{
                    background: 'rgba(240, 219, 165, 0.05)',
                    border: '1px solid rgba(240, 219, 165, 0.2)',
                    borderRadius: '6px',
                    padding: '1rem',
                    marginBottom: '0.75rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                      <div>
                        <strong style={{ color: '#f0dba5' }}>{req.label}</strong>
                        <span style={{ color: '#888', fontSize: '0.9rem', marginLeft: '0.5rem' }}>({req.filename})</span>
                      </div>
                      {uploaded && (
                        <span style={{ color: '#a7db6c', fontSize: '0.9rem' }}>✓ {uploaded.name}</span>
                      )}
                    </div>
                    <p style={{ color: '#999', fontSize: '0.85rem', marginBottom: '0.75rem' }}>{req.description}</p>
                    <div style={{ position: 'relative' }}>
                      <input
                        type="file"
                        accept=".txt,.yar,.yara"
                        onChange={(e) => handleFileUpload(key, e)}
                        ref={el => fileInputRefs.current[key] = el}
                        style={{
                          position: 'absolute',
                          width: '100%',
                          height: '100%',
                          opacity: 0,
                          cursor: 'pointer',
                          zIndex: 2
                        }}
                      />
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '1rem',
                        padding: '0.6rem 1rem',
                        borderRadius: '4px',
                        border: '1px solid #3f4b2a',
                        background: 'rgba(15, 15, 35, 0.8)',
                        color: '#f0dba5',
                      }}>
                        <span style={{
                          padding: '0.4rem 1rem',
                          background: 'linear-gradient(135deg, rgba(63, 75, 42, 0.8) 0%, rgba(45, 55, 30, 0.8) 100%)',
                          border: '1px solid rgba(240, 219, 165, 0.3)',
                          borderRadius: '4px',
                          color: '#f0dba5',
                          fontFamily: "'Cinzel', 'Times New Roman', serif",
                          fontSize: '0.85rem',
                          fontWeight: 600,
                          whiteSpace: 'nowrap'
                        }}>
                          Browse...
                        </span>
                        <span style={{ color: uploaded ? '#a7db6c' : '#666', fontSize: '0.9rem', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {uploaded ? uploaded.name : 'No file selected'}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {error && (
              <div style={{ color: '#f44336', marginBottom: '1rem', textAlign: 'center' }}>
                {error}
              </div>
            )}

            <div style={{
              display: 'flex',
              gap: '1rem',
              justifyContent: 'center'
            }}>
              <button
                onClick={handleFileUploadCancel}
                style={{
                  padding: '0.75rem 1.5rem',
                  minWidth: '120px',
                  height: '48px',
                  background: 'rgba(244, 67, 54, 0.2)',
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
                  e.target.style.background = 'rgba(244, 67, 54, 0.3)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(244, 67, 54, 0.2)';
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleFileUploadSkip}
                style={{
                  padding: '0.75rem 1.5rem',
                  minWidth: '120px',
                  height: '48px',
                  background: 'rgba(255, 193, 7, 0.2)',
                  border: '1px solid rgba(255, 193, 7, 0.5)',
                  borderRadius: '4px',
                  color: '#ffc107',
                  cursor: 'pointer',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => {
                  e.target.style.background = 'rgba(255, 193, 7, 0.3)';
                }}
                onMouseOut={(e) => {
                  e.target.style.background = 'rgba(255, 193, 7, 0.2)';
                }}
                title="Skip these options and continue without them"
              >
                Skip
              </button>
              <button
                onClick={handleFileUploadConfirm}
                disabled={!missingFiles.every(key => uploadedFiles[key])}
                style={{
                  padding: '0.75rem 1.5rem',
                  minWidth: '120px',
                  height: '48px',
                  background: missingFiles.every(key => uploadedFiles[key]) ? 'rgba(102, 217, 239, 0.3)' : 'rgba(102, 217, 239, 0.1)',
                  border: '1px solid rgba(102, 217, 239, 0.5)',
                  borderRadius: '4px',
                  color: missingFiles.every(key => uploadedFiles[key]) ? '#66d9ef' : '#666',
                  cursor: missingFiles.every(key => uploadedFiles[key]) ? 'pointer' : 'not-allowed',
                  fontFamily: "'Cinzel', 'Times New Roman', serif",
                  fontSize: '1rem',
                  fontWeight: 600,
                  transition: 'all 0.3s ease'
                }}
                onMouseOver={(e) => {
                  if (missingFiles.every(key => uploadedFiles[key])) {
                    e.target.style.background = 'rgba(102, 217, 239, 0.4)';
                  }
                }}
                onMouseOut={(e) => {
                  if (missingFiles.every(key => uploadedFiles[key])) {
                    e.target.style.background = 'rgba(102, 217, 239, 0.3)';
                  }
                }}
              >
                Upload
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <h2>New Forensic Analysis</h2>

        <form onSubmit={handleSubmit}>
          <div className="form-row">
            <div data-guide="elrond.case" className="form-group">
              <label htmlFor="caseNumber">
                Case Number / Investigation ID *
              </label>
              <div className="input-with-icon">
                <input
                  type="text"
                  id="caseNumber"
                  value={caseNumber}
                  onChange={(e) => setCaseNumber(e.target.value)}
                  placeholder="e.g., INC-2025-001"
                  required
                  className={isCaseNumberValid ? 'valid-input' : ''}
                />
                {isCaseNumberValid && (
                  <span className="input-checkmark">✓</span>
                )}
              </div>
              {caseNumberValidation.message && (
                <div className="validation-message invalid">
                  {caseNumberValidation.message}
                </div>
              )}
            </div>

            <div data-guide="elrond.source" className="form-group">
              <label>Evidence Source *</label>
              {!isCaseNumberValid && (
                <div className="info-message">
                  Please enter a valid case number to select evidence source.
                </div>
              )}
              <div style={{ display: 'flex', gap: '2rem', marginTop: '1.0rem', flexWrap: 'wrap' }}>
                <label
                  style={{ display: 'flex', alignItems: 'center', cursor: isCaseNumberValid ? 'pointer' : 'not-allowed', opacity: isCaseNumberValid ? 1 : 0.5, fontSize: '1.2rem', whiteSpace: 'nowrap' }}
                  title="Disk/Memory Images"
                >
                  <input
                    type="radio"
                    name="analysisMode"
                    value="local"
                    checked={analysisMode === 'local'}
                    onChange={(e) => setAnalysisMode(e.target.value)}
                    disabled={!isCaseNumberValid}
                    style={{ marginLeft: '1rem', marginRight: '0.5rem', width: '16px', height: '16px' }}
                  />
                  Local
                </label>
                <label
                  style={{ display: 'flex', alignItems: 'center', cursor: isCaseNumberValid ? 'pointer' : 'not-allowed', opacity: isCaseNumberValid ? 1 : 0.5, fontSize: '1.2rem', whiteSpace: 'nowrap' }}
                  title="Gandalf Acquisition Jobs"
                >
                  <input
                    type="radio"
                    name="analysisMode"
                    value="gandalf"
                    checked={analysisMode === 'gandalf'}
                    onChange={(e) => setAnalysisMode(e.target.value)}
                    disabled={!isCaseNumberValid}
                    style={{ marginRight: '0.5rem', width: '16px', height: '16px' }}
                  />
                  Gandalf
                </label>
                <label
                  style={{ display: 'flex', alignItems: 'center', cursor: isCaseNumberValid ? 'pointer' : 'not-allowed', opacity: isCaseNumberValid ? 1 : 0.5, fontSize: '1.2rem', whiteSpace: 'nowrap' }}
                  title="Cloud Storage"
                >
                  <input
                    type="radio"
                    name="analysisMode"
                    value="cloud"
                    checked={analysisMode === 'cloud'}
                    onChange={(e) => setAnalysisMode(e.target.value)}
                    disabled={!isCaseNumberValid}
                    style={{ marginRight: '0.5rem', width: '16px', height: '16px' }}
                  />
                  Cloud
                </label>
                <label
                  style={{ display: 'flex', alignItems: 'center', cursor: isCaseNumberValid ? 'pointer' : 'not-allowed', opacity: isCaseNumberValid ? 1 : 0.5, fontSize: '1.2rem', whiteSpace: 'nowrap' }}
                  title="OTRF Security Datasets - Pre-recorded attack simulations"
                >
                  <input
                    type="radio"
                    name="analysisMode"
                    value="mordor"
                    checked={analysisMode === 'mordor'}
                    onChange={(e) => setAnalysisMode(e.target.value)}
                    disabled={!isCaseNumberValid}
                    style={{ marginRight: '0.5rem', width: '16px', height: '16px' }}
                  />
                  Mordor
                </label>
                <label
                  style={{ display: 'flex', alignItems: 'center', cursor: 'pointer', opacity: 1, fontSize: '1.2rem', whiteSpace: 'nowrap' }}
                  title="Load configuration from JSON file"
                >
                  <input
                    type="radio"
                    name="analysisMode"
                    value="json"
                    checked={analysisMode === 'json'}
                    onChange={(e) => {
                      setAnalysisMode(e.target.value);
                      // Trigger file input when JSON is selected
                      setTimeout(() => jsonFileInputRef.current?.click(), 100);
                    }}
                    style={{ marginRight: '0.5rem', width: '16px', height: '16px' }}
                  />
                  JSON
                </label>
                <input
                  type="file"
                  ref={jsonFileInputRef}
                  accept=".json"
                  style={{ display: 'none' }}
                  onChange={handleJsonFileLoad}
                />
              </div>
              {loadedConfigName && (
                <div style={{ marginTop: '0.5rem', color: '#a7db6c', fontSize: '0.9rem' }}>
                  ✓ Loaded: {loadedConfigName}
                </div>
              )}
            </div>
          </div>

          {/* Evidence Source Selector - Only show when a source is selected */}
          {analysisMode && analysisMode !== 'json' && (
            <div data-guide="elrond.browse" className="form-group">
              <label>
                {analysisMode === 'gandalf' && 'Select Gandalf Acquisitions *'}
                {analysisMode === 'local' && 'Select Disk/Memory Images *'}
                {analysisMode === 'mordor' && 'Select Mordor Dataset *'}
                {analysisMode === 'cloud' && 'Cloud Storage URL *'}
              </label>

              {/* Local: File Browser */}
              {analysisMode === 'local' && (
                <FileBrowser
                  onSelectFiles={setSelectedFiles}
                  selectedFiles={selectedFiles}
                  disabled={!isCaseNumberValid}
                />
              )}

              {/* Gandalf: Gandalf Job Browser */}
              {analysisMode === 'gandalf' && (
                <GandalfJobBrowser
                  onSelectJobs={setSelectedFiles}
                  selectedJobs={selectedFiles}
                  disabled={!isCaseNumberValid}
                />
              )}

              {/* Mordor: Dropdown of downloaded datasets */}
              {analysisMode === 'mordor' && (
                <div style={{
                  background: 'rgba(15, 15, 35, 0.6)',
                  border: '1px solid rgba(240, 219, 165, 0.3)',
                  borderRadius: '6px',
                  padding: '1rem'
                }}>
                  {loadingMordorDatasets ? (
                    <div style={{ color: '#888', textAlign: 'center', padding: '1rem' }}>
                      Loading downloaded datasets...
                    </div>
                  ) : mordorDatasets.length === 0 ? (
                    <div style={{ color: '#f0dba5', textAlign: 'center', padding: '1rem' }}>
                      <p>No downloaded Mordor datasets found.</p>
                      <p style={{ color: '#888', fontSize: '0.9rem', marginTop: '0.5rem' }}>
                        Visit the <a href="/mordor#datasets" style={{ color: '#66d9ef' }}>Mordor page</a> to download datasets first.
                      </p>
                    </div>
                  ) : (
                    <select
                      value={selectedMordorDataset}
                      onChange={(e) => setSelectedMordorDataset(e.target.value)}
                      disabled={!isCaseNumberValid}
                      style={{
                        width: '100%',
                        padding: '0.75rem',
                        fontSize: '1rem',
                        background: 'rgba(15, 15, 35, 0.8)',
                        border: '1px solid rgba(240, 219, 165, 0.3)',
                        borderRadius: '4px',
                        color: '#f0dba5'
                      }}
                    >
                      <option value="">-- Select a downloaded dataset --</option>
                      {mordorDatasets.map(ds => (
                        <option key={ds.dataset_id} value={ds.dataset_id}>
                          {ds.title} ({ds.dataset_id}) - {ds.platform}
                        </option>
                      ))}
                    </select>
                  )}
                  {selectedMordorDataset && (
                    <div style={{ marginTop: '0.75rem', color: '#a7db6c', fontSize: '0.9rem' }}>
                      Selected: {mordorDatasets.find(ds => ds.dataset_id === selectedMordorDataset)?.local_path}
                    </div>
                  )}
                </div>
              )}

              {/* Cloud: URL input for S3/Azure */}
              {analysisMode === 'cloud' && (
                <div style={{
                  background: 'rgba(15, 15, 35, 0.6)',
                  border: '1px solid rgba(240, 219, 165, 0.3)',
                  borderRadius: '6px',
                  padding: '1rem'
                }}>
                  <p style={{ color: '#888', marginBottom: '0.75rem', fontSize: '0.9rem' }}>
                    Enter the URL for your cloud storage location (AWS S3 bucket or Azure Blob container)
                  </p>
                  <input
                    type="text"
                    value={cloudUrl}
                    onChange={(e) => setCloudUrl(e.target.value)}
                    placeholder="s3://bucket-name/path or https://account.blob.core.windows.net/container/path"
                    disabled={!isCaseNumberValid}
                    style={{
                      width: '100%',
                      padding: '0.75rem',
                      fontSize: '1rem',
                      background: 'rgba(15, 15, 35, 0.8)',
                      border: '1px solid rgba(240, 219, 165, 0.3)',
                      borderRadius: '4px',
                      color: '#f0dba5'
                    }}
                  />
                  {cloudUrl && (
                    <div style={{ marginTop: '0.75rem' }}>
                      <span style={{
                        display: 'inline-block',
                        padding: '0.25rem 0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.8rem',
                        background: cloudUrl.startsWith('s3://') ? 'rgba(255, 153, 0, 0.2)' :
                                   cloudUrl.includes('blob.core.windows.net') ? 'rgba(0, 120, 212, 0.2)' :
                                   'rgba(240, 219, 165, 0.2)',
                        color: cloudUrl.startsWith('s3://') ? '#ff9900' :
                               cloudUrl.includes('blob.core.windows.net') ? '#0078d4' :
                               '#f0dba5'
                      }}>
                        {cloudUrl.startsWith('s3://') ? 'AWS S3' :
                         cloudUrl.includes('blob.core.windows.net') ? 'Azure Blob' :
                         'Cloud Storage'}
                      </span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* JSON mode shows loaded config info */}
          {analysisMode === 'json' && loadedConfigName && (
            <div className="form-group">
              <label>Loaded Configuration</label>
              <div style={{
                background: 'rgba(15, 15, 35, 0.6)',
                border: '1px solid rgba(167, 219, 108, 0.3)',
                borderRadius: '6px',
                padding: '1rem'
              }}>
                <div style={{ color: '#a7db6c' }}>
                  ✓ Configuration loaded from: {loadedConfigName}
                </div>
                {selectedFiles.length > 0 && (
                  <div style={{ marginTop: '0.5rem', color: '#888', fontSize: '0.9rem' }}>
                    Source paths: {selectedFiles.join(', ')}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Prompt to select evidence source if none selected */}
          {!analysisMode && isCaseNumberValid && (
            <div className="form-group">
              <div className="info-message">
                Please select an evidence source above to continue.
              </div>
            </div>
          )}

          <div data-guide="elrond.options" className="form-group">
            <label>Processing Options</label>
            {!isCaseNumberValid && (
              <div className="info-message">
                Please enter a valid case number to configure processing options.
              </div>
            )}
            {isCaseNumberValid && !analysisMode && (
              <div className="info-message">
                Please select an evidence source to configure processing options.
              </div>
            )}
            {isCaseNumberValid && analysisMode && selectedFiles.length === 0 && (
              <div className="info-message">
                {analysisMode === 'mordor' && 'Please select a Mordor dataset to configure processing options.'}
                {analysisMode === 'cloud' && 'Please enter a cloud storage URL to configure processing options.'}
                {analysisMode === 'local' && 'Please select at least one disk or memory image to configure processing options.'}
                {analysisMode === 'gandalf' && 'Please select a Gandalf acquisition to configure processing options.'}
                {analysisMode === 'json' && 'Please load a JSON configuration file to configure processing options.'}
              </div>
            )}
            <OptionsPanel
              options={options}
              onChange={handleOptionsChange}
              disabled={!isCaseNumberValid || selectedFiles.length === 0 || !analysisMode}
              hasImages={selectedFiles.length > 0}
              onSubmit={handleSubmit}
              loading={loading}
              error={error}
            />
          </div>
        </form>
      </div>
    </div>
  );
}

export default NewAnalysis;
