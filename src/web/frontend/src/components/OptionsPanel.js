import React, { useState, useEffect } from 'react';

function OptionsPanel({ options, onChange, disabled = false, hasImages = false, onSubmit, loading = false, error = null }) {
  const [currentStep, setCurrentStep] = useState(0);
  const [operationMode, setOperationMode] = useState(''); // 'gandalf' or 'local'
  const [eta, setEta] = useState(0);
  const [gollumStep, setGollumStep] = useState(null); // Which step Gollum appears on
  const [savedTemplates, setSavedTemplates] = useState([]);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [pendingTemplateNav, setPendingTemplateNav] = useState(false);

  // Load saved templates from localStorage on mount
  useEffect(() => {
    const templates = JSON.parse(localStorage.getItem('rivendell_templates') || '[]');
    setSavedTemplates(templates);
  }, []);

  // Navigate to confirm step after template options are applied
  useEffect(() => {
    if (pendingTemplateNav && options.template) {
      setCurrentStep(steps.length - 1);
      setPendingTemplateNav(false);
    }
  }, [options, pendingTemplateNav]);

  // Step definitions in order
  const steps = [
    {
      key: 'mode',
      title: 'Mode',
      description: 'Choose your processing mode',
      type: 'single',
      options: [
        { key: 'brisk', label: 'Brisk', description: 'Optimized; balancing speed and thoroughness', time: -15 },
        { key: 'exhaustive', label: 'Exhaustive', description: 'Enable all options for maximum thoroughness' },
        { key: 'custom', label: 'Custom', description: 'Full control over all processing options' },
        { key: 'template', label: 'Template', description: 'Load a saved template of custom options' },
      ],
    },
    {
      key: 'collection',
      title: 'Collection',
      description: 'What to collect from the images',
      type: 'multi',
      options: [
        // Row 1 (3 options): Full User Profiles | Volume Shadow Copies | Hash Collected
        { key: 'userprofiles', label: 'Full User Profiles', description: 'Collect full user profile directories', time: 5 },
        { key: 'vss', label: 'Volume Shadow Copies', description: 'Process VSS images (if available)', time: 20, slow: true },
        { key: 'hash_collected', label: 'Hash Collected', description: 'Hash only collected artefacts', time: 10 },
        // Row 2 (3 options): Last Access Times | Archive Output | Debug Logging
        { key: 'last_access_times', label: 'Last Access Times', description: 'Obtain last access times of all files', time: 5 },
        { key: 'archive', label: 'Archive Output', description: 'Create ZIP archive after processing', time: 20 },
        { key: 'debug', label: 'Verbose Logging', description: 'Show all output in job log\nand write to verbose.log', time: 0 },
        // Row 3 (4 options): Carve Unallocated | Collect All Files | Collect Archives | Collect Binaries
        { key: 'collect_files_unalloc', label: 'Carve Unallocated', description: 'Carve unallocated space\nusing foremost', time: 60, slow: true },
        { key: 'collect_files_all', label: 'Collect All Files', description: 'Collect all file types\nfrom disk image', time: 60, slow: true },
        { key: 'collect_files_archive', label: 'Collect Archives', description: 'Collect archive files\n(zip, 7z, rar, tar)', time: 5 },
        { key: 'collect_files_bin', label: 'Collect Binaries', description: 'Collect executables\n(exe, dll, sys, drv)', time: 10 },
        // Row 4 (4 options): Collect Hidden | Collect Shortcuts | Collect Mail | Collect Masquerading
        { key: 'collect_files_hidden', label: 'Collect Hidden', description: 'Collect hidden files\n(NTFS attrib / dot-prefix)', time: 5 },
        { key: 'collect_files_lnk', label: 'Collect Shortcuts', description: 'Collect LNK files\nand symbolic links', time: 5 },
        { key: 'collect_files_mail', label: 'Collect Mail', description: 'Collect email files\n(PST, OST, mbox, emlx)', time: 10 },
        { key: 'masquerading', label: 'Collect Masquerading', description: 'Detect RLO, double ext,\nspaces, typosquats', time: 15 },
        // Row 5 (4 options): Collect Misplaced | Collect Scripts | Collect Virtual | Collect Web
        { key: 'misplaced_binaries', label: 'Collect Misplaced', description: 'Find system binaries in\nunexpected locations', time: 15 },
        { key: 'collect_files_scripts', label: 'Collect Scripts', description: 'Collect script files\n(ps1, py, sh, bat, js)', time: 5 },
        { key: 'collect_files_virtual', label: 'Collect Virtual', description: 'Collect VM files\n(vmdk, vhd, ova)', time: 10 },
        { key: 'collect_files_web', label: 'Collect Web', description: 'Collect web files\n(html, js, css, php)', time: 5 },
      ],
    },
    {
      key: 'analysis',
      title: 'Analysis',
      description: 'Analysis and processing features',
      type: 'multi',
      options: [
        { key: 'analysis', label: 'Automated Analysis', description: 'Conduct automated forensic analysis (includes magic-byte checks)', time: 30 },
        { key: 'extract_iocs', label: 'Extract IOCs', description: 'Extract Indicators of Compromise', time: 20 },
        { key: 'threat_intel', label: 'Threat Intelligence', description: 'Match artefacts and IOCs against\nthe indicators in Pippin', time: 10 },
        { key: 'memory', label: 'Memory Collection & Analysis', description: 'Analyze memory using Volatility', time: 45, slow: true },
        { key: 'timeline', label: 'Disk Image Timeline', description: 'Create timeline using plaso', time: 180, slow: true, disabledForGandalf: true },
        { key: 'memory_timeline', label: 'Memory Timeline', description: 'Create memory timeline using timeliner', time: 60, slow: true },
        { key: 'keywords', label: 'Keywords Search', description: 'Search for specific keywords\nacross artefacts', time: 30, requiresInput: true },
        { key: 'yara', label: 'YARA Rules', description: 'Apply custom YARA rules\nfor pattern matching', time: 30, requiresInput: true },
        { key: 'collectFiles', label: 'Collect Specific Files', description: 'Collect specific files\nbased on criteria', time: 5, requiresInput: true },
      ],
    },
    {
      key: 'output',
      title: 'Output',
      description: 'Where to send analysis results',
      type: 'multi',
      options: [
        { key: 'splunk', label: 'Splunk', description: 'Index into local Splunk instance', time: 10 },
        { key: 'elastic', label: 'Elastic', description: 'Index into local Elastic instance', time: 10 },
        { key: 'navigator', label: 'MITRE Navigator', description: 'Map to ATT&CK framework', time: 3 },
      ],
    },
    {
      key: 'confirm',
      title: 'Confirm',
      description: 'Review your selections and start processing',
      type: 'confirm',
    },
  ];

  // Get the current step data based on filtered steps
  const filteredSteps = getFilteredSteps();
  const currentStepData = filteredSteps[currentStep] || steps[0];

  // Get filtered steps based on operation mode (now returns all steps)
  function getFilteredSteps() {
    return steps;
  }

  // Check if a step is disabled based on operation mode
  function isStepDisabled(step, opMode = operationMode) {
    if (opMode === 'gandalf' && step.key === 'collection') {
      return true;
    }
    return false;
  }

  // Get filtered options for current step based on operation mode
  function getFilteredOptions() {
    if (!currentStepData.options) return [];

    // Return all options with disabled flag instead of filtering
    return currentStepData.options.map(opt => {
      let isDisabled = operationMode === 'gandalf' && opt.disabledForGandalf;

      // Disable collection options if no images are selected
      if (currentStepData.key === 'collection' && !hasImages) {
        isDisabled = true;
      }

      return {
        ...opt,
        disabled: isDisabled
      };
    });
  }

  // Calculate ETA whenever options change
  useEffect(() => {
    let totalTime = 15; // Base time in minutes (mounting, initial setup)
    steps.forEach(step => {
      if (step.options) {
        step.options.forEach(opt => {
          if (options[opt.key] && opt.time) {
            totalTime += opt.time;
          }
        });
      }
    });
    setEta(totalTime);
  }, [options]);

  // Auto-set collect and process
  useEffect(() => {
    onChange({
      ...options,
      collect: true,
      process: true,
    });
  }, []);

  const handleToggle = (key) => {
    if (disabled) return;

    const newOptions = {
      ...options,
      [key]: !options[key],
    };

    // For single select (Operation, Mode), auto-advance
    if (currentStepData.type === 'single') {
      // If already selected, allow deselection (don't auto-advance)
      if (options[key]) {
        newOptions[key] = false;
        onChange(newOptions);
        return;
      }

      // Clear other options in this group first
      currentStepData.options.forEach(opt => {
        if (opt.key !== key) {
          newOptions[opt.key] = false;
        }
      });
      newOptions[key] = true;

      // Special handling for Brisk mode
      if (key === 'brisk') {
        // Clear all non-mode options first
        steps.forEach(step => {
          if (step.options && step.key !== 'mode') {
            step.options.forEach(opt => {
              newOptions[opt.key] = false;
            });
          }
        });

        // Auto-enable specific options for Brisk mode
        newOptions.analysis = true;        // Automated Analysis
        newOptions.vss = false;             // Volume Shadow Copies (disabled for speed)
        newOptions.extract_iocs = false;    // Extract IOCs (disabled for speed)
        newOptions.navigator = true;        // ATT&CK Navigator
        newOptions.userprofiles = true;     // User Profiles

        onChange(newOptions);

        // Skip directly to Output step
        setTimeout(() => {
          const outputStepIndex = steps.findIndex(s => s.key === 'output');
          setCurrentStep(outputStepIndex !== -1 ? outputStepIndex : steps.length - 2);
        }, 300);
        return;
      }

      // Special handling for Exhaustive mode
      if (key === 'exhaustive') {
        // Clear all non-mode options first
        steps.forEach(step => {
          if (step.options && step.key !== 'mode') {
            step.options.forEach(opt => {
              newOptions[opt.key] = false;
            });
          }
        });

        // Enable ALL options from all steps except mode options
        steps.forEach(step => {
          if (step.options && step.key !== 'mode') {
            step.options.forEach(opt => {
              newOptions[opt.key] = true;
            });
          }
        });

        onChange(newOptions);

        // Skip directly to Confirm step (last step)
        setTimeout(() => {
          setCurrentStep(steps.length - 1);
        }, 300);
        return;
      }

      // Special handling for Custom mode
      if (key === 'custom') {
        // Clear all non-mode options first
        steps.forEach(step => {
          if (step.options && step.key !== 'mode') {
            step.options.forEach(opt => {
              newOptions[opt.key] = false;
            });
          }
        });

        onChange(newOptions);

        // Auto-advance to next step
        setTimeout(() => {
          handleNext();
        }, 300);
        return;
      }

      // Special handling for Template mode
      if (key === 'template') {
        // Keep template selected - show template selector below
        onChange(newOptions);
        return;
      }

      // Update operation mode if this is the operation step
      if (currentStepData.key === 'operation') {
        const newOpMode = key;
        setOperationMode(newOpMode);
        onChange(newOptions);

        // Auto-advance after a short delay for visual feedback
        setTimeout(() => {
          handleNextWithMode(newOpMode);
        }, 300);
      } else {
        // For other single-select steps (like Mode)
        onChange(newOptions);
        setTimeout(() => {
          handleNext();
        }, 300);
      }
    } else {
      onChange(newOptions);
    }
  };

  const handleToggleAll = (value) => {
    const newOptions = { ...options };
    const filteredOptions = getFilteredOptions();
    filteredOptions.forEach(opt => {
      newOptions[opt.key] = value;
    });
    onChange(newOptions);
  };

  const handleNextWithMode = (opMode) => {
    const filteredSteps = getFilteredSteps();
    if (currentStep < filteredSteps.length - 1) {
      let nextStep = currentStep + 1;

      // Skip disabled steps based on the provided operation mode
      while (nextStep < filteredSteps.length && isStepDisabled(filteredSteps[nextStep], opMode)) {
        nextStep++;
      }

      if (nextStep < filteredSteps.length) {
        setCurrentStep(nextStep);

        // Randomly spawn Gollum on steps 3-6 (indices 2-5) when moving forward
        if (nextStep >= 2 && nextStep <= 5 && Math.random() < 0.5) {
          // 50% chance Gollum appears
          const gollumAppears = Math.floor(Math.random() * 4) + 2; // Random step between 2-5
          setGollumStep(gollumAppears);

          // Remove Gollum after 3 seconds
          setTimeout(() => {
            setGollumStep(null);
          }, 3000);
        }
      }
    }
  };

  const handleNext = () => {
    handleNextWithMode(operationMode);
  };

  const handleBack = () => {
    if (currentStep > 0) {
      let prevStep = currentStep - 1;

      // Skip disabled steps when going back
      while (prevStep >= 0 && isStepDisabled(steps[prevStep])) {
        prevStep--;
      }

      if (prevStep >= 0) {
        setCurrentStep(prevStep);
      }
    }
  };

  const formatEta = (minutes) => {
    if (minutes < 60) {
      return `${minutes} min`;
    }
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  };

  // Apply a saved template
  const applyTemplate = (template) => {
    // Build new options object
    const newOptions = {};

    // Apply all options from template
    if (template.options && typeof template.options === 'object') {
      Object.keys(template.options).forEach((key) => {
        const value = template.options[key];
        newOptions[key] = value === true;
      });
    }

    // Set mode to template
    newOptions.template = true;
    newOptions.brisk = false;
    newOptions.exhaustive = false;
    newOptions.custom = false;

    // Ensure base processing options are set
    newOptions.collect = true;
    newOptions.process = true;

    // Update options and set pending navigation
    setSelectedTemplate(template);
    setPendingTemplateNav(true);
    onChange(newOptions);
  };

  // Delete a saved template
  const deleteTemplate = (templateId) => {
    const updatedTemplates = savedTemplates.filter(t => t.id !== templateId);
    setSavedTemplates(updatedTemplates);
    localStorage.setItem('rivendell_templates', JSON.stringify(updatedTemplates));
  };

  // Import a template from a JSON file
  const importTemplate = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const rawData = JSON.parse(e.target.result);

        // Flatten the template data - handle both nested and flat structures
        const flatOptions = {};

        const processValue = (value) => {
          if (typeof value === 'boolean') {
            return value;
          }
          if (Array.isArray(value) && value.length > 0 && typeof value[0] === 'object') {
            // Handle array of objects (e.g., "collection": [{ "vss": true }])
            Object.entries(value[0]).forEach(([k, v]) => {
              if (typeof v === 'boolean') {
                flatOptions[k] = v;
              }
            });
          } else if (typeof value === 'object' && value !== null) {
            // Handle nested objects
            Object.entries(value).forEach(([k, v]) => {
              if (typeof v === 'boolean') {
                flatOptions[k] = v;
              }
            });
          }
        };

        Object.entries(rawData).forEach(([key, value]) => {
          if (typeof value === 'boolean') {
            // Flat structure: { "analysis": true }
            flatOptions[key] = value;
          } else {
            // Nested structure: { "collection": [{ ... }] }
            processValue(value);
          }
        });

        // Create template object with flattened options
        const newTemplate = {
          id: Date.now(),
          name: file.name.replace('.json', '').replace(/_Template$/, ''),
          options: flatOptions,
          createdAt: new Date().toISOString()
        };

        const updatedTemplates = [...savedTemplates, newTemplate];
        setSavedTemplates(updatedTemplates);
        localStorage.setItem('rivendell_templates', JSON.stringify(updatedTemplates));
      } catch (err) {
        console.error('Failed to parse template file:', err);
      }
    };
    reader.readAsText(file);

    // Reset input so same file can be selected again
    event.target.value = '';
  };

  const handleStepClick = (index) => {
    const filteredSteps = getFilteredSteps();
    const targetStep = filteredSteps[index];

    // Don't allow clicking on disabled steps
    if (isStepDisabled(targetStep)) {
      return;
    }

    // Allow clicking on completed steps or the current step
    if (index <= currentStep) {
      setCurrentStep(index);
    }
  };

  const renderStepIndicator = () => {
    const filteredSteps = getFilteredSteps();
    const progressPercent = (currentStep / (filteredSteps.length - 1)) * 100;

    return (
      <div className="wizard-steps" style={{ '--journey-progress': `${progressPercent}%` }}>
        {filteredSteps.map((step, index) => {
          const disabled = isStepDisabled(step);
          const isClickable = !disabled && index <= currentStep;
          const hasGollum = gollumStep === index;

          return (
            <div
              key={step.key}
              className={`wizard-step ${index === currentStep ? 'active' : ''} ${index < currentStep ? 'completed' : ''} ${disabled ? 'disabled' : ''} ${isClickable ? 'clickable' : ''} ${hasGollum ? 'has-gollum' : ''}`}
              onClick={() => handleStepClick(index)}
            >
              <div className="wizard-step-number">{index + 1}</div>
              <div className="wizard-step-title">{step.title}</div>
              {hasGollum && (
                <div className="gollum-emoji">
                  <span role="img" aria-label="Gollum">🧟</span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  };

  const renderConfirmStep = () => {
    // Group selected options by step
    const groupedOptions = {};
    steps.forEach(step => {
      if (step.options) {
        const selectedInStep = [];
        step.options.forEach(opt => {
          if (options[opt.key]) {
            selectedInStep.push(opt.label);
          }
        });
        if (selectedInStep.length > 0) {
          groupedOptions[step.title] = selectedInStep;
        }
      }
    });

    return (
      <div className="confirm-step">
        {error && <div className="error" style={{ marginBottom: '1.5rem' }}>{error}</div>}
        <div className="confirm-summary">
          {Object.entries(groupedOptions).map(([stepTitle, optionLabels], index) => (
            <div key={index} className="confirm-item">
              <span className="confirm-step-name">{stepTitle}:</span>
              <span className="confirm-option-name">{optionLabels.join(', ')}</span>
            </div>
          ))}
        </div>
        {selectedTemplate && (
          <div className="using-template">
            Using template: <strong>{selectedTemplate.name}</strong>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className={`options-panel-wizard ${disabled ? 'disabled' : ''}`}>
      {renderStepIndicator()}

      <div className="wizard-content">
        <div className="wizard-header">
          <h3>{currentStepData.title}</h3>
          <p>{currentStepData.description}</p>
          <div className="indicator-keys">
            <div className="slow-key">
              <span className="slow-indicator-key">!</span> = Slow operation
            </div>
            <div className="input-key">
              <span className="input-indicator-key">+</span> = Requires input
            </div>
          </div>
        </div>

        <div className="wizard-navigation">
          <div className={`wizard-actions-left ${currentStepData.type === 'single' || currentStepData.type === 'confirm' ? 'hidden-buttons' : ''}`}>
            <button type="button" onClick={() => handleToggleAll(true)}>
              Enable All
            </button>
            <button type="button" onClick={() => handleToggleAll(false)}>
              Disable All
            </button>
          </div>
          <div className="wizard-actions-right">
            <div className="wizard-top-controls">
              {currentStepData.type === 'confirm' && (
                <div className="save-template-checkbox">
                  <label>
                    <input
                      type="checkbox"
                      checked={options.save_template || false}
                      onChange={() => onChange({ ...options, save_template: !options.save_template })}
                    />
                    <span>Save as Template</span>
                  </label>
                </div>
              )}
              <div className="eta-display">
                <strong>ETA:</strong> {formatEta(eta)}
              </div>
            </div>
            <div className="wizard-buttons-row">
              <button
                type="button"
                onClick={handleBack}
                disabled={currentStep === 0}
                className="button-back"
              >
                ← Back
              </button>
              {currentStepData.type === 'confirm' ? (
                onSubmit && (
                  <button
                    type="button"
                    onClick={onSubmit}
                    disabled={loading || disabled}
                    className="button-start"
                  >
                    {loading ? 'Starting...' : 'Start Analysis'}
                  </button>
                )
              ) : (
                <button
                  type="button"
                  onClick={handleNext}
                  disabled={currentStep >= steps.length - 1}
                  className="button-next"
                >
                  Next →
                </button>
              )}
            </div>
          </div>
        </div>

        {currentStepData.type === 'confirm' ? (
          renderConfirmStep()
        ) : (
          <>
            {(() => {
              const isAnalysisStep = currentStepData.key === 'analysis';
              const isCollectionStep = currentStepData.key === 'collection';
              const filteredOptions = getFilteredOptions();

              const analysisOrder = ['analysis', 'extract_iocs', 'threat_intel', 'memory', 'timeline', 'memory_timeline', 'keywords', 'yara', 'collectFiles'];

              const orderedOptions = (isAnalysisStep ? analysisOrder : [])
                .map(key => filteredOptions.find(opt => opt.key === key))
                .filter(Boolean);

              const finalOptions = orderedOptions.length ? orderedOptions : filteredOptions;

              const gridClassNames = [
                'wizard-options',
                currentStepData.type === 'single' ? 'radio-group' : 'checkbox-group',
                isAnalysisStep ? 'analysis-grid' : '',
                isCollectionStep ? 'collection-grid' : '',
              ]
                .filter(Boolean)
                .join(' ');

              return (
                <div
                  className={gridClassNames}
                  data-option-count={finalOptions.length}
                >
                  {finalOptions.map(option => {
                    const layoutStyle = {};

                    if (isAnalysisStep) {
                      // 3 rows x 3 columns using a 6-column grid (App.css)
                      const spans = {
                        analysis: 2,
                        extract_iocs: 2,
                        threat_intel: 2,
                        memory: 2,
                        memory_timeline: 2,
                        timeline: 2,
                      };
                      if (spans[option.key]) {
                        layoutStyle.gridColumn = `span ${spans[option.key]}`;
                      }
                    }

                    return (
                      <div
                        key={option.key}
                        className={`wizard-option-item ${option.disabled ? 'option-disabled' : ''} ${option.slow ? 'option-slow' : ''}`}
                        style={layoutStyle}
                      >
                        <input
                          type="checkbox"
                          id={option.key}
                          name={currentStepData.type === 'single' ? currentStepData.key : option.key}
                          checked={options[option.key] || false}
                          onChange={() => !option.disabled && handleToggle(option.key)}
                          disabled={option.disabled}
                          className={currentStepData.type === 'single' ? 'radio-style' : ''}
                        />
                        <label htmlFor={option.key} title={option.tooltip}>
                          <div className="option-label">
                            {option.label}
                            {option.slow && <span className="slow-indicator" title="This operation is slow">!</span>}
                            {option.requiresInput && <span className="input-indicator" title="Requires additional input">+</span>}
                            {option.tooltip && <span className="tooltip-icon" title={option.tooltip}>ⓘ</span>}
                          </div>
                          <div className="option-description">{option.description}</div>
                        </label>
                      </div>
                    );
                  })}
                </div>
              );
            })()}
            {/* Template selector - show when template mode is selected */}
            {currentStepData.key === 'mode' && options.template && (
              <div className="template-selector">
                <div className="template-selector-header">
                  <h4>Select a Saved Template</h4>
                  <label className="import-template-btn">
                    <input
                      type="file"
                      accept=".json"
                      onChange={importTemplate}
                      style={{ display: 'none' }}
                    />
                    Import Template
                  </label>
                </div>
                {savedTemplates.length === 0 ? (
                  <p className="no-templates">No saved templates yet. Import a template or complete a custom configuration and save it.</p>
                ) : (
                  <div className="template-list">
                    {savedTemplates.map(template => (
                      <div key={template.id} className="template-item">
                        <div className="template-info" onClick={() => applyTemplate(template)}>
                          <span className="template-name">{template.name}</span>
                          <span className="template-date">
                            {new Date(template.createdAt).toLocaleDateString()}
                          </span>
                        </div>
                        <button
                          type="button"
                          className="template-delete"
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteTemplate(template.id);
                          }}
                          title="Delete template"
                        >
                          ×
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </>
        )}

      </div>
    </div>
  );
}

export default OptionsPanel;
