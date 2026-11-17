import React, { useState } from 'react';

function OptionsPanel({ options, onChange }) {
  const [activeSection, setActiveSection] = useState('operation');

  const sections = {
    operation: {
      title: 'Operation Mode',
      description: 'Choose how you want to process the images',
      options: [
        { key: 'collect', label: 'Collect', description: 'Collect artifacts from disk image' },
        { key: 'gandalf', label: 'Custodian', description: 'Read artifacts acquired using Custodian' }
      ],
    },
    collection: {
      title: 'Collection Options',
      description: 'What to collect from the images',
      options: [
        { key: 'collect_files', label: 'Collect Files', description: 'Collect files (binaries, documents, scripts)' },
        { key: 'userprofiles', label: 'User Profiles', description: 'Collect content of user profiles' },
        { key: 'vss', label: 'Volume Shadow Copies', description: 'Process VSS  (if available)' },
        { key: 'symlinks', label: 'Follow Symlinks', description: 'Follow paths of symbolic links' },
      ],
    },
    analysis: {
      title: 'Analysis Options',
      description: 'Advanced analysis features',
      options: [
        { key: 'analysis', label: 'Automated Analysis', description: 'Conduct automated forensic analysis' },
        { key: 'extract_iocs', label: 'Extract IOCs', description: 'Extract Indicators of Compromise' },
        { key: 'timeline', label: 'Timeline', description: 'Create full timeline using plaso' },
        { key: 'clamav', label: 'ClamAV', description: 'Run ClamAV against mounted image' },
        { key: 'brisk', label: 'Brisk', description: 'Fast analysis with most features' },
        { key: 'quick', label: 'Quick', description: 'Get timestamps but skip hashing' },
        { key: 'super_quick', label: 'Super Quick', description: 'Skip timestamps and hashing' },
      ],
    },
    memory: {
      title: 'Memory Analysis',
      description: 'Memory image processing options',
      options: [
        { key: 'memory', label: 'Memory Analysis', description: 'Analyze memory using Volatility' },
        { key: 'memory_timeline', label: 'Memory Timeline', description: 'Create memory timeline' },
      ],
    },
    output: {
      title: 'Output Options',
      description: 'Where to send analysis results',
      options: [
        { key: 'splunk', label: 'Splunk', description: 'Index into local Splunk instance' },
        { key: 'elastic', label: 'Elastic', description: 'Index into local Elastic instance' },
        { key: 'navigator', label: 'MITRE Navigator', description: 'Map to ATT&CK framework' },
      ],
    },
    hashing: {
      title: 'Verification',
      description: 'File hashing and comparison options',
      options: [
        { key: 'nsrl', label: 'NSRL', description: 'Compare hashes against NSRL database' },
        { key: 'metacollected', label: 'Meta Only', description: 'Only hash collected artifacts' },
        { key: 'imageinfo', label: 'Image Info', description: 'Extract E01 metadata' },
      ],
    },
    postprocess: {
      title: 'Post-Processing',
      description: 'Cleanup and archiving options',
      options: [
        { key: 'archive', label: 'Archive', description: 'Create ZIP archive after processing' },
        { key: 'delete', label: 'Delete Raw Data', description: 'Delete raw data after processing' },
      ],
    },
  };

  const handleToggle = (key) => {
    onChange({
      ...options,
      [key]: !options[key],
    });
  };

  const handleToggleAll = (sectionKey, value) => {
    const newOptions = { ...options };
    sections[sectionKey].options.forEach(opt => {
      newOptions[opt.key] = value;
    });
    onChange(newOptions);
  };

  return (
    <div className="options-panel">
      <div className="options-sections">
        {Object.keys(sections).map(sectionKey => (
          <button
            key={sectionKey}
            className={activeSection === sectionKey ? 'active' : ''}
            onClick={() => setActiveSection(sectionKey)}
          >
            {sections[sectionKey].title}
          </button>
        ))}
      </div>

      <div className="options-content">
        <div className="section-header">
          <div>
            <h3>{sections[activeSection].title}</h3>
            <p>{sections[activeSection].description}</p>
          </div>
          <div className="section-actions">
            <button onClick={() => handleToggleAll(activeSection, true)}>
              Enable All
            </button>
            <button onClick={() => handleToggleAll(activeSection, false)}>
              Disable All
            </button>
          </div>
        </div>

        <div className="checkbox-group">
          {sections[activeSection].options.map(option => (
            <div key={option.key} className="checkbox-item">
              <input
                type="checkbox"
                id={option.key}
                checked={options[option.key] || false}
                onChange={() => handleToggle(option.key)}
              />
              <label htmlFor={option.key}>
                <div className="option-label">{option.label}</div>
                <div className="option-description">{option.description}</div>
              </label>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default OptionsPanel;
