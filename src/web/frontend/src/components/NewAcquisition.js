import React, { useState } from 'react';

// OS Icon component
const OSIcon = ({ os, style = {} }) => {
  const iconMap = {
    windows: `${process.env.PUBLIC_URL}/images/microsoft.png`,
    macos: `${process.env.PUBLIC_URL}/images/apple.png`,
    linux: `${process.env.PUBLIC_URL}/images/linux.png`,
  };

  return (
    <img
      src={iconMap[os]}
      alt={os}
      style={{
        height: '16px',
        width: 'auto',
        marginLeft: '4px',
        verticalAlign: 'middle',
        display: 'inline-block',
        ...style
      }}
    />
  );
};

// Each collector as it is (docs/CLI.md), so a copied command runs: its options and nothing else.
// Python and PowerShell read remote targets from src/acquisition/lists/hosts.list and run from
// src/acquisition; gandalf.sh takes one host (-h) or a hosts file (-f), with an SSH user (-u).
const COLLECTORS = {
  bash: {
    label: 'Bash (gandalf.sh)',
    os: ['linux', 'macos'],
    run: 'sudo ./src/acquisition/bash/gandalf.sh',
    output: '-o',
    options: [
      { key: 'memory', label: 'Memory dump', flag: '-m' },
      { key: 'accesstimes', label: 'Last access times', flag: '-a' },
      { key: 'files', label: 'Files named in files.list', flag: '-c' },
      { key: 'progress', label: 'Show progress', flag: '-p' },
      { key: 'noprompt', label: 'No questions (accept the defaults)', flag: '-n' },
      { key: 'livecontainers', label: 'Live containers (asks Docker and Podman; every command audited)', flag: '-l', os: ['linux'] },
    ],
  },
  python: {
    label: 'Python (gandalf.py)',
    os: ['linux', 'macos'],
    run: 'cd src/acquisition && sudo python3 python/gandalf.py',
    output: '-O',
    options: [
      { key: 'memory', label: 'Memory dump', flag: '-M' },
      { key: 'accesstimes', label: 'Last access times', flag: '-A' },
      { key: 'files', label: 'Files named in lists/files.list', flag: '-F' },
      { key: 'progress', label: 'Show progress', flag: '-P' },
      { key: 'noprompt', label: 'No questions (accept the defaults)', flag: '-N' },
      { key: 'livecontainers', label: 'Live containers (asks Docker and Podman; every command audited)', flag: '-L', os: ['linux'] },
    ],
  },
  powershell: {
    label: 'PowerShell (Invoke-Gandalf.ps1)',
    os: ['windows'],
    run: 'cd src\\acquisition; .\\windows\\Invoke-Gandalf.ps1',
    output: '-OutputDirectory',
    options: [
      { key: 'memory', label: 'Memory dump', flag: '-Memory' },
      { key: 'files', label: 'Files named in lists\\files.list', flag: '-CollectFiles' },
      { key: 'progress', label: 'Show progress', flag: '-ShowProgress' },
      { key: 'noprompt', label: 'No questions (accept the defaults)', flag: '-NoPrompt' },
      { key: 'livecontainers', label: 'Live containers (asks Docker; every command audited)', flag: '-LiveContainers' },
    ],
  },
};
const ENCRYPTIONS = [['key', 'Key'], ['password', 'Password'], ['none', 'None']];

const splitHosts = (text) => text.split(/[\s,]+/).map((h) => h.trim()).filter(Boolean);

// The command for these choices, and the hosts.list it reads (if any)
export const buildCommand = ({ collector, encryption, remote, hosts, sshUser, destination, options }) => {
  const spec = COLLECTORS[collector];
  if (!spec) return { command: '', hostsList: '' };
  const enc = (ENCRYPTIONS.find(([value]) => value === encryption) || [])[1];
  if (!enc) return { command: '', hostsList: '' };
  const parts = [spec.run];
  let hostsList = '';
  if (collector === 'powershell') {
    parts.push(`-EncryptionObject ${enc}`, `-Acquisition ${remote ? 'Remote' : 'Local'}`);
  } else {
    parts.push(enc, remote ? 'Remote' : 'Local');
  }
  if (destination) parts.push(`${spec.output} ${destination}`);
  spec.options.filter((o) => options[o.key]).forEach((o) => parts.push(o.flag));
  if (remote) {
    if (collector === 'bash' && hosts.length === 1) {
      parts.push(`-h ${hosts[0]}`);
    } else if (collector === 'bash' && hosts.length > 1) {
      parts.push('-f hosts.list');
      hostsList = 'hosts.list';
    } else if (hosts.length) {
      hostsList = collector === 'powershell' ? 'src\\acquisition\\lists\\hosts.list' : 'src/acquisition/lists/hosts.list';
    }
    if (collector === 'bash' && sshUser) parts.push(`-u ${sshUser}`);
  }
  return { command: parts.join(' '), hostsList };
};

function NewAcquisition() {
  const [caseNumber, setCaseNumber] = useState('');
  const [destinationPath, setDestinationPath] = useState('');
  const [locationMode, setLocationMode] = useState('');
  const [encryptionMode, setEncryptionMode] = useState('');
  const [hostOS, setHostOS] = useState('');
  const [scriptLanguage, setScriptLanguage] = useState('');
  const [hostnames, setHostnames] = useState('');
  const [sshUser, setSshUser] = useState('');
  const [collectionOptions, setCollectionOptions] = useState({});
  const [fileList, setFileList] = useState('');
  const [copied, setCopied] = useState('');

  // Validate case number and get validation message
  const getCaseNumberValidation = (value) => {
    if (value.length === 0) {
      return { valid: false, message: '' };
    }

    if (value.length < 6) {
      return { valid: false, message: `Case number must be at least 6 characters (currently ${value.length})` };
    }

    if (value.length > 20) {
      return { valid: false, message: `Case number must be no longer than 20 characters (currently ${value.length})` };
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

    return { valid: true, message: '' };
  };

  const caseNumberValidation = getCaseNumberValidation(caseNumber);
  const isCaseNumberValid = caseNumberValidation.valid;
  const remote = locationMode === 'remote';
  const hosts = splitHosts(hostnames);
  const spec = COLLECTORS[scriptLanguage];
  const options = spec ? spec.options.filter((o) => !o.os || o.os.includes(hostOS)) : [];

  const { command, hostsList } = isCaseNumberValid
    ? buildCommand({
        collector: scriptLanguage, encryption: encryptionMode, remote, hosts, sshUser,
        destination: destinationPath, options: collectionOptions,
      })
    : { command: '', hostsList: '' };
  const missing = !isCaseNumberValid ? 'a valid case number'
    : !locationMode ? 'Local or Remote'
    : !encryptionMode ? 'an encryption method'
    : !scriptLanguage ? 'a collector'
    : remote && !hosts.length ? 'at least one target host'
    : '';

  const copy = (text, what) => {
    navigator.clipboard.writeText(text);
    setCopied(what);
  };

  // Handle file list upload
  const handleFileListUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setFileList(event.target.result);
      };
      reader.readAsText(file);
    }
  };

  const collectorsFor = (os) => Object.entries(COLLECTORS).filter(([, c]) => c.os.includes(os));

  return (
    <div className="new-analysis">
      {/* Section headings take the page's card-heading style (acq-heading) */}
      <div className="card acq-form">
        <div data-guide="gandalf.case" className="form-row">
          <div className="form-group">
            <label className="acq-heading" htmlFor="caseNumber">
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

          <div className="form-group">
            <label className="acq-heading" htmlFor="destinationPath">
              Destination Directory
            </label>
            <input
              type="text"
              id="destinationPath"
              value={destinationPath}
              onChange={(e) => setDestinationPath(e.target.value)}
              placeholder="Leave empty for the collector's default"
              disabled={!isCaseNumberValid}
            />
          </div>
        </div>

        <div data-guide="gandalf.config" className="form-group">
          <label className="acq-heading">Acquisition Configuration *</label>
          <div className="dropdown-row">
            <select
              id="locationMode"
              value={locationMode}
              onChange={(e) => setLocationMode(e.target.value)}
              disabled={!isCaseNumberValid}
              className="large-select"
            >
              <option value="">-- Local or Remote --</option>
              <option value="local">Local</option>
              <option value="remote">Remote</option>
            </select>

            <select
              id="encryptionMode"
              value={encryptionMode}
              onChange={(e) => setEncryptionMode(e.target.value)}
              disabled={!isCaseNumberValid}
              className="large-select"
            >
              <option value="">-- Encryption --</option>
              {ENCRYPTIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>

            <select
              id="hostOS"
              value={hostOS}
              onChange={(e) => {
                const os = e.target.value;
                setHostOS(os);
                const only = collectorsFor(os);
                setScriptLanguage(only.length === 1 ? only[0][0] : '');
                setCollectionOptions({});
              }}
              disabled={!isCaseNumberValid}
              className="large-select"
            >
              <option value="">-- Target Platform --</option>
              <option value="windows">Windows</option>
              <option value="macos">macOS</option>
              <option value="linux">Linux</option>
            </select>

            <select
              id="scriptLanguage"
              value={scriptLanguage}
              onChange={(e) => { setScriptLanguage(e.target.value); setCollectionOptions({}); }}
              disabled={!isCaseNumberValid || !hostOS}
              className="large-select"
            >
              <option value="">-- Collector --</option>
              {collectorsFor(hostOS).map(([value, c]) => (
                <option key={value} value={value}>{c.label}</option>
              ))}
            </select>
          </div>
        </div>

        {remote && (
          <div data-guide="gandalf.hosts" className="form-row">
            <div className="form-group">
              <label className="acq-heading" htmlFor="hostnames">
                Target host(s): names or IP addresses, comma-separated
              </label>
              <input
                type="text"
                id="hostnames"
                value={hostnames}
                onChange={(e) => setHostnames(e.target.value)}
                placeholder="e.g., ws-01, 192.168.1.100"
                disabled={!isCaseNumberValid}
              />
            </div>
            {scriptLanguage === 'bash' && (
              <div className="form-group">
                <label className="acq-heading" htmlFor="sshUser">SSH user</label>
                <input
                  type="text"
                  id="sshUser"
                  value={sshUser}
                  onChange={(e) => setSshUser(e.target.value)}
                  placeholder="Asked for when it runs if left empty"
                  disabled={!isCaseNumberValid}
                />
              </div>
            )}
          </div>
        )}

        <div data-guide="gandalf.options" className="form-group">
          <label className="acq-heading">Collection Options</label>
          {!spec && (
            <div className="validation-message info">
              Choose the target platform and collector to see its options. Every collector takes its artefacts
              in order of volatility; these are what it adds on request.
            </div>
          )}
          {spec && (
            <div className="checkbox-group" style={{ gridTemplateColumns: 'repeat(2, 1fr)' }}>
              {options.map((o) => (
                <div key={o.key} className="checkbox-item">
                  <input
                    type="checkbox"
                    id={o.key}
                    checked={collectionOptions[o.key] || false}
                    onChange={(e) => setCollectionOptions({ ...collectionOptions, [o.key]: e.target.checked })}
                  />
                  <label htmlFor={o.key}>
                    <span>{o.label} <code>{o.flag}</code></span>
                    <span>{(o.os || spec.os).map((os) => <OSIcon key={os} os={os} />)}</span>
                  </label>
                </div>
              ))}
            </div>
          )}
          {spec && collectionOptions.files && (
            <div className="checkbox-item" style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', marginTop: '0.5rem' }}>
              <span style={{ fontSize: '0.85rem' }}>
                Names to look for, one per line, saved as <code>files.list</code>
                {scriptLanguage === 'bash' ? ' where gandalf.sh runs' : ' in src/acquisition/lists/'}
              </span>
              <input type="file" id="fileListUpload" accept=".txt,.list,.csv" onChange={handleFileListUpload} />
              {fileList && (
                <span style={{ fontSize: '0.75rem', color: '#a7db6c' }}>
                  {fileList.split('\n').filter((f) => f.trim()).length} name(s) listed
                </span>
              )}
            </div>
          )}
        </div>

        <div data-guide="gandalf.command" className="acquisition-actions">
          <div className="command-block-container">
            <div className="command-block-header">
              <label className="acq-heading">Generated Command</label>
              <div className="command-header-actions">
                <button
                  type="button"
                  className="copy-button"
                  onClick={() => copy(command, 'command')}
                  disabled={!command || !!missing}
                  title="Copy to clipboard"
                >
                  {copied === 'command' ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>
            <pre className="code-block command-preview command-preview-large">
              {missing ? `# Choose ${missing} to generate the command` : command}
            </pre>
          </div>
          {!missing && hostsList && (
            <div className="command-block-container">
              <div className="command-block-header">
                <label className="acq-heading">Save as {hostsList}</label>
                <div className="command-header-actions">
                  <button type="button" className="copy-button" onClick={() => copy(hosts.join('\n') + '\n', 'hosts')}>
                    {copied === 'hosts' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
              <pre className="code-block command-preview">{hosts.join('\n')}</pre>
              {scriptLanguage !== 'bash' && (
                <div className="validation-message info">
                  {scriptLanguage === 'python'
                    ? 'gandalf.py reads its targets from this list and asks for each one\'s IP address, user and password over SSH.'
                    : 'Invoke-Gandalf opens a PowerShell Remoting session to each host in this list.'}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default NewAcquisition;
