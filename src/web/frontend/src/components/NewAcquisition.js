import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

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

function NewAcquisition() {
  const navigate = useNavigate();
  const [caseNumber, setCaseNumber] = useState('');
  const [destinationPath, setDestinationPath] = useState('');
  const [locationMode, setLocationMode] = useState('');
  const [encryptionMode, setEncryptionMode] = useState('');
  const [hostOS, setHostOS] = useState('');
  const [scriptLanguage, setScriptLanguage] = useState('');
  const [hostnames, setHostnames] = useState('');
  const [ipAddresses, setIpAddresses] = useState('');
  const [collectionOptions, setCollectionOptions] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [hostValidationMessage, setHostValidationMessage] = useState('');
  const [useLongSwitches, setUseLongSwitches] = useState(false);
  const [ipValidationMessage, setIpValidationMessage] = useState('');
  const [fileList, setFileList] = useState('');

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

  // Generate command line
  const generateCommand = () => {
    if (!isCaseNumberValid) return '';

    let cmd = '';
    const isPowerShell = scriptLanguage === 'powershell';

    // Determine script path based on language
    if (scriptLanguage === 'python') {
      cmd = 'python3 acquisition/python/gandalf.py';
    } else if (scriptLanguage === 'powershell') {
      cmd = 'powershell.exe -File acquisition\\powershell\\gandalf.ps1';
    } else if (scriptLanguage === 'bash') {
      cmd = 'bash acquisition/bash/gandalf.sh';
    } else {
      return '# Select a script type to generate command';
    }

    // Add encryption mode
    if (encryptionMode) {
      const encModes = {
        'password': 'Password',
        'certificate': 'Certificate',
        'key': 'Key',
        'none': 'None'
      };
      cmd += ` ${isPowerShell ? '-' : ''}${encModes[encryptionMode]}`;
    }

    // Add location mode
    if (locationMode) {
      cmd += ` ${isPowerShell ? '-' : ''}${locationMode === 'local' ? 'Local' : 'Remote'}`;
    }

    // Add hostnames/IPs
    const hostnameList = hostnames.split(',').map(h => h.trim()).filter(h => h);
    const ipList = ipAddresses.split(',').map(ip => ip.trim()).filter(ip => ip);

    if (hostnameList.length > 0) {
      if (isPowerShell) {
        cmd += useLongSwitches ? ` -Hostname ${hostnameList.join(',')}` : ` -h ${hostnameList.join(',')}`;
      } else {
        cmd += useLongSwitches ? ` --hostname ${hostnameList.join(',')}` : ` -h ${hostnameList.join(',')}`;
      }
    }

    if (ipList.length > 0 && hostnameList.length === ipList.length) {
      if (isPowerShell) {
        cmd += useLongSwitches ? ` -IpAddress ${hostnameList.join(',')}` : ` -ip ${ipList.join(',')}`;
      } else {
        cmd += useLongSwitches ? ` --ip-address ${ipList.join(',')}` : ` -ip ${ipList.join(',')}`;
      }
    }

    // Add collection options
    const flags = [];
    if (isPowerShell) {
      // PowerShell uses single dash with PascalCase
      if (collectionOptions.memory) flags.push(useLongSwitches ? '-Memory' : '-M');
      if (collectionOptions.registry) flags.push(useLongSwitches ? '-Registry' : '-R');
      if (collectionOptions.eventlogs) flags.push(useLongSwitches ? '-EventLogs' : '-E');
      if (collectionOptions.browser) flags.push(useLongSwitches ? '-Browser' : '-B');
      if (collectionOptions.files) flags.push(useLongSwitches ? '-Files' : '-F');
      if (collectionOptions.userprofiles) flags.push(useLongSwitches ? '-UserProfiles' : '-U');
      if (collectionOptions.lastaccesstimes) flags.push(useLongSwitches ? '-LastAccessTimes' : '-L');
      if (collectionOptions.hash) flags.push(useLongSwitches ? '-Hash' : '-H');
      if (collectionOptions.mft) flags.push(useLongSwitches ? '-Mft' : '-MFT');
      if (collectionOptions.trash) flags.push(useLongSwitches ? '-Trash' : '-TR');
      if (collectionOptions.temp) flags.push(useLongSwitches ? '-Temp' : '-TMP');
      if (collectionOptions.scheduledtasks) flags.push(useLongSwitches ? '-ScheduledTasks' : '-ST');
      if (collectionOptions.wmi) flags.push(useLongSwitches ? '-Wmi' : '-WMI');
      if (collectionOptions.vss) flags.push(useLongSwitches ? '-Vss' : '-VSS');
      if (collectionOptions.livememory) flags.push(useLongSwitches ? '-LiveMemory' : '-LM');
    } else {
      // Bash/Python use double dash for long, single dash for short
      if (collectionOptions.memory) flags.push(useLongSwitches ? '--memory' : '-M');
      if (collectionOptions.registry) flags.push(useLongSwitches ? '--registry' : '-R');
      if (collectionOptions.eventlogs) flags.push(useLongSwitches ? '--eventlogs' : '-E');
      if (collectionOptions.browser) flags.push(useLongSwitches ? '--browser' : '-B');
      if (collectionOptions.files) flags.push(useLongSwitches ? '--files' : '-F');
      if (collectionOptions.userprofiles) flags.push(useLongSwitches ? '--userprofiles' : '-U');
      if (collectionOptions.lastaccesstimes) flags.push(useLongSwitches ? '--lastaccesstimes' : '-L');
      if (collectionOptions.hash) flags.push(useLongSwitches ? '--hash' : '-H');
      if (collectionOptions.systemlogs) flags.push(useLongSwitches ? '--systemlogs' : '-SL');
      if (collectionOptions.plists) flags.push(useLongSwitches ? '--plists' : '-PL');
      if (collectionOptions.mft) flags.push(useLongSwitches ? '--mft' : '-MFT');
      if (collectionOptions.trash) flags.push(useLongSwitches ? '--trash' : '-TR');
      if (collectionOptions.temp) flags.push(useLongSwitches ? '--temp' : '-TMP');
      if (collectionOptions.scheduledtasks) flags.push(useLongSwitches ? '--scheduledtasks' : '-ST');
      if (collectionOptions.wmi) flags.push(useLongSwitches ? '--wmi' : '-WMI');
      if (collectionOptions.vss) flags.push(useLongSwitches ? '--vss' : '-VSS');
      if (collectionOptions.livememory) flags.push(useLongSwitches ? '--livememory' : '-LM');
    }

    if (flags.length > 0) {
      cmd += ` ${flags.join(' ')}`;
    }

    // Add output directory
    if (destinationPath) {
      if (isPowerShell) {
        cmd += useLongSwitches ? ` -Output ${destinationPath}` : ` -o ${destinationPath}`;
      } else {
        cmd += useLongSwitches ? ` --output ${destinationPath}` : ` -o ${destinationPath}`;
      }
    } else if (caseNumber) {
      if (isPowerShell) {
        cmd += useLongSwitches ? ` -Output /evidence/${caseNumber}` : ` -o /evidence/${caseNumber}`;
      } else {
        cmd += useLongSwitches ? ` --output /evidence/${caseNumber}` : ` -o /evidence/${caseNumber}`;
      }
    }

    return cmd;
  };

  const command = generateCommand();

  // Copy command to clipboard
  const copyCommand = () => {
    if (command) {
      navigator.clipboard.writeText(command);
    }
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

  // Validate IP address format
  const validateIpAddress = (ip) => {
    const ipv4Pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = ip.match(ipv4Pattern);

    if (!match) {
      return false;
    }

    // Check each octet is between 0-255
    for (let i = 1; i <= 4; i++) {
      const octet = parseInt(match[i], 10);
      if (octet < 0 || octet > 255) {
        return false;
      }
    }

    return true;
  };

  // Validate IP addresses
  const validateIpAddresses = (ipAddressesStr) => {
    if (!ipAddressesStr.trim()) {
      setIpValidationMessage('');
      return true;
    }

    const ipList = ipAddressesStr.split(',').map(ip => ip.trim()).filter(ip => ip);

    for (const ip of ipList) {
      if (!validateIpAddress(ip)) {
        setIpValidationMessage(`Invalid IP address format: "${ip}". Use valid IPv4 format (e.g., 192.168.1.100)`);
        return false;
      }
    }

    setIpValidationMessage('');
    return true;
  };

  // Validate hostnames and IP addresses
  const validateHosts = (hostnamesStr, ipAddressesStr) => {
    if (!hostnamesStr.trim() && !ipAddressesStr.trim()) {
      setHostValidationMessage('');
      return true;
    }

    const hostnameList = hostnamesStr.split(',').map(h => h.trim()).filter(h => h);
    const ipList = ipAddressesStr.split(',').map(ip => ip.trim()).filter(ip => ip);

    if (hostnameList.length === 0 && ipList.length === 0) {
      setHostValidationMessage('');
      return true;
    }

    if (hostnameList.length !== ipList.length) {
      setHostValidationMessage(`Number of hostnames (${hostnameList.length}) must match number of IP addresses (${ipList.length})`);
      return false;
    }

    setHostValidationMessage(`${hostnameList.length} host(s) configured`);
    return true;
  };

  // Validate hosts whenever they change
  React.useEffect(() => {
    validateHosts(hostnames, ipAddresses);
  }, [hostnames, ipAddresses]);

  // Validate IP addresses whenever they change
  React.useEffect(() => {
    validateIpAddresses(ipAddresses);
  }, [ipAddresses]);

  // Get available script languages based on selected OS
  const getScriptLanguages = () => {
    if (hostOS === 'windows') {
      return [
        { value: 'powershell', label: 'PowerShell' },
        { value: 'python', label: 'Python' }
      ];
    } else if (hostOS === 'macos' || hostOS === 'linux') {
      return [
        { value: 'bash', label: 'Bash' },
        { value: 'python', label: 'Python' }
      ];
    }
    return [];
  };

  // Toggle all collection options
  const toggleAllCollectionOptions = () => {
    // Options that should be toggled (excludes: hash, lastaccesstimes, files, livememory, memory)
    const toggleableOptions = ['browser', 'userprofiles', 'mft', 'trash', 'temp', 'scheduledtasks'];
    const windowsOnlyOptions = ['registry', 'eventlogs', 'wmi', 'vss'];
    const macLinuxOptions = ['systemlogs'];
    const macOnlyOptions = ['plists'];

    // Check if all available toggleable options are selected
    let availableOptions = [...toggleableOptions];

    if (hostOS === 'windows') {
      availableOptions = [...availableOptions, ...windowsOnlyOptions];
    } else if (hostOS === 'macos') {
      availableOptions = [...availableOptions, ...macLinuxOptions, ...macOnlyOptions];
    } else if (hostOS === 'linux') {
      availableOptions = [...availableOptions, ...macLinuxOptions];
    }

    const allSelected = availableOptions.every(opt => collectionOptions[opt]);

    if (allSelected) {
      // Deselect all toggleable options, but preserve the excluded ones
      const newOptions = {
        hash: collectionOptions.hash || false,
        lastaccesstimes: collectionOptions.lastaccesstimes || false,
        files: collectionOptions.files || false,
        livememory: collectionOptions.livememory || false,
        memory: collectionOptions.memory || false
      };
      setCollectionOptions(newOptions);
    } else {
      // Select all available toggleable options, preserving the excluded ones
      const newOptions = {
        hash: collectionOptions.hash || false,
        lastaccesstimes: collectionOptions.lastaccesstimes || false,
        files: collectionOptions.files || false,
        livememory: collectionOptions.livememory || false,
        memory: collectionOptions.memory || false
      };
      availableOptions.forEach(opt => {
        newOptions[opt] = true;
      });
      setCollectionOptions(newOptions);
    }
  };

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

    if (!locationMode) {
      setError('Please select Local or Remote');
      return;
    }

    if (!encryptionMode) {
      setError('Please select an encryption mode');
      return;
    }

    if (!hostOS) {
      setError('Please select host architecture/OS');
      return;
    }

    if (!scriptLanguage) {
      setError('Please select a script language');
      return;
    }

    if (!hostnames && !ipAddresses) {
      setError('Please enter at least one hostname or IP address');
      return;
    }

    if (!validateHosts(hostnames, ipAddresses)) {
      setError('Number of hostnames must match number of IP addresses');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      // TODO: Implement API call for acquisition
      console.log('Starting acquisition:', {
        case_number: caseNumber,
        destination_path: destinationPath || null,
        host_os: hostOS,
        script_language: scriptLanguage,
        hostname: hostnames || null,
        ip_address: ipAddresses || null,
        collection_options: collectionOptions,
      });

      // Redirect after starting acquisition
      navigate('/jobs');
    } catch (err) {
      setError('Failed to start acquisition');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="new-analysis">
      <div className="card">
        <h2>New Forensic Acquisition</h2>

        {error && <div className="error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div data-guide="gandalf.case" className="form-row">
            <div className="form-group">
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

            <div className="form-group">
              <label htmlFor="destinationPath">
                Destination Directory
              </label>
              <input
                type="text"
                id="destinationPath"
                value={destinationPath}
                onChange={(e) => setDestinationPath(e.target.value)}
                placeholder="Leave empty to use default location"
                disabled={!isCaseNumberValid}
              />
            </div>
          </div>

          <div data-guide="gandalf.config" className="form-group">
            <label>Acquisition Configuration *</label>
            <div className="dropdown-row">
              <select
                id="locationMode"
                value={locationMode}
                onChange={(e) => setLocationMode(e.target.value)}
                required
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
                required
                disabled={!isCaseNumberValid}
                className="large-select"
              >
                <option value="">-- Encryption --</option>
                <option value="password">Password</option>
                <option value="certificate">Certificate</option>
                <option value="key">Key-based</option>
                <option value="none">None</option>
              </select>

              <select
                id="hostOS"
                value={hostOS}
                onChange={(e) => {
                  const newOS = e.target.value;
                  setHostOS(newOS);
                  setScriptLanguage(''); // Reset script language when OS changes

                  // Clear OS-specific options based on the new selection
                  const newOptions = { ...collectionOptions };

                  if (newOS === 'windows') {
                    // Clear macOS/Linux-only options
                    newOptions.systemlogs = false;
                    newOptions.plists = false;
                  } else if (newOS === 'macos') {
                    // Clear Windows-only options
                    newOptions.registry = false;
                    newOptions.eventlogs = false;
                    newOptions.wmi = false;
                    newOptions.vss = false;
                  } else if (newOS === 'linux') {
                    // Clear Windows-only and macOS-only options
                    newOptions.registry = false;
                    newOptions.eventlogs = false;
                    newOptions.wmi = false;
                    newOptions.vss = false;
                    newOptions.plists = false;
                  }

                  setCollectionOptions(newOptions);
                }}
                required
                disabled={!isCaseNumberValid}
                className="large-select"
              >
                <option value="">-- Host Platform --</option>
                <option value="windows">Windows</option>
                <option value="macos">macOS</option>
                <option value="linux">Linux</option>
              </select>

              <select
                id="scriptLanguage"
                value={scriptLanguage}
                onChange={(e) => setScriptLanguage(e.target.value)}
                required
                disabled={!isCaseNumberValid || !hostOS}
                className="large-select"
              >
                <option value="">-- Script Type --</option>
                {getScriptLanguages().map(lang => (
                  <option key={lang.value} value={lang.value}>
                    {lang.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div data-guide="gandalf.hosts" className="form-row">
            <div className="form-group">
              <label htmlFor="hostnames">
                Hostname(s) (comma-separated)
              </label>
              <input
                type="text"
                id="hostnames"
                value={hostnames}
                onChange={(e) => setHostnames(e.target.value)}
                placeholder="e.g., workstation-01, laptop-02"
                disabled={!isCaseNumberValid}
              />
            </div>

            <div className="form-group">
              <label htmlFor="ipAddresses">
                IP Address(es) (comma-separated)
              </label>
              <input
                type="text"
                id="ipAddresses"
                value={ipAddresses}
                onChange={(e) => setIpAddresses(e.target.value)}
                placeholder="e.g., 192.168.1.100, 192.168.1.101"
                disabled={!isCaseNumberValid}
              />
            </div>
          </div>

          <div data-guide="gandalf.options" className="form-group">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <label style={{ margin: 0 }}>Collection Options</label>
              {isCaseNumberValid && (
                <button
                  type="button"
                  className="toggle-button"
                  onClick={toggleAllCollectionOptions}
                  style={{ padding: '0.3rem 0.8rem', fontSize: '0.85rem', minWidth: 'auto' }}
                >
                  Select All / Deselect All
                </button>
              )}
            </div>
            {ipValidationMessage && (
              <div className="validation-message invalid">
                {ipValidationMessage}
              </div>
            )}
            {hostValidationMessage && (
              <div className={`validation-message ${hostValidationMessage.includes('must match') ? 'invalid' : 'info'}`}>
                {hostValidationMessage}
              </div>
            )}
            {!isCaseNumberValid && (
              <div className="validation-message info">
                Please enter a valid case number to configure collection options.
              </div>
            )}
            {isCaseNumberValid && (
              <div className="checkbox-group" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
                {/* Row 1: Event Logs | Registry | WMI/WBEM | Volume Shadow Copies */}
                <div className={`checkbox-item ${!hostOS || hostOS !== 'windows' ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="eventlogs"
                    checked={collectionOptions.eventlogs || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, eventlogs: e.target.checked})}
                    disabled={!hostOS || hostOS !== 'windows'}
                  />
                  <label htmlFor="eventlogs">
                    <span>Event Logs</span>
                    <span><OSIcon os="windows" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS || hostOS !== 'windows' ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="registry"
                    checked={collectionOptions.registry || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, registry: e.target.checked})}
                    disabled={!hostOS || hostOS !== 'windows'}
                  />
                  <label htmlFor="registry">
                    <span>Registry</span>
                    <span><OSIcon os="windows" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS || hostOS !== 'windows' ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="wmi"
                    checked={collectionOptions.wmi || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, wmi: e.target.checked})}
                    disabled={!hostOS || hostOS !== 'windows'}
                  />
                  <label htmlFor="wmi">
                    <span>WMI/WBEM</span>
                    <span><OSIcon os="windows" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS || hostOS !== 'windows' ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="vss"
                    checked={collectionOptions.vss || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, vss: e.target.checked})}
                    disabled={!hostOS || hostOS !== 'windows'}
                  />
                  <label htmlFor="vss">
                    <span>Volume Shadow Copies</span>
                    <span><OSIcon os="windows" /></span>
                  </label>
                </div>

                {/* Spacing after Row 1 */}
                <div style={{ gridColumn: '1 / -1', height: '0.5rem' }}></div>

                {/* Row 2: $MFT/Journal | Scheduled Tasks/Cron | System Logs | Plists */}
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="mft"
                    checked={collectionOptions.mft || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, mft: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="mft">
                    <span>$MFT/Journal</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="scheduledtasks"
                    checked={collectionOptions.scheduledtasks || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, scheduledtasks: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="scheduledtasks">
                    <span>Scheduled Tasks/Cron</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS || hostOS === 'windows' ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="systemlogs"
                    checked={collectionOptions.systemlogs || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, systemlogs: e.target.checked})}
                    disabled={!hostOS || hostOS === 'windows'}
                  />
                  <label htmlFor="systemlogs">
                    <span>System Logs</span>
                    <span><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS || hostOS !== 'macos' ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="plists"
                    checked={collectionOptions.plists || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, plists: e.target.checked})}
                    disabled={!hostOS || hostOS !== 'macos'}
                  />
                  <label htmlFor="plists">
                    <span>Plists</span>
                    <span><OSIcon os="macos" /></span>
                  </label>
                </div>

                {/* Spacing after Row 2 */}
                <div style={{ gridColumn: '1 / -1', height: '0.5rem' }}></div>

                {/* Row 3: Browser Data | User Profiles | Trash | Temp */}
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="browser"
                    checked={collectionOptions.browser || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, browser: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="browser">
                    <span>Browser Data</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="userprofiles"
                    checked={collectionOptions.userprofiles || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, userprofiles: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="userprofiles">
                    <span>User Profiles</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="trash"
                    checked={collectionOptions.trash || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, trash: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="trash">
                    <span>Trash</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="temp"
                    checked={collectionOptions.temp || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, temp: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="temp">
                    <span>Temp</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>

                {/* Horizontal Divider */}
                <div style={{ gridColumn: '1 / -1', height: '1px', background: '#3f4b2a', margin: '0.25rem 0' }}></div>

                {/* Row 4: Hash Artifacts | Last Access Times | File Collection | <File Upload> */}
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="hash"
                    checked={collectionOptions.hash || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, hash: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="hash">
                    <span>Hash Artifacts</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`}>
                  <input
                    type="checkbox"
                    id="lastaccesstimes"
                    checked={collectionOptions.lastaccesstimes || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, lastaccesstimes: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="lastaccesstimes">
                    <span>Last Access Times</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <input
                    type="checkbox"
                    id="files"
                    checked={collectionOptions.files || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, files: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="files" style={{ margin: 0 }}>
                    <span>File Collection</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
                <div className="checkbox-item" style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem', pointerEvents: 'auto', opacity: collectionOptions.files ? 1 : 0.5 }}>
                  <input
                    type="file"
                    id="fileListUpload"
                    accept=".txt,.csv"
                    onChange={handleFileListUpload}
                    disabled={!collectionOptions.files}
                    style={{
                      width: '100%',
                      padding: '0.3rem',
                      borderRadius: '4px',
                      border: '1px solid #3f4b2a',
                      background: '#0e1009',
                      color: '#f0dba5',
                      fontSize: '0.85rem',
                      cursor: collectionOptions.files ? 'pointer' : 'not-allowed',
                      pointerEvents: collectionOptions.files ? 'auto' : 'none'
                    }}
                  />
                  {fileList && (
                    <span style={{ fontSize: '0.75rem', color: '#a7db6c' }}>
                      {fileList.split('\n').filter(f => f.trim()).length} file(s) listed
                    </span>
                  )}
                </div>

                {/* Horizontal Divider */}
                <div style={{ gridColumn: '1 / -1', height: '1px', background: '#3f4b2a', margin: '0.25rem 0' }}></div>

                {/* Row 5: Live Memory Capture | Memory Dump */}
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`} style={{ gridColumn: 'span 2' }}>
                  <input
                    type="checkbox"
                    id="livememory"
                    checked={collectionOptions.livememory || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, livememory: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="livememory">
                    <span>Live Memory Capture</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
                <div className={`checkbox-item ${!hostOS ? 'disabled' : ''}`} style={{ gridColumn: 'span 2' }}>
                  <input
                    type="checkbox"
                    id="memory"
                    checked={collectionOptions.memory || false}
                    onChange={(e) => setCollectionOptions({...collectionOptions, memory: e.target.checked})}
                    disabled={!hostOS}
                  />
                  <label htmlFor="memory">
                    <span>Memory Dump</span>
                    <span><OSIcon os="windows" /><OSIcon os="macos" /><OSIcon os="linux" /></span>
                  </label>
                </div>
              </div>
            )}
          </div>

          <div data-guide="gandalf.command" className="acquisition-actions">
            <div className="command-block-container">
              <div className="command-block-header">
                <label>Generated Command</label>
                <div className="command-header-actions">
                  <button
                    type="button"
                    className="toggle-button"
                    onClick={() => setUseLongSwitches(!useLongSwitches)}
                    title={useLongSwitches ? 'Switch to short switches' : 'Switch to long switches'}
                  >
                    {useLongSwitches ? 'Short' : 'Long'}
                  </button>
                  <button
                    type="submit"
                    className="copy-button"
                    disabled={loading || !isCaseNumberValid || !hostnames.trim() || !ipAddresses.trim() || !!ipValidationMessage}
                  >
                    {loading ? 'Starting Acquisition...' : 'Start Acquisition'}
                  </button>
                  <button
                    type="button"
                    className="copy-button"
                    onClick={copyCommand}
                    disabled={!command || command.includes('# Select')}
                    title="Copy to clipboard"
                  >
                    Copy
                  </button>
                </div>
              </div>
              <pre className="code-block command-preview command-preview-large">
                {command || '# Configure options above to generate command'}
              </pre>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}

export default NewAcquisition;
