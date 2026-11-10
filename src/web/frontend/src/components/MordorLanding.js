import React, { useState, useEffect } from 'react';
import MordorCatalog from './MordorCatalog';
import { getLocalMordorDatasets, refreshMordorCatalog, getMordorCatalog, downloadMordorDataset } from '../api';

// MITRE ATT&CK Tactic ID to Name mapping, for the OTRF datasets' own tags, which predate
// ATT&CK v20: their TA0005 is Defense Evasion, which v20 split into Stealth and Defense
// Impairment (the pinned v20.1 data gives those no TA numbers to map here)
const TACTIC_NAMES = {
  'TA0001': 'Initial Access',
  'TA0002': 'Execution',
  'TA0003': 'Persistence',
  'TA0004': 'Privilege Escalation',
  'TA0005': 'Defense Evasion (now Stealth, Defense Impairment)',
  'TA0006': 'Credential Access',
  'TA0007': 'Discovery',
  'TA0008': 'Lateral Movement',
  'TA0009': 'Collection',
  'TA0010': 'Exfiltration',
  'TA0011': 'Command and Control',
  'TA0040': 'Impact',
  'TA0042': 'Resource Development',
  'TA0043': 'Reconnaissance',
};

// The Mordor page's last section (components/MordorTelemetry.js): the OTRF catalogue to download from
const MordorLanding = () => {
  const [localCount, setLocalCount] = useState(0);
  const [search, setSearch] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [catalogKey, setCatalogKey] = useState(0);
  const [showDownloadedOnly, setShowDownloadedOnly] = useState(false);
  const [platform, setPlatform] = useState('');
  const [tactic, setTactic] = useState('');
  const [tacticName, setTacticName] = useState('');
  const [technique, setTechnique] = useState('');
  const [stats, setStats] = useState({ platforms: {}, tactics: {}, techniques: {} });
  const [selectedDatasets, setSelectedDatasets] = useState([]);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    loadLocalCount();
    loadStats();
    const interval = setInterval(loadLocalCount, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadStats = async () => {
    try {
      const result = await getMordorCatalog({ limit: 200 });
      // Collect techniques from all datasets
      const techniques = {};
      (result.datasets || []).forEach(ds => {
        (ds.techniques || []).forEach(t => {
          techniques[t] = (techniques[t] || 0) + 1;
        });
      });
      setStats({
        platforms: result.platforms || {},
        tactics: result.tactics || {},
        techniques
      });
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  };

  const loadLocalCount = async () => {
    try {
      const result = await getLocalMordorDatasets({ limit: 1 });
      setLocalCount(result.total);
    } catch (err) {
      console.error('Failed to load local dataset count:', err);
    }
  };

  const handleRefresh = async () => {
    try {
      setRefreshing(true);
      await refreshMordorCatalog(true);
      setCatalogKey(prev => prev + 1);
    } catch (err) {
      console.error('Failed to refresh catalog:', err);
    } finally {
      setRefreshing(false);
    }
  };

  const handleBulkDownload = async () => {
    try {
      setDownloading(true);
      for (const datasetId of selectedDatasets) {
        await downloadMordorDataset(datasetId);
      }
      setSelectedDatasets([]);
      setCatalogKey(prev => prev + 1);
      loadLocalCount();
    } catch (err) {
      console.error('Failed to download datasets:', err);
    } finally {
      setDownloading(false);
    }
  };

  const toggleStyle = (isActive) => ({
    padding: '0.75rem 1.5rem',
    background: isActive
      ? 'rgba(102, 217, 239, 0.3)'
      : 'rgba(240, 219, 165, 0.1)',
    border: isActive
      ? '1px solid rgba(102, 217, 239, 0.5)'
      : '1px solid rgba(240, 219, 165, 0.2)',
    borderRadius: '4px',
    color: isActive ? '#66d9ef' : '#f0dba5',
    cursor: 'pointer',
    fontFamily: "'Cinzel', 'Times New Roman', serif",
    fontSize: '1rem',
    transition: 'all 0.3s ease'
  });

  return (
    <div className="card" id="datasets">
      <h2>Downloadable datasets</h2>
      <p className="lab-note">
        The OTRF Security-Datasets catalogue, for the raw events: download a dataset and Elrond analyses it
        (<code>python elrond.py CASE001 /tmp/elrond/output/mordor/SDWIN-xxx --Mordor</code>, or from the Elrond page).
        It includes the datasets that span several techniques (APT29's days), and bulk download.
      </p>
      <div>
        {/* Row 1: Buttons and Search */}
        <div style={{
          display: 'flex',
          gap: '0.75rem',
          marginBottom: '0.75rem',
          alignItems: 'center'
        }}>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            style={{
              padding: '0.75rem 1.25rem',
              background: 'rgba(107, 142, 63, 0.3)',
              border: '1px solid #6b8e3f',
              borderRadius: '4px',
              color: '#a7db6c',
              cursor: refreshing ? 'wait' : 'pointer',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1rem',
              transition: 'all 0.3s ease',
              whiteSpace: 'nowrap'
            }}
          >
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
          <button
            onClick={handleBulkDownload}
            disabled={selectedDatasets.length === 0 || downloading}
            style={{
              padding: '0.75rem 1.25rem',
              background: selectedDatasets.length > 0 ? 'rgba(102, 217, 239, 0.3)' : 'rgba(102, 217, 239, 0.1)',
              border: selectedDatasets.length > 0 ? '1px solid #5ac8d8' : '1px solid rgba(90, 200, 216, 0.3)',
              borderRadius: '4px',
              color: selectedDatasets.length > 0 ? '#66d9ef' : 'rgba(102, 217, 239, 0.4)',
              cursor: selectedDatasets.length > 0 && !downloading ? 'pointer' : 'not-allowed',
              fontFamily: "'Cinzel', 'Times New Roman', serif",
              fontSize: '1rem',
              transition: 'all 0.3s ease',
              whiteSpace: 'nowrap',
              opacity: selectedDatasets.length > 0 ? 1 : 0.5
            }}
          >
            {downloading ? 'Downloading...' : `Download Selected (${selectedDatasets.length})`}
          </button>
          <button
            onClick={() => setShowDownloadedOnly(!showDownloadedOnly)}
            style={{ ...toggleStyle(showDownloadedOnly), whiteSpace: 'nowrap' }}
          >
            Downloaded ({localCount})
          </button>
          <input
            type="text"
            placeholder="Search datasets..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ flex: 1, minWidth: '100px' }}
          />
        </div>

        {/* Row 2: Filter Dropdowns */}
        <div style={{
          display: 'flex',
          gap: '0.75rem',
          marginBottom: '1.5rem',
          borderBottom: '1px solid rgba(240, 219, 165, 0.2)',
          paddingBottom: '1rem',
          alignItems: 'center'
        }}>
          <select
            className="large-select"
            value={platform}
            onChange={(e) => setPlatform(e.target.value)}
            style={{ flex: 1 }}
          >
            <option value="">All Platforms</option>
            {Object.entries(stats.platforms).map(([p, count]) => (
              <option key={p} value={p}>{p} ({count})</option>
            ))}
          </select>
          <select
            className="large-select"
            value={tactic}
            onChange={(e) => { setTactic(e.target.value); setTacticName(''); }}
            style={{ flex: 1 }}
          >
            <option value="">All Tactic IDs</option>
            {Object.entries(stats.tactics).sort().map(([t, count]) => (
              <option key={t} value={t}>{t} ({count})</option>
            ))}
          </select>
          <select
            className="large-select"
            value={tacticName}
            onChange={(e) => {
              setTacticName(e.target.value);
              // Find matching tactic ID for the selected name
              const tacticId = Object.entries(TACTIC_NAMES).find(([id, name]) => name === e.target.value)?.[0] || '';
              setTactic(tacticId);
            }}
            style={{ flex: 1 }}
          >
            <option value="">All Tactic Names</option>
            {Object.entries(TACTIC_NAMES)
              .filter(([id]) => stats.tactics[id])
              .sort((a, b) => a[1].localeCompare(b[1]))
              .map(([id, name]) => (
                <option key={id} value={name}>{name} ({stats.tactics[id] || 0})</option>
              ))}
          </select>
          <select
            className="large-select"
            value={technique}
            onChange={(e) => setTechnique(e.target.value)}
            style={{ flex: 1 }}
          >
            <option value="">All Techniques</option>
            {Object.entries(stats.techniques).sort().map(([t, count]) => (
              <option key={t} value={t}>{t} ({count})</option>
            ))}
          </select>
        </div>

        {/* Catalog Content */}
        <MordorCatalog
          key={catalogKey}
          onDownloadComplete={loadLocalCount}
          search={search}
          showDownloadedOnly={showDownloadedOnly}
          platform={platform}
          tactic={tactic}
          technique={technique}
          selectedDatasets={selectedDatasets}
          setSelectedDatasets={setSelectedDatasets}
        />
      </div>
    </div>
  );
};

export default MordorLanding;
