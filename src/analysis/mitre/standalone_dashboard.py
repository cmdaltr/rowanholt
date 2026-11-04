"""
MITRE ATT&CK Standalone Dashboard Generator

Generates interactive HTML dashboards without requiring SIEM.
Complete offline dashboard with ATT&CK matrix, timeline, and evidence browser.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .attck_updater import MitreAttackUpdater


class StandaloneDashboard:
    """
    Generate interactive standalone HTML dashboard.

    Features:
    - Interactive ATT&CK matrix heatmap
    - Technique timeline view
    - Evidence browser with search
    - Coverage statistics
    - Export capabilities
    - No server required (single HTML file)
    """

    def __init__(self, updater: Optional[MitreAttackUpdater] = None):
        """
        Initialize dashboard generator.

        Args:
            updater: MitreAttackUpdater instance (creates new if not provided)
        """
        self.updater = updater or MitreAttackUpdater()
        self.attck_data = self.updater.load_cached_data()

    def generate_html(self, coverage_data: dict, output_file: str) -> str:
        """
        Generate complete HTML dashboard.

        Args:
            coverage_data: Coverage report data from MitreCoverageAnalyzer
            output_file: Output file path

        Returns:
            Path to generated HTML file
        """
        html = self._get_html_template()

        # Inject data and components
        html = html.replace("{{COVERAGE_DATA}}", json.dumps(coverage_data))
        html = html.replace("{{CASE_ID}}", coverage_data.get("case_id", "Unknown"))
        html = html.replace(
            "{{TIMESTAMP}}", coverage_data.get("timestamp", datetime.utcnow().isoformat())
        )
        html = html.replace("{{ATTCK_VERSION}}", coverage_data.get("attck_version", "unknown"))

        # Write to file
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

        return output_file

    def _get_html_template(self) -> str:
        """Get HTML template with embedded JavaScript."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MITRE ATT&CK Coverage - {{CASE_ID}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f5f5;
            color: #333;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .header .meta {
            opacity: 0.9;
            font-size: 0.9rem;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .stat-card .label {
            color: #666;
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }

        .stat-card .subvalue {
            color: #999;
            font-size: 0.875rem;
            margin-top: 0.25rem;
        }

        .tabs {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .tab-buttons {
            display: flex;
            border-bottom: 1px solid #e0e0e0;
        }

        .tab-button {
            padding: 1rem 2rem;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            color: #666;
            transition: all 0.3s;
            border-bottom: 3px solid transparent;
        }

        .tab-button:hover {
            background: #f5f5f5;
        }

        .tab-button.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }

        .tab-content {
            display: none;
            padding: 2rem;
        }

        .tab-content.active {
            display: block;
        }

        .search-box {
            margin-bottom: 1.5rem;
        }

        .search-box input {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 1rem;
        }

        .techniques-table {
            width: 100%;
            border-collapse: collapse;
        }

        .techniques-table th {
            background: #f5f5f5;
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #e0e0e0;
        }

        .techniques-table td {
            padding: 0.75rem;
            border-bottom: 1px solid #e0e0e0;
        }

        .techniques-table tbody tr:hover {
            background: #f9f9f9;
            cursor: pointer;
        }

        .confidence-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.875rem;
            font-weight: 500;
        }

        .confidence-high {
            background: #4caf50;
            color: white;
        }

        .confidence-medium {
            background: #ff9800;
            color: white;
        }

        .confidence-low {
            background: #f44336;
            color: white;
        }

        .tactic-tag {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            background: #e3f2fd;
            color: #1976d2;
            border-radius: 4px;
            font-size: 0.75rem;
            margin-right: 0.25rem;
            margin-bottom: 0.25rem;
        }

        .evidence-list {
            list-style: none;
        }

        .evidence-item {
            background: #f9f9f9;
            padding: 1rem;
            border-left: 4px solid #667eea;
            margin-bottom: 1rem;
            border-radius: 4px;
        }

        .evidence-item .path {
            font-family: monospace;
            font-size: 0.875rem;
            color: #666;
            margin-bottom: 0.5rem;
        }

        .evidence-item .details {
            font-size: 0.875rem;
            color: #999;
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }

        .modal.active {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            max-width: 800px;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #e0e0e0;
        }

        .modal-header h2 {
            color: #667eea;
        }

        .close-btn {
            background: none;
            border: none;
            font-size: 1.5rem;
            cursor: pointer;
            color: #999;
        }

        .close-btn:hover {
            color: #333;
        }

        .export-buttons {
            margin-top: 1.5rem;
            display: flex;
            gap: 1rem;
        }

        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.3s;
        }

        .btn-primary {
            background: #667eea;
            color: white;
        }

        .btn-primary:hover {
            background: #5568d3;
        }

        .btn-secondary {
            background: #e0e0e0;
            color: #333;
        }

        .btn-secondary:hover {
            background: #d0d0d0;
        }

        .timeline {
            position: relative;
            padding-left: 2rem;
        }

        .timeline-item {
            position: relative;
            padding-bottom: 2rem;
        }

        .timeline-item::before {
            content: '';
            position: absolute;
            left: -2rem;
            top: 0;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #667eea;
            border: 3px solid white;
            box-shadow: 0 0 0 2px #667eea;
        }

        .timeline-item::after {
            content: '';
            position: absolute;
            left: -1.69rem;
            top: 12px;
            width: 2px;
            height: calc(100% - 12px);
            background: #e0e0e0;
        }

        .timeline-item:last-child::after {
            display: none;
        }

        .timeline-content {
            background: white;
            padding: 1rem;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .timeline-time {
            color: #999;
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ MITRE ATT&CK Coverage Analysis</h1>
        <div class="meta">
            Case: <strong>{{CASE_ID}}</strong> |
            Generated: <strong>{{TIMESTAMP}}</strong> |
            ATT&CK Version: <strong>{{ATTCK_VERSION}}</strong>
        </div>
    </div>

    <div class="container">
        <!-- Statistics Cards -->
        <div class="stats-grid" id="statsGrid"></div>

        <!-- Tabs -->
        <div class="tabs">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="switchTab('techniques')">Techniques</button>
                <button class="tab-button" onclick="switchTab('tactics')">Tactics Summary</button>
                <button class="tab-button" onclick="switchTab('timeline')">Timeline</button>
                <button class="tab-button" onclick="switchTab('evidence')">Evidence Map</button>
                <button class="tab-button" onclick="switchTab('export')">Export</button>
            </div>

            <!-- Techniques Tab -->
            <div id="techniques-tab" class="tab-content active">
                <div class="search-box">
                    <input type="text" id="techniqueSearch" placeholder="Search techniques..." onkeyup="searchTechniques()">
                </div>
                <table class="techniques-table">
                    <thead>
                        <tr>
                            <th>Technique ID</th>
                            <th>Name</th>
                            <th>Tactics</th>
                            <th>Confidence</th>
                            <th>Detections</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody id="techniquesTableBody"></tbody>
                </table>
            </div>

            <!-- Tactics Tab -->
            <div id="tactics-tab" class="tab-content">
                <div id="tacticsSummary"></div>
            </div>

            <!-- Timeline Tab -->
            <div id="timeline-tab" class="tab-content">
                <div class="timeline" id="timeline"></div>
            </div>

            <!-- Evidence Tab -->
            <div id="evidence-tab" class="tab-content">
                <div class="search-box">
                    <input type="text" id="evidenceSearch" placeholder="Search evidence..." onkeyup="searchEvidence()">
                </div>
                <ul class="evidence-list" id="evidenceList"></ul>
            </div>

            <!-- Export Tab -->
            <div id="export-tab" class="tab-content">
                <h2>Export Options</h2>
                <p>Download coverage data in various formats:</p>
                <div class="export-buttons">
                    <button class="btn btn-primary" onclick="exportJSON()">Export JSON</button>
                    <button class="btn btn-primary" onclick="exportCSV()">Export CSV</button>
                    <button class="btn btn-primary" onclick="exportNavigator()">Export Navigator</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Technique Detail Modal -->
    <div id="techniqueModal" class="modal" onclick="closeModal()">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h2 id="modalTitle"></h2>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div id="modalBody"></div>
        </div>
    </div>

    <script>
        // Coverage data injected from Python
        const coverageData = {{COVERAGE_DATA}};

        // Initialize dashboard
        function init() {
            renderStats();
            renderTechniques();
            renderTactics();
            renderTimeline();
            renderEvidence();
        }

        // Render statistics cards
        function renderStats() {
            const stats = coverageData.statistics;
            const html = `
                <div class="stat-card">
                    <div class="label">Coverage</div>
                    <div class="value">${stats.coverage_percentage.toFixed(1)}%</div>
                    <div class="subvalue">${stats.detected_techniques} / ${stats.total_techniques} techniques</div>
                </div>
                <div class="stat-card">
                    <div class="label">High Confidence</div>
                    <div class="value">${stats.confidence_distribution.high}</div>
                    <div class="subvalue">≥ 0.8 confidence</div>
                </div>
                <div class="stat-card">
                    <div class="label">Medium Confidence</div>
                    <div class="value">${stats.confidence_distribution.medium}</div>
                    <div class="subvalue">0.5 - 0.8 confidence</div>
                </div>
                <div class="stat-card">
                    <div class="label">Artifacts Processed</div>
                    <div class="value">${stats.total_artifacts}</div>
                    <div class="subvalue">${stats.tactics_with_coverage} / ${stats.total_tactics} tactics</div>
                </div>
            `;
            document.getElementById('statsGrid').innerHTML = html;
        }

        // Render techniques table
        function renderTechniques() {
            const tbody = document.getElementById('techniquesTableBody');
            let html = '';

            coverageData.techniques.forEach(tech => {
                const confClass = tech.confidence >= 0.8 ? 'high' : tech.confidence >= 0.5 ? 'medium' : 'low';
                const tactics = tech.tactics.map(t => `<span class="tactic-tag">${t}</span>`).join('');

                html += `
                    <tr onclick="showTechniqueDetail('${tech.technique_id}')">
                        <td><strong>${tech.technique_id}</strong></td>
                        <td>${tech.technique_name}</td>
                        <td>${tactics}</td>
                        <td><span class="confidence-badge confidence-${confClass}">${tech.confidence.toFixed(2)}</span></td>
                        <td>${tech.detection_count}</td>
                        <td>${tech.evidence.length}</td>
                    </tr>
                `;
            });

            tbody.innerHTML = html;
        }

        // Render tactics summary
        function renderTactics() {
            const summary = coverageData.tactics_summary;
            let html = '<div class="techniques-table"><table><thead><tr><th>Tactic</th><th>Technique Count</th><th>Techniques</th></tr></thead><tbody>';

            Object.keys(summary).sort().forEach(tactic => {
                const data = summary[tactic];
                html += `
                    <tr>
                        <td><strong>${tactic}</strong></td>
                        <td>${data.count}</td>
                        <td>${data.techniques.join(', ')}</td>
                    </tr>
                `;
            });

            html += '</tbody></table></div>';
            document.getElementById('tacticsSummary').innerHTML = html;
        }

        // Render timeline
        function renderTimeline() {
            const timeline = document.getElementById('timeline');
            let html = '';

            // Sort techniques by first seen
            const sorted = [...coverageData.techniques].sort((a, b) =>
                new Date(a.first_seen) - new Date(b.first_seen)
            );

            sorted.forEach(tech => {
                const time = new Date(tech.first_seen).toLocaleString();
                html += `
                    <div class="timeline-item">
                        <div class="timeline-content">
                            <div class="timeline-time">${time}</div>
                            <strong>${tech.technique_id}: ${tech.technique_name}</strong>
                            <div style="margin-top: 0.5rem;">
                                Confidence: <span class="confidence-badge confidence-${tech.confidence >= 0.8 ? 'high' : tech.confidence >= 0.5 ? 'medium' : 'low'}">${tech.confidence.toFixed(2)}</span>
                            </div>
                        </div>
                    </div>
                `;
            });

            timeline.innerHTML = html;
        }

        // Render evidence map
        function renderEvidence() {
            const list = document.getElementById('evidenceList');
            let html = '';

            Object.keys(coverageData.evidence_map).forEach(path => {
                const techniques = coverageData.evidence_map[path];
                html += `
                    <li class="evidence-item">
                        <div class="path">${path}</div>
                        <div class="details">
                            ${techniques.length} technique(s) detected:
                            ${techniques.map(t => `${t.technique_id} (${t.confidence.toFixed(2)})`).join(', ')}
                        </div>
                    </li>
                `;
            });

            list.innerHTML = html;
        }

        // Show technique detail modal
        function showTechniqueDetail(techId) {
            const tech = coverageData.techniques.find(t => t.technique_id === techId);
            if (!tech) return;

            document.getElementById('modalTitle').textContent = `${tech.technique_id}: ${tech.technique_name}`;

            let html = `
                <p><strong>Tactics:</strong> ${tech.tactics.join(', ')}</p>
                <p><strong>Confidence:</strong> ${tech.confidence.toFixed(2)}</p>
                <p><strong>Detection Count:</strong> ${tech.detection_count}</p>
                <p><strong>First Seen:</strong> ${new Date(tech.first_seen).toLocaleString()}</p>
                <p><strong>Last Seen:</strong> ${new Date(tech.last_seen).toLocaleString()}</p>
                <h3 style="margin-top: 1.5rem;">Evidence (${tech.evidence.length})</h3>
                <ul class="evidence-list">
            `;

            tech.evidence.forEach(ev => {
                html += `
                    <li class="evidence-item">
                        <div class="path">${ev.artifact_path}</div>
                        <div class="details">
                            Type: ${ev.artifact_type} |
                            Time: ${new Date(ev.timestamp).toLocaleString()} |
                            Confidence: ${ev.confidence.toFixed(2)}
                            ${ev.context ? `<br>Context: ${ev.context}` : ''}
                        </div>
                    </li>
                `;
            });

            html += '</ul>';
            document.getElementById('modalBody').innerHTML = html;
            document.getElementById('techniqueModal').classList.add('active');
        }

        // Close modal
        function closeModal() {
            document.getElementById('techniqueModal').classList.remove('active');
        }

        // Switch tabs
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });

            // Show selected tab
            document.getElementById(`${tabName}-tab`).classList.add('active');
            event.target.classList.add('active');
        }

        // Search techniques
        function searchTechniques() {
            const query = document.getElementById('techniqueSearch').value.toLowerCase();
            const rows = document.querySelectorAll('#techniquesTableBody tr');

            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(query) ? '' : 'none';
            });
        }

        // Search evidence
        function searchEvidence() {
            const query = document.getElementById('evidenceSearch').value.toLowerCase();
            const items = document.querySelectorAll('.evidence-item');

            items.forEach(item => {
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(query) ? '' : 'none';
            });
        }

        // Export functions
        function exportJSON() {
            const dataStr = JSON.stringify(coverageData, null, 2);
            const blob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${coverageData.case_id}_coverage.json`;
            a.click();
        }

        function exportCSV() {
            let csv = 'Technique ID,Technique Name,Tactics,Confidence,Detection Count,Evidence Count\\n';

            coverageData.techniques.forEach(tech => {
                csv += `"${tech.technique_id}","${tech.technique_name}","${tech.tactics.join('; ')}",${tech.confidence},${tech.detection_count},${tech.evidence.length}\\n`;
            });

            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${coverageData.case_id}_techniques.csv`;
            a.click();
        }

        function exportNavigator() {
            // Generate ATT&CK Navigator layer
            const layer = {
                name: coverageData.case_id,
                versions: {
                    attack: coverageData.attck_version,
                    navigator: "4.8.0",
                    layer: "4.3"
                },
                domain: "enterprise-attack",
                description: `Coverage analysis for ${coverageData.case_id}`,
                techniques: coverageData.techniques.map(tech => ({
                    techniqueID: tech.technique_id,
                    score: Math.round(tech.confidence * 100),
                    color: tech.confidence >= 0.8 ? "#2ecc71" : tech.confidence >= 0.5 ? "#f39c12" : "#e74c3c",
                    comment: `Detections: ${tech.detection_count}`
                }))
            };

            const dataStr = JSON.stringify(layer, null, 2);
            const blob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${coverageData.case_id}_navigator.json`;
            a.click();
        }

        // Initialize on load
        window.onload = init;
    </script>
</body>
</html>"""


# Convenience function


def generate_standalone_dashboard(coverage_data: dict, output_file: str) -> str:
    """
    Convenience function to generate standalone dashboard.

    Args:
        coverage_data: Coverage report from MitreCoverageAnalyzer
        output_file: Output HTML file path

    Returns:
        Path to generated HTML file
    """
    dashboard = StandaloneDashboard()
    return dashboard.generate_html(coverage_data, output_file)
