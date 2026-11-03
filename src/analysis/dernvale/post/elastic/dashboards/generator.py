#!/usr/bin/env python3 -tt
"""
Kibana Dashboard Generator for Elrond DFIR

Generates Kibana/OpenSearch dashboards equivalent to the Splunk dashboards,
including MITRE ATT&CK technique dashboards, overview panels, and analysis views.
"""

import json
import os
import uuid
from datetime import datetime

from .techniques import (
    TECHNIQUES,
    get_technique_by_id,
    get_techniques_by_tactic,
    get_all_tactics,
    get_parent_techniques,
)


def generate_uuid():
    """Generate a unique ID for Kibana saved objects."""
    return str(uuid.uuid4())


def generate_mitre_overview_dashboard(case_name, index_pattern):
    """
    Generate the main MITRE ATT&CK overview dashboard.

    Args:
        case_name: The case/index name
        index_pattern: The Elasticsearch index pattern

    Returns:
        dict containing the Kibana dashboard definition
    """
    dashboard_id = f"mitre-overview-{case_name}"

    # Create visualization panels
    panels = []

    # Panel 1: Technique Distribution Pie Chart
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "panel_0"},
        "panelIndex": "panel_0",
        "embeddableConfig": {
            "attributes": {
                "title": "MITRE ATT&CK Technique Distribution",
                "description": "Distribution of detected techniques",
                "visualizationType": "lnsPie",
                "state": {
                    "visualization": {
                        "shape": "donut",
                        "layers": [{
                            "layerId": "layer1",
                            "primaryGroups": ["mitre_technique_id"],
                            "metrics": ["count"],
                            "numberDisplay": "percent",
                            "categoryDisplay": "default",
                            "legendDisplay": "default"
                        }]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                "layer1": {
                                    "columns": {
                                        "mitre_technique_id": {
                                            "label": "Technique",
                                            "dataType": "string",
                                            "operationType": "terms",
                                            "sourceField": "mitre_technique_id.keyword",
                                            "params": {"size": 20, "orderBy": {"type": "column", "columnId": "count"}, "orderDirection": "desc"}
                                        },
                                        "count": {
                                            "label": "Count",
                                            "dataType": "number",
                                            "operationType": "count",
                                            "isBucketed": False
                                        }
                                    },
                                    "columnOrder": ["mitre_technique_id", "count"]
                                }
                            }
                        }
                    }
                },
                "references": [{"type": "index-pattern", "id": index_pattern, "name": "indexpattern-datasource-layer-layer1"}]
            }
        }
    })

    # Panel 2: Timeline of Technique Activity
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 24, "y": 0, "w": 24, "h": 15, "i": "panel_1"},
        "panelIndex": "panel_1",
        "embeddableConfig": {
            "attributes": {
                "title": "Technique Activity Timeline",
                "description": "Timeline of MITRE ATT&CK technique detections",
                "visualizationType": "lnsXY",
                "state": {
                    "visualization": {
                        "legend": {"isVisible": True, "position": "right"},
                        "valueLabels": "hide",
                        "preferredSeriesType": "bar_stacked",
                        "layers": [{
                            "layerId": "layer1",
                            "accessors": ["count"],
                            "position": "top",
                            "seriesType": "bar_stacked",
                            "showGridlines": False,
                            "xAccessor": "@timestamp",
                            "splitAccessor": "mitre_technique_id"
                        }]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": []
                },
                "references": [{"type": "index-pattern", "id": index_pattern, "name": "indexpattern-datasource-layer-layer1"}]
            }
        }
    })

    # Panel 3: Tactic Breakdown
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 15, "w": 16, "h": 12, "i": "panel_2"},
        "panelIndex": "panel_2",
        "embeddableConfig": {
            "attributes": {
                "title": "Tactics Breakdown",
                "visualizationType": "lnsXY",
                "state": {
                    "visualization": {
                        "legend": {"isVisible": True},
                        "preferredSeriesType": "bar_horizontal",
                        "layers": [{
                            "layerId": "layer1",
                            "accessors": ["count"],
                            "seriesType": "bar_horizontal",
                            "xAccessor": "tactic"
                        }]
                    }
                },
                "references": [{"type": "index-pattern", "id": index_pattern, "name": "indexpattern-datasource-layer-layer1"}]
            }
        }
    })

    # Panel 4: Top Hosts with Detections
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 16, "y": 15, "w": 16, "h": 12, "i": "panel_3"},
        "panelIndex": "panel_3",
        "embeddableConfig": {
            "attributes": {
                "title": "Top Hosts with Detections",
                "visualizationType": "lnsDatatable",
                "state": {
                    "visualization": {
                        "columns": [
                            {"columnId": "hostname", "isTransposed": False},
                            {"columnId": "count", "isTransposed": False}
                        ],
                        "layerId": "layer1",
                        "layerType": "data"
                    }
                },
                "references": [{"type": "index-pattern", "id": index_pattern, "name": "indexpattern-datasource-layer-layer1"}]
            }
        }
    })

    # Panel 5: Unique Techniques Count (Metric)
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 32, "y": 15, "w": 8, "h": 6, "i": "panel_4"},
        "panelIndex": "panel_4",
        "embeddableConfig": {
            "attributes": {
                "title": "Unique Techniques",
                "visualizationType": "lnsMetric",
                "state": {
                    "visualization": {
                        "layerId": "layer1",
                        "layerType": "data",
                        "metricAccessor": "unique_techniques"
                    }
                },
                "references": [{"type": "index-pattern", "id": index_pattern, "name": "indexpattern-datasource-layer-layer1"}]
            }
        }
    })

    # Panel 6: Total Events Count (Metric)
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 40, "y": 15, "w": 8, "h": 6, "i": "panel_5"},
        "panelIndex": "panel_5",
        "embeddableConfig": {
            "attributes": {
                "title": "Total Events",
                "visualizationType": "lnsMetric",
                "state": {
                    "visualization": {
                        "layerId": "layer1",
                        "layerType": "data",
                        "metricAccessor": "total_count"
                    }
                },
                "references": [{"type": "index-pattern", "id": index_pattern, "name": "indexpattern-datasource-layer-layer1"}]
            }
        }
    })

    # Panel 7: Events Data Table
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 27, "w": 48, "h": 20, "i": "panel_6"},
        "panelIndex": "panel_6",
        "embeddableConfig": {
            "attributes": {
                "title": "Recent MITRE ATT&CK Events",
                "visualizationType": "lnsDatatable",
                "state": {
                    "visualization": {
                        "columns": [
                            {"columnId": "@timestamp"},
                            {"columnId": "hostname"},
                            {"columnId": "mitre_technique_id"},
                            {"columnId": "artefact"},
                            {"columnId": "_source"}
                        ],
                        "layerId": "layer1",
                        "layerType": "data",
                        "paging": {"size": 25, "enabled": True}
                    }
                },
                "references": [{"type": "index-pattern", "id": index_pattern, "name": "indexpattern-datasource-layer-layer1"}]
            }
        }
    })

    dashboard = {
        "id": dashboard_id,
        "type": "dashboard",
        "attributes": {
            "title": f"MITRE ATT&CK Overview - {case_name}",
            "description": "Overview of MITRE ATT&CK technique detections for forensic analysis",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({
                "useMargins": True,
                "syncColors": False,
                "syncCursor": True,
                "syncTooltips": False,
                "hidePanelTitles": False
            }),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-90d",
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [
            {"name": "indexpattern-datasource-layer-layer1", "type": "index-pattern", "id": index_pattern}
        ]
    }

    return dashboard


def generate_technique_dashboard(technique_id, case_name, index_pattern):
    """
    Generate a dashboard for a specific MITRE ATT&CK technique.

    Args:
        technique_id: The MITRE technique ID (e.g., 'T1059')
        case_name: The case/index name
        index_pattern: The Elasticsearch index pattern

    Returns:
        dict containing the Kibana dashboard definition
    """
    technique_info = get_technique_by_id(technique_id)
    if not technique_info:
        return None

    technique_name = technique_info.get("name", "Unknown Technique")
    tactic = technique_info.get("tactic", "Unknown Tactic")
    parent = technique_info.get("parent")

    dashboard_id = f"technique-{technique_id.lower()}-{case_name}"

    panels = []

    # Panel 0: Technique Info (Markdown)
    technique_description = f"""
## {technique_name} ({technique_id})

**Tactic:** {tactic}
{"**Parent Technique:** " + parent if parent else ""}

[View on MITRE ATT&CK](https://attack.mitre.org/techniques/{technique_id.replace('.', '/')})
"""

    panels.append({
        "version": "8.11.0",
        "type": "visualization",
        "gridData": {"x": 0, "y": 0, "w": 48, "h": 6, "i": "panel_info"},
        "panelIndex": "panel_info",
        "embeddableConfig": {
            "savedVis": {
                "title": f"{technique_id} - {technique_name}",
                "description": "",
                "type": "markdown",
                "params": {
                    "markdown": technique_description,
                    "openLinksInNewTab": True,
                    "fontSize": 12
                }
            }
        }
    })

    # Panel 1: Events Over Time
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 6, "w": 32, "h": 12, "i": "panel_0"},
        "panelIndex": "panel_0",
        "embeddableConfig": {
            "attributes": {
                "title": f"Events Timeline - {technique_id}",
                "visualizationType": "lnsXY",
                "state": {
                    "visualization": {
                        "legend": {"isVisible": True, "position": "right"},
                        "preferredSeriesType": "bar",
                        "layers": [{
                            "layerId": "layer1",
                            "accessors": ["count"],
                            "seriesType": "bar",
                            "xAccessor": "@timestamp",
                            "splitAccessor": "hostname"
                        }]
                    },
                    "query": {"query": f'mitre_technique_id:"{technique_id}"', "language": "kuery"},
                    "filters": []
                }
            }
        }
    })

    # Panel 2: Event Count Metric
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 32, "y": 6, "w": 8, "h": 6, "i": "panel_1"},
        "panelIndex": "panel_1",
        "embeddableConfig": {
            "attributes": {
                "title": "Total Events",
                "visualizationType": "lnsMetric",
                "state": {
                    "query": {"query": f'mitre_technique_id:"{technique_id}"', "language": "kuery"}
                }
            }
        }
    })

    # Panel 3: Unique Hosts Metric
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 40, "y": 6, "w": 8, "h": 6, "i": "panel_2"},
        "panelIndex": "panel_2",
        "embeddableConfig": {
            "attributes": {
                "title": "Unique Hosts",
                "visualizationType": "lnsMetric",
                "state": {
                    "query": {"query": f'mitre_technique_id:"{technique_id}"', "language": "kuery"}
                }
            }
        }
    })

    # Panel 4: Host Distribution
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 32, "y": 12, "w": 16, "h": 6, "i": "panel_3"},
        "panelIndex": "panel_3",
        "embeddableConfig": {
            "attributes": {
                "title": "Events by Host",
                "visualizationType": "lnsPie",
                "state": {
                    "visualization": {
                        "shape": "donut",
                        "layers": [{
                            "layerId": "layer1",
                            "primaryGroups": ["hostname"],
                            "metrics": ["count"]
                        }]
                    },
                    "query": {"query": f'mitre_technique_id:"{technique_id}"', "language": "kuery"}
                }
            }
        }
    })

    # Panel 5: Artefact Types
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 18, "w": 24, "h": 10, "i": "panel_4"},
        "panelIndex": "panel_4",
        "embeddableConfig": {
            "attributes": {
                "title": "Artefact Types",
                "visualizationType": "lnsXY",
                "state": {
                    "visualization": {
                        "preferredSeriesType": "bar_horizontal",
                        "layers": [{
                            "layerId": "layer1",
                            "accessors": ["count"],
                            "seriesType": "bar_horizontal",
                            "xAccessor": "artefact"
                        }]
                    },
                    "query": {"query": f'mitre_technique_id:"{technique_id}"', "language": "kuery"}
                }
            }
        }
    })

    # Panel 6: Data Table
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 28, "w": 48, "h": 20, "i": "panel_5"},
        "panelIndex": "panel_5",
        "embeddableConfig": {
            "attributes": {
                "title": f"Event Details - {technique_id}",
                "visualizationType": "lnsDatatable",
                "state": {
                    "visualization": {
                        "columns": [
                            {"columnId": "@timestamp"},
                            {"columnId": "hostname"},
                            {"columnId": "artefact"},
                            {"columnId": "_source"}
                        ],
                        "layerId": "layer1",
                        "paging": {"size": 50, "enabled": True}
                    },
                    "query": {"query": f'mitre_technique_id:"{technique_id}"', "language": "kuery"}
                }
            }
        }
    })

    dashboard = {
        "id": dashboard_id,
        "type": "dashboard",
        "attributes": {
            "title": f"{technique_id}: {technique_name} - {case_name}",
            "description": f"Dashboard for MITRE ATT&CK technique {technique_id} ({technique_name}) - {tactic}",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({
                "useMargins": True,
                "syncColors": False,
                "hidePanelTitles": False
            }),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-90d",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": f'mitre_technique_id:"{technique_id}"', "language": "kuery"},
                    "filter": []
                })
            }
        },
        "references": [
            {"name": "indexpattern-datasource-layer-layer1", "type": "index-pattern", "id": index_pattern}
        ]
    }

    return dashboard


def generate_technique_dashboards(case_name, index_pattern, techniques=None):
    """
    Generate dashboards for all or specified MITRE ATT&CK techniques.

    Args:
        case_name: The case/index name
        index_pattern: The Elasticsearch index pattern
        techniques: Optional list of technique IDs to generate (generates all if None)

    Returns:
        list of dashboard definitions
    """
    dashboards = []

    technique_ids = techniques if techniques else list(TECHNIQUES.keys())

    for technique_id in technique_ids:
        dashboard = generate_technique_dashboard(technique_id, case_name, index_pattern)
        if dashboard:
            dashboards.append(dashboard)

    return dashboards


def generate_analysis_dashboard(case_name, index_pattern):
    """Generate a general analysis dashboard for IOCs, keywords, etc."""
    dashboard_id = f"analysis-{case_name}"

    panels = []

    # Panel: IOC Summary
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 0, "w": 24, "h": 12, "i": "panel_0"},
        "panelIndex": "panel_0",
        "embeddableConfig": {
            "attributes": {
                "title": "Potential IOCs by Type",
                "visualizationType": "lnsXY",
                "state": {
                    "visualization": {
                        "preferredSeriesType": "bar_horizontal",
                        "layers": [{
                            "layerId": "layer1",
                            "accessors": ["count"],
                            "seriesType": "bar_horizontal",
                            "xAccessor": "ioc_type"
                        }]
                    }
                }
            }
        }
    })

    # Panel: Top Domains/URLs
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 24, "y": 0, "w": 24, "h": 12, "i": "panel_1"},
        "panelIndex": "panel_1",
        "embeddableConfig": {
            "attributes": {
                "title": "Top Domains/URLs",
                "visualizationType": "lnsDatatable",
                "state": {
                    "visualization": {
                        "columns": [
                            {"columnId": "domain"},
                            {"columnId": "count"}
                        ],
                        "layerId": "layer1",
                        "paging": {"size": 20, "enabled": True}
                    }
                }
            }
        }
    })

    # Panel: File Activity
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 12, "w": 48, "h": 15, "i": "panel_2"},
        "panelIndex": "panel_2",
        "embeddableConfig": {
            "attributes": {
                "title": "File Activity Timeline",
                "visualizationType": "lnsXY",
                "state": {
                    "visualization": {
                        "preferredSeriesType": "bar_stacked",
                        "layers": [{
                            "layerId": "layer1",
                            "accessors": ["count"],
                            "seriesType": "bar_stacked",
                            "xAccessor": "@timestamp",
                            "splitAccessor": "artefact"
                        }]
                    }
                }
            }
        }
    })

    dashboard = {
        "id": dashboard_id,
        "type": "dashboard",
        "attributes": {
            "title": f"Analysis Dashboard - {case_name}",
            "description": "General analysis dashboard for IOCs, keywords, and file activity",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-90d"
        },
        "references": [
            {"name": "indexpattern-datasource-layer-layer1", "type": "index-pattern", "id": index_pattern}
        ]
    }

    return dashboard


def generate_actors_software_dashboard(case_name, index_pattern):
    """Generate a dashboard for threat actors and malware/software analysis."""
    dashboard_id = f"actors-software-{case_name}"

    panels = []

    # Panel: Known Threat Actors
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "panel_0"},
        "panelIndex": "panel_0",
        "embeddableConfig": {
            "attributes": {
                "title": "Detected Threat Actor Indicators",
                "visualizationType": "lnsDatatable",
                "state": {
                    "visualization": {
                        "columns": [
                            {"columnId": "actor"},
                            {"columnId": "indicator"},
                            {"columnId": "count"}
                        ],
                        "layerId": "layer1"
                    }
                }
            }
        }
    })

    # Panel: Known Malware/Tools
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 24, "y": 0, "w": 24, "h": 15, "i": "panel_1"},
        "panelIndex": "panel_1",
        "embeddableConfig": {
            "attributes": {
                "title": "Detected Software/Tools",
                "visualizationType": "lnsPie",
                "state": {
                    "visualization": {
                        "shape": "donut",
                        "layers": [{
                            "layerId": "layer1",
                            "primaryGroups": ["software"],
                            "metrics": ["count"]
                        }]
                    }
                }
            }
        }
    })

    dashboard = {
        "id": dashboard_id,
        "type": "dashboard",
        "attributes": {
            "title": f"Threat Actors & Software - {case_name}",
            "description": "Dashboard for threat actor and malware/software analysis",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True}),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-90d"
        },
        "references": [
            {"name": "indexpattern-datasource-layer-layer1", "type": "index-pattern", "id": index_pattern}
        ]
    }

    return dashboard


def generate_case_overview_dashboard(case_name, index_pattern):
    """Generate a case overview dashboard."""
    dashboard_id = f"case-{case_name}"

    panels = []

    # Panel: Case Summary (Markdown)
    panels.append({
        "version": "8.11.0",
        "type": "visualization",
        "gridData": {"x": 0, "y": 0, "w": 24, "h": 8, "i": "panel_summary"},
        "panelIndex": "panel_summary",
        "embeddableConfig": {
            "savedVis": {
                "title": f"Case: {case_name}",
                "type": "markdown",
                "params": {
                    "markdown": f"""
# Case: {case_name}

**Created:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Use the navigation to explore:
- **MITRE ATT&CK Overview**: Detected techniques and tactics
- **Analysis**: IOCs, keywords, and indicators
- **Actors & Software**: Threat attribution
- **Individual Techniques**: Detailed technique analysis
""",
                    "fontSize": 12
                }
            }
        }
    })

    # Panel: Total Events
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 24, "y": 0, "w": 8, "h": 8, "i": "panel_0"},
        "panelIndex": "panel_0",
        "embeddableConfig": {
            "attributes": {
                "title": "Total Events",
                "visualizationType": "lnsMetric"
            }
        }
    })

    # Panel: Unique Hosts
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 32, "y": 0, "w": 8, "h": 8, "i": "panel_1"},
        "panelIndex": "panel_1",
        "embeddableConfig": {
            "attributes": {
                "title": "Unique Hosts",
                "visualizationType": "lnsMetric"
            }
        }
    })

    # Panel: Unique Techniques
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 40, "y": 0, "w": 8, "h": 8, "i": "panel_2"},
        "panelIndex": "panel_2",
        "embeddableConfig": {
            "attributes": {
                "title": "Techniques Detected",
                "visualizationType": "lnsMetric"
            }
        }
    })

    # Panel: Event Timeline
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 8, "w": 48, "h": 15, "i": "panel_3"},
        "panelIndex": "panel_3",
        "embeddableConfig": {
            "attributes": {
                "title": "Event Timeline",
                "visualizationType": "lnsXY",
                "state": {
                    "visualization": {
                        "preferredSeriesType": "area",
                        "layers": [{
                            "layerId": "layer1",
                            "accessors": ["count"],
                            "seriesType": "area",
                            "xAccessor": "@timestamp"
                        }]
                    }
                }
            }
        }
    })

    # Panel: Top Artefacts
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 0, "y": 23, "w": 24, "h": 12, "i": "panel_4"},
        "panelIndex": "panel_4",
        "embeddableConfig": {
            "attributes": {
                "title": "Top Artefact Types",
                "visualizationType": "lnsXY",
                "state": {
                    "visualization": {
                        "preferredSeriesType": "bar_horizontal"
                    }
                }
            }
        }
    })

    # Panel: Hosts Activity
    panels.append({
        "version": "8.11.0",
        "type": "lens",
        "gridData": {"x": 24, "y": 23, "w": 24, "h": 12, "i": "panel_5"},
        "panelIndex": "panel_5",
        "embeddableConfig": {
            "attributes": {
                "title": "Events by Host",
                "visualizationType": "lnsPie",
                "state": {
                    "visualization": {
                        "shape": "donut"
                    }
                }
            }
        }
    })

    dashboard = {
        "id": dashboard_id,
        "type": "dashboard",
        "attributes": {
            "title": f"Case Overview - {case_name}",
            "description": f"Overview dashboard for case {case_name}",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-90d"
        },
        "references": [
            {"name": "indexpattern-datasource-layer-layer1", "type": "index-pattern", "id": index_pattern}
        ]
    }

    return dashboard


def generate_all_dashboards(case_name, index_pattern=None, include_techniques=True, parent_only=False):
    """
    Generate all dashboards for a case.

    Args:
        case_name: The case/index name
        index_pattern: The Elasticsearch index pattern (defaults to case_name)
        include_techniques: Whether to include individual technique dashboards
        parent_only: If True, only generate dashboards for parent techniques

    Returns:
        list of all dashboard definitions
    """
    if index_pattern is None:
        index_pattern = case_name.lower()

    dashboards = []

    # Core dashboards
    dashboards.append(generate_case_overview_dashboard(case_name, index_pattern))
    dashboards.append(generate_mitre_overview_dashboard(case_name, index_pattern))
    dashboards.append(generate_analysis_dashboard(case_name, index_pattern))
    dashboards.append(generate_actors_software_dashboard(case_name, index_pattern))

    # Technique dashboards
    if include_techniques:
        if parent_only:
            parent_techniques = get_parent_techniques()
            technique_dashboards = generate_technique_dashboards(
                case_name, index_pattern,
                techniques=list(parent_techniques.keys())
            )
        else:
            technique_dashboards = generate_technique_dashboards(case_name, index_pattern)

        dashboards.extend(technique_dashboards)

    return dashboards


def export_dashboards_to_ndjson(dashboards, output_path):
    """
    Export dashboards to NDJSON format for Kibana import.

    Args:
        dashboards: List of dashboard definitions
        output_path: Path to save the NDJSON file
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        for dashboard in dashboards:
            f.write(json.dumps(dashboard, ensure_ascii=False) + '\n')


def deploy_dashboards_to_kibana(dashboards, kibana_url="http://localhost:5601", space_id="default"):
    """
    Deploy dashboards to Kibana via API.

    Args:
        dashboards: List of dashboard definitions
        kibana_url: Kibana base URL
        space_id: Kibana space ID

    Returns:
        dict with deployment results
    """
    import subprocess
    import shlex

    results = {"success": [], "failed": []}

    for dashboard in dashboards:
        dashboard_json = json.dumps(dashboard)

        curl_cmd = shlex.split(
            f'curl -X POST "{kibana_url}/s/{space_id}/api/saved_objects/dashboard/{dashboard["id"]}" '
            f'-H "kbn-xsrf: true" '
            f'-H "Content-Type: application/json" '
            f'-d \'{dashboard_json}\''
        )

        try:
            result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and "error" not in result.stdout.lower():
                results["success"].append(dashboard["id"])
            else:
                results["failed"].append({"id": dashboard["id"], "error": result.stdout})
        except Exception as e:
            results["failed"].append({"id": dashboard["id"], "error": str(e)})

    return results


if __name__ == "__main__":
    # Example usage
    case_name = "test_case"

    print(f"Generating dashboards for case: {case_name}")

    # Generate all dashboards (parent techniques only for speed)
    dashboards = generate_all_dashboards(case_name, parent_only=True)

    print(f"Generated {len(dashboards)} dashboards")

    # Export to NDJSON
    output_file = f"{case_name}_dashboards.ndjson"
    export_dashboards_to_ndjson(dashboards, output_file)
    print(f"Exported to {output_file}")
