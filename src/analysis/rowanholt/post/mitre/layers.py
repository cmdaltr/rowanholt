#!/usr/bin/env python3 -tt
"""
ATT&CK Navigator layers (format 4.5), one per domain: Elrond's per case (nav_config.py) and the
web app's of confirmed findings (case_routes.py).

A case's Enterprise layer is assets/<case>.json and its Mobile layer assets/<case>.mobile.json:
the server's Navigator check (auth/access.py) gives both the case's own access.
"""

import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _load_attack_lookup():
    """attack_lookup.py beside this file: imported in Elrond, loaded by path in the backend."""
    try:
        from rowanholt.post.mitre import attack_lookup as module
        return module
    except ImportError:
        path = Path(__file__).resolve().parent / "attack_lookup.py"
        spec = importlib.util.spec_from_file_location("rowanholt_attack_lookup", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


attack_lookup = _load_attack_lookup()

NAVIGATOR_VERSION = "5.3.2"  # docker-compose.yml's navigator service clones this tag
LAYER_VERSION = "4.5"
MOBILE_SUFFIX = ".mobile"


def layer_file(case: str, domain: str) -> str:
    """<case>.json for Enterprise, <case>.mobile.json for Mobile."""
    return f"{case}{MOBILE_SUFFIX if domain == attack_lookup.MOBILE else ''}.json"


def attack_major() -> str:
    """The release's major version ("20"), the one the Navigator's config and layers name."""
    return attack_lookup.version().split(".")[0]


def build_layer(name: str, domain: str, techniques: Dict[str, Tuple[str, str]], description: str = "",
                legend: Optional[List[Dict[str, str]]] = None, show_ids: bool = False) -> Dict:
    """A layer of ``techniques`` ({ID: (colour, comment)}, all of ``domain``). With no tactic
    given, the Navigator marks a technique under every tactic it has; a parent whose
    sub-techniques are marked opens to show them."""
    parents = {tid.split(".")[0] for tid in techniques if "." in tid}
    return {
        "name": name,
        "versions": {"attack": attack_major(), "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": domain,
        "description": description,
        # Every platform the domain has: Enterprise's cloud ones (IaaS, SaaS, Office Suite,
        # Identity Provider) included, or cloud-only techniques would be filtered out of sight
        "filters": {"platforms": attack_lookup.platforms(domain)},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": show_ids, "showName": True,
                   "showAggregateScores": False, "countUnscored": False},
        "hideDisabled": False,
        "techniques": [{"techniqueID": tid, "color": colour, "comment": comment, "enabled": True,
                        "metadata": [], "showSubtechniques": tid in parents}
                       for tid, (colour, comment) in sorted(techniques.items())],
        "gradient": {"colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"], "minValue": 0, "maxValue": 100},
        "legendItems": legend or [],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def navigator_config(default_layers: List[str]) -> Dict:
    """The Navigator's assets/config.json: the pinned release with both domains, opening on
    ``default_layers`` (asset paths)."""
    major = attack_major()
    return {
        "versions": {
            "enabled": True,
            "entries": [{
                "name": f"ATT&CK v{attack_lookup.version()}",
                "version": major,
                "domains": [{"name": attack_lookup.DOMAIN_NAMES[d], "identifier": d,
                             "data": [f"assets/{d}.json"]} for d in attack_lookup.DOMAINS],
            }],
        },
        "custom_context_menu_items": [],
        "default_layers": {"enabled": bool(default_layers), "urls": default_layers},
        "comment_color": "yellow",
        "link_color": "blue",
        "metadata_color": "purple",
        "banner": "",
        "customize_features": [
            {
                "name": "multiselect",
                "enabled": True,
                "description": ""
            },
            {
                "name": "export_render",
                "enabled": True,
                "description": ""
            },
            {
                "name": "export_excel",
                "enabled": True,
                "description": ""
            },
            {
                "name": "legend",
                "enabled": True,
                "description": ""
            },
            {
                "name": "background_color",
                "enabled": True,
                "description": ""
            },
            {
                "name": "non_aggregate_score_color",
                "enabled": True,
                "description": ""
            },
            {
                "name": "aggregate_score_color",
                "enabled": True,
                "description": ""
            },
            {
                "name": "comment_underline",
                "enabled": True,
                "description": ""
            },
            {
                "name": "metadata_underline",
                "enabled": True,
                "description": ""
            },
            {
                "name": "link_underline",
                "enabled": True,
                "description": ""
            }
        ],
        "features": [
            {
                "name": "leave_site_dialog",
                "enabled": True,
                "description": ""
            },
            {
                "name": "tabs",
                "enabled": True,
                "description": ""
            },
            {
                "name": "header",
                "enabled": True,
                "description": ""
            },
            {
                "name": "selection_controls",
                "enabled": True,
                "description": "",
                "subfeatures": [
                    {
                        "name": "search",
                        "enabled": True,
                        "display_name": "search & multiselect",
                        "description": ""
                    },
                    {
                        "name": "deselect_all",
                        "enabled": True,
                        "display_name": "deselect techniques",
                        "description": ""
                    },
                    {
                        "name": "selecting_techniques",
                        "enabled": True,
                        "display_name": "selection behavior",
                        "description": ""
                    }
                ]
            },
            {
                "name": "layer_controls",
                "enabled": True,
                "description": "",
                "subfeatures": [
                    {
                        "name": "layer_settings",
                        "enabled": True,
                        "display_name": "layer settings",
                        "description": ""
                    },
                    {
                        "name": "download_layer",
                        "enabled": True,
                        "display_name": "export",
                        "description": ""
                    },
                    {
                        "name": "filters",
                        "enabled": True,
                        "display_name": "filters",
                        "description": ""
                    },
                    {
                        "name": "sorting",
                        "enabled": True,
                        "display_name": "sorting",
                        "description": ""
                    },
                    {
                        "name": "color_setup",
                        "enabled": True,
                        "display_name": "color setup",
                        "description": ""
                    },
                    {
                        "name": "toggle_hide_disabled",
                        "enabled": True,
                        "display_name": "show/hide disabled",
                        "description": ""
                    },
                    {
                        "name": "subtechniques",
                        "enabled": True,
                        "display_name": "sub-techniques",
                        "description": ""
                    }
                ]
            },
            {
                "name": "technique_controls",
                "enabled": True,
                "description": "",
                "subfeatures": [
                    {
                        "name": "disable_techniques",
                        "enabled": True,
                        "display_name": "toggle state",
                        "description": ""
                    },
                    {
                        "name": "manual_color",
                        "enabled": True,
                        "display_name": "background color",
                        "description": ""
                    },
                    {
                        "name": "scoring",
                        "enabled": True,
                        "display_name": "scoring",
                        "description": ""
                    },
                    {
                        "name": "comments",
                        "enabled": True,
                        "display_name": "comment",
                        "description": ""
                    },
                    {
                        "name": "links",
                        "enabled": True,
                        "display_name": "link",
                        "description": ""
                    },
                    {
                        "name": "metadata",
                        "enabled": True,
                        "display_name": "metadata",
                        "description": ""
                    },
                    {
                        "name": "clear_annotations",
                        "enabled": True,
                        "display_name": "clear annotations on selected",
                        "description": ""
                    }
                ]
            },
            {
                "name": "toolbar_controls",
                "enabled": True,
                "description": "",
                "subfeatures": [
                    {
                        "name": "sticky_toolbar",
                        "enabled": True,
                        "description": ""
                    }
                ]
            }
        ],
    }
