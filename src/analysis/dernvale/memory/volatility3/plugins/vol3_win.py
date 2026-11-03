#!/usr/bin/env python3 -tt
"""Volatility 3 Windows plugin output parser for Dernvale."""

import json
import re


def windows_vol3(
    output_directory,
    mempath,
    volver,
    profile,
    symbolorprofile,
    plugin,
    plugoutlist,
    jsondict,
    jsonlist,
):
    """Parse Volatility 3 Windows plugin JSON output.

    Volatility 3 outputs clean JSON format. This function parses the JSON
    output and converts it to Dernvale's internal format.

    Args:
        output_directory: Base output directory
        mempath: Memory image path component
        volver: Volatility version (should be "3")
        profile: Windows profile/symbol table
        symbolorprofile: Label for profile field
        plugin: Plugin name (e.g., "windows.pslist.PsList")
        plugoutlist: Volatility command output split by newlines
        jsondict: Dictionary template for JSON entries
        jsonlist: List to append parsed entries to

    Returns:
        jsonlist with parsed entries appended
    """
    try:
        # Join the output lines back together with actual newlines
        # plugoutlist comes from str(bytes)[2:-1].split("\\n") so we need real newlines
        output_text = "\n".join(plugoutlist)

        print(f"    [DEBUG-VOL3] windows_vol3 called for plugin: {plugin}")
        print(f"    [DEBUG-VOL3] Input lines: {len(plugoutlist)}, Total chars: {len(output_text)}")
        print(f"    [DEBUG-VOL3] First 200 chars: {repr(output_text[:200])}")

        # Remove the Volatility framework header and progress lines
        # Look for the start of JSON (should be '[' or '{')
        json_start = -1
        for i, char in enumerate(output_text):
            if char in '[{':
                json_start = i
                break

        if json_start == -1:
            # No JSON found, might be empty output or error
            print(f"    [DEBUG-VOL3] No JSON start found in output!")
            return jsonlist

        json_text = output_text[json_start:]

        # Parse the JSON array
        try:
            data = json.loads(json_text)
        except json.JSONDecodeError as e:
            # If JSON parsing fails, try to clean up the text more aggressively
            # Remove any remaining non-JSON text
            json_text = re.sub(r'b\'|\'$|^b"', '', json_text)
            json_text = json_text.replace('\\\\n', '').replace('\\\\t', '')
            try:
                data = json.loads(json_text)
            except:
                # Still failed, return empty
                return jsonlist

        # If data is not a list, make it one
        if not isinstance(data, list):
            data = [data]

        # Process each entry
        for entry in data:
            if not isinstance(entry, dict):
                continue

            # Add Volatility metadata to each entry
            entry_with_metadata = {
                "VolatilityVersion": volver,
                symbolorprofile: profile,
                "VolatilityPlugin": plugin,
            }

            # Merge the original entry data
            entry_with_metadata.update(entry)

            # Remove the __children field if present (Volatility 3 adds this)
            if "__children" in entry_with_metadata:
                del entry_with_metadata["__children"]

            # Convert to JSON string and add to list
            jsonlist.append(json.dumps(entry_with_metadata))

    except Exception as e:
        # Log the error but don't crash
        print(f"    [ERROR] Failed to parse Volatility 3 output for {plugin}: {e}")
        import traceback
        traceback.print_exc()

    return jsonlist
