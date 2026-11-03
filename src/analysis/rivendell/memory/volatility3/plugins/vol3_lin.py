#!/usr/bin/env python3 -tt
"""Volatility 3 Linux plugin output parser for Rivendell."""

import json
import re


def linux_vol3(
    volver,
    profile,
    symbolorprofile,
    plugin,
    plugoutlist,
    jsondict,
    jsonlist,
):
    """Parse Volatility 3 Linux plugin JSON output.

    Args:
        volver: Volatility version (should be "3")
        profile: Linux profile/symbol table
        symbolorprofile: Label for profile field
        plugin: Plugin name (e.g., "linux.pslist.PsList")
        plugoutlist: Volatility command output split by newlines
        jsondict: Dictionary template for JSON entries
        jsonlist: List to append parsed entries to

    Returns:
        jsonlist with parsed entries appended
    """
    try:
        # Join with actual newlines (plugoutlist is from str(bytes).split("\\n"))
        output_text = "\n".join(plugoutlist)

        json_start = -1
        for i, char in enumerate(output_text):
            if char in '[{':
                json_start = i
                break

        if json_start == -1:
            return jsonlist

        json_text = output_text[json_start:]

        try:
            data = json.loads(json_text)
        except json.JSONDecodeError:
            json_text = re.sub(r'b\'|\'$|^b"', '', json_text)
            json_text = json_text.replace('\\\\n', '').replace('\\\\t', '')
            try:
                data = json.loads(json_text)
            except:
                return jsonlist

        if not isinstance(data, list):
            data = [data]

        for entry in data:
            if not isinstance(entry, dict):
                continue

            entry_with_metadata = {
                "VolatilityVersion": volver,
                symbolorprofile: profile,
                "VolatilityPlugin": plugin,
            }

            entry_with_metadata.update(entry)

            if "__children" in entry_with_metadata:
                del entry_with_metadata["__children"]

            jsonlist.append(json.dumps(entry_with_metadata))

    except Exception as e:
        print(f"    [ERROR] Failed to parse Volatility 3 Linux output for {plugin}: {e}")
        import traceback
        traceback.print_exc()

    return jsonlist
