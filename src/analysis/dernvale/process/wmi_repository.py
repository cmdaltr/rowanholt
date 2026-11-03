"""WMI event subscriptions carved from a raw OBJECTS.DATA.

Artemis's wmipersist returns nothing for Windows 11 repositories (E35), so this
reads the bindings, consumers and filters directly. A __FilterToConsumerBinding
instance stores its references as text (`<Class>.Name="..."` and
`__EventFilter.Name="..."`), and consumer and filter instances keep their
property values as null-terminated strings after the class name, each with a
leading flag byte and with the creator's binary SID in among them.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional

BINDING = re.compile(
    rb'__FilterToConsumerBinding\x00+(\w+EventConsumer)\.Name="([^"\x00]{1,256})"\x00'
    rb'.{0,256}?__EventFilter\.Name="([^"\x00]{1,256})"',
    re.S,
)
STRING = re.compile(rb"[\x20-\x7e]{3,}")  # 3+, so SID bytes don't read as values
INSTANCE_WINDOW = 4096

# Subscriptions Windows creates itself
KNOWN_SUBSCRIPTIONS = {
    ("SCM Event Log Filter", "SCM Event Log Consumer"): "Windows Service Control Manager event logging",
    ("BVTFilter", "BVTConsumer"): "Windows WMI build verification test",
}


def _strings(data: bytes) -> List[str]:
    return [s.decode("ascii") for s in STRING.findall(data)]


def _instance_values(data: bytes, class_name: str, instance_name: str) -> Optional[List[str]]:
    """Strings of the instance of class_name whose values include instance_name."""
    marker = b"\x00" + class_name.encode() + b"\x00"
    start = data.find(marker)
    while start != -1:
        window = data[start + 1:start + INSTANCE_WINDOW]
        values = _strings(window)
        # The class name opens the instance and its values follow within a few
        # strings; the record ends at its null padding, or a few values on
        if instance_name in values[:12]:
            end = window.find(b"\x00" * 16, window.find(instance_name.encode()))
            values = _strings(window[:end] if end != -1 else window)
            return values[1:values.index(instance_name) + 4]
        start = data.find(marker, start + 1)
    return None


def wmi_subscriptions(objects_data: Path) -> List[Dict]:
    """Every filter-to-consumer binding in OBJECTS.DATA, with the consumer's
    values (command line, script, etc.) and the filter's WQL query."""
    data = objects_data.read_bytes()
    seen, subscriptions = set(), []
    for match in BINDING.finditer(data):
        consumer_class, consumer, event_filter = (g.decode("ascii", "replace") for g in match.groups())
        if (consumer_class, consumer, event_filter) in seen:
            continue
        seen.add((consumer_class, consumer, event_filter))
        consumer_values = _instance_values(data, consumer_class, consumer) or []
        filter_values = _instance_values(data, "__EventFilter", event_filter) or []
        query = next((v for v in filter_values if v.upper().startswith("SELECT ")), "")
        record = {
            "filter_name": event_filter,
            "filter_query": query,
            "consumer_class": consumer_class,
            "consumer_name": consumer,
            "consumer_values": [v for v in consumer_values if v != consumer],
        }
        known = KNOWN_SUBSCRIPTIONS.get((event_filter, consumer))
        if known:
            record["note"] = f"likely benign: {known}"
        subscriptions.append(record)
    return subscriptions
