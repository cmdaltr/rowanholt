"""Tool definitions and data classes."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class ToolPlatform(Enum):
    """Supported platforms for tools."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ALL = "all"


@dataclass
class ToolDefinition:
    """Defines a forensic tool's requirements and locations."""

    name: str
    description: str
    platforms: List[ToolPlatform]
    executable_name: str
    common_paths: Dict[str, List[str]] = field(default_factory=dict)
    install_methods: Dict[str, str] = field(default_factory=dict)
    version_command: Optional[str] = None
    min_version: Optional[str] = None
    required: bool = True
    category: str = "general"

    def __post_init__(self):
        """Validate and convert platform strings to enums if needed."""
        if self.platforms and isinstance(self.platforms[0], str):
            self.platforms = [ToolPlatform(p) for p in self.platforms]


# Phones (--Mobile): run by rowanholt/process/mobile.py as subprocesses, each from its own
# virtualenv in the worker image (src/web/backend/Dockerfile.forensics, step 4h), pinned there
# to the release tag in min_version
ILEAPP = ToolDefinition(
    name="iLEAPP",
    description="iOS Logs, Events, And Plists Parser: iTunes/Finder backups (encrypted too) and full file system extractions",
    platforms=[ToolPlatform.LINUX],
    executable_name="ileapp",
    common_paths={"linux": ["/usr/local/bin"]},
    install_methods={"linux": "Worker image: git clone --branch v2026.4.6 https://github.com/abrignoni/iLEAPP, "
                              "its requirements.txt in a Python 3.12 venv at /opt/ileapp/venv"},
    version_command="ileapp --version",
    min_version="v2026.4.6",
    required=False,
    category="mobile",
)
ALEAPP = ToolDefinition(
    name="ALEAPP",
    description="Android Logs, Events, And Protobuf Parser: file system extractions, bug reports and ADB backups "
                "(which Elrond lays out as a file system first)",
    platforms=[ToolPlatform.LINUX],
    executable_name="aleapp",
    common_paths={"linux": ["/usr/local/bin"]},
    install_methods={"linux": "Worker image: git clone --branch v2026.4.5 https://github.com/abrignoni/ALEAPP, "
                              "its requirements.txt in a Python 3.12 venv at /opt/aleapp/venv"},
    version_command="aleapp --version",
    min_version="v2026.4.5",
    required=False,
    category="mobile",
)
MOBILE_TOOLS: Dict[str, ToolDefinition] = {"ileapp": ILEAPP, "aleapp": ALEAPP}
