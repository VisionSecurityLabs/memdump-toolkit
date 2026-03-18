"""Detection signature loader — reads signatures.default.yml on first run,
copies to ~/.memdump-toolkit/signatures.yml for user customization."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

SIGNATURES_CONFIG = Path.home() / ".memdump-toolkit" / "signatures.yml"
_BUNDLED_DEFAULT = Path(__file__).parent / "signatures.default.yml"


def _str_to_bytes(s: str) -> bytes:
    """Convert a YAML string value to bytes via latin-1 encoding.
    Handles both plain ASCII ('UPX0') and \\x-escaped binary ('\\xfc\\x48').
    """
    return s.encode("latin-1")


def _write_default_config() -> None:
    SIGNATURES_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(_BUNDLED_DEFAULT, SIGNATURES_CONFIG)


def _load_yaml(path: Path) -> dict[str, Any]:
    import yaml

    with open(path) as f:
        return yaml.safe_load(f) or {}


def _decode_bytes_list(items: list[str]) -> list[bytes]:
    return [_str_to_bytes(s) for s in items]


def _decode_bytes_dict_of_lists(data: dict[str, list[str]]) -> dict[str, list[bytes]]:
    return {k: _decode_bytes_list(v) for k, v in data.items()}


def load_signatures() -> dict[str, Any]:
    """Load signatures from user config, copying defaults on first run."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        # PyYAML not available — parse bundled default directly
        pass

    if not SIGNATURES_CONFIG.exists():
        _write_default_config()

    try:
        raw = _load_yaml(SIGNATURES_CONFIG)
    except Exception:
        raw = _load_yaml(_BUNDLED_DEFAULT)

    # Decode bytes-valued sections
    result: dict[str, Any] = {}

    for key in (
        "KNOWN_TOOLS",
        "CAPABILITY_STRONG",
        "CAPABILITY_WEAK",
        "PACKER_SIGNATURES",
        "LANG_SIGNATURES",
        "DOTNET_OBFUSCATORS",
        "DOTNET_OFFENSIVE_TOOLS",
    ):
        result[key] = _decode_bytes_dict_of_lists(raw.get(key, {}))

    # SHELLCODE_PROLOGUES: dict[str, bytes]
    result["SHELLCODE_PROLOGUES"] = {
        k: _str_to_bytes(v)
        for k, v in raw.get("SHELLCODE_PROLOGUES", {}).items()
    }

    # SHELLCODE_PATTERNS: dict[str, tuple[bytes, str]]
    result["SHELLCODE_PATTERNS"] = {
        k: (_str_to_bytes(v["pattern"]), v["description"])
        for k, v in raw.get("SHELLCODE_PATTERNS", {}).items()
    }

    # NOP_PATTERNS: list[bytes]
    result["NOP_PATTERNS"] = [
        _str_to_bytes(s) for s in raw.get("NOP_PATTERNS", [])
    ]

    # String-only sections (sets and lists)
    result["SUSPICIOUS_IMPORTS"] = {
        k: set(v) for k, v in raw.get("SUSPICIOUS_IMPORTS", {}).items()
    }
    result["DOTNET_SUSPICIOUS_PINVOKE"] = {
        k: set(v) for k, v in raw.get("DOTNET_SUSPICIOUS_PINVOKE", {}).items()
    }
    result["DOTNET_SUSPICIOUS_APIS"] = dict(raw.get("DOTNET_SUSPICIOUS_APIS", {}))

    return result


_SIGS = load_signatures()

KNOWN_TOOLS: dict[str, list[bytes]] = _SIGS["KNOWN_TOOLS"]
CAPABILITY_STRONG: dict[str, list[bytes]] = _SIGS["CAPABILITY_STRONG"]
CAPABILITY_WEAK: dict[str, list[bytes]] = _SIGS["CAPABILITY_WEAK"]
PACKER_SIGNATURES: dict[str, list[bytes]] = _SIGS["PACKER_SIGNATURES"]
LANG_SIGNATURES: dict[str, list[bytes]] = _SIGS["LANG_SIGNATURES"]
DOTNET_OBFUSCATORS: dict[str, list[bytes]] = _SIGS["DOTNET_OBFUSCATORS"]
DOTNET_OFFENSIVE_TOOLS: dict[str, list[bytes]] = _SIGS["DOTNET_OFFENSIVE_TOOLS"]
SHELLCODE_PROLOGUES: dict[str, bytes] = _SIGS["SHELLCODE_PROLOGUES"]
SHELLCODE_PATTERNS: dict[str, tuple[bytes, str]] = _SIGS["SHELLCODE_PATTERNS"]
NOP_PATTERNS: list[bytes] = _SIGS["NOP_PATTERNS"]
SUSPICIOUS_IMPORTS: dict[str, set[str]] = _SIGS["SUSPICIOUS_IMPORTS"]
DOTNET_SUSPICIOUS_PINVOKE: dict[str, set[str]] = _SIGS["DOTNET_SUSPICIOUS_PINVOKE"]
DOTNET_SUSPICIOUS_APIS: dict[str, list[str]] = _SIGS["DOTNET_SUSPICIOUS_APIS"]
