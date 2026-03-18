"""YARA rule scanning for PE binaries extracted from memory dumps.

Compiles YARA rules from a directory (with per-directory caching),
scans binary data, and returns structured match results with ruleset
attribution.
"""

from __future__ import annotations

import os
import warnings
from typing import Any

import logging

logger = logging.getLogger("memdump_toolkit")

# YARA compilation cache -- avoids recompiling rules for every binary.
# Key: resolved rules_dir path. Value: list of (compiled_rule, source_path).
_yara_rule_cache: dict[str, list[tuple[Any, str]]] = {}


def _compile_yara_rules(rules_dir: str) -> list[tuple[Any, str]]:
    """Compile YARA rules from a directory, with caching.

    Compiles each .yar/.yara file individually so one broken file does
    not prevent the rest from loading.  Results are cached by resolved
    directory path.

    Args:
        rules_dir: Absolute path to the rules directory.

    Returns:
        List of (compiled_rule, source_path) tuples.
    """
    if rules_dir in _yara_rule_cache:
        return _yara_rule_cache[rules_dir]

    import yara

    rule_files: dict[str, str] = {}
    for root, _dirs, files in os.walk(rules_dir):
        for fname in files:
            if fname.endswith((".yar", ".yara")):
                fpath = os.path.join(root, fname)
                rule_files[fpath] = fpath

    if not rule_files:
        _yara_rule_cache[rules_dir] = []
        return []

    # Many community rulesets use external variables -- provide defaults.
    externals = {
        "filepath": "",
        "filename": "",
        "filetype": "",
        "extension": "",
        "owner": "",
    }

    compiled_rules: list[tuple[Any, str]] = []
    skipped = 0
    for fpath in rule_files.values():
        try:
            compiled_rules.append(
                (yara.compile(filepath=fpath, externals=externals), fpath)
            )
        except yara.SyntaxError as e:
            logger.debug("YARA skip %s: %s", fpath, e)
            skipped += 1
        except yara.Error as e:
            logger.debug("YARA skip %s: %s", fpath, e)
            skipped += 1

    if skipped:
        logger.info("YARA: compiled %d rules, skipped %d broken files",
                     len(compiled_rules), skipped)
    else:
        logger.debug("YARA: compiled all %d rule files", len(compiled_rules))

    _yara_rule_cache[rules_dir] = compiled_rules
    return compiled_rules


def _extract_matches(
    matches: list[Any],
    source_path: str,
    rules_dir: str,
) -> list[dict[str, Any]]:
    """Extract structured match data from yara match objects.

    Handles both yara-python v3 (tuple-based strings) and v4+
    (StringMatch objects with .instances).

    Args:
        matches: List of yara.Match objects from a scan.
        source_path: File path of the rule that produced these matches.
        rules_dir: Base rules directory for computing relative paths.

    Returns:
        List of match dicts with rule, tags, meta, strings, source, and ruleset.
    """
    source = os.path.relpath(source_path, rules_dir)
    ruleset = source.split(os.sep)[0] if os.sep in source else ""

    results: list[dict[str, Any]] = []
    for m in matches:
        str_entries: list[dict] = []
        if hasattr(m, "strings"):
            for s in m.strings[:10]:
                if hasattr(s, "identifier"):
                    # v4+: StringMatch objects with .instances
                    for inst in (s.instances[:3] if hasattr(s, "instances") else []):
                        str_entries.append({
                            "offset": inst.offset,
                            "identifier": s.identifier,
                            "data": bytes(inst.matched_data[:100]).hex(),
                        })
                else:
                    # v3: plain tuples (offset, identifier, data)
                    str_entries.append({
                        "offset": s[0], "identifier": s[1],
                        "data": s[2][:100].hex(),
                    })

        results.append({
            "rule": m.rule,
            "tags": list(m.tags),
            "meta": dict(m.meta) if hasattr(m, "meta") else {},
            "strings": str_entries,
            "source": source,
            "ruleset": ruleset,
        })

    return results


def scan_with_yara(data: bytes, rules_dir: str | None = None) -> list[dict[str, Any]]:
    """Scan binary data with YARA rules from a directory.

    Returns list of matches: [{"rule": name, "tags": [...], "strings": [...]}]
    Silently returns [] if yara-python is not installed or no rules found.
    """
    if rules_dir is None:
        return []

    try:
        import yara  # noqa: F401
    except ImportError:
        logger.warning("yara-python is not installed — YARA scan skipped. Run: pip install yara-python")
        return []

    # Validate and resolve rules directory
    rules_dir = os.path.realpath(rules_dir)
    if not os.path.isdir(rules_dir):
        return []

    compiled_rules = _compile_yara_rules(rules_dir)
    if not compiled_rules:
        return []

    matches_out: list[dict[str, Any]] = []
    for rules, source_path in compiled_rules:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                matches = rules.match(data=data)
        except Exception as e:
            logger.debug("YARA match error: %s", e)
            continue

        matches_out.extend(_extract_matches(matches, source_path, rules_dir))

    return matches_out
