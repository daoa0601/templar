#!/usr/bin/env python3
"""Export bounded, normalized Windows forensic facts without executing collected content.

Runtime dependencies are intentionally external to the TypeScript package:
`python-evtx`, `dissect.target`, and `pylnk3`. The exporter reads an already extracted host tree and
writes JSON to stdout. It does not interpret the facts as course answers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree

import pylnk3
from Evtx.Evtx import Evtx
from dissect.target import Target
from dissect.target.exceptions import RegistryKeyNotFoundError

SCHEMA_VERSION = "1"
TOOL_VERSION = "1.0.0"
EVENT_NAMESPACE = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
DEFAULT_EVENT_IDS = {
    1102,
    1149,
    400,
    403,
    600,
    800,
    4103,
    4104,
    4624,
    4625,
    4634,
    4648,
    4662,
    4672,
    4688,
    4697,
    4698,
    4702,
    4720,
    4728,
    4729,
    4732,
    4733,
    4738,
    4756,
    4757,
    4768,
    4769,
    4776,
    4798,
    4799,
    5140,
    5145,
    7045,
    21,
    22,
    24,
    25,
    106,
    140,
    141,
    200,
    201,
}
DEFAULT_MFT_PATTERN = re.compile(
    r"(?:mimikatz|rubeus|\.kirbi$|krbtgt|dpapi|backupkey|\.pfx$|\.der$|\.key$|"
    r"psexec|powersploit|creds|\\output(?:\\|$))",
    re.IGNORECASE,
)
EVENT_LOG_NAMES = (
    "Security.evtx",
    "System.evtx",
    "Windows PowerShell.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    "Microsoft-Windows-SMBClient%4Operational.evtx",
    "Microsoft-Windows-SMBServer%4Operational.evtx",
)
MACHINE_REGISTRY_KEYS = (
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\ComputerName\ComputerName",
    r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\TimeZoneInformation",
    r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
)
USER_REGISTRY_SUFFIXES = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    r"Software\Microsoft\Internet Explorer\TypedURLs",
)


def iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        current = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include an offset")
    return parsed.astimezone(timezone.utc)


def bounded(value: Any, maximum: int = 4096) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\x00", "").strip()
    return text[:maximum]


def utf16_strings(value: bytes) -> list[str]:
    found: list[str] = []
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){2,}", value):
        decoded = match.group(0).decode("utf-16-le", errors="strict")
        if decoded not in found:
            found.append(decoded[:512])
    return found[:64]


def registry_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {
            "byte_length": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "utf16_strings": utf16_strings(value),
        }
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value if not isinstance(value, str) else bounded(value)
    if isinstance(value, (list, tuple)):
        return [registry_value(item) for item in value[:256]]
    return bounded(value)


def registry_key(target: Target, key_path: str, recursive_depth: int = 0) -> dict[str, Any] | None:
    try:
        key = target.registry.key(key_path)
    except RegistryKeyNotFoundError:
        return None
    values = {bounded(value.name, 256): registry_value(value.value) for value in key.values()}
    result: dict[str, Any] = {"path": key_path, "timestamp_utc": iso(key.ts), "values": values}
    if recursive_depth > 0:
        subkeys = []
        for subkey in key.subkeys():
            child = registry_key(target, f"{key_path}\\{subkey.name}", recursive_depth - 1)
            if child is not None:
                subkeys.append(child)
        result["subkeys"] = subkeys[:4096]
    return result


def registry_evidence(target: Target) -> list[dict[str, Any]]:
    keys = [entry for path in MACHINE_REGISTRY_KEYS if (entry := registry_key(target, path))]
    for path in (
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        r"HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names",
    ):
        entry = registry_key(target, path, 1)
        if entry:
            keys.append(entry)
    try:
        users = target.registry.key("HKEY_USERS")
        user_ids = sorted({bounded(subkey.name, 256) for subkey in users.subkeys()})
    except RegistryKeyNotFoundError:
        user_ids = []
    for user_id in user_ids:
        for suffix in USER_REGISTRY_SUFFIXES:
            entry = registry_key(target, f"HKEY_USERS\\{user_id}\\{suffix}", 1)
            if entry:
                keys.append(entry)
    return keys


def event_fields(root: ElementTree.Element) -> dict[str, str]:
    fields: dict[str, str] = {}
    for node in root.findall(".//e:EventData/e:Data", EVENT_NAMESPACE):
        name = bounded(node.attrib.get("Name") or f"value_{len(fields)}", 128)
        fields[name] = bounded(node.text)
    for node in root.findall(".//e:UserData//*", EVENT_NAMESPACE):
        if list(node):
            continue
        name = bounded(node.tag.rsplit("}", 1)[-1], 128)
        if name and name not in fields:
            fields[name] = bounded(node.text)
    return fields


def event_evidence(
    logs_root: Path,
    start: datetime | None,
    end: datetime | None,
    event_ids: set[int],
    maximum: int,
) -> tuple[list[dict[str, Any]], list[Path]]:
    events: list[dict[str, Any]] = []
    sources: list[Path] = []
    for name in EVENT_LOG_NAMES:
        path = logs_root / name
        if not path.is_file() or path.is_symlink():
            continue
        sources.append(path)
        with Evtx(str(path)) as log:
            for record in log.records():
                root = ElementTree.fromstring(record.xml())
                event_id_text = root.findtext(".//e:EventID", namespaces=EVENT_NAMESPACE)
                if not event_id_text or not event_id_text.isdigit():
                    continue
                event_id = int(event_id_text)
                if event_id not in event_ids:
                    continue
                system = root.find(".//e:System", EVENT_NAMESPACE)
                if system is None:
                    continue
                time_node = system.find("e:TimeCreated", EVENT_NAMESPACE)
                if time_node is None or "SystemTime" not in time_node.attrib:
                    continue
                timestamp = parse_time(time_node.attrib["SystemTime"])
                if timestamp is None or (start and timestamp < start) or (end and timestamp > end):
                    continue
                provider = system.find("e:Provider", EVENT_NAMESPACE)
                events.append(
                    {
                        "timestamp_utc": iso(timestamp),
                        "event_id": event_id,
                        "record_id": bounded(
                            system.findtext("e:EventRecordID", namespaces=EVENT_NAMESPACE), 64
                        ),
                        "provider": bounded(provider.attrib.get("Name") if provider is not None else "", 256),
                        "channel": bounded(
                            system.findtext("e:Channel", namespaces=EVENT_NAMESPACE), 256
                        ),
                        "computer": bounded(
                            system.findtext("e:Computer", namespaces=EVENT_NAMESPACE), 256
                        ),
                        "fields": event_fields(root),
                        "source": f"C/Windows/System32/winevt/Logs/{name}",
                    }
                )
                if len(events) > maximum:
                    raise ValueError(f"selected event count exceeds {maximum}")
    events.sort(key=lambda item: (item["timestamp_utc"] or "", item["source"], item["record_id"]))
    return events, sources


def prefetch_evidence(target: Target, maximum: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for record in target.prefetch(compact=True):
        values = record._asdict()
        records.append(
            {
                "filename": bounded(values.get("filename"), 512),
                "prefetch": bounded(values.get("prefetch"), 512),
                "latest_run_utc": iso(values.get("ts")),
                "previous_runs_utc": [iso(item) for item in values.get("previousruns", []) if item],
                "run_count": int(values.get("runcount") or 0),
                "linked_files": [bounded(item, 1024) for item in values.get("linkedfiles", [])[:128]],
            }
        )
        if len(records) > maximum:
            raise ValueError(f"prefetch count exceeds {maximum}")
    return sorted(records, key=lambda item: (item["filename"], item["prefetch"]))


def history_evidence(root: Path) -> tuple[list[dict[str, Any]], list[Path]]:
    records: list[dict[str, Any]] = []
    sources: list[Path] = []
    pattern = "C/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
    for path in sorted(root.glob(pattern)):
        if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        sources.append(path)
        text = path.read_text("utf-8", errors="replace")
        records.append(
            {
                "user": path.parts[-7],
                "path": path.relative_to(root).as_posix(),
                "lines": [line[:4096] for line in text.splitlines()[:10_000]],
            }
        )
    return records, sources


def lnk_evidence(root: Path, maximum: int) -> tuple[list[dict[str, Any]], list[Path]]:
    records: list[dict[str, Any]] = []
    sources: list[Path] = []
    pattern = "C/Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk"
    for path in sorted(root.glob(pattern)):
        if path.is_symlink() or path.stat().st_size > 16 * 1024 * 1024:
            continue
        try:
            link = pylnk3.parse(str(path))
        except Exception as error:  # malformed evidence is reported, never executed
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "parse_error": type(error).__name__,
                }
            )
        else:
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "target": bounded(getattr(link, "path", None), 2048),
                    "arguments": bounded(getattr(link, "arguments", None), 2048),
                    "working_directory": bounded(getattr(link, "working_dir", None), 2048),
                    "description": bounded(getattr(link, "description", None), 2048),
                    "file_size": int(getattr(link, "file_size", 0) or 0),
                    "target_creation_time": iso(getattr(link, "creation_time", None)),
                    "target_modification_time": iso(getattr(link, "modification_time", None)),
                    "target_access_time": iso(getattr(link, "access_time", None)),
                }
            )
        sources.append(path)
        if len(records) > maximum:
            raise ValueError(f"LNK count exceeds {maximum}")
    return records, sources


def mft_evidence(target: Target, pattern: re.Pattern[str], maximum: int) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for record in target.mft(compact=True):
        values = record._asdict()
        path = bounded(values.get("path"), 4096)
        segment = int(values.get("segment") or 0)
        identity = (segment, path.lower())
        if not path or not pattern.search(path) or identity in seen:
            continue
        seen.add(identity)
        matches.append(
            {
                "path": path,
                "segment": segment,
                "creation_time_utc": iso(values.get("creation_time")),
                "last_modification_time_utc": iso(values.get("last_modification_time")),
                "last_change_time_utc": iso(values.get("last_change_time")),
                "last_access_time_utc": iso(values.get("last_access_time")),
                "size": bounded(values.get("filesize"), 128),
                "resident": bool(values.get("resident")),
                "in_use": bool(values.get("inuse")),
            }
        )
        if len(matches) > maximum:
            raise ValueError(f"MFT match count exceeds {maximum}")
    return sorted(matches, key=lambda item: (item["path"].lower(), item["segment"]))


def source_identity(root: Path, path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"source is not a regular file: {path.relative_to(root)}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "path": path.relative_to(root).as_posix(),
        "byte_length": metadata.st_size,
        "sha256": digest.hexdigest(),
    }


def passive_source_paths(root: Path, include_mft: bool) -> list[Path]:
    patterns = (
        "C/Windows/System32/config/SYSTEM*",
        "C/Windows/System32/config/SOFTWARE*",
        "C/Windows/System32/config/SAM*",
        "C/Users/*/NTUSER.DAT*",
        "C/Users/*/ntuser.dat*",
        "C/Windows/Prefetch/*.pf",
    )
    paths: set[Path] = set()
    for pattern in patterns:
        for path in root.glob(pattern):
            if path.is_file() and not path.is_symlink():
                paths.add(path)
    mft = root / "C/$MFT"
    if include_mft and mft.is_file() and not mft.is_symlink():
        paths.add(mft)
    return sorted(paths)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-root", required=True)
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--event-id", type=int, action="append")
    parser.add_argument("--mft-pattern")
    parser.add_argument(
        "--skip-mft",
        action="store_true",
        help="Skip the separately bounded but potentially slow MFT pass",
    )
    parser.add_argument("--max-events", type=int, default=25_000)
    parser.add_argument("--max-prefetch", type=int, default=10_000)
    parser.add_argument("--max-lnk", type=int, default=10_000)
    parser.add_argument("--max-mft-matches", type=int, default=10_000)
    return parser.parse_args()


def main() -> int:
    options = arguments()
    root = Path(options.host_root).resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("host root must be a real directory")
    host_id = bounded(options.host_id, 128)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", host_id):
        raise ValueError("host ID is invalid")
    start = parse_time(options.start)
    end = parse_time(options.end)
    if start and end and start > end:
        raise ValueError("start must not be after end")
    target = Target.open(str(root))
    logs_root = root / "C/Windows/System32/winevt/Logs"
    event_ids = set(options.event_id or DEFAULT_EVENT_IDS)
    events, event_sources = event_evidence(
        logs_root, start, end, event_ids, options.max_events
    )
    histories, history_sources = history_evidence(root)
    links, link_sources = lnk_evidence(root, options.max_lnk)
    pattern = (
        re.compile(options.mft_pattern, re.IGNORECASE)
        if options.mft_pattern
        else DEFAULT_MFT_PATTERN
    )
    source_paths = sorted(
        set(
            event_sources
            + history_sources
            + link_sources
            + passive_source_paths(root, include_mft=not options.skip_mft)
        )
    )
    result = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"id": "templar.windows-evidence", "version": TOOL_VERSION},
        "host_id": host_id,
        "time_filter": {"start_utc": iso(start), "end_utc": iso(end)},
        "source_files": [source_identity(root, path) for path in source_paths],
        "registry": registry_evidence(target),
        "prefetch": prefetch_evidence(target, options.max_prefetch),
        "events": events,
        "powershell_histories": histories,
        "recent_links": links,
        "mft_matches": (
            [] if options.skip_mft else mft_evidence(target, pattern, options.max_mft_matches)
        ),
    }
    json.dump(result, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        sys.stderr.write(f"windows_evidence failed: {type(error).__name__}: {error}\n")
        raise SystemExit(1) from error
