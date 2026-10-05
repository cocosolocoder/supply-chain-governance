"""Parsing, validation and matching of local OSV vulnerability files.

The responsibilities are kept as separate layers so each rule can be
maintained on its own:

1. record/envelope validation (:func:`parse_osv_record`);
2. affected-entry validation (:func:`parse_affected_entry`) — every entry
   independently supplies its own version conditions and package identity;
3. ECOSYSTEM range interpretation (:func:`parse_ecosystem_range` and
   :func:`parse_ecosystem_events`) — event order, interval bounds and PEP 440
   parsing of event versions;
4. package merging (:func:`merge_entry_conditions`) — only already-valid
   entries merge, by normalized PyPI package name;
5. version matching and human-readable condition descriptions
   (:func:`condition_matches`, :func:`format_condition`).

Validation functions carry the JSON location (record/affected/range/event
indices) in their own error messages; higher layers only prepend their own
position. The plain-dict condition shape produced here is also what gets
persisted as JSON, so records saved by older releases keep matching.
"""

from __future__ import annotations

import re
from datetime import datetime

from packaging.version import InvalidVersion, Version


# ---------------------------------------------------------------------------
# Shared small primitives
# ---------------------------------------------------------------------------

def normalize_pypi_name(name: str) -> str:
    """Normalize a PyPI package name per PEP 503.

    Case is folded and runs of hyphens, underscores and dots are treated as
    equivalent. Component identities are kept verbatim; this normalization
    is only used to match OSV records against components and to merge
    entries of the same record.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_pep440_version(value: object, context: str) -> Version:
    """Parse a version that must be a non-empty PEP 440 string.

    ``context`` is the JSON location of the value and is quoted back in the
    error so the offending field can be located.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} 必须为非空字符串")
    try:
        return Version(value.strip())
    except InvalidVersion as error:
        raise ValueError(f"无法解析的版本 {value!r}（{context}）") from error


def parse_withdrawn(value: object) -> str:
    """Validate the optional withdrawn timestamp; keep the original text."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("withdrawn 必须为非空时间戳字符串")
    timestamp = value.strip()
    try:
        datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise ValueError(f"withdrawn 时间戳无效: {timestamp!r}") from error
    return timestamp


# ---------------------------------------------------------------------------
# Layer 3: ECOSYSTEM range interpretation
# ---------------------------------------------------------------------------

def parse_ecosystem_events(events: object, range_path: str) -> list[dict]:
    """Interpret the event list of one ECOSYSTEM range.

    ``range_path`` is the JSON location of the owning range, e.g.
    ``affected[0].ranges[1]``; event and interval errors quote that location
    plus their own index.

    Events alternate ``introduced`` with at most one closing ``fixed``/
    ``last_affected``; a trailing ``introduced`` describes an open interval.
    Every bound other than the special ``introduced == "0"`` must be a
    parseable PEP 440 version, and a closed interval's lower bound must not
    pass its upper bound. The returned conditions are interval dicts in
    event order.
    """
    intervals: list[dict] = []
    opened = False
    for event_index, event in enumerate(events):
        prefix = f"{range_path}.events[{event_index}]"
        if not isinstance(event, dict):
            raise ValueError(f"{prefix} 必须为对象")
        keys = set(event.keys())
        if len(keys) != 1:
            raise ValueError(f"{prefix} 必须恰好包含一个事件字段")
        key = next(iter(keys))
        if key not in ("introduced", "fixed", "last_affected"):
            raise ValueError(f"{prefix} 的事件类型 {key!r} 不受支持")
        value = event[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{prefix}.{key} 必须为非空字符串")
        value = value.strip()
        if key == "introduced":
            if opened:
                raise ValueError(
                    f"{prefix} 事件次序非法：introduced 之后不能再次 introduced"
                )
            intervals.append(
                {"type": "interval", "introduced": value,
                 "fixed": None, "last_affected": None}
            )
            opened = True
        else:
            if not opened:
                raise ValueError(
                    f"{prefix} 事件次序非法：{key} 之前缺少 introduced"
                )
            intervals[-1][key] = value
            opened = False

    for interval in intervals:
        introduced = interval["introduced"]
        if introduced != "0":
            parse_pep440_version(introduced, f"{range_path}.introduced")
        if interval["fixed"] is not None:
            fixed = interval["fixed"]
            parse_pep440_version(fixed, f"{range_path}.fixed")
            if introduced != "0" and not (
                Version(introduced) < Version(fixed)
            ):
                raise ValueError(
                    f"{range_path} 区间倒置："
                    f"introduced {introduced} 必须小于 fixed {fixed}"
                )
        if interval["last_affected"] is not None:
            last_affected = interval["last_affected"]
            parse_pep440_version(last_affected, f"{range_path}.last_affected")
            if introduced != "0" and not (
                Version(introduced) <= Version(last_affected)
            ):
                raise ValueError(
                    f"{range_path} 区间倒置："
                    f"introduced {introduced} 不能大于 last_affected "
                    f"{last_affected}"
                )
    return intervals


def parse_ecosystem_range(
    range_entry: object, *, entry_path: str, range_index: int
) -> list[dict]:
    """Validate one ranges[] object and return its interval conditions."""
    range_path = f"{entry_path}.ranges[{range_index}]"
    if not isinstance(range_entry, dict):
        raise ValueError(f"{range_path} 必须为对象")
    range_type = range_entry.get("type")
    if not isinstance(range_type, str) or not range_type.strip():
        raise ValueError(f"{range_path}.type 必须为非空字符串")
    if range_type.strip().upper() != "ECOSYSTEM":
        raise ValueError(
            f"{range_path} 的范围类型 {range_type!r} 不受支持，仅支持 ECOSYSTEM"
        )
    events = range_entry.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError(f"{range_path}.events 必须为非空数组")
    return parse_ecosystem_events(events, range_path)


# ---------------------------------------------------------------------------
# Layer 2: affected-entry validation
# ---------------------------------------------------------------------------

def parse_affected_entry(entry: object, index: int) -> tuple[str, list[dict]]:
    """Validate one affected entry on its own.

    Returns the normalized package name and that entry's own version
    conditions (explicit versions first, then range intervals, in declared
    order). The entry is validated independently of any sibling entry: an
    entry without non-empty conditions is rejected here, never by reference
    to another entry. ``entry_path`` (``affected[index]``) is the location
    prefix used by every error raised while parsing the entry.
    """
    entry_path = f"affected[{index}]"
    if not isinstance(entry, dict):
        raise ValueError(f"{entry_path} 必须为对象")
    package = entry.get("package")
    if not isinstance(package, dict):
        raise ValueError(f"{entry_path}.package 必须为对象")
    ecosystem = package.get("ecosystem")
    if not isinstance(ecosystem, str) or not ecosystem.strip():
        raise ValueError(f"{entry_path}.package.ecosystem 必须为非空字符串")
    if ecosystem.strip().lower() != "pypi":
        raise ValueError(
            f"{entry_path} 的生态系统 {ecosystem!r} 不受支持，仅支持 PyPI"
        )
    name = package.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{entry_path}.package.name 必须为非空字符串")
    raw_name = name.strip()
    package_name = normalize_pypi_name(raw_name)

    conditions: list[dict] = []

    versions = entry.get("versions", [])
    if not isinstance(versions, list):
        raise ValueError(f"{entry_path}.versions 必须为数组")
    for version in versions:
        parsed = parse_pep440_version(version, f"{entry_path}.versions")
        conditions.append({"type": "explicit", "version": str(parsed)})

    ranges = entry.get("ranges", [])
    if not isinstance(ranges, list):
        raise ValueError(f"{entry_path}.ranges 必须为数组")
    for range_index, range_entry in enumerate(ranges):
        conditions.extend(
            parse_ecosystem_range(
                range_entry, entry_path=entry_path, range_index=range_index
            )
        )

    if not conditions:
        raise ValueError(
            f"{entry_path}（包 {raw_name}）缺少版本条件："
            "必须提供非空 versions 或至少一个合法 ECOSYSTEM ranges"
        )
    return package_name, conditions


# ---------------------------------------------------------------------------
# Layer 4: merge validated entries by normalized package name
# ---------------------------------------------------------------------------

def merge_entry_conditions(entries: list[tuple[str, list[dict]]]) -> dict[str, list[dict]]:
    """Merge validated entry conditions keyed by normalized package name.

    Every entry has already passed :func:`parse_affected_entry`, so merging
    never rescues an entry that lacked conditions: conditions of valid
    entries for the same normalized name are concatenated in entry order,
    producing one (vulnerability, package) combination instead of one per
    entry.
    """
    packages: dict[str, list[dict]] = {}
    for package_name, conditions in entries:
        packages.setdefault(package_name, []).extend(conditions)
    return packages


def parse_affected(affected: object) -> dict[str, list[dict]]:
    """Validate the affected array of one OSV record.

    All entries are validated independently first; only then do their
    conditions merge by normalized PyPI package name. Identical or
    normalization-equivalent package names therefore never let one entry
    borrow another entry's conditions. Other ecosystems, unknown range
    types/events, malformed event orders, inverted intervals and
    unparseable versions reject the whole record.
    """
    if not isinstance(affected, list) or not affected:
        raise ValueError("affected 必须为非空数组")
    validated = [
        parse_affected_entry(entry, index)
        for index, entry in enumerate(affected)
    ]
    return merge_entry_conditions(validated)


# ---------------------------------------------------------------------------
# Layer 1: record/envelope validation
# ---------------------------------------------------------------------------

_SEVERITIES = ("low", "medium", "high", "critical")


def parse_osv_record(record: object) -> list[dict]:
    """Validate one OSV record and return its normalized rows.

    Each returned row describes one (package, version conditions) pair. The
    whole record is validated before anything is returned, so callers can
    reject the entire import on the first invalid record.
    """
    if not isinstance(record, dict):
        raise ValueError("记录必须为 JSON 对象")
    identifier = record.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("id 必须为非空字符串")
    identifier = identifier.strip()

    packages = parse_affected(record.get("affected"))

    severity = "medium"
    severity_default = True
    database_specific = record.get("database_specific")
    if database_specific is not None:
        if not isinstance(database_specific, dict):
            raise ValueError("database_specific 必须为对象")
        declared = database_specific.get("severity")
        if declared is not None:
            if not isinstance(declared, str) or declared.strip().lower() not in _SEVERITIES:
                raise ValueError(
                    f"database_specific.severity {declared!r} 不受支持，"
                    "仅接受 low、medium、high、critical"
                )
            severity = declared.strip().lower()
            severity_default = False

    withdrawn = None
    if "withdrawn" in record:
        withdrawn = parse_withdrawn(record["withdrawn"])

    return [
        {
            "id": identifier,
            "package_name": package_name,
            "severity": severity,
            "severity_default": severity_default,
            "withdrawn": withdrawn,
            "conditions": conditions,
        }
        for package_name, conditions in packages.items()
    ]


# ---------------------------------------------------------------------------
# Layer 5: PEP 440 matching and condition descriptions
# ---------------------------------------------------------------------------

def condition_matches(condition: dict, version: Version) -> bool:
    """Whether one explicit/interval condition covers ``version``.

    Explicit conditions use PEP 440 equality, so prereleases and local
    versions participate normally. ``introduced == "0"`` means no lower
    bound; a ``fixed`` version is itself unaffected while ``last_affected``
    is still affected. Ranges may be open-ended and a fixed interval can be
    followed by a later introduced one.
    """
    if condition["type"] == "explicit":
        return version == Version(condition["version"])
    if condition["type"] != "interval":
        return False
    introduced = condition["introduced"]
    if introduced != "0" and version < Version(introduced):
        return False
    if condition["fixed"] is not None and version >= Version(condition["fixed"]):
        return False
    if condition["last_affected"] is not None and version > Version(
        condition["last_affected"]
    ):
        return False
    return True


def format_condition(condition: dict) -> str:
    """Describe one condition in the user-facing explanation order."""
    if condition["type"] == "explicit":
        return f"=={condition['version']}"
    parts: list[str] = []
    introduced = condition["introduced"]
    if introduced != "0":
        parts.append(f">={introduced}")
    if condition["fixed"] is not None:
        parts.append(f"<{condition['fixed']}")
    if condition["last_affected"] is not None:
        parts.append(f"<={condition['last_affected']}")
    return ",".join(parts) if parts else "*"


def matched_condition_texts(conditions: list[dict], version: Version) -> list[str]:
    """Descriptions of every condition covering ``version``, in stored order.

    Returns an empty list when nothing matches. The order is the conditions'
    own order (explicit versions then range intervals), so an indirect
    component's explanation stays tied to the direct-hit version of the path
    that explains it and never mixes in another version's conditions.
    """
    return [
        format_condition(condition)
        for condition in conditions
        if condition_matches(condition, version)
    ]
