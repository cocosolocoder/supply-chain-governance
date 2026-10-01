from __future__ import annotations

import itertools
import json
import re
import sqlite3
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS components (
    id INTEGER PRIMARY KEY,
    service TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    manual INTEGER NOT NULL DEFAULT 0,
    UNIQUE(service, ecosystem, name, version)
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT NOT NULL,
    component_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    PRIMARY KEY(id, component_name)
);
CREATE TABLE IF NOT EXISTS dependencies (
    id INTEGER PRIMARY KEY,
    dependent_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    dependency_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    manual INTEGER NOT NULL DEFAULT 0,
    UNIQUE(dependent_id, dependency_id)
);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    service TEXT NOT NULL,
    name TEXT NOT NULL,
    UNIQUE(service, name)
);
CREATE TABLE IF NOT EXISTS component_sources (
    component_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    PRIMARY KEY(component_id, source_id)
);
CREATE TABLE IF NOT EXISTS dependency_sources (
    dependency_id INTEGER NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    PRIMARY KEY(dependency_id, source_id)
);
CREATE TABLE IF NOT EXISTS osv_sources (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS osv_vulnerabilities (
    id INTEGER PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES osv_sources(id) ON DELETE CASCADE,
    vid TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    severity_defaulted INTEGER NOT NULL DEFAULT 0,
    withdrawn TEXT,
    UNIQUE(source_id, vid)
);
CREATE TABLE IF NOT EXISTS osv_affected (
    id INTEGER PRIMARY KEY,
    osv_vulnerability_id INTEGER NOT NULL REFERENCES osv_vulnerabilities(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    UNIQUE(osv_vulnerability_id, package_name)
);
CREATE TABLE IF NOT EXISTS osv_versions (
    osv_affected_id INTEGER NOT NULL REFERENCES osv_affected(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    PRIMARY KEY(osv_affected_id, version)
);
CREATE TABLE IF NOT EXISTS osv_ranges (
    id INTEGER PRIMARY KEY,
    osv_affected_id INTEGER NOT NULL REFERENCES osv_affected(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS osv_events (
    id INTEGER PRIMARY KEY,
    range_id INTEGER NOT NULL REFERENCES osv_ranges(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    introduced TEXT,
    fixed TEXT,
    last_affected TEXT
);
"""

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

SUPPORTED_ECOSYSTEMS = ("pypi", "npm")


@dataclass(frozen=True)
class Summary:
    components: int
    affected_components: int
    vulnerabilities: int
    highest_severity: str | None


@dataclass(frozen=True)
class ImportResult:
    source_components: int
    added_components: int
    deleted_components: int
    added_dependencies: int
    deleted_dependencies: int


def parse_purl(purl: object) -> tuple[str, str, str]:
    """Return (ecosystem, name, version) from a Package URL.

    Percent-encoding is decoded and npm package names keep their scope.
    Raises ValueError when the purl is missing, malformed, unsupported or
    carries no version.
    """
    if not isinstance(purl, str) or not purl:
        raise ValueError("purl 必须为非空字符串")
    if not purl.startswith("pkg:"):
        raise ValueError("purl 必须以 pkg: 开头")
    rest = purl[4:]
    if "/" not in rest:
        raise ValueError("purl 格式无效")
    raw_type, path = rest.split("/", 1)
    ecosystem = unquote(raw_type).lower()
    if ecosystem not in SUPPORTED_ECOSYSTEMS:
        raise ValueError(f"不支持的包类型: {ecosystem}")
    # Strip qualifiers (?...) and subpath (#...).
    path = path.split("?", 1)[0].split("#", 1)[0]
    if "@" not in path:
        raise ValueError("purl 缺少版本")
    name_part, version = path.rsplit("@", 1)
    version = unquote(version)
    if not version:
        raise ValueError("purl 版本为空")
    segments = [unquote(segment) for segment in name_part.split("/") if segment != ""]
    if ecosystem == "npm":
        if len(segments) == 1:
            name = segments[0]
        elif len(segments) == 2:
            name = segments[0] + "/" + segments[1]
        else:
            raise ValueError("npm purl 格式无效")
    else:
        if len(segments) != 1:
            raise ValueError("pypi purl 不应包含命名空间")
        name = segments[0]
    if not name:
        raise ValueError("purl 包名为空")
    return ecosystem, name, version


def _parse_sbom(sbom: object) -> tuple[set[tuple[str, str, str]], set[tuple[tuple[str, str, str], tuple[str, str, str]]]]:
    """Validate a CycloneDX 1.5 SBOM and return (identities, edges).

    identities is the set of (ecosystem, name, version) tuples registered
    under the importing service. edges is a set of (dependent, dependency)
    identity pairs. All validation happens before any database write.
    """
    if not isinstance(sbom, dict):
        raise ValueError("清单必须是 JSON 对象")
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("bomFormat 必须为 CycloneDX")
    if sbom.get("specVersion") != "1.5":
        raise ValueError("specVersion 必须为 1.5")
    if "components" not in sbom:
        raise ValueError("缺少 components 字段")
    components = sbom["components"]
    if not isinstance(components, list):
        raise ValueError("components 必须为数组")

    root_ref: str | None = None
    metadata = sbom.get("metadata")
    if isinstance(metadata, dict):
        root_component = metadata.get("component")
        if isinstance(root_component, dict) and "bom-ref" in root_component:
            root_ref = root_component["bom-ref"]
            if not isinstance(root_ref, str) or not root_ref:
                raise ValueError("metadata.component.bom-ref 必须为非空字符串")

    identities: dict[str, tuple[str, str, str]] = {}
    identity_set: set[tuple[str, str, str]] = set()
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise ValueError(f"components[{index}] 必须为对象")
        nested = component.get("components")
        if isinstance(nested, list) and nested:
            raise ValueError(f"components[{index}] 存在嵌套组件，不予登记")
        ref = component.get("bom-ref")
        if not isinstance(ref, str) or not ref:
            raise ValueError(f"components[{index}] 的 bom-ref 必须为非空字符串")
        if ref in identities:
            raise ValueError(f"bom-ref 重复: {ref}")
        if root_ref is not None and ref == root_ref:
            raise ValueError(f"bom-ref 与 metadata.component 根引用冲突: {ref}")
        purl = component.get("purl")
        try:
            ecosystem, name, version = parse_purl(purl)
        except ValueError as error:
            raise ValueError(
                f"components[{index}] (bom-ref {ref}) purl 无效: {error}"
            ) from error
        if "version" in component:
            version_field = component["version"]
            if not isinstance(version_field, str) or not version_field:
                raise ValueError(
                    f"components[{index}] (bom-ref {ref}) version 必须为非空字符串"
                )
            if version_field != version:
                raise ValueError(
                    f"components[{index}] (bom-ref {ref}) version 与 purl 版本不一致"
                )
        identity = (ecosystem, name, version)
        identities[ref] = identity
        identity_set.add(identity)

    edges: set[tuple[tuple[str, str, str], tuple[str, str, str]]] = set()
    dependencies = sbom.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("dependencies 必须为数组")
    for index, entry in enumerate(dependencies):
        if not isinstance(entry, dict):
            raise ValueError(f"dependencies[{index}] 必须为对象")
        ref = entry.get("ref")
        if not isinstance(ref, str) or not ref:
            raise ValueError(f"dependencies[{index}].ref 必须为非空字符串")
        depends_on = entry.get("dependsOn", [])
        if not isinstance(depends_on, list):
            raise ValueError(f"dependencies[{index}].dependsOn 必须为数组")
        if ref == root_ref:
            # The list root's own outgoing edges are not registered.
            continue
        if ref not in identities:
            raise ValueError(f"dependencies[{index}].ref 引用未知组件: {ref}")
        dependent_identity = identities[ref]
        for target in depends_on:
            if not isinstance(target, str) or not target:
                raise ValueError(
                    f"dependencies[{index}].dependsOn 必须为非空字符串数组"
                )
            if target == root_ref:
                raise ValueError(
                    f"dependencies[{index}] 组件 {ref} 依赖了 metadata.component 根引用"
                )
            if target not in identities:
                raise ValueError(
                    f"dependencies[{index}] 依赖引用未知组件: {target}"
                )
            dependency_identity = identities[target]
            if dependent_identity == dependency_identity:
                raise ValueError(
                    f"合并后产生自依赖: {ref} -> {target}"
                )
            edges.add((dependent_identity, dependency_identity))

    return identity_set, edges


# --- PEP 440 version comparison ---------------------------------------------
#
# A self-contained implementation of the PEP 440 ordering rules (the project
# ships without third-party dependencies). Comparison keys mirror the standard
# packaging semantics, including pre/post/dev releases and local versions.

_VERSION_PATTERN = r"""
    v?
    (?:
        (?:(?P<epoch>[0-9]+)!)?
        (?P<release>[0-9]+(?:\.[0-9]+)*)
        (?P<pre>
            [-_\.]?
            (?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)
            [-_\.]?
            (?P<pre_n>[0-9]+)?
        )?
        (?P<post>
            (?:-(?P<post_n1>[0-9]+))
            |
            (?:
                [-_\.]?
                (?P<post_l>post|rev|r)
                [-_\.]?
                (?P<post_n2>[0-9]+)?
            )
        )?
        (?P<dev>
            [-_\.]?
            (?P<dev_l>dev)
            [-_\.]?
            (?P<dev_n>[0-9]+)?
        )?
    )
    (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?
"""
_VERSION_RE = re.compile(
    r"^\s*" + _VERSION_PATTERN + r"\s*$", re.VERBOSE | re.IGNORECASE
)
_LOCAL_SEPARATORS = re.compile(r"[._-]")


class InvalidVersion(ValueError):
    """Raised when a string is not a valid PEP 440 version."""


class _Infinity:
    __slots__ = ()

    def __repr__(self) -> str:
        return "Infinity"

    def __lt__(self, other: object) -> bool:
        return False

    def __le__(self, other: object) -> bool:
        return False

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Infinity)

    def __gt__(self, other: object) -> bool:
        return True

    def __ge__(self, other: object) -> bool:
        return True

    def __neg__(self) -> "_NegativeInfinity":
        return _NEGATIVE_INFINITY

    def __hash__(self) -> int:
        return hash("Infinity")


class _NegativeInfinity:
    __slots__ = ()

    def __repr__(self) -> str:
        return "-Infinity"

    def __lt__(self, other: object) -> bool:
        return True

    def __le__(self, other: object) -> bool:
        return True

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _NegativeInfinity)

    def __gt__(self, other: object) -> bool:
        return False

    def __ge__(self, other: object) -> bool:
        return False

    def __hash__(self) -> int:
        return hash("-Infinity")


_INFINITY = _Infinity()
_NEGATIVE_INFINITY = _NegativeInfinity()


def _parse_letter_version(letter, number):
    if letter:
        if number is None:
            number = 0
        letter = letter.lower()
        if letter == "alpha":
            letter = "a"
        elif letter == "beta":
            letter = "b"
        elif letter in ("c", "pre", "preview"):
            letter = "rc"
        elif letter in ("rev", "r"):
            letter = "post"
        return letter, int(number)
    if not letter and number:
        return "post", int(number)
    return None


def _parse_local_version(local):
    if local is not None:
        return tuple(
            part.lower() if not part.isdigit() else int(part)
            for part in _LOCAL_SEPARATORS.split(local)
        )
    return None


def _cmpkey(epoch, release, pre, post, dev, local):
    trimmed = tuple(
        reversed(list(itertools.dropwhile(lambda x: x == 0, reversed(release))))
    )
    if pre is None and post is None and dev is not None:
        pre_key = _NEGATIVE_INFINITY
    elif pre is None:
        pre_key = _INFINITY
    else:
        pre_key = pre
    post_key = _NEGATIVE_INFINITY if post is None else post
    dev_key = _INFINITY if dev is None else dev
    if local is None:
        local_key = _NEGATIVE_INFINITY
    else:
        local_key = tuple(
            (segment, "") if isinstance(segment, int) else (_NEGATIVE_INFINITY, segment)
            for segment in local
        )
    return epoch, trimmed, pre_key, post_key, dev_key, local_key


def parse_pep440(version: object):
    """Parse a PEP 440 version string into an opaque, comparable key.

    Raises InvalidVersion (a ValueError) when the string cannot be parsed.
    """
    if not isinstance(version, str) or not version.strip():
        raise InvalidVersion(f"无效的版本: {version!r}")
    match = _VERSION_RE.search(version)
    if match is None:
        raise InvalidVersion(f"无效的 PEP 440 版本: {version!r}")
    return _cmpkey(
        int(match.group("epoch")) if match.group("epoch") else 0,
        tuple(int(part) for part in match.group("release").split(".")),
        _parse_letter_version(match.group("pre_l"), match.group("pre_n")),
        _parse_letter_version(
            match.group("post_l"),
            match.group("post_n1") or match.group("post_n2"),
        ),
        _parse_letter_version(match.group("dev_l"), match.group("dev_n")),
        _parse_local_version(match.group("local")),
    )


def normalize_pypi_name(name: str) -> str:
    """PEP 503 style normalization: case-insensitive, runs of ._- equivalent."""
    return re.sub(r"[-_.]+", "-", name).lower()


# --- OSV record parsing ------------------------------------------------------


@dataclass(frozen=True)
class OsvAffected:
    package: str
    versions: tuple[str, ...]
    # One tuple of events per ECOSYSTEM range; intervals never cross ranges.
    ranges: tuple[tuple[tuple[str, str | None], ...], ...]


@dataclass(frozen=True)
class OsvRecord:
    id: str
    severity: str
    severity_defaulted: bool
    withdrawn: str | None
    affected: tuple[OsvAffected, ...]


VALID_SEVERITIES = ("low", "medium", "high", "critical")


def _require_object(value, label: str, record_id: str | None) -> dict:
    if not isinstance(value, dict):
        where = f"记录 {record_id} " if record_id is not None else ""
        raise ValueError(f"{where}{label} 必须是对象")
    return value


def _require_list(value, label: str, record_id: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"记录 {record_id} {label} 必须是数组")
    return value


def _parse_withdrawn(value, record_id: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"记录 {record_id} withdrawn 必须是非空字符串")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        datetime.fromisoformat(text)
    except ValueError as error:
        raise ValueError(f"记录 {record_id} withdrawn 时间无效: {value}") from error
    return value.strip()


def _event_bound(
    value, record_id: str, kind: str, index: int
) -> str | None:
    """Return the normalized value of an introduced/fixed/last_affected event."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"记录 {record_id} affected[{index}] ranges 事件 {kind} 值必须是非空字符串"
        )
    text = value.strip()
    if kind != "introduced" or text != "0":
        try:
            parse_pep440(text)
        except InvalidVersion as error:
            raise ValueError(
                f"记录 {record_id} affected[{index}] ranges 事件 {kind} 版本无法解析: "
                f"{value}"
            ) from error
    return text


def _parse_range_events(events, record_id: str, index: int):
    events = _require_list(events, "ranges[].events", record_id)
    if not events:
        raise ValueError(
            f"记录 {record_id} affected[{index}] ranges 的 events 不能为空"
        )
    parsed: list[tuple[str, str | None]] = []
    for event_index, event in enumerate(events):
        event = _require_object(
            event, f"ranges[].events[{event_index}]", record_id
        )
        known = ("introduced", "fixed", "last_affected")
        kinds = [kind for kind in known if kind in event]
        if len(kinds) != 1:
            raise ValueError(
                f"记录 {record_id} affected[{index}] events[{event_index}] "
                "必须只包含 introduced/fixed/last_affected 之一"
            )
        kind = kinds[0]
        extras = [key for key in event if key not in known]
        if extras:
            raise ValueError(
                f"记录 {record_id} affected[{index}] events[{event_index}] "
                f"含不支持的事件字段: {', '.join(sorted(extras))}"
            )
        parsed.append((kind, _event_bound(event[kind], record_id, kind, index)))
    return tuple(parsed)


def _parse_osv_record(record: object, index: int) -> OsvRecord:
    location = f"records[{index}]"
    if not isinstance(record, dict):
        raise ValueError(f"{location} 必须是对象")
    identifier = record.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError(f"{location} 缺少非空 id")
    record_id = identifier.strip()

    database_specific = record.get("database_specific")
    severity = "medium"
    severity_defaulted = True
    if database_specific is not None:
        database_specific = _require_object(
            database_specific, "database_specific", record_id
        )
        if "severity" in database_specific:
            raw = database_specific["severity"]
            if not isinstance(raw, str) or raw.strip().lower() not in VALID_SEVERITIES:
                raise ValueError(
                    f"记录 {record_id} severity 必须是 low/medium/high/critical 之一"
                )
            severity = raw.strip().lower()
            severity_defaulted = False

    withdrawn = _parse_withdrawn(record.get("withdrawn"), record_id)

    affected_entries = record.get("affected", [])
    if "affected" in record:
        affected_entries = _require_list(affected_entries, "affected", record_id)
    affected: list[OsvAffected] = []
    for affected_index, entry in enumerate(affected_entries):
        entry = _require_object(entry, f"affected[{affected_index}]", record_id)
        package = entry.get("package")
        package = _require_object(package, f"affected[{affected_index}].package", record_id)
        ecosystem = package.get("ecosystem")
        if not isinstance(ecosystem, str) or not ecosystem.strip():
            raise ValueError(
                f"记录 {record_id} affected[{affected_index}] 缺少非空 ecosystem"
            )
        if ecosystem.strip().lower() != "pypi":
            raise ValueError(
                f"记录 {record_id} affected[{affected_index}] 不支持的生态: {ecosystem}"
            )
        name = package.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(
                f"记录 {record_id} affected[{affected_index}] 缺少非空 PyPI 包名"
            )
        name = name.strip()

        versions: list[str] = []
        if "versions" in entry:
            raw_versions = _require_list(
                entry["versions"], f"affected[{affected_index}].versions", record_id
            )
            for raw_version in raw_versions:
                if not isinstance(raw_version, str) or not raw_version.strip():
                    raise ValueError(
                        f"记录 {record_id} affected[{affected_index}] "
                        "versions 必须为非空字符串数组"
                    )
                text = raw_version.strip()
                try:
                    parse_pep440(text)
                except InvalidVersion as error:
                    raise ValueError(
                        f"记录 {record_id} affected[{affected_index}] "
                        f"漏洞版本无法解析: {raw_version}"
                    ) from error
                if text not in versions:
                    versions.append(text)

        ranges_events: list[tuple[tuple[str, str | None], ...]] = []
        if "ranges" in entry:
            ranges = _require_list(
                entry["ranges"], f"affected[{affected_index}].ranges", record_id
            )
            for range_entry in ranges:
                range_entry = _require_object(
                    range_entry,
                    f"affected[{affected_index}].ranges[]",
                    record_id,
                )
                range_type = range_entry.get("type")
                if range_type != "ECOSYSTEM":
                    raise ValueError(
                        f"记录 {record_id} affected[{affected_index}] "
                        f"不支持的 range 类型: {range_type}"
                    )
                range_events = _parse_range_events(
                    range_entry.get("events"), record_id, affected_index
                )
                _validate_range_order(range_events, record_id, affected_index)
                ranges_events.append(range_events)

        if not versions and not ranges_events:
            raise ValueError(
                f"记录 {record_id} affected[{affected_index}] 没有有效的版本条件"
            )
        affected.append(OsvAffected(name, tuple(versions), tuple(ranges_events)))

    if not affected:
        raise ValueError(f"记录 {record_id} 缺少有效的 affected 条目")

    # Merge entries that reference the exact same PyPI package: their explicit
    # versions and ranges already combine as a union when matching.
    merged: dict[str, OsvAffected] = {}
    order: list[str] = []
    for entry in affected:
        if entry.package in merged:
            current = merged[entry.package]
            versions = list(current.versions)
            for version in entry.versions:
                if version not in versions:
                    versions.append(version)
            merged[entry.package] = OsvAffected(
                entry.package,
                tuple(versions),
                current.ranges + entry.ranges,
            )
        else:
            merged[entry.package] = entry
            order.append(entry.package)
    affected_entries = tuple(merged[package] for package in order)
    return OsvRecord(
        record_id, severity, severity_defaulted, withdrawn, affected_entries
    )


def _validate_range_order(events, record_id: str, index: int) -> None:
    """Validate the event stream and the intervals it describes.

    introduced opens an interval, fixed/last_affected closes it. A fixed
    version must be strictly greater than its introducing version and an
    interval may not be fixed before it is (re)introduced.
    """
    opened: str | None = None
    for event_index, (kind, value) in enumerate(events):
        if kind == "introduced":
            if opened is not None:
                raise ValueError(
                    f"记录 {record_id} affected[{index}] events[{event_index}] "
                    "在区间未结束时再次 introduced"
                )
            opened = value
        else:
            if opened is None:
                raise ValueError(
                    f"记录 {record_id} affected[{index}] events[{event_index}] "
                    f"{kind} 之前没有 introduced"
                )
            if opened != "0" and parse_pep440(value) <= parse_pep440(opened):
                raise ValueError(
                    f"记录 {record_id} affected[{index}] 区间倒置: "
                    f"{opened} 之后 {kind} {value}"
                )
            opened = None


def parse_osv_documents(document: object) -> list[OsvRecord]:
    """Validate an OSV document (a JSON array of records).

    Every record is validated before anything is written, so a failed import
    leaves existing data untouched.
    """
    if not isinstance(document, list):
        raise ValueError("OSV 文件必须是记录数组")
    records: list[OsvRecord] = []
    seen: set[str] = set()
    for index, entry in enumerate(document):
        record = _parse_osv_record(entry, index)
        if record.id in seen:
            raise ValueError(f"文件内漏洞 id 重复: {record.id}")
        seen.add(record.id)
        records.append(record)
    return records


class Catalog:
    def __init__(self, database: str | Path = ":memory:") -> None:
        self.connection = sqlite3.connect(str(database))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Add ownership columns to databases created by earlier releases.

        Components and relationships already present are considered manually
        registered, so they survive source replacement.
        """
        component_columns = {
            str(row["name"])
            for row in self.connection.execute("PRAGMA table_info(components)")
        }
        if "manual" not in component_columns:
            self.connection.execute(
                "ALTER TABLE components ADD COLUMN manual INTEGER NOT NULL DEFAULT 0"
            )
            self.connection.execute("UPDATE components SET manual = 1")
        dependency_columns = {
            str(row["name"])
            for row in self.connection.execute("PRAGMA table_info(dependencies)")
        }
        if "manual" not in dependency_columns:
            self.connection.execute(
                "ALTER TABLE dependencies ADD COLUMN manual INTEGER NOT NULL DEFAULT 0"
            )
            self.connection.execute("UPDATE dependencies SET manual = 1")
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def add_component(
        self, service: str, ecosystem: str, name: str, version: str
    ) -> None:
        values = tuple(value.strip() for value in (service, ecosystem, name, version))
        if any(not value for value in values):
            raise ValueError("component fields must not be empty")
        with self.connection:
            self.connection.execute(
                "INSERT INTO components(service, ecosystem, name, version, manual) "
                "VALUES (?, ?, ?, ?, 1) "
                "ON CONFLICT(service, ecosystem, name, version) DO UPDATE SET manual = 1",
                values,
            )

    def add_vulnerability(self, identifier: str, component_name: str, severity: str) -> None:
        identifier, component_name, severity = (
            identifier.strip(),
            component_name.strip(),
            severity.strip().lower(),
        )
        if not identifier or not component_name:
            raise ValueError("vulnerability identity must not be empty")
        if severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("unsupported severity")
        with self.connection:
            self.connection.execute(
                "INSERT INTO vulnerabilities(id, component_name, severity) VALUES (?, ?, ?) "
                "ON CONFLICT(id, component_name) DO UPDATE SET severity=excluded.severity",
                (identifier, component_name, severity),
            )

    def _component_id(
        self, service: str, ecosystem: str, name: str, version: str
    ) -> int | None:
        row = self.connection.execute(
            "SELECT id FROM components "
            "WHERE service = ? AND ecosystem = ? AND name = ? AND version = ?",
            (service, ecosystem, name, version),
        ).fetchone()
        return None if row is None else int(row["id"])

    @staticmethod
    def _format_identity(values: tuple[str, ...]) -> str:
        return "/".join(values)

    def add_dependency(
        self,
        service: str,
        ecosystem: str,
        name: str,
        version: str,
        dependency_service: str,
        dependency_ecosystem: str,
        dependency_name: str,
        dependency_version: str,
    ) -> None:
        dependent = tuple(value.strip() for value in (service, ecosystem, name, version))
        dependency = tuple(
            value.strip()
            for value in (
                dependency_service,
                dependency_ecosystem,
                dependency_name,
                dependency_version,
            )
        )
        if any(not value for value in dependent + dependency):
            raise ValueError("dependency fields must not be empty")
        if dependent == dependency:
            raise ValueError("a component cannot depend on itself")
        if dependent[0] != dependency[0]:
            raise ValueError("dependencies must stay within the same service")
        dependent_id = self._component_id(*dependent)
        if dependent_id is None:
            raise ValueError(
                "dependent component is not registered: "
                + self._format_identity(dependent)
            )
        dependency_id = self._component_id(*dependency)
        if dependency_id is None:
            raise ValueError(
                "dependency component is not registered: "
                + self._format_identity(dependency)
            )
        with self.connection:
            self.connection.execute(
                "INSERT INTO dependencies(dependent_id, dependency_id, manual) "
                "VALUES (?, ?, 1) "
                "ON CONFLICT(dependent_id, dependency_id) DO UPDATE SET manual = 1",
                (dependent_id, dependency_id),
            )

    def remove_dependency(
        self,
        service: str,
        ecosystem: str,
        name: str,
        version: str,
        dependency_service: str,
        dependency_ecosystem: str,
        dependency_name: str,
        dependency_version: str,
    ) -> None:
        dependent = tuple(value.strip() for value in (service, ecosystem, name, version))
        dependency = tuple(
            value.strip()
            for value in (
                dependency_service,
                dependency_ecosystem,
                dependency_name,
                dependency_version,
            )
        )
        if any(not value for value in dependent + dependency):
            raise ValueError("dependency fields must not be empty")
        dependent_id = self._component_id(*dependent)
        dependency_id = self._component_id(*dependency)
        if dependent_id is None or dependency_id is None:
            return
        with self.connection:
            # Only revoke the manual registration; relationships still declared
            # by an imported source continue to participate in impact queries.
            self.connection.execute(
                "UPDATE dependencies SET manual = 0 "
                "WHERE dependent_id = ? AND dependency_id = ?",
                (dependent_id, dependency_id),
            )
            self.connection.execute(
                """
                DELETE FROM dependencies
                WHERE dependent_id = ? AND dependency_id = ?
                  AND manual = 0
                  AND NOT EXISTS (
                      SELECT 1 FROM dependency_sources ds
                      WHERE ds.dependency_id = dependencies.id
                  )
                """,
                (dependent_id, dependency_id),
            )

    def import_sbom(
        self, service: str, source_name: str, sbom: object
    ) -> ImportResult:
        """Register the components and dependencies of a CycloneDX 1.5 SBOM.

        The source (service, source_name) is replaced: its previous components
        and relationships lose ownership, and components/relationships no
        longer owned by any source or manually registered are deleted. The
        whole list is validated before any write, so failures leave the
        catalog untouched.
        """
        service = service.strip()
        source_name = source_name.strip()
        if not service or not source_name:
            raise ValueError("service 和 source 名称不能为空")
        identities, edges = _parse_sbom(sbom)

        with self.connection:
            source_row = self.connection.execute(
                "SELECT id FROM sources WHERE service = ? AND name = ?",
                (service, source_name),
            ).fetchone()
            if source_row is None:
                source_id = int(
                    self.connection.execute(
                        "INSERT INTO sources(service, name) VALUES (?, ?)",
                        (service, source_name),
                    ).lastrowid
                )
            else:
                source_id = int(source_row["id"])

            # Drop the previous ownership of this source.
            self.connection.execute(
                "DELETE FROM component_sources WHERE source_id = ?", (source_id,)
            )
            self.connection.execute(
                "DELETE FROM dependency_sources WHERE source_id = ?", (source_id,)
            )

            added_components = 0
            component_ids: dict[tuple[str, str, str], int] = {}
            for ecosystem, name, version in sorted(identities):
                row = self.connection.execute(
                    "SELECT id FROM components "
                    "WHERE service = ? AND ecosystem = ? AND name = ? AND version = ?",
                    (service, ecosystem, name, version),
                ).fetchone()
                if row is None:
                    component_id = int(
                        self.connection.execute(
                            "INSERT INTO components(service, ecosystem, name, version, manual) "
                            "VALUES (?, ?, ?, ?, 0)",
                            (service, ecosystem, name, version),
                        ).lastrowid
                    )
                    added_components += 1
                else:
                    component_id = int(row["id"])
                component_ids[(ecosystem, name, version)] = component_id
                self.connection.execute(
                    "INSERT OR IGNORE INTO component_sources(component_id, source_id) "
                    "VALUES (?, ?)",
                    (component_id, source_id),
                )

            added_dependencies = 0
            for dependent_identity, dependency_identity in sorted(edges):
                dependent_id = component_ids[dependent_identity]
                dependency_id = component_ids[dependency_identity]
                row = self.connection.execute(
                    "SELECT id FROM dependencies "
                    "WHERE dependent_id = ? AND dependency_id = ?",
                    (dependent_id, dependency_id),
                ).fetchone()
                if row is None:
                    dependency_row_id = int(
                        self.connection.execute(
                            "INSERT INTO dependencies(dependent_id, dependency_id, manual) "
                            "VALUES (?, ?, 0)",
                            (dependent_id, dependency_id),
                        ).lastrowid
                    )
                    added_dependencies += 1
                else:
                    dependency_row_id = int(row["id"])
                self.connection.execute(
                    "INSERT OR IGNORE INTO dependency_sources(dependency_id, source_id) "
                    "VALUES (?, ?)",
                    (dependency_row_id, source_id),
                )

            # Orphan cleanup: relationships and components with no source
            # ownership and no manual registration are deleted. Components
            # that are endpoints of a manual relationship are kept.
            orphan_dependency_ids = [
                int(row["id"])
                for row in self.connection.execute(
                    """
                    SELECT d.id FROM dependencies d
                    WHERE d.manual = 0
                      AND NOT EXISTS (
                          SELECT 1 FROM dependency_sources ds
                          WHERE ds.dependency_id = d.id
                      )
                    """
                )
            ]
            for dependency_row_id in orphan_dependency_ids:
                self.connection.execute(
                    "DELETE FROM dependencies WHERE id = ?", (dependency_row_id,)
                )

            orphan_component_ids = [
                int(row["id"])
                for row in self.connection.execute(
                    """
                    SELECT c.id FROM components c
                    WHERE c.manual = 0
                      AND NOT EXISTS (
                          SELECT 1 FROM component_sources cs
                          WHERE cs.component_id = c.id
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM dependencies d
                          WHERE d.manual = 1
                            AND (d.dependent_id = c.id OR d.dependency_id = c.id)
                      )
                    """
                )
            ]
            for component_id in orphan_component_ids:
                self.connection.execute(
                    "DELETE FROM components WHERE id = ?", (component_id,)
                )

        return ImportResult(
            source_components=len(identities),
            added_components=added_components,
            deleted_components=len(orphan_component_ids),
            added_dependencies=added_dependencies,
            deleted_dependencies=len(orphan_dependency_ids),
        )

    def import_sbom_file(
        self, service: str, source_name: str, path: str | Path
    ) -> ImportResult:
        """Read a CycloneDX 1.5 JSON file and import it."""
        try:
            with open(path, "r", encoding="utf-8") as handle:
                sbom = json.load(handle)
        except OSError as error:
            raise ValueError(f"无法读取文件 {path}: {error}") from error
        except json.JSONDecodeError as error:
            raise ValueError(f"文件 {path} 不是有效的 JSON: {error}") from error
        return self.import_sbom(service, source_name, sbom)

    # --- OSV imports -------------------------------------------------------

    def import_osv(self, source_name: str, document: object) -> int:
        """Replace every OSV record of ``source_name`` with ``document``.

        The document is an array of OSV records. Validation of every record
        completes before any write, so an invalid import leaves the catalog
        untouched. An empty array clears the source. Records belonging to
        other sources and manually registered vulnerabilities are preserved.
        Returns the number of imported records.
        """
        source_name = source_name.strip() if isinstance(source_name, str) else ""
        if not source_name:
            raise ValueError("OSV 来源名称不能为空")
        records = parse_osv_documents(document)

        with self.connection:
            source_row = self.connection.execute(
                "SELECT id FROM osv_sources WHERE name = ?", (source_name,)
            ).fetchone()
            if source_row is None:
                source_id = int(
                    self.connection.execute(
                        "INSERT INTO osv_sources(name) VALUES (?)", (source_name,)
                    ).lastrowid
                )
            else:
                source_id = int(source_row["id"])
                # Cascades remove the previous records of this source.
                self.connection.execute(
                    "DELETE FROM osv_vulnerabilities WHERE source_id = ?",
                    (source_id,),
                )

            for record in records:
                vulnerability_id = int(
                    self.connection.execute(
                        "INSERT INTO osv_vulnerabilities"
                        "(source_id, vid, severity, severity_defaulted, withdrawn) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (
                            source_id,
                            record.id,
                            record.severity,
                            1 if record.severity_defaulted else 0,
                            record.withdrawn,
                        ),
                    ).lastrowid
                )
                # Rows are ordered deterministically so a repeated import of
                # identical content keeps stable row ordering.
                for affected_index, entry in enumerate(record.affected):
                    affected_id = int(
                        self.connection.execute(
                            "INSERT INTO osv_affected(osv_vulnerability_id, package_name) "
                            "VALUES (?, ?)",
                            (vulnerability_id, entry.package),
                        ).lastrowid
                    )
                    for version in entry.versions:
                        self.connection.execute(
                            "INSERT INTO osv_versions(osv_affected_id, version) "
                            "VALUES (?, ?)",
                            (affected_id, version),
                        )
                    for range_events in entry.ranges:
                        range_id = int(
                            self.connection.execute(
                                "INSERT INTO osv_ranges(osv_affected_id) VALUES (?)",
                                (affected_id,),
                            ).lastrowid
                        )
                        for position, (kind, value) in enumerate(range_events):
                            self.connection.execute(
                                "INSERT INTO osv_events"
                                "(range_id, position, introduced, fixed, last_affected) "
                                "VALUES (?, ?, ?, ?, ?)",
                                (
                                    range_id,
                                    position,
                                    value if kind == "introduced" else None,
                                    value if kind == "fixed" else None,
                                    value if kind == "last_affected" else None,
                                ),
                            )
        return len(records)

    def import_osv_file(self, source_name: str, path: str | Path) -> int:
        """Read an OSV JSON file (an array of records) and import it."""
        try:
            with open(path, "r", encoding="utf-8") as handle:
                document = json.load(handle)
        except OSError as error:
            raise ValueError(f"无法读取文件 {path}: {error}") from error
        except json.JSONDecodeError as error:
            raise ValueError(f"文件 {path} 不是有效的 JSON: {error}") from error
        return self.import_osv(source_name, document)

    def _osv_entries(self):
        """Load active OSV records as (source, vid, severity, defaulted, entries).

        Each entry is (affected_pk, package, versions, ranges) where ranges is
        a list of ordered (kind, value) event lists grouped by range.
        """
        sources = {
            int(row["id"]): str(row["name"])
            for row in self.connection.execute("SELECT id, name FROM osv_sources")
        }
        vulnerability_rows = self.connection.execute(
            "SELECT id, source_id, vid, severity, severity_defaulted, withdrawn "
            "FROM osv_vulnerabilities ORDER BY source_id, vid"
        ).fetchall()
        loaded = []
        for vulnerability in vulnerability_rows:
            if vulnerability["withdrawn"] is not None:
                continue
            entries = []
            affected_rows = self.connection.execute(
                "SELECT id, package_name FROM osv_affected WHERE osv_vulnerability_id = ?",
                (int(vulnerability["id"]),),
            ).fetchall()
            for affected in affected_rows:
                affected_id = int(affected["id"])
                versions = tuple(
                    str(row["version"])
                    for row in self.connection.execute(
                        "SELECT version FROM osv_versions WHERE osv_affected_id = ?",
                        (affected_id,),
                    )
                )
                ranges = []
                range_rows = self.connection.execute(
                    "SELECT id FROM osv_ranges WHERE osv_affected_id = ?", (affected_id,)
                ).fetchall()
                for range_row in range_rows:
                    events = []
                    event_rows = self.connection.execute(
                        "SELECT introduced, fixed, last_affected FROM osv_events "
                        "WHERE range_id = ? ORDER BY position",
                        (int(range_row["id"]),),
                    ).fetchall()
                    for event in event_rows:
                        if event["introduced"] is not None:
                            events.append(("introduced", str(event["introduced"])))
                        elif event["fixed"] is not None:
                            events.append(("fixed", str(event["fixed"])))
                        else:
                            events.append(
                                ("last_affected", str(event["last_affected"]))
                            )
                    ranges.append(events)
                entries.append(
                    (affected_id, str(affected["package_name"]), versions, ranges)
                )
            loaded.append(
                (
                    sources[int(vulnerability["source_id"])],
                    str(vulnerability["vid"]),
                    str(vulnerability["severity"]),
                    bool(vulnerability["severity_defaulted"]),
                    entries,
                )
            )
        return loaded

    @staticmethod
    def _version_in_conditions(component_key, versions, ranges) -> tuple[bool, str]:
        """Match a parsed component version against versions ∪ ECOSYSTEM ranges.

        Returns (matched, description). The description identifies the exact
        explicit version or interval that matched, e.g. ``version:1.2.3`` or
        ``range:>=1.0,<2.0`` (an open lower bound is rendered ``>=0``).
        """
        for version in versions:
            if component_key == parse_pep440(version):
                return True, f"version:{version}"
        for events in ranges:
            lower_text = None
            lower_key = None
            for kind, value in events:
                if kind == "introduced":
                    lower_text = value
                    lower_key = None if value == "0" else parse_pep440(value)
                else:
                    lower_label = "0" if lower_text is None else lower_text
                    above_lower = lower_key is None or component_key >= lower_key
                    if kind == "fixed":
                        if above_lower and component_key < parse_pep440(value):
                            return True, f"range:>={lower_label},<{value}"
                    else:  # last_affected: closed upper bound
                        if above_lower and component_key <= parse_pep440(value):
                            return True, f"range:>={lower_label},<={value}"
                    lower_text = None
                    lower_key = None
            # A trailing introduced leaves an interval without an upper bound.
            if lower_text is not None and (
                lower_key is None or component_key >= lower_key
            ):
                return True, f"range:>={lower_text}"
        return False, ""

    def _components_by_id(self) -> dict[int, dict[str, str]]:
        rows = self.connection.execute(
            "SELECT id, service, ecosystem, name, version FROM components"
        )
        return {
            int(row["id"]): {
                "service": str(row["service"]),
                "ecosystem": str(row["ecosystem"]),
                "name": str(row["name"]),
                "version": str(row["version"]),
            }
            for row in rows
        }

    def _dependency_edges(self) -> tuple[dict[int, list[int]], dict[int, list[int]]]:
        forward: dict[int, list[int]] = {}
        reverse: dict[int, list[int]] = {}
        for row in self.connection.execute(
            "SELECT dependent_id, dependency_id FROM dependencies"
        ):
            dependent = int(row["dependent_id"])
            dependency = int(row["dependency_id"])
            forward.setdefault(dependent, []).append(dependency)
            reverse.setdefault(dependency, []).append(dependent)
        return forward, reverse

    def _osv_hit_groups(self, components):
        """Group the direct OSV hits by (source, vulnerability, package).

        Returns a list of ``(source, vid, severity, defaulted, norm_name,
        seeds, conditions)`` where ``seeds`` is the set of directly hit
        component ids for that normalized PyPI package and ``conditions`` maps
        every seed to the version condition that matched it.

        Raises ValueError naming the component when a candidate component
        (pypi ecosystem, normalized name equal to an affected package) carries
        a version that cannot be parsed as PEP 440.
        """
        version_keys: dict[int, object] = {}

        def key_for(component_id: int):
            if component_id not in version_keys:
                try:
                    version_keys[component_id] = parse_pep440(
                        components[component_id]["version"]
                    )
                except InvalidVersion as error:
                    component = components[component_id]
                    raise ValueError(
                        "组件版本无法解析: "
                        + self._format_identity(
                            (
                                component["service"],
                                component["ecosystem"],
                                component["name"],
                                component["version"],
                            )
                        )
                    ) from error
            return version_keys[component_id]

        groups: dict[tuple[str, str, str], dict] = {}
        for source, vid, severity, defaulted, entries in self._osv_entries():
            for _affected_id, package, versions, ranges in entries:
                norm_name = normalize_pypi_name(package)
                group = groups.setdefault(
                    (source, vid, norm_name),
                    {
                        "severity": severity,
                        "defaulted": defaulted,
                        "seeds": set(),
                        "conditions": {},
                    },
                )
                for component_id, component in components.items():
                    if component["ecosystem"] != "pypi":
                        # npm (and other) components can never be directly hit;
                        # they may still be reached through propagation.
                        continue
                    if normalize_pypi_name(component["name"]) != norm_name:
                        continue
                    component_key = key_for(component_id)
                    matched, description = self._version_in_conditions(
                        component_key, versions, ranges
                    )
                    if matched:
                        group["seeds"].add(component_id)
                        # Keep the first matching condition when several
                        # affected entries cover the same component.
                        group["conditions"].setdefault(component_id, description)

        return [
            (source, vid, group["severity"], group["defaulted"], norm_name,
             group["seeds"], group["conditions"])
            for (source, vid, norm_name), group in groups.items()
            if group["seeds"]
        ]

    @staticmethod
    def _propagate(seeds, reverse) -> dict[int, int]:
        """Multi-source BFS: fewest dependency hops from a seed to each node."""
        distance: dict[int, int] = {component_id: 0 for component_id in seeds}
        queue = deque(seeds)
        while queue:
            node = queue.popleft()
            for dependent in reverse.get(node, ()):
                if dependent not in distance:
                    distance[dependent] = distance[node] + 1
                    queue.append(dependent)
        return distance

    def _manual_seeds(self, components) -> dict[str, set[int]]:
        vulnerable_names = {
            str(row["component_name"])
            for row in self.connection.execute(
                "SELECT DISTINCT component_name FROM vulnerabilities"
            )
        }
        seeds: dict[str, set[int]] = {}
        for component_id, component in components.items():
            if component["name"] in vulnerable_names:
                seeds.setdefault(component["name"], set()).add(component_id)
        return seeds

    def _affected_ids(self) -> set[int]:
        """Components directly hit by a vulnerability or depending on one that is."""
        components = self._components_by_id()
        _, reverse = self._dependency_edges()
        affected: set[int] = set()
        for seeds in self._manual_seeds(components).values():
            affected.update(self._propagate(seeds, reverse))
        # Also surfaces unparseable candidate versions as query errors.
        for group in self._osv_hit_groups(components):
            affected.update(self._propagate(group[5], reverse))
        return affected

    def summary(self) -> Summary:
        components = self._components_by_id()
        _, reverse = self._dependency_edges()

        affected: set[int] = set()
        highest_rank = 0

        # Manually registered vulnerabilities keep their original matching and
        # counting rules: one count per (id, component_name) that matches a
        # component by name.
        manual_count = 0
        manual_rows = self.connection.execute(
            "SELECT id, component_name, severity FROM vulnerabilities"
        ).fetchall()
        for observation in manual_rows:
            matched_name = str(observation["component_name"])
            seeds = [
                component_id
                for component_id, component in components.items()
                if component["name"] == matched_name
            ]
            if not seeds:
                continue
            manual_count += 1
            highest_rank = max(highest_rank, SEVERITY_RANK[str(observation["severity"])])
            affected.update(self._propagate(seeds, reverse))

        # Imported OSV records are counted once per (vulnerability id,
        # normalized package) over the records that actually hit.
        counted_imports: set[tuple[str, str]] = set()
        for source, vid, severity, _defaulted, norm_name, seeds, _conditions in (
            self._osv_hit_groups(components)
        ):
            affected.update(self._propagate(seeds, reverse))
            highest_rank = max(highest_rank, SEVERITY_RANK[severity])
            counted_imports.add((vid, norm_name))

        highest_severity = next(
            (name for name, rank in SEVERITY_RANK.items() if rank == highest_rank),
            None,
        )
        row = self.connection.execute(
            "SELECT COUNT(*) AS components FROM components"
        ).fetchone()
        return Summary(
            components=int(row["components"]),
            affected_components=len(affected),
            vulnerabilities=manual_count + len(counted_imports),
            highest_severity=highest_severity,
        )

    def affected_services(self) -> list[str]:
        affected = self._affected_ids()
        if not affected:
            return []
        placeholders = ", ".join("?" for _ in affected)
        rows = self.connection.execute(
            f"SELECT DISTINCT service FROM components WHERE id IN ({placeholders}) "
            "ORDER BY service",
            sorted(affected),
        )
        return [str(row["service"]) for row in rows]

    @staticmethod
    def _shortest_path(component_id, distance, forward, components) -> list[int]:
        """Rebuild one shortest path to a distance-0 seed; ties break by identity."""
        path_ids = [component_id]
        while distance[path_ids[-1]] > 0:
            current = path_ids[-1]
            candidates = [
                nxt
                for nxt in forward.get(current, ())
                if distance.get(nxt) == distance[current] - 1
            ]
            path_ids.append(
                min(
                    candidates,
                    key=lambda nxt: (
                        components[nxt]["ecosystem"],
                        components[nxt]["name"],
                        components[nxt]["version"],
                    ),
                )
            )
        return path_ids

    def impact(
        self,
        service: str | None = None,
        ecosystem: str | None = None,
        name: str | None = None,
        version: str | None = None,
    ) -> list[dict]:
        identity_filter = (ecosystem, name, version)
        if any(value is not None for value in identity_filter):
            if not all(value is not None for value in identity_filter):
                raise ValueError(
                    "ecosystem, name and version must be provided together"
                )
            if service is None:
                raise ValueError(
                    "service is required when filtering by component identity"
                )

        components = self._components_by_id()
        forward, reverse = self._dependency_edges()

        records: list[dict] = []

        # Manually registered vulnerabilities: match by component name across
        # every ecosystem, exactly as before.
        observations = self.connection.execute(
            "SELECT id, component_name, severity FROM vulnerabilities "
            "ORDER BY id, component_name"
        ).fetchall()
        for observation in observations:
            matched_name = str(observation["component_name"])
            seeds = [
                component_id
                for component_id, component in components.items()
                if component["name"] == matched_name
            ]
            if not seeds:
                continue
            distance = self._propagate(seeds, reverse)
            for component_id, hops in distance.items():
                path_ids = self._shortest_path(
                    component_id, distance, forward, components
                )
                records.append(
                    {
                        "component": dict(components[component_id]),
                        "vulnerability": str(observation["id"]),
                        "matched_name": matched_name,
                        "severity": str(observation["severity"]),
                        "direct": hops == 0,
                        "path": [dict(components[node]) for node in path_ids],
                    }
                )

        # Imported OSV records: per (source, vulnerability, normalized package)
        # a component appears at most once, carrying the terminal version
        # condition and the severity basis.
        for source, vid, severity, defaulted, norm_name, seeds, conditions in (
            self._osv_hit_groups(components)
        ):
            distance = self._propagate(seeds, reverse)
            for component_id, hops in distance.items():
                path_ids = self._shortest_path(
                    component_id, distance, forward, components
                )
                terminal = path_ids[-1]
                records.append(
                    {
                        "component": dict(components[component_id]),
                        "vulnerability": vid,
                        "source": source,
                        "matched_name": components[terminal]["name"],
                        "matched_package": norm_name,
                        "version_condition": conditions[terminal],
                        "severity": severity,
                        "severity_defaulted": defaulted,
                        "severity_basis": (
                            "缺失 database_specific.severity，默认定为 medium"
                            if defaulted
                            else "database_specific.severity"
                        ),
                        "direct": hops == 0,
                        "path": [dict(components[node]) for node in path_ids],
                    }
                )

        if service is not None:
            records = [
                record
                for record in records
                if record["component"]["service"] == service
            ]
        if all(value is not None for value in identity_filter):
            records = [
                record
                for record in records
                if record["component"]["ecosystem"] == ecosystem
                and record["component"]["name"] == name
                and record["component"]["version"] == version
            ]

        records.sort(
            key=lambda record: (
                record["component"]["service"],
                record["component"]["ecosystem"],
                record["component"]["name"],
                record["component"]["version"],
                record["vulnerability"],
                record.get("source") or "",
                record["matched_name"],
                record.get("version_condition") or "",
            )
        )
        return records
