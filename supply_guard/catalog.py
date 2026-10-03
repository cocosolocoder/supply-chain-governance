from __future__ import annotations

import json
import re
import sqlite3
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from packaging.version import InvalidVersion, Version


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
CREATE TABLE IF NOT EXISTS osv_vulnerabilities (
    source TEXT NOT NULL,
    id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    severity_default INTEGER NOT NULL DEFAULT 0,
    withdrawn TEXT,
    conditions TEXT NOT NULL,
    PRIMARY KEY(source, id, package_name)
);
CREATE TABLE IF NOT EXISTS exemption_requests (
    id TEXT PRIMARY KEY,
    service TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    vulnerability TEXT NOT NULL,
    matched_name TEXT NOT NULL,
    source TEXT,
    created_at TEXT NOT NULL,
    applicant TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    decided_at TEXT,
    approver TEXT,
    decision_note TEXT,
    approved_severity TEXT,
    revoked_at TEXT,
    revoker TEXT,
    revoke_note TEXT
);
CREATE TABLE IF NOT EXISTS exemption_events (
    id INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('request', 'approve', 'reject', 'revoke')),
    reason TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    UNIQUE(request_id, seq)
);
"""

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

SUPPORTED_ECOSYSTEMS = ("pypi", "npm")

EXEMPTION_PENDING = "pending"
EXEMPTION_APPROVED = "approved"
EXEMPTION_REJECTED = "rejected"
EXEMPTION_REVOKED = "revoked"
# Terminal states a request never leaves; every other state is a live request.
EXEMPTION_TERMINAL = frozenset({EXEMPTION_REJECTED, EXEMPTION_REVOKED})
# Statuses that block a fresh request for the same scope while in force.
EXEMPTION_OPEN = frozenset({EXEMPTION_PENDING, EXEMPTION_APPROVED})


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def parse_timestamp(value: object, context: str) -> datetime:
    """Parse an ISO 8601 timestamp that must carry explicit timezone info.

    The returned datetime is timezone-aware so it can be compared with UTC
    instants. Naive timestamps are rejected because their meaning is
    ambiguous.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}必须为非空时间字符串")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise ValueError(f"{context}时间无效: {text!r}") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{context}必须带有时区信息: {text!r}")
    return parsed.astimezone(timezone.utc)


def format_timestamp(moment: datetime) -> str:
    """Render a datetime as a canonical fixed-length UTC string.

    All instants are stored in this one form (``...Z``, six-digit
    microseconds), so lexicographic string comparison in SQL and Python is
    strictly chronological.
    """
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def normalize_pypi_name(name: str) -> str:
    """Normalize a PyPI package name per PEP 503.

    Case is folded and runs of hyphens, underscores and dots are treated as
    equivalent. Component identities are kept verbatim; this normalization
    is only used to match OSV records against components.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_pep440_version(value: object, context: str) -> Version:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} 必须为非空字符串")
    try:
        return Version(value.strip())
    except InvalidVersion as error:
        raise ValueError(f"无法解析的版本 {value!r}（{context}）") from error


def _parse_withdrawn(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("withdrawn 必须为非空时间戳字符串")
    timestamp = value.strip()
    try:
        datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise ValueError(f"withdrawn 时间戳无效: {timestamp!r}") from error
    return timestamp


def _parse_osv_affected(affected: object) -> dict[str, list[dict]]:
    """Validate the affected entries of one OSV record.

    Returns a mapping of normalized package name to the version conditions
    declared for that package. Every affected entry must target PyPI; other
    ecosystems, unknown range types/events, malformed event orders, inverted
    intervals and unparseable versions reject the whole import.
    """
    if not isinstance(affected, list) or not affected:
        raise ValueError("affected 必须为非空数组")
    packages: dict[str, list[dict]] = {}
    for index, entry in enumerate(affected):
        if not isinstance(entry, dict):
            raise ValueError(f"affected[{index}] 必须为对象")
        package = entry.get("package")
        if not isinstance(package, dict):
            raise ValueError(f"affected[{index}].package 必须为对象")
        ecosystem = package.get("ecosystem")
        if not isinstance(ecosystem, str) or not ecosystem.strip():
            raise ValueError(f"affected[{index}].package.ecosystem 必须为非空字符串")
        if ecosystem.strip().lower() != "pypi":
            raise ValueError(
                f"affected[{index}] 的生态系统 {ecosystem!r} 不受支持，仅支持 PyPI"
            )
        name = package.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"affected[{index}].package.name 必须为非空字符串")
        package_name = normalize_pypi_name(name)
        conditions: list[dict] = []

        versions = entry.get("versions", [])
        if not isinstance(versions, list):
            raise ValueError(f"affected[{index}].versions 必须为数组")
        for version in versions:
            parsed = _parse_pep440_version(version, f"affected[{index}].versions")
            conditions.append({"type": "explicit", "version": str(parsed)})

        ranges = entry.get("ranges", [])
        if not isinstance(ranges, list):
            raise ValueError(f"affected[{index}].ranges 必须为数组")
        for range_index, range_entry in enumerate(ranges):
            if not isinstance(range_entry, dict):
                raise ValueError(f"affected[{index}].ranges[{range_index}] 必须为对象")
            range_type = range_entry.get("type")
            if not isinstance(range_type, str) or not range_type.strip():
                raise ValueError(
                    f"affected[{index}].ranges[{range_index}].type 必须为非空字符串"
                )
            if range_type.strip().upper() != "ECOSYSTEM":
                raise ValueError(
                    f"affected[{index}].ranges[{range_index}] 的范围类型 "
                    f"{range_type!r} 不受支持，仅支持 ECOSYSTEM"
                )
            events = range_entry.get("events")
            if not isinstance(events, list) or not events:
                raise ValueError(
                    f"affected[{index}].ranges[{range_index}].events 必须为非空数组"
                )
            intervals: list[dict] = []
            opened = False
            for event_index, event in enumerate(events):
                if not isinstance(event, dict):
                    raise ValueError(
                        f"affected[{index}].ranges[{range_index}].events[{event_index}] "
                        "必须为对象"
                    )
                keys = set(event.keys())
                if len(keys) != 1:
                    raise ValueError(
                        f"affected[{index}].ranges[{range_index}].events[{event_index}] "
                        "必须恰好包含一个事件字段"
                    )
                key = next(iter(keys))
                if key not in ("introduced", "fixed", "last_affected"):
                    raise ValueError(
                        f"affected[{index}].ranges[{range_index}].events[{event_index}] "
                        f"的事件类型 {key!r} 不受支持"
                    )
                value = event[key]
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(
                        f"affected[{index}].ranges[{range_index}].events[{event_index}]"
                        f".{key} 必须为非空字符串"
                    )
                value = value.strip()
                if key == "introduced":
                    if opened:
                        raise ValueError(
                            f"affected[{index}].ranges[{range_index}].events[{event_index}] "
                            "事件次序非法：introduced 之后不能再次 introduced"
                        )
                    intervals.append(
                        {"type": "interval", "introduced": value,
                         "fixed": None, "last_affected": None}
                    )
                    opened = True
                else:
                    if not opened:
                        raise ValueError(
                            f"affected[{index}].ranges[{range_index}].events[{event_index}] "
                            f"事件次序非法：{key} 之前缺少 introduced"
                        )
                    intervals[-1][key] = value
                    opened = False
            for interval in intervals:
                introduced = interval["introduced"]
                if introduced != "0":
                    _parse_pep440_version(
                        introduced,
                        f"affected[{index}].ranges[{range_index}].introduced",
                    )
                if interval["fixed"] is not None:
                    fixed = interval["fixed"]
                    _parse_pep440_version(
                        fixed, f"affected[{index}].ranges[{range_index}].fixed"
                    )
                    if introduced != "0" and not (
                        Version(introduced) < Version(fixed)
                    ):
                        raise ValueError(
                            f"affected[{index}].ranges[{range_index}] 区间倒置："
                            f"introduced {introduced} 必须小于 fixed {fixed}"
                        )
                if interval["last_affected"] is not None:
                    last_affected = interval["last_affected"]
                    _parse_pep440_version(
                        last_affected,
                        f"affected[{index}].ranges[{range_index}].last_affected",
                    )
                    if introduced != "0" and not (
                        Version(introduced) <= Version(last_affected)
                    ):
                        raise ValueError(
                            f"affected[{index}].ranges[{range_index}] 区间倒置："
                            f"introduced {introduced} 不能大于 last_affected {last_affected}"
                        )
            conditions.extend(intervals)
        packages.setdefault(package_name, []).extend(conditions)
    return packages


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

    packages = _parse_osv_affected(record.get("affected"))
    for package_name, conditions in packages.items():
        if not conditions:
            raise ValueError(f"包 {package_name} 缺少有效版本条件")

    severity = "medium"
    severity_default = True
    database_specific = record.get("database_specific")
    if database_specific is not None:
        if not isinstance(database_specific, dict):
            raise ValueError("database_specific 必须为对象")
        declared = database_specific.get("severity")
        if declared is not None:
            if not isinstance(declared, str) or declared.strip().lower() not in SEVERITY_RANK:
                raise ValueError(
                    f"database_specific.severity {declared!r} 不受支持，"
                    "仅接受 low、medium、high、critical"
                )
            severity = declared.strip().lower()
            severity_default = False

    withdrawn = None
    if "withdrawn" in record:
        withdrawn = _parse_withdrawn(record["withdrawn"])

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


def _condition_matches(condition: dict, version: Version) -> bool:
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


def _format_condition(condition: dict) -> str:
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


@dataclass(frozen=True)
class Summary:
    components: int
    affected_components: int
    vulnerabilities: int
    highest_severity: str | None


def _impact_sort_key(record: dict) -> tuple:
    """Deterministic ordering shared by impact and the risk report."""
    component = record["component"]
    return (
        component["service"],
        component["ecosystem"],
        component["name"],
        component["version"],
        record["vulnerability"],
        record["matched_name"],
        record["source"] or "",
    )


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
    """Validate an SBOM document and return (identities, edges).

    Both CycloneDX 1.5 and SPDX 2.3 JSON are accepted; the format is
    recognized from the document itself. identities is the set of
    (ecosystem, name, version) tuples registered under the importing
    service. edges is a set of (dependent, dependency) identity pairs.
    All validation happens before any database write.
    """
    if not isinstance(sbom, dict):
        raise ValueError("清单必须是 JSON 对象")
    if "spdxVersion" in sbom:
        return _parse_spdx(sbom)
    return _parse_cyclonedx(sbom)


def _parse_cyclonedx(sbom: dict) -> tuple[set[tuple[str, str, str]], set[tuple[tuple[str, str, str], tuple[str, str, str]]]]:
    """Validate a CycloneDX 1.5 SBOM and return (identities, edges)."""
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


def _spdx_purl_identity(package: dict, index: int, ref: str) -> tuple[str, str, str]:
    """Extract a component identity from a package's purl external refs."""
    external_refs = package.get("externalRefs")
    if external_refs is None:
        raise ValueError(f"packages[{index}] (SPDXID {ref}) 缺少 purl 引用")
    if not isinstance(external_refs, list) or not external_refs:
        raise ValueError(f"packages[{index}] (SPDXID {ref}) externalRefs 必须为非空数组")
    identity: tuple[str, str, str] | None = None
    for ref_index, external_ref in enumerate(external_refs):
        if not isinstance(external_ref, dict):
            raise ValueError(
                f"packages[{index}].externalRefs[{ref_index}] 必须为对象"
            )
        if external_ref.get("referenceType") != "purl":
            continue
        try:
            candidate = parse_purl(external_ref.get("referenceLocator"))
        except ValueError as error:
            raise ValueError(
                f"packages[{index}] (SPDXID {ref}) purl 无效: {error}"
            ) from error
        if identity is None:
            identity = candidate
        elif candidate != identity:
            raise ValueError(
                f"packages[{index}] (SPDXID {ref}) 多个 purl 指向不同组件身份"
            )
    if identity is None:
        raise ValueError(f"packages[{index}] (SPDXID {ref}) 缺少 purl 引用")
    return identity


def _parse_spdx(document: dict) -> tuple[set[tuple[str, str, str]], set[tuple[tuple[str, str, str], tuple[str, str, str]]]]:
    """Validate an SPDX 2.3 JSON document and return (identities, edges)."""
    if document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("spdxVersion 必须为 SPDX-2.3")
    document_spdxid = document.get("SPDXID")
    if not isinstance(document_spdxid, str) or not document_spdxid:
        raise ValueError("文档 SPDXID 必须为非空字符串")
    if "packages" not in document:
        raise ValueError("缺少 packages 字段")
    packages = document["packages"]
    if not isinstance(packages, list):
        raise ValueError("packages 必须为数组")

    identities: dict[str, tuple[str, str, str]] = {}
    identity_set: set[tuple[str, str, str]] = set()
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise ValueError(f"packages[{index}] 必须为对象")
        spdxid = package.get("SPDXID")
        if not isinstance(spdxid, str) or not spdxid:
            raise ValueError(f"packages[{index}] SPDXID 必须为非空字符串")
        if spdxid == document_spdxid:
            raise ValueError(f"packages[{index}] SPDXID 与文档标识冲突: {spdxid}")
        if spdxid in identities:
            raise ValueError(f"SPDXID 重复: {spdxid}")
        identity = _spdx_purl_identity(package, index, spdxid)
        if "versionInfo" in package:
            version_info = package["versionInfo"]
            if not isinstance(version_info, str) or not version_info:
                raise ValueError(
                    f"packages[{index}] (SPDXID {spdxid}) versionInfo 必须为非空字符串"
                )
            if version_info != identity[2]:
                raise ValueError(
                    f"packages[{index}] (SPDXID {spdxid}) versionInfo 与 purl 版本不一致"
                )
        identities[spdxid] = identity
        identity_set.add(identity)

    edges: set[tuple[tuple[str, str, str], tuple[str, str, str]]] = set()
    if "relationships" in document:
        relationships = document["relationships"]
        if not isinstance(relationships, list):
            raise ValueError("relationships 必须为数组")
    else:
        relationships = []
    for index, relationship in enumerate(relationships):
        if not isinstance(relationship, dict):
            raise ValueError(f"relationships[{index}] 必须为对象")
        relationship_type = relationship.get("relationshipType")
        if relationship_type == "DEPENDS_ON":
            source_key, target_key = "spdxElementId", "relatedSpdxElement"
        elif relationship_type == "DEPENDENCY_OF":
            source_key, target_key = "relatedSpdxElement", "spdxElementId"
        else:
            # DESCRIBES and every other non-dependency relation are ignored;
            # the document itself is never a component.
            continue
        source = relationship.get(source_key)
        target = relationship.get(target_key)
        if not isinstance(source, str) or not source:
            raise ValueError(
                f"relationships[{index}].{source_key} 必须为非空字符串"
            )
        if not isinstance(target, str) or not target:
            raise ValueError(
                f"relationships[{index}].{target_key} 必须为非空字符串"
            )
        if source == document_spdxid or target == document_spdxid:
            raise ValueError(
                f"relationships[{index}] 引用了文档标识而非包: {source} -> {target}"
            )
        if source not in identities:
            raise ValueError(f"relationships[{index}] 引用未知标识: {source}")
        if target not in identities:
            raise ValueError(f"relationships[{index}] 引用未知标识: {target}")
        dependent_identity = identities[source]
        dependency_identity = identities[target]
        if dependent_identity == dependency_identity:
            raise ValueError(
                f"合并后产生自依赖: {source} -> {target}"
            )
        edges.add((dependent_identity, dependency_identity))

    return identity_set, edges


class Catalog:
    def __init__(self, database: str | Path = ":memory:") -> None:
        self.connection = sqlite3.connect(str(database))
        self.connection.row_factory = sqlite3.Row
        # Let concurrent writers wait for each other; guarded UPDATEs still
        # ensure that two processes processing one request produce at most a
        # single state change.
        self.connection.execute("PRAGMA busy_timeout = 10000")
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

    @contextmanager
    def _write_tx(self):
        """A serialized write transaction.

        ``BEGIN IMMEDIATE`` takes the database write lock up front, so two
        concurrent processes serialize their check-then-write sequences: the
        second blocks until the first commits and then observes its changes.
        Used for exemption requests and decisions to guarantee that a scope
        never gets two live requests and that a request changes state at most
        once.
        """
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except Exception:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

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

    def _delete_orphan_endpoints(self, candidate_ids) -> None:
        """Delete candidate components no registration or relationship keeps.

        A component stays while any of these holds: it is manually registered,
        some SBOM source still declares it, or it is an endpoint of another
        manually registered dependency. Each candidate is judged on its own,
        so deleting one relationship never removes a whole component group.
        """
        for component_id in candidate_ids:
            self.connection.execute(
                """
                DELETE FROM components
                WHERE id = ?
                  AND manual = 0
                  AND NOT EXISTS (
                      SELECT 1 FROM component_sources cs
                      WHERE cs.component_id = components.id
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM dependencies d
                      WHERE d.manual = 1
                        AND (d.dependent_id = components.id
                             OR d.dependency_id = components.id)
                  )
                """,
                (component_id,),
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
            # Nothing targeted: succeed without touching the catalog.
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
            # Endpoints that this edge was the last reason to keep leave the
            # catalog immediately; each end is retained or removed on its own.
            self._delete_orphan_endpoints((dependent_id, dependency_id))

    def import_sbom(
        self, service: str, source_name: str, sbom: object
    ) -> ImportResult:
        """Register the components and dependencies of an SBOM document.

        Both CycloneDX 1.5 and SPDX 2.3 JSON are accepted; the format is
        detected automatically.

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
            self._delete_orphan_endpoints(orphan_component_ids)

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
        """Read a CycloneDX 1.5 or SPDX 2.3 JSON file and import it."""
        try:
            with open(path, "r", encoding="utf-8") as handle:
                sbom = json.load(handle)
        except OSError as error:
            raise ValueError(f"无法读取文件 {path}: {error}") from error
        except json.JSONDecodeError as error:
            raise ValueError(f"文件 {path} 不是有效的 JSON: {error}") from error
        return self.import_sbom(service, source_name, sbom)

    def import_osv(self, source_name: str, records: object) -> int:
        """Replace the OSV records of one source.

        The source name is global: records apply to the whole catalog. The
        whole file is validated before any write, so failures leave the
        catalog untouched. An empty array clears the source; other sources
        and manually registered vulnerabilities are preserved.
        """
        source_name = source_name.strip()
        if not source_name:
            raise ValueError("source 名称不能为空")
        if not isinstance(records, list):
            raise ValueError("OSV 文件必须为记录数组")

        parsed: list[dict] = []
        seen_ids: set[str] = set()
        for index, record in enumerate(records):
            try:
                rows = parse_osv_record(record)
            except ValueError as error:
                raise ValueError(f"记录 {index}: {error}") from error
            identifier = rows[0]["id"]
            if identifier in seen_ids:
                raise ValueError(f"记录 {index}: id 重复: {identifier}")
            seen_ids.add(identifier)
            parsed.extend(rows)

        with self.connection:
            self.connection.execute(
                "DELETE FROM osv_vulnerabilities WHERE source = ?", (source_name,)
            )
            for row in parsed:
                self.connection.execute(
                    """
                    INSERT INTO osv_vulnerabilities(
                        source, id, package_name, severity, severity_default,
                        withdrawn, conditions
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_name,
                        row["id"],
                        row["package_name"],
                        row["severity"],
                        int(row["severity_default"]),
                        row["withdrawn"],
                        json.dumps(row["conditions"], ensure_ascii=False),
                    ),
                )
        return len(parsed)

    def import_osv_file(self, source_name: str, path: str | Path) -> int:
        """Read an OSV JSON file (an array of records) and import it."""
        try:
            with open(path, "r", encoding="utf-8") as handle:
                records = json.load(handle)
        except OSError as error:
            raise ValueError(f"无法读取文件 {path}: {error}") from error
        except json.JSONDecodeError as error:
            raise ValueError(f"文件 {path} 不是有效的 JSON: {error}") from error
        return self.import_osv(source_name, records)

    def _osv_records(self) -> list[dict]:
        """All participating (non-withdrawn) OSV records across sources."""
        rows = self.connection.execute(
            """
            SELECT source, id, package_name, severity, severity_default,
                   withdrawn, conditions
            FROM osv_vulnerabilities
            """
        )
        result: list[dict] = []
        for row in rows:
            if row["withdrawn"] is not None:
                continue
            result.append(
                {
                    "source": str(row["source"]),
                    "id": str(row["id"]),
                    "package_name": str(row["package_name"]),
                    "severity": str(row["severity"]),
                    "severity_default": bool(row["severity_default"]),
                    "conditions": json.loads(row["conditions"]),
                }
            )
        return result

    def _direct_hits(
        self, components: dict[int, dict[str, str]]
    ) -> dict[tuple[str | None, str, str], dict[int, dict]]:
        """Find the components directly hit by every vulnerability kind.

        Returns a mapping from an impact-group key
        ``(source, vulnerability id, matched package)`` — ``source`` is None
        for a manually registered vulnerability and the source name for an
        imported OSV record — to a mapping of directly hit component ids to
        the hit description recorded at that terminal: ``severity``,
        ``severity_basis`` and ``matched_conditions``.

        Manual observations hit components by their verbatim package name and
        carry no version conditions or severity basis. OSV records match on
        the normalized PyPI package name and on the union of explicit
        versions and ECOSYSTEM ranges compared with PEP 440; a candidate
        component whose version cannot be parsed is a query error that
        points out the component. Gathering both kinds here lets dependency
        propagation, path selection and record generation share one code
        path.
        """
        groups: dict[tuple[str | None, str, str], dict[int, dict]] = {}

        for observation in self.connection.execute(
            "SELECT id, component_name, severity FROM vulnerabilities"
        ):
            matched_name = str(observation["component_name"])
            key = (None, str(observation["id"]), matched_name)
            detail = {
                "severity": str(observation["severity"]),
                "severity_basis": None,
                "matched_conditions": None,
            }
            terminals = groups.setdefault(key, {})
            for component_id, component in components.items():
                if component["name"] == matched_name:
                    terminals[component_id] = detail

        records = self._osv_records()
        if records:
            by_package: dict[str, list[dict]] = {}
            for record in records:
                by_package.setdefault(record["package_name"], []).append(record)

            for component_id, component in components.items():
                if component["ecosystem"] != "pypi":
                    continue
                normalized = normalize_pypi_name(component["name"])
                candidates = by_package.get(normalized)
                if candidates is None:
                    continue
                try:
                    version = Version(component["version"])
                except InvalidVersion as error:
                    raise ValueError(
                        f"组件 {component['service']}/{component['ecosystem']}/"
                        f"{component['name']}/{component['version']} 版本无法解析"
                    ) from error
                for record in candidates:
                    matched_conditions = [
                        _format_condition(condition)
                        for condition in record["conditions"]
                        if _condition_matches(condition, version)
                    ]
                    if matched_conditions:
                        key = (record["source"], record["id"], normalized)
                        groups.setdefault(key, {})[component_id] = {
                            "severity": record["severity"],
                            "severity_basis": (
                                "default"
                                if record["severity_default"]
                                else "declared"
                            ),
                            "matched_conditions": matched_conditions,
                        }
        return groups

    def _components_by_id(
        self, service: str | None = None
    ) -> dict[int, dict[str, str]]:
        if service is None:
            rows = self.connection.execute(
                "SELECT id, service, ecosystem, name, version FROM components"
            )
        else:
            rows = self.connection.execute(
                "SELECT id, service, ecosystem, name, version FROM components "
                "WHERE service = ?",
                (service,),
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

    def _dependency_edges(
        self, component_ids: set[int] | None = None
    ) -> tuple[dict[int, list[int]], dict[int, list[int]]]:
        # Dependencies never cross services, so a service-scoped graph only
        # needs edges whose endpoints belong to the loaded components.
        if component_ids is None:
            rows = self.connection.execute(
                "SELECT dependent_id, dependency_id FROM dependencies"
            )
        else:
            if not component_ids:
                return {}, {}
            id_list = sorted(component_ids)
            placeholders = ", ".join("?" for _ in id_list)
            rows = self.connection.execute(
                "SELECT dependent_id, dependency_id FROM dependencies "
                f"WHERE dependent_id IN ({placeholders}) "
                f"AND dependency_id IN ({placeholders})",
                (*id_list, *id_list),
            )
        forward: dict[int, list[int]] = {}
        reverse: dict[int, list[int]] = {}
        for row in rows:
            dependent = int(row["dependent_id"])
            dependency = int(row["dependency_id"])
            forward.setdefault(dependent, []).append(dependency)
            reverse.setdefault(dependency, []).append(dependent)
        return forward, reverse

    @staticmethod
    def _component_identity_key(
        component: dict[str, str]
    ) -> tuple[str, str, str]:
        """Identity fields used as the deterministic path tie-breaker."""
        return (
            component["ecosystem"],
            component["name"],
            component["version"],
        )

    @staticmethod
    def _reconstruct_path(
        component_id: int,
        distance: dict[int, int],
        forward: dict[int, list[int]],
        components: dict[int, dict[str, str]],
    ) -> list[int]:
        """Reconstruct the shortest path, ties broken by component identity."""
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
                    key=lambda nxt: Catalog._component_identity_key(
                        components[nxt]
                    ),
                )
            )
        return path_ids

    @staticmethod
    def _propagate_distances(
        terminals: dict[int, dict],
        reverse: dict[int, list[int]],
    ) -> dict[int, int]:
        """Fewest dependency hops from each component to a directly hit one.

        Multi-source BFS over the reverse dependency edges starting from all
        directly hit components of one vulnerability/source/package group.
        Cycles are handled by the distance map, so every component is
        visited at most once and a path never repeats a component.
        """
        distance = {component_id: 0 for component_id in sorted(terminals)}
        queue = deque(distance)
        while queue:
            node = queue.popleft()
            for dependent in reverse.get(node, ()):
                if dependent not in distance:
                    distance[dependent] = distance[node] + 1
                    queue.append(dependent)
        return distance

    def _impact_graph(
        self, service: str | None = None
    ) -> tuple[
        dict[int, dict[str, str]],
        dict[int, list[int]],
        dict[int, list[int]],
        dict[tuple[str | None, str, str], dict[int, dict]],
    ]:
        """Load the component/dependency graph and all direct vulnerability hits.

        This is the single entry point shared by impact propagation, summary
        counts and the risk report: manual observations and imported OSV
        records are gathered into the same direct-hit groups, so a change to
        propagation or path rules applies to every vulnerability source at
        once.

        When ``service`` is given, only that service's components, dependency
        edges and hits participate: identically named components, dependencies
        and exemptions of other services never enter the analysis, so an
        unparseable component version registered elsewhere cannot fail a
        scoped query. Dependencies never cross services, so limiting the
        graph this way leaves every in-service propagation path intact.
        """
        components = self._components_by_id(service)
        forward, reverse = self._dependency_edges(set(components))
        return components, forward, reverse, self._direct_hits(components)

    @staticmethod
    def _affected_ids_from_groups(
        direct_groups: dict[tuple[str | None, str, str], dict[int, dict]],
        reverse: dict[int, list[int]],
    ) -> set[int]:
        """Components directly hit or depending (transitively) on a hit one."""
        affected: set[int] = set()
        for terminals in direct_groups.values():
            affected.update(terminals)
        queue = deque(affected)
        while queue:
            node = queue.popleft()
            for dependent in reverse.get(node, ()):
                if dependent not in affected:
                    affected.add(dependent)
                    queue.append(dependent)
        return affected

    def _affected_ids(self) -> set[int]:
        _, _, reverse, direct_groups = self._impact_graph()
        return self._affected_ids_from_groups(direct_groups, reverse)

    def summary(self) -> Summary:
        _, _, reverse, direct_groups = self._impact_graph()
        affected = self._affected_ids_from_groups(direct_groups, reverse)

        # Manual observations and OSV hits share the direct-hit model; only
        # groups with at least one directly hit component participate.
        manual_severities: list[str] = []
        osv_pairs: set[tuple[str, str]] = set()
        osv_severities: list[str] = []
        for (source, identifier, matched_name), terminals in direct_groups.items():
            if not terminals:
                continue
            if source is None:
                # One manual vulnerability row per group; its severity is the
                # same at every directly hit component.
                manual_severities.append(next(iter(terminals.values()))["severity"])
            else:
                # Imported vulnerabilities are deduplicated by id and
                # normalized package name across sources, and only records
                # that actually hit a component count.
                osv_pairs.add((identifier, matched_name))
                osv_severities.extend(
                    detail["severity"] for detail in terminals.values()
                )

        row = self.connection.execute(
            "SELECT COUNT(*) AS components FROM components"
        ).fetchone()

        highest: str | None = None
        for severity in manual_severities + osv_severities:
            if highest is None or SEVERITY_RANK[severity] > SEVERITY_RANK[highest]:
                highest = severity

        return Summary(
            components=int(row["components"]),
            affected_components=len(affected),
            vulnerabilities=len(manual_severities) + len(osv_pairs),
            highest_severity=highest,
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

        records = self._impact_records(service)

        if all(value is not None for value in identity_filter):
            records = [
                record
                for record in records
                if record["component"]["ecosystem"] == ecosystem
                and record["component"]["name"] == name
                and record["component"]["version"] == version
            ]

        records.sort(key=_impact_sort_key)
        return records

    def _impact_records(self, service: str | None = None) -> list[dict]:
        """All current impact records, unfiltered and in an unspecified order.

        One record per (component, vulnerability, source, matched package),
        for both manual observations (``source`` None, no version conditions
        and no severity basis) and named OSV sources (normalized PyPI package
        match, terminal version conditions and a declared/default severity
        basis). Every group goes through the same shortest-path propagation
        and record construction, so propagation rules live in exactly one
        place.

        With ``service`` set, analysis runs over that service's graph alone,
        so transitive impacts through the target component's dependencies are
        still found while identically named components of other services can
        neither leak into the records nor abort the query with their own
        unparseable versions.
        """
        components, forward, reverse, direct_groups = self._impact_graph(service)
        records: list[dict] = []

        for (source, identifier, matched_name), terminals in direct_groups.items():
            if not terminals:
                continue
            # Multi-source BFS over reverse edges: distance = fewest
            # dependency hops from an affected component to a directly hit
            # one. All directly hit components of the group are distance 0,
            # so a component reached by several paths gets one record and
            # propagation through cycles terminates at visited nodes.
            distance = self._propagate_distances(terminals, reverse)

            for component_id in sorted(distance):
                hops = distance[component_id]
                path_ids = self._reconstruct_path(
                    component_id, distance, forward, components
                )
                # The hit details belong to the terminal component of the
                # chosen shortest path; with several directly hit versions of
                # the same normalized package this keeps each path's
                # explanation tied to its own endpoint.
                terminal_hit = terminals[path_ids[-1]]
                records.append(
                    {
                        "component": dict(components[component_id]),
                        "vulnerability": identifier,
                        "source": source,
                        "matched_name": matched_name,
                        "severity": terminal_hit["severity"],
                        "severity_basis": terminal_hit["severity_basis"],
                        "direct": hops == 0,
                        "matched_conditions": terminal_hit["matched_conditions"],
                        "path": [dict(components[node]) for node in path_ids],
                    }
                )

        return records

    # ------------------------------------------------------------------
    # Vulnerability exemptions
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_identity(
        service: object,
        ecosystem: object,
        name: object,
        version: object,
    ) -> tuple[str, str, str, str]:
        values = tuple(
            value.strip() if isinstance(value, str) else ""
            for value in (service, ecosystem, name, version)
        )
        if any(not value for value in values):
            raise ValueError("组件的 service、ecosystem、name、version 均不能为空")
        return values  # type: ignore[return-value]

    @staticmethod
    def _clean_text(value: object, context: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{context}不能为空")
        return value.strip()

    def _impact_exists(
        self,
        service: str,
        ecosystem: str,
        name: str,
        version: str,
        vulnerability: str,
        matched_name: str,
        source: str | None,
    ) -> bool:
        """Whether the exact scope currently names a live impact record."""
        for record in self._impact_records():
            component = record["component"]
            if (
                component["service"] == service
                and component["ecosystem"] == ecosystem
                and component["name"] == name
                and component["version"] == version
                and record["vulnerability"] == vulnerability
                and record["matched_name"] == matched_name
                and record["source"] == source
            ):
                return True
        return False

    def request_exemption(
        self,
        request_id: str,
        service: str,
        ecosystem: str,
        name: str,
        version: str,
        vulnerability: str,
        matched_name: str,
        source: str | None,
        applicant: str,
        reason: str,
        expires_at: str | datetime,
        *,
        submitted_at: datetime | None = None,
    ) -> dict:
        """Apply to exempt one specific impact record.

        The scope is exactly (component identity, vulnerability id, matched
        package, source); ``source`` is None for a manually registered
        vulnerability and the source name for an imported OSV record. A retry
        with the same id and identical content confirms the original
        submission and returns the stored request exactly as it currently
        stands — its term, decision state and history are never altered, even
        when the retry happens at or after expiry, after the request was
        approved/rejected/revoked, or after the target impact disappeared. A
        reused id with any different content is rejected as a conflict. Only
        one live (pending or unexpired approved) request may exist per scope,
        and the expiry must be later than the submission instant only for a
        genuinely new request.
        """
        request_id = self._clean_text(request_id, "申请编号")
        service, ecosystem, name, version = self._clean_identity(
            service, ecosystem, name, version
        )
        vulnerability = self._clean_text(vulnerability, "漏洞编号")
        matched_name = self._clean_text(matched_name, "匹配包名")
        if source is not None:
            source = self._clean_text(source, "漏洞来源")
        applicant = self._clean_text(applicant, "申请人")
        reason = self._clean_text(reason, "申请理由")

        if submitted_at is None:
            submitted_at = utc_now()
        elif submitted_at.tzinfo is None:
            raise ValueError("提交时刻必须带有时区信息")
        else:
            submitted_at = submitted_at.astimezone(timezone.utc)

        if isinstance(expires_at, datetime):
            expiry = expires_at
            if expiry.tzinfo is None:
                raise ValueError("到期时间必须带有时区信息")
            expiry = expiry.astimezone(timezone.utc)
        else:
            expiry = parse_timestamp(expires_at, "到期时间")

        scope = (
            service, ecosystem, name, version,
            vulnerability, matched_name, source,
        )
        with self._write_tx():
            existing = self.connection.execute(
                "SELECT * FROM exemption_requests WHERE id = ?", (request_id,)
            ).fetchone()
            if existing is not None:
                # An id names exactly one request for all time. Identical
                # content confirms the original submission and returns the
                # record exactly as it is now — no expiry check (the retry may
                # run at or after expiry), no impact-existence check (the
                # scope may have disappeared), no scope re-occupation, and no
                # change to the term, the approved severity or the history.
                # Any differing content is a conflict, never an overwrite.
                stored_scope = (
                    str(existing["service"]),
                    str(existing["ecosystem"]),
                    str(existing["name"]),
                    str(existing["version"]),
                    str(existing["vulnerability"]),
                    str(existing["matched_name"]),
                    None if existing["source"] is None else str(existing["source"]),
                )
                same_content = (
                    stored_scope == scope
                    and str(existing["applicant"]) == applicant
                    and str(existing["reason"]) == reason
                    and str(existing["expires_at"]) == format_timestamp(expiry)
                )
                if not same_content:
                    raise ValueError(f"申请编号 {request_id!r} 已用于不同内容的申请")
                return self._fetch_request(request_id)

            # Everything below applies only to a genuinely new request id.
            if expiry <= submitted_at:
                raise ValueError("到期时间必须晚于提交时刻")

            if not self._impact_exists(*scope):
                raise ValueError("申请目标不存在：当前没有匹配的漏洞影响记录")

            # No other live request may occupy the same scope.
            self._ensure_scope_open(scope, exclude_id=None, now=submitted_at)

            created = format_timestamp(submitted_at)
            self.connection.execute(
                """
                INSERT INTO exemption_requests(
                    id, service, ecosystem, name, version,
                    vulnerability, matched_name, source,
                    created_at, applicant, reason, expires_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id, *scope,
                    created, applicant, reason, format_timestamp(expiry),
                    EXEMPTION_PENDING,
                ),
            )
            self._append_event(
                request_id, submitted_at, applicant, "request", reason,
                None, EXEMPTION_PENDING,
            )
        return self._fetch_request(request_id)

    def _ensure_scope_open(
        self,
        scope: tuple,
        exclude_id: str | None,
        now: datetime,
    ) -> None:
        rows = self.connection.execute(
            """
            SELECT id, status, expires_at FROM exemption_requests
            WHERE service = ? AND ecosystem = ? AND name = ? AND version = ?
              AND vulnerability = ? AND matched_name = ?
              AND ((source IS NULL AND ? IS NULL) OR source = ?)
            """,
            (*scope[:6], scope[6], scope[6]),
        ).fetchall()
        now_text = format_timestamp(now)
        for row in rows:
            if str(row["id"]) == exclude_id:
                continue
            status = str(row["status"])
            if status not in EXEMPTION_OPEN:
                continue
            if str(row["expires_at"]) > now_text:
                raise ValueError(
                    f"同一范围已存在未到期的{_status_label(status)}申请: {row['id']}"
                )

    def _append_event(
        self,
        request_id: str,
        occurred_at: datetime,
        actor: str,
        action: str,
        reason: str,
        from_status: str | None,
        to_status: str,
    ) -> None:
        next_seq = self.connection.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM exemption_events WHERE request_id = ?",
            (request_id,),
        ).fetchone()[0]
        self.connection.execute(
            """
            INSERT INTO exemption_events(
                request_id, seq, occurred_at, actor, action, reason,
                from_status, to_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id, int(next_seq), format_timestamp(occurred_at),
                actor, action, reason, from_status, to_status,
            ),
        )

    def _fetch_request(self, request_id: str) -> dict:
        row = self.connection.execute(
            "SELECT * FROM exemption_requests WHERE id = ?", (request_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"未知申请编号: {request_id}")
        return self._request_dict(row)

    def _request_dict(self, row: sqlite3.Row) -> dict:
        events = [
            {
                "seq": int(event["seq"]),
                "at": str(event["occurred_at"]),
                "actor": str(event["actor"]),
                "action": str(event["action"]),
                "reason": str(event["reason"]),
                "from_status": (
                    None if event["from_status"] is None
                    else str(event["from_status"])
                ),
                "to_status": str(event["to_status"]),
            }
            for event in self.connection.execute(
                """
                SELECT seq, occurred_at, actor, action, reason, from_status,
                       to_status
                FROM exemption_events
                WHERE request_id = ?
                ORDER BY seq
                """,
                (str(row["id"]),),
            )
        ]
        return {
            "id": str(row["id"]),
            "scope": {
                "service": str(row["service"]),
                "ecosystem": str(row["ecosystem"]),
                "name": str(row["name"]),
                "version": str(row["version"]),
                "vulnerability": str(row["vulnerability"]),
                "matched_name": str(row["matched_name"]),
                "source": None if row["source"] is None else str(row["source"]),
            },
            "applicant": str(row["applicant"]),
            "reason": str(row["reason"]),
            "created_at": str(row["created_at"]),
            "expires_at": str(row["expires_at"]),
            "status": str(row["status"]),
            "decided_at": (
                None if row["decided_at"] is None else str(row["decided_at"])
            ),
            "approver": None if row["approver"] is None else str(row["approver"]),
            "decision_note": (
                None if row["decision_note"] is None
                else str(row["decision_note"])
            ),
            "approved_severity": (
                None if row["approved_severity"] is None
                else str(row["approved_severity"])
            ),
            "revoked_at": (
                None if row["revoked_at"] is None else str(row["revoked_at"])
            ),
            "revoker": None if row["revoker"] is None else str(row["revoker"]),
            "revoke_note": (
                None if row["revoke_note"] is None else str(row["revoke_note"])
            ),
            "events": events,
        }

    def get_exemption(self, request_id: str) -> dict:
        """Return one request with its full processing history."""
        request_id = self._clean_text(request_id, "申请编号")
        return self._fetch_request(request_id)

    def list_exemptions(self, status: str | None = None) -> list[dict]:
        """List requests (with history), newest first, id as tiebreaker."""
        query = (
            "SELECT * FROM exemption_requests "
            + ("WHERE status = ? " if status is not None else "")
            + "ORDER BY created_at DESC, id ASC"
        )
        parameters: tuple = () if status is None else (status,)
        rows = self.connection.execute(query, parameters).fetchall()
        return [self._request_dict(row) for row in rows]

    def _process_decision(
        self,
        request_id: str,
        handler: str,
        note: str,
        action: str,
        target_status: str,
        when: datetime,
    ) -> dict:
        request_id = self._clean_text(request_id, "申请编号")
        handler = self._clean_text(handler, "处理人")
        note = self._clean_text(note, "处理说明")

        with self._write_tx():
            # Lock the row so two concurrent processes cannot both transition
            # it; the second transaction blocks here and then sees the new
            # status, so exactly one state change is accepted.
            row = self.connection.execute(
                "SELECT * FROM exemption_requests WHERE id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"未知申请编号: {request_id}")
            current_status = str(row["status"])
            if current_status != EXEMPTION_PENDING:
                raise ValueError(
                    f"只有待审批申请可以{_action_label(action)}，"
                    f"当前状态为{_status_label(current_status)}"
                )
            if format_timestamp(when) >= str(row["expires_at"]):
                raise ValueError("申请已到期，不能再审批")

            approved_severity = None
            if target_status == EXEMPTION_APPROVED:
                if handler == str(row["applicant"]):
                    raise ValueError("申请人不能批准自己的申请")
                scope = (
                    str(row["service"]), str(row["ecosystem"]),
                    str(row["name"]), str(row["version"]),
                    str(row["vulnerability"]), str(row["matched_name"]),
                    None if row["source"] is None else str(row["source"]),
                )
                current_severity = self._current_scope_severity(scope)
                if current_severity is None:
                    raise ValueError("审批时目标影响记录已不存在")
                approved_severity = current_severity
                cursor = self.connection.execute(
                    """
                    UPDATE exemption_requests
                    SET status = ?, decided_at = ?, approver = ?,
                        decision_note = ?, approved_severity = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        target_status, format_timestamp(when), handler, note,
                        approved_severity, request_id, EXEMPTION_PENDING,
                    ),
                )
            else:
                cursor = self.connection.execute(
                    """
                    UPDATE exemption_requests
                    SET status = ?, decided_at = ?, approver = ?,
                        decision_note = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        target_status, format_timestamp(when), handler, note,
                        request_id, EXEMPTION_PENDING,
                    ),
                )
            if cursor.rowcount == 0:
                raise ValueError("申请状态已被其他进程改变")
            self._append_event(
                request_id, when, handler, action, note,
                EXEMPTION_PENDING, target_status,
            )
        return self._fetch_request(request_id)

    def approve_exemption(
        self,
        request_id: str,
        handler: str,
        note: str,
        *,
        decided_at: datetime | None = None,
    ) -> dict:
        """Approve a pending request, recording the severity then in force."""
        return self._process_decision(
            request_id, handler, note, "approve", EXEMPTION_APPROVED,
            decided_at or utc_now(),
        )

    def reject_exemption(
        self,
        request_id: str,
        handler: str,
        note: str,
        *,
        decided_at: datetime | None = None,
    ) -> dict:
        """Reject a pending request."""
        return self._process_decision(
            request_id, handler, note, "reject", EXEMPTION_REJECTED,
            decided_at or utc_now(),
        )

    def revoke_exemption(
        self,
        request_id: str,
        handler: str,
        note: str,
        *,
        revoked_at: datetime | None = None,
    ) -> dict:
        """Revoke an approved exemption that has not yet expired."""
        request_id = self._clean_text(request_id, "申请编号")
        handler = self._clean_text(handler, "处理人")
        note = self._clean_text(note, "处理说明")
        when = revoked_at or utc_now()
        if revoked_at is not None:
            if revoked_at.tzinfo is None:
                raise ValueError("撤销时刻必须带有时区信息")
            when = revoked_at.astimezone(timezone.utc)

        with self._write_tx():
            row = self.connection.execute(
                "SELECT * FROM exemption_requests WHERE id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"未知申请编号: {request_id}")
            status = str(row["status"])
            if status != EXEMPTION_APPROVED:
                raise ValueError(
                    f"只有已批准且未到期的申请可以撤销，"
                    f"当前状态为{_status_label(status)}"
                )
            if format_timestamp(when) >= str(row["expires_at"]):
                raise ValueError("豁免已到期，无需撤销")
            cursor = self.connection.execute(
                """
                UPDATE exemption_requests
                SET status = ?, revoked_at = ?, revoker = ?, revoke_note = ?
                WHERE id = ? AND status = ?
                """,
                (
                    EXEMPTION_REVOKED, format_timestamp(when), handler, note,
                    request_id, EXEMPTION_APPROVED,
                ),
            )
            if cursor.rowcount == 0:
                raise ValueError("申请状态已被其他进程改变")
            self._append_event(
                request_id, when, handler, "revoke", note,
                EXEMPTION_APPROVED, EXEMPTION_REVOKED,
            )
        return self._fetch_request(request_id)

    def _current_scope_severity(self, scope: tuple) -> str | None:
        """Severity of the live impact record exactly matching ``scope``."""
        for record in self._impact_records():
            component = record["component"]
            if (
                component["service"] == scope[0]
                and component["ecosystem"] == scope[1]
                and component["name"] == scope[2]
                and component["version"] == scope[3]
                and record["vulnerability"] == scope[4]
                and record["matched_name"] == scope[5]
                and record["source"] == scope[6]
            ):
                return str(record["severity"])
        return None

    def _active_exemptions(self, at: datetime) -> dict[tuple, dict]:
        """Approved, unexpired exemptions keyed by scope, evaluated at ``at``.

        The exemption stops at the expiry instant itself. Directory and
        approval state are taken at the current moment; ``at`` only decides
        whether the term is in force.
        """
        at_text = format_timestamp(at)
        rows = self.connection.execute(
            """
            SELECT * FROM exemption_requests
            WHERE status = ? AND expires_at > ?
            """,
            (EXEMPTION_APPROVED, at_text),
        ).fetchall()
        result: dict[tuple, dict] = {}
        for row in rows:
            scope = (
                str(row["service"]), str(row["ecosystem"]),
                str(row["name"]), str(row["version"]),
                str(row["vulnerability"]), str(row["matched_name"]),
                None if row["source"] is None else str(row["source"]),
            )
            result[scope] = {
                "id": str(row["id"]),
                "approved_severity": str(row["approved_severity"]),
                "expires_at": str(row["expires_at"]),
            }
        return result

    def risk_report(
        self,
        service: str | None = None,
        evaluated_at: str | datetime | None = None,
    ) -> dict:
        """Build the JSON risk report.

        Every current impact record is reported with its source, severity,
        direct/indirect flag and dependency path, plus exemption status: the
        linked request and, when an approved exemption is not in force for the
        record, the reason why. Counts and the highest severity consider only
        unexempted records.
        """
        if evaluated_at is None:
            moment = utc_now()
        elif isinstance(evaluated_at, datetime):
            if evaluated_at.tzinfo is None:
                raise ValueError("评估时刻必须带有时区信息")
            moment = evaluated_at.astimezone(timezone.utc)
        else:
            moment = parse_timestamp(evaluated_at, "评估时刻")

        if service is not None:
            service = service.strip()
            if not service:
                raise ValueError("service 不能为空")

        records = self._impact_records(service)

        active = self._active_exemptions(moment)
        reported: list[dict] = []
        unexempted_components: set[tuple] = set()
        highest: str | None = None

        for record in records:
            component = record["component"]
            scope = (
                component["service"], component["ecosystem"],
                component["name"], component["version"],
                record["vulnerability"], record["matched_name"],
                record["source"],
            )
            entry = {
                "component": dict(component),
                "vulnerability": record["vulnerability"],
                "source": record["source"],
                "matched_name": record["matched_name"],
                "severity": record["severity"],
                "severity_basis": record["severity_basis"],
                "direct": record["direct"],
                "matched_conditions": record["matched_conditions"],
                "path": [dict(node) for node in record["path"]],
                "exempted": False,
                "exemption_request": None,
                "not_exempt_reason": None,
            }

            exemption = active.get(scope)
            if exemption is not None:
                current_severity = str(record["severity"])
                approved_rank = SEVERITY_RANK[exemption["approved_severity"]]
                if SEVERITY_RANK[current_severity] > approved_rank:
                    # The current rating exceeds what was approved: the
                    # exemption no longer covers this record.
                    entry["exemption_request"] = exemption["id"]
                    entry["not_exempt_reason"] = (
                        f"当前风险等级 {current_severity} 高于审批时的"
                        f"{exemption['approved_severity']}，超出审批范围"
                    )
                else:
                    entry["exempted"] = True
                    entry["exemption_request"] = exemption["id"]
            else:
                linked = self._scope_request_link(scope, moment)
                if linked is not None:
                    entry["exemption_request"] = linked["id"]
                    entry["not_exempt_reason"] = linked["reason"]

            if not entry["exempted"]:
                unexempted_components.add(
                    (
                        component["service"], component["ecosystem"],
                        component["name"], component["version"],
                    )
                )
                if (
                    highest is None
                    or SEVERITY_RANK[record["severity"]] > SEVERITY_RANK[highest]
                ):
                    highest = str(record["severity"])

            reported.append(entry)

        reported.sort(key=_impact_sort_key)

        return {
            "evaluated_at": format_timestamp(moment),
            "service": service,
            "impact_count": len(reported),
            "unhandled_component_count": len(unexempted_components),
            "highest_severity": highest,
            "impacts": reported,
        }

    def _scope_request_link(self, scope: tuple, moment: datetime) -> dict | None:
        """The most relevant request for a scope without an active exemption.

        Reports why an approved exemption is not in force (expired or
        outgrown), or the live/closed request otherwise. The newest request
        for the scope wins.
        """
        rows = self.connection.execute(
            """
            SELECT * FROM exemption_requests
            WHERE service = ? AND ecosystem = ? AND name = ? AND version = ?
              AND vulnerability = ? AND matched_name = ?
              AND ((source IS NULL AND ? IS NULL) OR source = ?)
            ORDER BY created_at DESC, id DESC
            """,
            (*scope[:6], scope[6], scope[6]),
        ).fetchall()
        if not rows:
            return None
        row = rows[0]
        status = str(row["status"])
        at_text = format_timestamp(moment)
        reason: str
        if status == EXEMPTION_PENDING:
            if str(row["expires_at"]) <= at_text:
                reason = f"申请已于 {row['expires_at']} 到期，未获审批"
            else:
                reason = "豁免申请尚在待审批"
        elif status == EXEMPTION_REJECTED:
            reason = "豁免申请已被拒绝"
        elif status == EXEMPTION_REVOKED:
            reason = "豁免已被撤销"
        elif status == EXEMPTION_APPROVED:
            reason = f"豁免已于 {row['expires_at']} 到期"
        else:  # pragma: no cover - every status handled above
            reason = "豁免未生效"
        return {"id": str(row["id"]), "reason": reason}


def _status_label(status: str) -> str:
    return {
        EXEMPTION_PENDING: "待审批",
        EXEMPTION_APPROVED: "已批准",
        EXEMPTION_REJECTED: "已拒绝",
        EXEMPTION_REVOKED: "已撤销",
    }.get(status, status)


def _action_label(action: str) -> str:
    return {
        "approve": "批准",
        "reject": "拒绝",
        "revoke": "撤销",
    }.get(action, action)
