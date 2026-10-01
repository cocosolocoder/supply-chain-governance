from __future__ import annotations

import json
import re
import sqlite3
from collections import deque
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
CREATE TABLE IF NOT EXISTS exemptions (
    id INTEGER PRIMARY KEY,
    application_no TEXT NOT NULL UNIQUE,
    service TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    matched_name TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    applicant TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    risk_level TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exemptions_scope
    ON exemptions(service, ecosystem, name, version,
                  vulnerability_id, matched_name, source);
CREATE TABLE IF NOT EXISTS exemption_history (
    id INTEGER PRIMARY KEY,
    application_no TEXT NOT NULL,
    action TEXT NOT NULL,
    operator TEXT NOT NULL,
    reason TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    acted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exemption_history_no
    ON exemption_history(application_no);
"""

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

EXEMPTION_STATUSES = ("pending", "approved", "rejected", "revoked")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_timestamp(value: object, context: str) -> datetime:
    """Parse a timezone-aware timestamp, returning it normalized to UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} 必须为非空字符串")
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError as error:
        raise ValueError(f"{context} 时间戳无效: {value!r}") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{context} 必须包含时区")
    return parsed.astimezone(timezone.utc)


def _nonempty(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context} 不能为空")
    return value.strip()

SUPPORTED_ECOSYSTEMS = ("pypi", "npm")


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

    def _osv_direct_hits(self, components: dict[int, dict[str, str]]) -> dict[int, list[dict]]:
        """Map directly hit component ids to their OSV hit descriptions.

        Components match on the normalized PyPI package name and on the
        union of explicit versions and ECOSYSTEM ranges, compared with PEP
        440. A candidate component whose version cannot be parsed is a query
        error that points out the component.
        """
        records = self._osv_records()
        if not records:
            return {}
        by_package: dict[str, list[dict]] = {}
        for record in records:
            by_package.setdefault(record["package_name"], []).append(record)

        hits: dict[int, list[dict]] = {}
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
                    hits.setdefault(component_id, []).append(
                        {
                            "source": record["source"],
                            "id": record["id"],
                            "package_name": normalized,
                            "severity": record["severity"],
                            "severity_basis": (
                                "default" if record["severity_default"] else "declared"
                            ),
                            "matched_conditions": matched_conditions,
                        }
                    )
        return hits

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
                    key=lambda nxt: (
                        components[nxt]["ecosystem"],
                        components[nxt]["name"],
                        components[nxt]["version"],
                    ),
                )
            )
        return path_ids

    def _affected_ids(self) -> set[int]:
        """Components directly hit by a vulnerability or depending on one that is."""
        components = self._components_by_id()
        vulnerable_names = {
            str(row["component_name"])
            for row in self.connection.execute(
                "SELECT DISTINCT component_name FROM vulnerabilities"
            )
        }
        _, reverse = self._dependency_edges()
        affected = {
            component_id
            for component_id, component in components.items()
            if component["name"] in vulnerable_names
        }
        affected.update(self._osv_direct_hits(components))
        queue = deque(affected)
        while queue:
            node = queue.popleft()
            for dependent in reverse.get(node, ()):
                if dependent not in affected:
                    affected.add(dependent)
                    queue.append(dependent)
        return affected

    def summary(self) -> Summary:
        components = self._components_by_id()
        affected = self._affected_ids()
        osv_hits = self._osv_direct_hits(components)

        row = self.connection.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM components) AS components,
              COUNT(*) AS vulnerabilities,
              CASE MAX(CASE v.severity
                WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
                WHEN 4 THEN 'critical' WHEN 3 THEN 'high'
                WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE NULL END AS highest_severity
            FROM vulnerabilities v
            WHERE EXISTS (SELECT 1 FROM components c WHERE c.name = v.component_name)
            """
        ).fetchone()

        # Imported vulnerabilities are deduplicated by id and normalized
        # package name, and only records that actually hit a component count.
        osv_pairs: set[tuple[str, str]] = set()
        osv_severities: list[str] = []
        for hit_list in osv_hits.values():
            for hit in hit_list:
                osv_pairs.add((hit["id"], hit["package_name"]))
                osv_severities.append(hit["severity"])

        highest = row["highest_severity"]
        for severity in osv_severities:
            if highest is None or SEVERITY_RANK[severity] > SEVERITY_RANK[highest]:
                highest = severity

        return Summary(
            components=int(row["components"]),
            affected_components=len(affected),
            vulnerabilities=int(row["vulnerabilities"]) + len(osv_pairs),
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

        components = self._components_by_id()
        forward, reverse = self._dependency_edges()
        records: list[dict] = []

        observations = self.connection.execute(
            """
            SELECT v.id, v.component_name, v.severity
            FROM vulnerabilities v
            WHERE EXISTS (SELECT 1 FROM components c WHERE c.name = v.component_name)
            ORDER BY v.id, v.component_name
            """
        ).fetchall()
        for observation in observations:
            matched_name = str(observation["component_name"])
            sources = [
                component_id
                for component_id, component in components.items()
                if component["name"] == matched_name
            ]
            # Multi-source BFS over reverse edges: distance = fewest dependency
            # hops from an affected component to a directly hit one.
            distance = {component_id: 0 for component_id in sources}
            queue = deque(sources)
            while queue:
                node = queue.popleft()
                for dependent in reverse.get(node, ()):
                    if dependent not in distance:
                        distance[dependent] = distance[node] + 1
                        queue.append(dependent)

            for component_id, hops in distance.items():
                path_ids = self._reconstruct_path(
                    component_id, distance, forward, components
                )
                records.append(
                    {
                        "component": dict(components[component_id]),
                        "vulnerability": str(observation["id"]),
                        "source": None,
                        "matched_name": matched_name,
                        "severity": str(observation["severity"]),
                        "severity_basis": None,
                        "direct": hops == 0,
                        "matched_conditions": None,
                        "path": [dict(components[node]) for node in path_ids],
                    }
                )

        # Imported records: one impact record per (component, source, id,
        # matched package), with the shortest dependency path, the version
        # conditions hit at the terminal component and the severity basis.
        osv_hits = self._osv_direct_hits(components)
        groups: dict[tuple[str, str, str], list[tuple[int, dict]]] = {}
        for component_id, hit_list in osv_hits.items():
            for hit in hit_list:
                key = (hit["source"], hit["id"], hit["package_name"])
                groups.setdefault(key, []).append((component_id, hit))
        for (source, identifier, package_name), entries in groups.items():
            hit_by_component = {component_id: hit for component_id, hit in entries}
            sources = list(hit_by_component)
            distance = {component_id: 0 for component_id in sources}
            queue = deque(sources)
            while queue:
                node = queue.popleft()
                for dependent in reverse.get(node, ()):
                    if dependent not in distance:
                        distance[dependent] = distance[node] + 1
                        queue.append(dependent)

            for component_id, hops in distance.items():
                path_ids = self._reconstruct_path(
                    component_id, distance, forward, components
                )
                terminal_hit = hit_by_component[path_ids[-1]]
                records.append(
                    {
                        "component": dict(components[component_id]),
                        "vulnerability": identifier,
                        "source": source,
                        "matched_name": package_name,
                        "severity": terminal_hit["severity"],
                        "severity_basis": terminal_hit["severity_basis"],
                        "direct": hops == 0,
                        "matched_conditions": terminal_hit["matched_conditions"],
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
                record["matched_name"],
                record["source"] or "",
            )
        )
        return records

    # ------------------------------------------------------------------
    # Exemption applications
    # ------------------------------------------------------------------

    @staticmethod
    def _exemption_dict(row: sqlite3.Row) -> dict:
        return {
            "application_no": str(row["application_no"]),
            "service": str(row["service"]),
            "ecosystem": str(row["ecosystem"]),
            "name": str(row["name"]),
            "version": str(row["version"]),
            "vulnerability_id": str(row["vulnerability_id"]),
            "matched_name": str(row["matched_name"]),
            "source": str(row["source"]),
            "applicant": str(row["applicant"]),
            "reason": str(row["reason"]),
            "expires_at": str(row["expires_at"]),
            "status": str(row["status"]),
            "risk_level": row["risk_level"],
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _history_dict(row: sqlite3.Row) -> dict:
        return {
            "application_no": str(row["application_no"]),
            "action": str(row["action"]),
            "operator": str(row["operator"]),
            "reason": str(row["reason"]),
            "from_status": str(row["from_status"]),
            "to_status": str(row["to_status"]),
            "acted_at": str(row["acted_at"]),
        }

    def _find_impact_record(
        self,
        service: str,
        ecosystem: str,
        name: str,
        version: str,
        vulnerability_id: str,
        matched_name: str,
        source: str,
    ) -> dict | None:
        """Find the current impact record matching an exemption scope.

        Returns the impact record (which carries the current severity) or
        None when the impact no longer exists.
        """
        for record in self.impact():
            if (
                record["component"]["service"] == service
                and record["component"]["ecosystem"] == ecosystem
                and record["component"]["name"] == name
                and record["component"]["version"] == version
                and record["vulnerability"] == vulnerability_id
                and record["matched_name"] == matched_name
                and (record["source"] or "") == source
            ):
                return record
        return None

    def _insert_history(
        self,
        application_no: str,
        action: str,
        operator: str,
        reason: str,
        from_status: str,
        to_status: str,
        acted_at: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO exemption_history(
                application_no, action, operator, reason,
                from_status, to_status, acted_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (application_no, action, operator, reason, from_status, to_status, acted_at),
        )

    def apply_exemption(
        self,
        application_no: str,
        service: str,
        ecosystem: str,
        name: str,
        version: str,
        vulnerability_id: str,
        matched_name: str,
        source: str | None,
        applicant: str,
        reason: str,
        expires_at: str,
    ) -> dict:
        """Apply for an exemption on one current impact record.

        The scope is limited to this single impact record: other versions,
        services and sources require separate applications. Repeating the
        same number with identical content returns the original application;
        the same number with different content is an error. Only one
        unexpired pending or approved application is allowed per scope.
        """
        service = _nonempty(service, "service")
        ecosystem = _nonempty(ecosystem, "ecosystem")
        name = _nonempty(name, "name")
        version = _nonempty(version, "version")
        vulnerability_id = _nonempty(vulnerability_id, "vulnerability_id")
        matched_name = _nonempty(matched_name, "matched_name")
        source = "" if source is None else source.strip()
        applicant = _nonempty(applicant, "applicant")
        reason = _nonempty(reason, "reason")
        application_no = _nonempty(application_no, "application_no")
        expiry = _parse_timestamp(expires_at, "expires_at")
        now = _now_utc()
        if expiry <= now:
            raise ValueError("到期时间必须晚于提交时刻")
        now_iso = _format_utc(now)
        expires_iso = _format_utc(expiry)

        try:
            self.connection.execute("BEGIN IMMEDIATE")
            existing = self.connection.execute(
                "SELECT * FROM exemptions WHERE application_no = ?",
                (application_no,),
            ).fetchone()
            if existing is not None:
                if all(
                    existing[column] == value
                    for column, value in (
                        ("service", service),
                        ("ecosystem", ecosystem),
                        ("name", name),
                        ("version", version),
                        ("vulnerability_id", vulnerability_id),
                        ("matched_name", matched_name),
                        ("source", source),
                        ("applicant", applicant),
                        ("reason", reason),
                        ("expires_at", expires_iso),
                    )
                ):
                    self.connection.execute("COMMIT")
                    return self._exemption_dict(existing)
                raise ValueError("申请编号已存在但内容不同")

            scope_row = self.connection.execute(
                """
                SELECT application_no, status, expires_at FROM exemptions
                WHERE service = ? AND ecosystem = ? AND name = ? AND version = ?
                  AND vulnerability_id = ? AND matched_name = ? AND source = ?
                  AND status IN ('pending', 'approved')
                ORDER BY id DESC LIMIT 1
                """,
                (service, ecosystem, name, version,
                 vulnerability_id, matched_name, source),
            ).fetchone()
            if scope_row is not None:
                scope_expiry = _parse_timestamp(
                    scope_row["expires_at"], "expires_at"
                )
                if scope_expiry > now:
                    raise ValueError(
                        f"同一范围已存在未到期的{scope_row['status']}申请: "
                        f"{scope_row['application_no']}"
                    )

            if self._find_impact_record(
                service, ecosystem, name, version,
                vulnerability_id, matched_name, source,
            ) is None:
                raise ValueError("目标影响记录不存在")

            cursor = self.connection.execute(
                """
                INSERT INTO exemptions(
                    application_no, service, ecosystem, name, version,
                    vulnerability_id, matched_name, source, applicant, reason,
                    expires_at, status, risk_level, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?, ?)
                """,
                (application_no, service, ecosystem, name, version,
                 vulnerability_id, matched_name, source, applicant, reason,
                 expires_iso, now_iso, now_iso),
            )
            self._insert_history(
                application_no, "applied", applicant, reason,
                "", "pending", now_iso,
            )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.rollback()
            raise
        row = self.connection.execute(
            "SELECT * FROM exemptions WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        return self._exemption_dict(row)

    def _transition_exemption(
        self,
        application_no: str,
        action: str,
        operator: str,
        reason: str,
        from_status: str,
        to_status: str,
        extra_checks,
    ) -> dict:
        """Perform a state transition with concurrency protection.

        The conditional UPDATE ... WHERE status = ? ensures that two
        concurrent processes cannot both accept the same transition.
        """
        application_no = _nonempty(application_no, "application_no")
        operator = _nonempty(operator, "operator")
        reason = _nonempty(reason, "reason")
        now_iso = _format_utc(_now_utc())

        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                "SELECT * FROM exemptions WHERE application_no = ?",
                (application_no,),
            ).fetchone()
            if row is None:
                raise ValueError(f"申请不存在: {application_no}")
            if str(row["status"]) != from_status:
                raise ValueError(
                    f"申请状态为 {row['status']}，无法执行{action}"
                )
            extra_checks(row)
            cursor = self.connection.execute(
                "UPDATE exemptions SET status = ?, updated_at = ? "
                "WHERE application_no = ? AND status = ?",
                (to_status, now_iso, application_no, from_status),
            )
            if cursor.rowcount != 1:
                raise ValueError("申请已被其他进程处理")
            self._insert_history(
                application_no, action, operator, reason,
                from_status, to_status, now_iso,
            )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.rollback()
            raise
        return self._exemption_dict(
            self.connection.execute(
                "SELECT * FROM exemptions WHERE application_no = ?",
                (application_no,),
            ).fetchone()
        )

    def approve_exemption(
        self, application_no: str, operator: str, reason: str
    ) -> dict:
        """Approve a pending exemption.

        The target impact must still exist, the applicant cannot approve
        their own application, and the application must not be expired.
        The current risk level is saved; later levels above it stop the
        exemption from applying.
        """
        def checks(row: sqlite3.Row) -> None:
            if operator == str(row["applicant"]):
                raise ValueError("申请人不能批准自己的申请")
            expiry = _parse_timestamp(row["expires_at"], "expires_at")
            if expiry <= _now_utc():
                raise ValueError("申请已到期，无法批准")
            record = self._find_impact_record(
                str(row["service"]), str(row["ecosystem"]), str(row["name"]),
                str(row["version"]), str(row["vulnerability_id"]),
                str(row["matched_name"]), str(row["source"]),
            )
            if record is None:
                raise ValueError("目标影响记录不存在，无法批准")
            self.connection.execute(
                "UPDATE exemptions SET risk_level = ? WHERE application_no = ?",
                (record["severity"], application_no),
            )

        return self._transition_exemption(
            application_no, "approved", operator, reason,
            "pending", "approved", checks,
        )

    def reject_exemption(
        self, application_no: str, operator: str, reason: str
    ) -> dict:
        """Reject a pending exemption."""
        return self._transition_exemption(
            application_no, "rejected", operator, reason,
            "pending", "rejected", lambda row: None,
        )

    def revoke_exemption(
        self, application_no: str, operator: str, reason: str
    ) -> dict:
        """Revoke an approved, unexpired exemption."""
        def checks(row: sqlite3.Row) -> None:
            expiry = _parse_timestamp(row["expires_at"], "expires_at")
            if expiry <= _now_utc():
                raise ValueError("申请已到期，无法撤销")

        return self._transition_exemption(
            application_no, "revoked", operator, reason,
            "approved", "revoked", checks,
        )

    def list_exemptions(
        self, status: str | None = None, service: str | None = None
    ) -> list[dict]:
        """List exemption applications, optionally filtered by status/service."""
        clauses: list[str] = []
        values: list[str] = []
        if status is not None:
            status = status.strip().lower()
            if status not in EXEMPTION_STATUSES:
                raise ValueError(f"非法的申请状态: {status}")
            clauses.append("status = ?")
            values.append(status)
        if service is not None:
            service = service.strip()
            if not service:
                raise ValueError("service 不能为空")
            clauses.append("service = ?")
            values.append(service)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.connection.execute(
            f"SELECT * FROM exemptions{where} ORDER BY id", values
        ).fetchall()
        return [self._exemption_dict(row) for row in rows]

    def exemption_history(self, application_no: str) -> list[dict]:
        """Return the processing history of one application."""
        application_no = _nonempty(application_no, "application_no")
        rows = self.connection.execute(
            "SELECT * FROM exemption_history WHERE application_no = ? ORDER BY id",
            (application_no,),
        ).fetchall()
        return [self._history_dict(row) for row in rows]

    def _exemption_for_impact(
        self, record: dict, evaluation_at: datetime
    ) -> tuple[bool, str | None, str | None]:
        """Return (exempt, application_no, reason) for one impact record."""
        source = record["source"] or ""
        row = self.connection.execute(
            """
            SELECT * FROM exemptions
            WHERE service = ? AND ecosystem = ? AND name = ? AND version = ?
              AND vulnerability_id = ? AND matched_name = ? AND source = ?
            ORDER BY id DESC LIMIT 1
            """,
            (
                record["component"]["service"],
                record["component"]["ecosystem"],
                record["component"]["name"],
                record["component"]["version"],
                record["vulnerability"],
                record["matched_name"],
                source,
            ),
        ).fetchone()
        if row is None:
            return False, None, "无豁免申请"
        application_no = str(row["application_no"])
        status = str(row["status"])
        if status == "pending":
            return False, application_no, "审批中"
        if status == "rejected":
            return False, application_no, "已拒绝"
        if status == "revoked":
            return False, application_no, "已撤销"
        expiry = _parse_timestamp(row["expires_at"], "expires_at")
        if expiry <= evaluation_at:
            return False, application_no, "已过期"
        risk_level = row["risk_level"]
        if risk_level is not None and SEVERITY_RANK[record["severity"]] > SEVERITY_RANK[str(risk_level)]:
            return False, application_no, "超出审批范围"
        return True, application_no, None

    def risk_report(
        self, service: str | None = None, evaluation_at: str | None = None
    ) -> dict:
        """Generate a JSON report of current impacts and their exemption state.

        Each impact record carries its source, severity, direct/indirect hit
        and dependency path, plus whether it is exempt, the associated
        application and the reason it is not effective. Times are compared
        in UTC; an approved exemption stops applying from its expiry moment.
        The evaluation moment only affects deadline judgment; catalog and
        approval status both take current values.
        """
        if service is not None:
            service = service.strip()
            if not service:
                raise ValueError("service 不能为空")
        if evaluation_at is not None:
            eval_at = _parse_timestamp(evaluation_at, "evaluation_at")
        else:
            eval_at = _now_utc()

        impacts: list[dict] = []
        unexempted_components: set[tuple[str, str, str, str]] = set()
        highest: str | None = None
        for record in self.impact(service=service):
            exempt, application_no, reason = self._exemption_for_impact(
                record, eval_at
            )
            entry = dict(record)
            entry["exempt"] = exempt
            entry["application_no"] = application_no
            entry["reason"] = reason
            impacts.append(entry)
            if not exempt:
                unexempted_components.add(
                    (
                        record["component"]["service"],
                        record["component"]["ecosystem"],
                        record["component"]["name"],
                        record["component"]["version"],
                    )
                )
                if highest is None or SEVERITY_RANK[record["severity"]] > SEVERITY_RANK[highest]:
                    highest = record["severity"]

        return {
            "evaluation_at": _format_utc(eval_at),
            "service": service,
            "impacts": impacts,
            "summary": {
                "components": self.summary().components,
                "unexempted_components": len(unexempted_components),
                "highest_severity": highest,
            },
        }
