from __future__ import annotations

import json
import sqlite3
from collections import deque
from dataclasses import dataclass
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
        queue = deque(affected)
        while queue:
            node = queue.popleft()
            for dependent in reverse.get(node, ()):
                if dependent not in affected:
                    affected.add(dependent)
                    queue.append(dependent)
        return affected

    def summary(self) -> Summary:
        affected = self._affected_ids()
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
        return Summary(
            components=int(row["components"]),
            affected_components=len(affected),
            vulnerabilities=int(row["vulnerabilities"]),
            highest_severity=row["highest_severity"],
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
        observations = self.connection.execute(
            """
            SELECT v.id, v.component_name, v.severity
            FROM vulnerabilities v
            WHERE EXISTS (SELECT 1 FROM components c WHERE c.name = v.component_name)
            ORDER BY v.id, v.component_name
            """
        ).fetchall()

        records: list[dict] = []
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
            )
        )
        return records
