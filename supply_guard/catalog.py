from __future__ import annotations

import json
import re
import sqlite3
from collections import deque
from dataclasses import dataclass
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS components (
    id INTEGER PRIMARY KEY,
    service TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    UNIQUE(service, ecosystem, name, version)
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT NOT NULL,
    component_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    PRIMARY KEY(id, component_name)
);
CREATE TABLE IF NOT EXISTS dependencies (
    dependent_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    dependency_id INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
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
CREATE TABLE IF NOT EXISTS manual_components (
    component_id INTEGER PRIMARY KEY REFERENCES components(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS dependency_sources (
    dependent_id INTEGER NOT NULL,
    dependency_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    PRIMARY KEY(dependent_id, dependency_id, source_id),
    FOREIGN KEY(dependent_id, dependency_id)
        REFERENCES dependencies(dependent_id, dependency_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS manual_dependencies (
    dependent_id INTEGER NOT NULL,
    dependency_id INTEGER NOT NULL,
    PRIMARY KEY(dependent_id, dependency_id),
    FOREIGN KEY(dependent_id, dependency_id)
        REFERENCES dependencies(dependent_id, dependency_id) ON DELETE CASCADE
);
"""

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

SUPPORTED_ECOSYSTEMS = ("pypi", "npm")


class ManifestError(ValueError):
    """Raised when a CycloneDX manifest cannot be read or imported."""


@dataclass(frozen=True)
class Summary:
    components: int
    affected_components: int
    vulnerabilities: int
    highest_severity: str | None


@dataclass(frozen=True)
class ImportResult:
    service: str
    source: str
    source_components: int
    components_added: int
    components_deleted: int
    dependencies_added: int
    dependencies_deleted: int


_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_BAD_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _percent_decode(value: str, location: str) -> str:
    bad = _BAD_PERCENT_ESCAPE.search(value)
    if bad is not None:
        raise ManifestError(
            f"{location}: malformed percent-encoding at position {bad.start()}"
        )
    return _PERCENT_ESCAPE.sub(
        lambda match: chr(int(match.group(1), 16)), value
    )


def _parse_purl(purl: object, location: str) -> tuple[str, str, str]:
    """Resolve a Package URL into (ecosystem, name, version)."""
    if not isinstance(purl, str) or not purl:
        raise ManifestError(f"{location}: purl must be a non-empty string")
    if not purl.startswith("pkg:"):
        raise ManifestError(f"{location}: purl must start with 'pkg:': {purl!r}")
    body = purl[len("pkg:") :]
    # Qualifiers and subpath are irrelevant to component identity.
    body = body.split("#", 1)[0]
    body = body.split("?", 1)[0]
    if "/" not in body:
        raise ManifestError(f"{location}: purl is missing its package name: {purl!r}")
    package_type, path = body.split("/", 1)
    if package_type not in SUPPORTED_ECOSYSTEMS:
        raise ManifestError(
            f"{location}: unsupported purl type {package_type!r}; "
            "only pypi and npm are supported"
        )
    if "@" not in path:
        raise ManifestError(f"{location}: purl must include a version: {purl!r}")
    name_part, raw_version = path.rsplit("@", 1)
    if not name_part:
        raise ManifestError(f"{location}: purl is missing its package name: {purl!r}")
    segments = name_part.split("/")
    if any(segment == "" for segment in segments):
        raise ManifestError(f"{location}: purl has an empty path segment: {purl!r}")
    decoded_segments = [
        _percent_decode(segment, f"{location}: purl segment {segment!r}")
        for segment in segments
    ]
    if any(segment == "" for segment in decoded_segments):
        raise ManifestError(f"{location}: purl package name must not be empty: {purl!r}")
    if package_type == "npm" and len(decoded_segments) > 1:
        # Keep the npm scope, e.g. '@angular/core'.
        name = "/".join(decoded_segments)
    else:
        name = decoded_segments[-1]
    version = _percent_decode(raw_version, f"{location}: purl version {raw_version!r}")
    if not version:
        raise ManifestError(f"{location}: purl version must not be empty: {purl!r}")
    return package_type, name, version


def _validate_manifest(
    document: object,
) -> tuple[list[tuple[str, str, str]], set[tuple[tuple[str, str, str], tuple[str, str, str]]]]:
    """Parse a CycloneDX 1.5 document into distinct identities and identity edges."""
    if not isinstance(document, dict):
        raise ManifestError("manifest root must be a JSON object")
    bom_format = document.get("bomFormat")
    if bom_format != "CycloneDX":
        raise ManifestError(
            f"bomFormat must be 'CycloneDX', got {bom_format!r}"
        )
    spec_version = document.get("specVersion")
    if spec_version != "1.5":
        raise ManifestError(f"specVersion must be '1.5', got {spec_version!r}")
    components = document.get("components")
    if not isinstance(components, list):
        raise ManifestError("'components' must be an array")

    ref_identities: dict[str, tuple[str, str, str]] = {}
    identities: list[tuple[str, str, str]] = []
    seen_identities: set[tuple[str, str, str]] = set()
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            raise ManifestError(f"components[{index}] must be an object")
        nested = component.get("components")
        if nested is not None and not isinstance(nested, list):
            raise ManifestError(f"components[{index}]: components must be an array")
        if isinstance(nested, list) and nested:
            raise ManifestError(
                f"components[{index}]: nested components are not supported"
            )
        ref = component.get("bom-ref")
        if not isinstance(ref, str) or not ref:
            raise ManifestError(
                f"components[{index}]: bom-ref must be a unique non-empty string"
            )
        location = f"components[{index}] (bom-ref={ref!r})"
        if ref in ref_identities:
            raise ManifestError(f"{location}: duplicate bom-ref {ref!r}")
        identity = _parse_purl(component.get("purl"), location)
        if "version" in component:
            explicit_version = component["version"]
            if not isinstance(explicit_version, str):
                raise ManifestError(f"{location}: component version must be a string")
            if explicit_version != identity[2]:
                raise ManifestError(
                    f"{location}: component version {explicit_version!r} "
                    f"does not match purl version {identity[2]!r}"
                )
        ref_identities[ref] = identity
        if identity not in seen_identities:
            seen_identities.add(identity)
            identities.append(identity)

    root_ref: str | None = None
    metadata = document.get("metadata")
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise ManifestError("'metadata' must be an object")
        root = metadata.get("component")
        if root is not None:
            if not isinstance(root, dict):
                raise ManifestError("metadata.component must be an object")
            bom_ref = root.get("bom-ref")
            if bom_ref is not None and not isinstance(bom_ref, str):
                raise ManifestError("metadata.component bom-ref must be a string")
            if isinstance(bom_ref, str) and bom_ref:
                root_ref = bom_ref
    if root_ref is not None and root_ref in ref_identities:
        raise ManifestError(
            f"metadata.component bom-ref {root_ref!r} must not be reused "
            "by a component"
        )

    edges: set[
        tuple[tuple[str, str, str], tuple[str, str, str]]
    ] = set()
    declarations = document.get("dependencies")
    if declarations is not None:
        if not isinstance(declarations, list):
            raise ManifestError("'dependencies' must be an array")
        for index, entry in enumerate(declarations):
            location = f"dependencies[{index}]"
            if not isinstance(entry, dict):
                raise ManifestError(f"{location} must be an object")
            ref = entry.get("ref")
            if not isinstance(ref, str) or not ref:
                raise ManifestError(
                    f"{location}: ref must be a non-empty string"
                )
            # The root component only anchors the manifest; its outgoing
            # edges are neither registered nor interpreted.
            if ref == root_ref:
                continue
            if ref not in ref_identities:
                raise ManifestError(f"{location}: unknown ref {ref!r}")
            targets = entry.get("dependencies", [])
            if not isinstance(targets, list):
                raise ManifestError(f"{location}: dependencies must be an array")
            for target_index, target in enumerate(targets):
                target_location = f"{location}.dependencies[{target_index}]"
                if not isinstance(target, str) or not target:
                    raise ManifestError(
                        f"{target_location}: dependency ref must be a non-empty string"
                    )
                if target == root_ref:
                    raise ManifestError(
                        f"{target_location}: components must not depend on the "
                        f"manifest root {root_ref!r}"
                    )
                if target not in ref_identities:
                    raise ManifestError(
                        f"{target_location}: unknown ref {target!r}"
                    )
                dependent_identity = ref_identities[ref]
                dependency_identity = ref_identities[target]
                if dependent_identity == dependency_identity:
                    raise ManifestError(
                        f"{target_location}: {ref!r} and {target!r} resolve to the "
                        "same component; self-dependencies are not allowed"
                    )
                edges.add((dependent_identity, dependency_identity))

    return identities, edges


class Catalog:
    def __init__(self, database: str | Path = ":memory:") -> None:
        self.connection = sqlite3.connect(str(database))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self._migrate_manual_registrations()

    def close(self) -> None:
        self.connection.close()

    def _migrate_manual_registrations(self) -> None:
        """Catalogs created before provenance tracking treated everything as manual."""
        version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        if version >= 1:
            return
        with self.connection:
            self.connection.execute(
                "INSERT OR IGNORE INTO manual_components(component_id) "
                "SELECT id FROM components"
            )
            self.connection.execute(
                "INSERT OR IGNORE INTO manual_dependencies(dependent_id, dependency_id) "
                "SELECT dependent_id, dependency_id FROM dependencies"
            )
            self.connection.execute("PRAGMA user_version = 1")

    def add_component(
        self, service: str, ecosystem: str, name: str, version: str
    ) -> None:
        values = tuple(value.strip() for value in (service, ecosystem, name, version))
        if any(not value for value in values):
            raise ValueError("component fields must not be empty")
        with self.connection:
            self.connection.execute(
                "INSERT OR IGNORE INTO components(service, ecosystem, name, version) "
                "VALUES (?, ?, ?, ?)",
                values,
            )
            component_id = self._component_id(*values)
            self.connection.execute(
                "INSERT OR IGNORE INTO manual_components(component_id) VALUES (?)",
                (component_id,),
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
                "INSERT OR IGNORE INTO dependencies(dependent_id, dependency_id) "
                "VALUES (?, ?)",
                (dependent_id, dependency_id),
            )
            self.connection.execute(
                "INSERT OR IGNORE INTO manual_dependencies(dependent_id, dependency_id) "
                "VALUES (?, ?)",
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
            # Only the manual registration is revoked; edges another source
            # still declares stay in the graph.
            self.connection.execute(
                "DELETE FROM manual_dependencies "
                "WHERE dependent_id = ? AND dependency_id = ?",
                (dependent_id, dependency_id),
            )
            self.connection.execute(
                "DELETE FROM dependencies "
                "WHERE dependent_id = ? AND dependency_id = ? "
                "AND NOT EXISTS ( "
                "SELECT 1 FROM dependency_sources ds "
                "WHERE ds.dependent_id = dependencies.dependent_id "
                "AND ds.dependency_id = dependencies.dependency_id)",
                (dependent_id, dependency_id),
            )

    def import_cyclonedx(
        self, service: str, source: str, file: str | Path
    ) -> ImportResult:
        """Import (or replace) one named CycloneDX 1.5 JSON manifest source."""
        service = service.strip()
        source = source.strip()
        if not service:
            raise ManifestError("service must not be empty")
        if not source:
            raise ManifestError("source must not be empty")
        path = Path(file)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ManifestError(f"cannot read manifest file {path}: {error}") from None
        try:
            document = json.loads(text)
        except json.JSONDecodeError as error:
            raise ManifestError(
                f"invalid JSON in {path}: {error.msg} "
                f"(line {error.lineno}, column {error.colno})"
            ) from None
        identities, edges = _validate_manifest(document)
        return self._replace_manifest_source(service, source, identities, edges)

    # Convenience aliases for Python callers.
    import_manifest = import_cyclonedx
    import_bom = import_cyclonedx

    def _replace_manifest_source(
        self,
        service: str,
        source: str,
        identities: list[tuple[str, str, str]],
        edges: set[tuple[tuple[str, str, str], tuple[str, str, str]]],
    ) -> ImportResult:
        # Sort so insertion order never depends on document order or ref names.
        ordered_identities = sorted(set(identities))
        ordered_edges = sorted(edges)
        with self.connection:
            source_row = self.connection.execute(
                "SELECT id FROM sources WHERE service = ? AND name = ?",
                (service, source),
            ).fetchone()
            if source_row is None:
                cursor = self.connection.execute(
                    "INSERT INTO sources(service, name) VALUES (?, ?)",
                    (service, source),
                )
                source_id = int(cursor.lastrowid)
            else:
                source_id = int(source_row["id"])

            # This source's previous declarations are fully replaced.
            self.connection.execute(
                "DELETE FROM dependency_sources WHERE source_id = ?", (source_id,)
            )
            self.connection.execute(
                "DELETE FROM component_sources WHERE source_id = ?", (source_id,)
            )

            components_added = 0
            component_ids: dict[tuple[str, str, str], int] = {}
            for ecosystem, name, version in ordered_identities:
                component_id = self._component_id(service, ecosystem, name, version)
                if component_id is None:
                    cursor = self.connection.execute(
                        "INSERT INTO components(service, ecosystem, name, version) "
                        "VALUES (?, ?, ?, ?)",
                        (service, ecosystem, name, version),
                    )
                    component_id = int(cursor.lastrowid)
                    components_added += 1
                component_ids[(ecosystem, name, version)] = component_id
                self.connection.execute(
                    "INSERT OR IGNORE INTO component_sources(component_id, source_id) "
                    "VALUES (?, ?)",
                    (component_id, source_id),
                )

            dependencies_added = 0
            for dependent_identity, dependency_identity in ordered_edges:
                dependent_id = component_ids[dependent_identity]
                dependency_id = component_ids[dependency_identity]
                existing = self.connection.execute(
                    "SELECT 1 FROM dependencies "
                    "WHERE dependent_id = ? AND dependency_id = ?",
                    (dependent_id, dependency_id),
                ).fetchone()
                if existing is None:
                    self.connection.execute(
                        "INSERT INTO dependencies(dependent_id, dependency_id) "
                        "VALUES (?, ?)",
                        (dependent_id, dependency_id),
                    )
                    dependencies_added += 1
                self.connection.execute(
                    "INSERT OR IGNORE INTO dependency_sources"
                    "(dependent_id, dependency_id, source_id) VALUES (?, ?, ?)",
                    (dependent_id, dependency_id, source_id),
                )

            # Drop relationships and components that no source or manual
            # registration backs. Endpoints of surviving manual relationships
            # survive with the relationship.
            deleted_edges_cursor = self.connection.execute(
                "DELETE FROM dependencies "
                "WHERE NOT EXISTS ( "
                "SELECT 1 FROM dependency_sources ds "
                "WHERE ds.dependent_id = dependencies.dependent_id "
                "AND ds.dependency_id = dependencies.dependency_id) "
                "AND NOT EXISTS ( "
                "SELECT 1 FROM manual_dependencies md "
                "WHERE md.dependent_id = dependencies.dependent_id "
                "AND md.dependency_id = dependencies.dependency_id)"
            )
            dependencies_deleted = deleted_edges_cursor.rowcount
            deleted_components_cursor = self.connection.execute(
                "DELETE FROM components "
                "WHERE NOT EXISTS ( "
                "SELECT 1 FROM component_sources cs "
                "WHERE cs.component_id = components.id) "
                "AND NOT EXISTS ( "
                "SELECT 1 FROM manual_components mc "
                "WHERE mc.component_id = components.id) "
                "AND NOT EXISTS ( "
                "SELECT 1 FROM manual_dependencies md "
                "JOIN dependencies d "
                "ON d.dependent_id = md.dependent_id "
                "AND d.dependency_id = md.dependency_id "
                "WHERE components.id IN (md.dependent_id, md.dependency_id)) "
                "AND NOT EXISTS ( "
                "SELECT 1 FROM dependency_sources ds "
                "JOIN dependencies d "
                "ON d.dependent_id = ds.dependent_id "
                "AND d.dependency_id = ds.dependency_id "
                "WHERE components.id IN (ds.dependent_id, ds.dependency_id))"
            )
            components_deleted = deleted_components_cursor.rowcount

        return ImportResult(
            service=service,
            source=source,
            source_components=len(ordered_identities),
            components_added=components_added,
            components_deleted=components_deleted,
            dependencies_added=dependencies_added,
            dependencies_deleted=dependencies_deleted,
        )

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
