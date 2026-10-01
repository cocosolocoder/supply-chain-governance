from __future__ import annotations

import sqlite3
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


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
    service TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    depends_on_service TEXT NOT NULL,
    depends_on_ecosystem TEXT NOT NULL,
    depends_on_name TEXT NOT NULL,
    depends_on_version TEXT NOT NULL,
    UNIQUE(service, ecosystem, name, version,
           depends_on_service, depends_on_ecosystem, depends_on_name, depends_on_version),
    FOREIGN KEY(service, ecosystem, name, version)
        REFERENCES components(service, ecosystem, name, version),
    FOREIGN KEY(depends_on_service, depends_on_ecosystem, depends_on_name, depends_on_version)
        REFERENCES components(service, ecosystem, name, version)
);
"""

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True, order=True)
class Component:
    service: str
    ecosystem: str
    name: str
    version: str


@dataclass(frozen=True)
class Vulnerability:
    identifier: str
    component_name: str
    severity: str


@dataclass(frozen=True)
class ImpactRecord:
    component: Component
    vulnerability: Vulnerability
    direct: bool
    path: tuple[Component, ...]


@dataclass(frozen=True)
class Summary:
    components: int
    affected_components: int
    vulnerabilities: int
    highest_severity: str | None


class Catalog:
    def __init__(self, database: str | Path = ":memory:") -> None:
        self.connection = sqlite3.connect(str(database))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)

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
                "INSERT OR IGNORE INTO components(service, ecosystem, name, version) "
                "VALUES (?, ?, ?, ?)",
                values,
            )

    def add_vulnerability(
        self, identifier: str, component_name: str, severity: str
    ) -> None:
        identifier, component_name, severity = (
            identifier.strip(),
            component_name.strip(),
            severity.strip().lower(),
        )
        if not identifier or not component_name:
            raise ValueError("vulnerability identity must not be empty")
        if severity not in _SEVERITY_RANK:
            raise ValueError("unsupported severity")
        with self.connection:
            self.connection.execute(
                "INSERT INTO vulnerabilities(id, component_name, severity) VALUES (?, ?, ?) "
                "ON CONFLICT(id, component_name) DO UPDATE SET severity=excluded.severity",
                (identifier, component_name, severity),
            )

    def add_dependency(
        self,
        service: str,
        ecosystem: str,
        name: str,
        version: str,
        depends_on_service: str,
        depends_on_ecosystem: str,
        depends_on_name: str,
        depends_on_version: str,
    ) -> None:
        values = tuple(
            value.strip()
            for value in (
                service,
                ecosystem,
                name,
                version,
                depends_on_service,
                depends_on_ecosystem,
                depends_on_name,
                depends_on_version,
            )
        )
        (
            service,
            ecosystem,
            name,
            version,
            depends_on_service,
            depends_on_ecosystem,
            depends_on_name,
            depends_on_version,
        ) = values
        if any(not value for value in values):
            raise ValueError("dependency fields must not be empty")
        dependent = (service, ecosystem, name, version)
        dependency = (
            depends_on_service,
            depends_on_ecosystem,
            depends_on_name,
            depends_on_version,
        )
        if dependent == dependency:
            raise ValueError("a component cannot depend on itself")
        with self.connection:
            if not self._component_exists(service, ecosystem, name, version):
                raise ValueError(
                    f"component {service}/{ecosystem}/{name}/{version} is not registered"
                )
            if not self._component_exists(
                depends_on_service, depends_on_ecosystem, depends_on_name, depends_on_version
            ):
                raise ValueError(
                    f"component {depends_on_service}/{depends_on_ecosystem}/"
                    f"{depends_on_name}/{depends_on_version} is not registered"
                )
            if service != depends_on_service:
                raise ValueError(
                    "dependency relationships must stay within the same service"
                )
            self.connection.execute(
                "INSERT OR IGNORE INTO dependencies("
                "service, ecosystem, name, version, "
                "depends_on_service, depends_on_ecosystem, depends_on_name, depends_on_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )

    def delete_dependency(
        self,
        service: str,
        ecosystem: str,
        name: str,
        version: str,
        depends_on_service: str,
        depends_on_ecosystem: str,
        depends_on_name: str,
        depends_on_version: str,
    ) -> None:
        values = tuple(
            value.strip()
            for value in (
                service,
                ecosystem,
                name,
                version,
                depends_on_service,
                depends_on_ecosystem,
                depends_on_name,
                depends_on_version,
            )
        )
        with self.connection:
            self.connection.execute(
                "DELETE FROM dependencies WHERE "
                "service=? AND ecosystem=? AND name=? AND version=? AND "
                "depends_on_service=? AND depends_on_ecosystem=? AND "
                "depends_on_name=? AND depends_on_version=?",
                values,
            )

    def _component_exists(
        self, service: str, ecosystem: str, name: str, version: str
    ) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM components "
            "WHERE service=? AND ecosystem=? AND name=? AND version=?",
            (service, ecosystem, name, version),
        ).fetchone()
        return row is not None

    def _load_components(self) -> list[Component]:
        rows = self.connection.execute(
            "SELECT service, ecosystem, name, version FROM components"
        )
        return [
            Component(
                str(row["service"]),
                str(row["ecosystem"]),
                str(row["name"]),
                str(row["version"]),
            )
            for row in rows
        ]

    def _load_vulnerabilities(self) -> list[Vulnerability]:
        rows = self.connection.execute(
            "SELECT id, component_name, severity FROM vulnerabilities"
        )
        return [
            Vulnerability(
                str(row["id"]), str(row["component_name"]), str(row["severity"])
            )
            for row in rows
        ]

    def _load_graph(
        self,
    ) -> tuple[
        list[Component],
        dict[Component, list[Component]],
        dict[Component, list[Component]],
    ]:
        components = self._load_components()
        by_key = {
            (component.service, component.ecosystem, component.name, component.version): component
            for component in components
        }
        adjacency: dict[Component, list[Component]] = {
            component: [] for component in components
        }
        reverse: dict[Component, list[Component]] = {
            component: [] for component in components
        }
        rows = self.connection.execute(
            "SELECT service, ecosystem, name, version, "
            "depends_on_service, depends_on_ecosystem, depends_on_name, depends_on_version "
            "FROM dependencies"
        )
        for row in rows:
            dependent = by_key[
                (
                    str(row["service"]),
                    str(row["ecosystem"]),
                    str(row["name"]),
                    str(row["version"]),
                )
            ]
            dependency = by_key[
                (
                    str(row["depends_on_service"]),
                    str(row["depends_on_ecosystem"]),
                    str(row["depends_on_name"]),
                    str(row["depends_on_version"]),
                )
            ]
            adjacency[dependent].append(dependency)
            reverse[dependency].append(dependent)
        return components, adjacency, reverse

    def _count_components(self) -> int:
        row = self.connection.execute("SELECT COUNT(*) AS n FROM components").fetchone()
        return int(row["n"])

    @staticmethod
    def _highest_severity(severities: Iterable[str]) -> str | None:
        highest: str | None = None
        for severity in severities:
            if severity in _SEVERITY_RANK and (
                highest is None or _SEVERITY_RANK[severity] > _SEVERITY_RANK[highest]
            ):
                highest = severity
        return highest

    def _all_records(
        self,
        components: list[Component] | None = None,
        adjacency: dict[Component, list[Component]] | None = None,
        reverse: dict[Component, list[Component]] | None = None,
        vulnerabilities: list[Vulnerability] | None = None,
    ) -> list[ImpactRecord]:
        if components is None:
            components, adjacency, reverse = self._load_graph()
        if vulnerabilities is None:
            vulnerabilities = self._load_vulnerabilities()
        assert adjacency is not None and reverse is not None
        by_name: dict[str, list[Vulnerability]] = defaultdict(list)
        for vulnerability in vulnerabilities:
            by_name[vulnerability.component_name].append(vulnerability)
        records: list[ImpactRecord] = []
        for component_name, group in by_name.items():
            sources = [component for component in components if component.name == component_name]
            if not sources:
                continue
            best = self._propagate(sources, adjacency, reverse)
            for component, path in best.items():
                direct = component in sources
                for vulnerability in group:
                    records.append(
                        ImpactRecord(component, vulnerability, direct, path)
                    )
        records.sort(
            key=lambda record: (
                record.component.service,
                record.component.ecosystem,
                record.component.name,
                record.component.version,
                record.vulnerability.identifier,
                record.vulnerability.component_name,
            )
        )
        return records

    def summary(self) -> Summary:
        records = self._all_records()
        affected = {record.component for record in records}
        vulnerability_pairs = {
            (record.vulnerability.identifier, record.vulnerability.component_name)
            for record in records
        }
        return Summary(
            components=self._count_components(),
            affected_components=len(affected),
            vulnerabilities=len(vulnerability_pairs),
            highest_severity=self._highest_severity(
                record.vulnerability.severity for record in records
            ),
        )

    def affected_services(self) -> list[str]:
        records = self._all_records()
        return sorted({record.component.service for record in records})

    def impact(
        self,
        service: str | None = None,
        ecosystem: str | None = None,
        name: str | None = None,
        version: str | None = None,
    ) -> list[ImpactRecord]:
        components, adjacency, reverse = self._load_graph()
        vulnerabilities = self._load_vulnerabilities()
        component_filter = any(value is not None for value in (ecosystem, name, version))
        if component_filter:
            if service is None or ecosystem is None or name is None or version is None:
                raise ValueError(
                    "component filter requires service, ecosystem, name and version"
                )
            target = next(
                (
                    component
                    for component in components
                    if component.service == service
                    and component.ecosystem == ecosystem
                    and component.name == name
                    and component.version == version
                ),
                None,
            )
            if target is None:
                return []
            records = self._records_from_component(target, adjacency, vulnerabilities)
        else:
            records = self._all_records(components, adjacency, reverse, vulnerabilities)
            if service is not None:
                records = [
                    record for record in records if record.component.service == service
                ]
        return records

    @staticmethod
    def _propagate(
        sources: list[Component],
        adjacency: dict[Component, list[Component]],
        reverse: dict[Component, list[Component]],
    ) -> dict[Component, tuple[Component, ...]]:
        dist = {source: 0 for source in sources}
        best = {source: (source,) for source in sources}
        queue = deque(sources)
        order: list[Component] = []
        while queue:
            current = queue.popleft()
            order.append(current)
            for dependent in reverse[current]:
                if dependent not in dist:
                    dist[dependent] = dist[current] + 1
                    queue.append(dependent)
        for current in order:
            if dist[current] == 0:
                continue
            predecessors = [
                dependency
                for dependency in adjacency[current]
                if dist.get(dependency) == dist[current] - 1
            ]
            best[current] = (current,) + min(
                best[dependency] for dependency in predecessors
            )
        return best

    def _records_from_component(
        self,
        start: Component,
        adjacency: dict[Component, list[Component]],
        vulnerabilities: list[Vulnerability],
    ) -> list[ImpactRecord]:
        dist = {start: 0}
        best = {start: (start,)}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for dependency in adjacency[current]:
                candidate = best[current] + (dependency,)
                if dependency not in dist:
                    dist[dependency] = dist[current] + 1
                    best[dependency] = candidate
                    queue.append(dependency)
                elif dist[dependency] == dist[current] + 1 and candidate < best[dependency]:
                    best[dependency] = candidate
        by_name: dict[str, list[Vulnerability]] = defaultdict(list)
        for vulnerability in vulnerabilities:
            by_name[vulnerability.component_name].append(vulnerability)
        records: list[ImpactRecord] = []
        for component, path in best.items():
            if component is start:
                continue
            for vulnerability in by_name.get(component.name, ()):
                records.append(
                    ImpactRecord(start, vulnerability, False, path)
                )
        for vulnerability in by_name.get(start.name, ()):
            records.append(ImpactRecord(start, vulnerability, True, (start,)))
        return self._dedupe(records)

    @staticmethod
    def _dedupe(records: Iterable[ImpactRecord]) -> list[ImpactRecord]:
        chosen: dict[tuple[str, str], ImpactRecord] = {}
        for record in records:
            key = (record.vulnerability.identifier, record.vulnerability.component_name)
            current = chosen.get(key)
            if current is None or (len(record.path), record.path) < (
                len(current.path),
                current.path,
            ):
                chosen[key] = record
        return list(chosen.values())
