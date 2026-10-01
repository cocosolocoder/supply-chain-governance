from __future__ import annotations

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
"""

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


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
            self.connection.execute(
                "DELETE FROM dependencies WHERE dependent_id = ? AND dependency_id = ?",
                (dependent_id, dependency_id),
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
