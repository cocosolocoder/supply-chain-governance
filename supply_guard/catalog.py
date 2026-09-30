from __future__ import annotations

import sqlite3
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
"""


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

    def summary(self) -> Summary:
        row = self.connection.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM components) AS components,
              COUNT(DISTINCT CASE WHEN v.id IS NOT NULL THEN c.id END) AS affected_components,
              COUNT(DISTINCT v.id || ':' || v.component_name) AS vulnerabilities,
              CASE MAX(CASE v.severity
                WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
                WHEN 4 THEN 'critical' WHEN 3 THEN 'high'
                WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE NULL END AS highest_severity
            FROM components c
            LEFT JOIN vulnerabilities v ON v.component_name = c.name
            """
        ).fetchone()
        return Summary(
            components=int(row["components"]),
            affected_components=int(row["affected_components"]),
            vulnerabilities=int(row["vulnerabilities"]),
            highest_severity=row["highest_severity"],
        )

    def affected_services(self) -> list[str]:
        rows = self.connection.execute(
            """
            SELECT DISTINCT c.service
            FROM components c
            JOIN vulnerabilities v ON v.component_name = c.name
            ORDER BY c.service
            """
        )
        return [str(row["service"]) for row in rows]
