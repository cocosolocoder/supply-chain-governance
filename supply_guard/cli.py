from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .catalog import Catalog, ImpactRecord


def _identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("service")
    parser.add_argument("ecosystem")
    parser.add_argument("name")
    parser.add_argument("version")
    parser.add_argument("depends_on_service")
    parser.add_argument("depends_on_ecosystem")
    parser.add_argument("depends_on_name")
    parser.add_argument("depends_on_version")


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(prog="supply-guard")
    command.add_argument("--database", default=":memory:")
    subcommands = command.add_subparsers(dest="command", required=True)
    subcommands.add_parser("init")
    component = subcommands.add_parser("add-component")
    component.add_argument("service")
    component.add_argument("ecosystem")
    component.add_argument("name")
    component.add_argument("version")
    vulnerability = subcommands.add_parser("add-vulnerability")
    vulnerability.add_argument("identifier")
    vulnerability.add_argument("component")
    vulnerability.add_argument("severity")
    add_dependency = subcommands.add_parser(
        "add-dependency", aliases=["add-dep"]
    )
    _identity_arguments(add_dependency)
    delete_dependency = subcommands.add_parser(
        "delete-dependency", aliases=["delete-dep"]
    )
    _identity_arguments(delete_dependency)
    subcommands.add_parser("summary")
    impact = subcommands.add_parser("impact", aliases=["impact-details"])
    impact.add_argument("--service")
    impact.add_argument("--ecosystem")
    impact.add_argument("--name")
    impact.add_argument("--version")
    subcommands.add_parser("demo")
    return command


def render_summary(catalog: Catalog) -> str:
    summary = catalog.summary()
    services = catalog.affected_services()
    return "\n".join(
        [
            "软件供应链治理摘要",
            f"组件数量: {summary.components}",
            f"受影响组件: {summary.affected_components}",
            f"漏洞数量: {summary.vulnerabilities}",
            f"最高风险: {summary.highest_severity or 'none'}",
            f"受影响服务: {', '.join(services) if services else 'none'}",
        ]
    )


def render_impact(records: Sequence[ImpactRecord]) -> str:
    payload = [
        {
            "service": record.component.service,
            "ecosystem": record.component.ecosystem,
            "name": record.component.name,
            "version": record.component.version,
            "vulnerability_id": record.vulnerability.identifier,
            "vulnerability_name": record.vulnerability.component_name,
            "severity": record.vulnerability.severity,
            "direct": record.direct,
            "path": [
                {
                    "service": node.service,
                    "ecosystem": node.ecosystem,
                    "name": node.name,
                    "version": node.version,
                }
                for node in record.path
            ],
        }
        for record in records
    ]
    return json.dumps(payload, ensure_ascii=False, indent=2)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    catalog = Catalog(arguments.database)
    try:
        if arguments.command == "init":
            print("catalog initialized")
        elif arguments.command == "add-component":
            catalog.add_component(
                arguments.service, arguments.ecosystem, arguments.name, arguments.version
            )
            print("component recorded")
        elif arguments.command == "add-vulnerability":
            catalog.add_vulnerability(
                arguments.identifier, arguments.component, arguments.severity
            )
            print("vulnerability recorded")
        elif arguments.command in ("add-dependency", "add-dep"):
            catalog.add_dependency(
                arguments.service,
                arguments.ecosystem,
                arguments.name,
                arguments.version,
                arguments.depends_on_service,
                arguments.depends_on_ecosystem,
                arguments.depends_on_name,
                arguments.depends_on_version,
            )
            print("dependency recorded")
        elif arguments.command in ("delete-dependency", "delete-dep"):
            catalog.delete_dependency(
                arguments.service,
                arguments.ecosystem,
                arguments.name,
                arguments.version,
                arguments.depends_on_service,
                arguments.depends_on_ecosystem,
                arguments.depends_on_name,
                arguments.depends_on_version,
            )
            print("dependency removed")
        elif arguments.command == "summary":
            print(render_summary(catalog))
        elif arguments.command in ("impact", "impact-details"):
            print(
                render_impact(
                    catalog.impact(
                        arguments.service,
                        arguments.ecosystem,
                        arguments.name,
                        arguments.version,
                    )
                )
            )
        elif arguments.command == "demo":
            catalog.add_component("checkout-api", "pypi", "fastapi", "0.115.0")
            catalog.add_component("checkout-api", "pypi", "gunicorn", "21.2.0")
            catalog.add_component("worker", "pypi", "urllib3", "2.2.2")
            catalog.add_component("portal", "npm", "react", "18.3.1")
            catalog.add_dependency(
                "checkout-api",
                "pypi",
                "gunicorn",
                "21.2.0",
                "checkout-api",
                "pypi",
                "fastapi",
                "0.115.0",
            )
            catalog.add_vulnerability("CVE-2026-1000", "urllib3", "high")
            catalog.add_vulnerability("CVE-2026-1001", "fastapi", "medium")
            print(render_summary(catalog))
        return 0
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        catalog.close()


if __name__ == "__main__":
    raise SystemExit(main())
