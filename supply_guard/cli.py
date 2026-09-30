from __future__ import annotations

import argparse
from collections.abc import Sequence

from .catalog import Catalog


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
    subcommands.add_parser("summary")
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
        elif arguments.command == "summary":
            print(render_summary(catalog))
        elif arguments.command == "demo":
            catalog.add_component("checkout-api", "pypi", "fastapi", "0.115.0")
            catalog.add_component("worker", "pypi", "urllib3", "2.2.2")
            catalog.add_component("portal", "npm", "react", "18.3.1")
            catalog.add_vulnerability("CVE-2026-1000", "urllib3", "high")
            catalog.add_vulnerability("CVE-2026-1001", "fastapi", "medium")
            print(render_summary(catalog))
        return 0
    finally:
        catalog.close()


if __name__ == "__main__":
    raise SystemExit(main())
