from __future__ import annotations

import argparse
import json
import sys
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
    for action in ("add-dependency", "remove-dependency"):
        dependency = subcommands.add_parser(action)
        dependency.add_argument("service")
        dependency.add_argument("ecosystem")
        dependency.add_argument("name")
        dependency.add_argument("version")
        dependency.add_argument("dependency_service")
        dependency.add_argument("dependency_ecosystem")
        dependency.add_argument("dependency_name")
        dependency.add_argument("dependency_version")
    impact = subcommands.add_parser("impact")
    impact.add_argument("--service")
    impact.add_argument("--ecosystem")
    impact.add_argument("--name")
    impact.add_argument("--version")
    sbom = subcommands.add_parser("import-sbom")
    sbom.add_argument("service")
    sbom.add_argument("source")
    sbom.add_argument("file")
    osv = subcommands.add_parser("import-osv")
    osv.add_argument("source")
    osv.add_argument("file")
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


def run(arguments: argparse.Namespace, catalog: Catalog) -> None:
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
    elif arguments.command == "add-dependency":
        catalog.add_dependency(
            arguments.service,
            arguments.ecosystem,
            arguments.name,
            arguments.version,
            arguments.dependency_service,
            arguments.dependency_ecosystem,
            arguments.dependency_name,
            arguments.dependency_version,
        )
        print("dependency recorded")
    elif arguments.command == "remove-dependency":
        catalog.remove_dependency(
            arguments.service,
            arguments.ecosystem,
            arguments.name,
            arguments.version,
            arguments.dependency_service,
            arguments.dependency_ecosystem,
            arguments.dependency_name,
            arguments.dependency_version,
        )
        print("dependency removed")
    elif arguments.command == "impact":
        records = catalog.impact(
            service=arguments.service,
            ecosystem=arguments.ecosystem,
            name=arguments.name,
            version=arguments.version,
        )
        print(json.dumps(records, ensure_ascii=False, indent=2))
    elif arguments.command == "import-sbom":
        result = catalog.import_sbom_file(
            arguments.service, arguments.source, arguments.file
        )
        print(f"来源组件数: {result.source_components}")
        print(f"新增组件: {result.added_components}")
        print(f"删除组件: {result.deleted_components}")
        print(f"新增关系: {result.added_dependencies}")
        print(f"删除关系: {result.deleted_dependencies}")
    elif arguments.command == "import-osv":
        count = catalog.import_osv_file(arguments.source, arguments.file)
        print(f"导入记录数: {count}")
    elif arguments.command == "summary":
        print(render_summary(catalog))
    elif arguments.command == "demo":
        catalog.add_component("checkout-api", "pypi", "fastapi", "0.115.0")
        catalog.add_component("worker", "pypi", "urllib3", "2.2.2")
        catalog.add_component("portal", "npm", "react", "18.3.1")
        catalog.add_vulnerability("CVE-2026-1000", "urllib3", "high")
        catalog.add_vulnerability("CVE-2026-1001", "fastapi", "medium")
        print(render_summary(catalog))


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    catalog = Catalog(arguments.database)
    try:
        run(arguments, catalog)
        return 0
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        catalog.close()


if __name__ == "__main__":
    raise SystemExit(main())
