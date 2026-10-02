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

    request = subcommands.add_parser("request-exemption")
    request.add_argument("id")
    request.add_argument("service")
    request.add_argument("ecosystem")
    request.add_argument("name")
    request.add_argument("version")
    request.add_argument("vulnerability")
    request.add_argument("matched_name")
    request.add_argument(
        "source",
        nargs="?",
        default=None,
        help="OSV 来源名称；省略表示手工登记的漏洞",
    )
    request.add_argument("--applicant", required=True)
    request.add_argument("--reason", required=True)
    request.add_argument(
        "--expires-at",
        required=True,
        help="带时区的到期时间，例如 2026-12-31T23:59:59+08:00",
    )

    approve = subcommands.add_parser("approve-exemption")
    approve.add_argument("id")
    approve.add_argument("--handler", required=True)
    approve.add_argument("--note", required=True)

    reject = subcommands.add_parser("reject-exemption")
    reject.add_argument("id")
    reject.add_argument("--handler", required=True)
    reject.add_argument("--note", required=True)

    revoke = subcommands.add_parser("revoke-exemption")
    revoke.add_argument("id")
    revoke.add_argument("--handler", required=True)
    revoke.add_argument("--note", required=True)

    show = subcommands.add_parser("exemption-show")
    show.add_argument("id")

    exemptions = subcommands.add_parser("exemption-list")
    exemptions.add_argument(
        "--status",
        choices=["pending", "approved", "rejected", "revoked"],
        default=None,
    )

    report = subcommands.add_parser("risk-report")
    report.add_argument("--service")
    report.add_argument(
        "--at",
        dest="evaluated_at",
        default=None,
        help="带时区的评估时刻，仅用于判断豁免期限；省略时取当前时间",
    )
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
        print(f"导入漏洞记录: {count} 条")
    elif arguments.command == "summary":
        print(render_summary(catalog))
    elif arguments.command == "request-exemption":
        record = catalog.request_exemption(
            arguments.id,
            arguments.service,
            arguments.ecosystem,
            arguments.name,
            arguments.version,
            arguments.vulnerability,
            arguments.matched_name,
            arguments.source,
            arguments.applicant,
            arguments.reason,
            arguments.expires_at,
        )
        print(json.dumps(record, ensure_ascii=False, indent=2))
    elif arguments.command == "approve-exemption":
        record = catalog.approve_exemption(
            arguments.id, arguments.handler, arguments.note
        )
        print(json.dumps(record, ensure_ascii=False, indent=2))
    elif arguments.command == "reject-exemption":
        record = catalog.reject_exemption(
            arguments.id, arguments.handler, arguments.note
        )
        print(json.dumps(record, ensure_ascii=False, indent=2))
    elif arguments.command == "revoke-exemption":
        record = catalog.revoke_exemption(
            arguments.id, arguments.handler, arguments.note
        )
        print(json.dumps(record, ensure_ascii=False, indent=2))
    elif arguments.command == "exemption-show":
        print(
            json.dumps(
                catalog.get_exemption(arguments.id), ensure_ascii=False, indent=2
            )
        )
    elif arguments.command == "exemption-list":
        print(
            json.dumps(
                catalog.list_exemptions(status=arguments.status),
                ensure_ascii=False,
                indent=2,
            )
        )
    elif arguments.command == "risk-report":
        print(
            json.dumps(
                catalog.risk_report(
                    service=arguments.service,
                    evaluated_at=arguments.evaluated_at,
                ),
                ensure_ascii=False,
                indent=2,
            )
        )
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
