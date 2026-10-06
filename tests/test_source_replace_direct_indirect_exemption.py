"""Regression coverage for a source replacement that flips the same component
from a direct hit to a dependency-only hit while an approved exemption is in
force.

业务情形：同一服务 ``api`` 内注册同一个 PyPI 包 ``pkg`` 的两个版本，
``pkg 2.0.0`` 依赖 ``pkg 1.0.0``。本地 OSV 来源 ``nvd`` 先声明两个版本都受
``CVE-2026-9001``（high）影响；随后在豁免有效期内整体替换同一来源，使漏洞只
影响 ``1.0.0``——漏洞编号、包名与 high 等级保持一致，组件和依赖关系不变。

豁免的范围是具体的影响记录身份（组件四元组 + 漏洞编号 + 命中包名 + 来源），
既不包含直接/间接标记，也不包含依赖路径；因此来源替换只改变该记录的当前解释
（direct 标记、path、matched_conditions），已批准的豁免仍按原范围继续生效，
申请范围、批准时等级与处理历史都保持原样，且解释变化本身不追加任何审批事件。
"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main


SERVICE = "api"
PACKAGE = "pkg"
VULN = "CVE-2026-9001"
SOURCE = "nvd"
OTHER_SOURCE = "ghsa"
REQUEST_ID = "EXM-2026-9001"
EXPIRES = "2030-01-01T00:00:00+00:00"
# 申请、审批与报告评估时刻都严格落在豁免有效期内，因此期限问题不能解释任何结果。
SUBMITTED = datetime(2026, 3, 1, tzinfo=timezone.utc)
DECIDED = datetime(2026, 3, 2, tzinfo=timezone.utc)
EVALUATED = datetime(2026, 6, 1, tzinfo=timezone.utc)


def osv_doc(affected_versions, severity="high", vuln=VULN, package=PACKAGE):
    """一个 high 等级的本地 OSV 文件内容，仅按显式版本命中给定版本列表。"""
    return [
        {
            "id": vuln,
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": package},
                    "versions": list(affected_versions),
                }
            ],
            "database_specific": {"severity": severity},
        }
    ]


def identity(version):
    return {"service": SERVICE, "ecosystem": "pypi", "name": PACKAGE,
            "version": version}


class DirectToIndirectSourceReplacementTests(unittest.TestCase):
    """来源替换使 2.0.0 从直接命中变为仅经依赖命中的回归保障。"""

    def setUp(self) -> None:
        self.catalog = Catalog()
        self.catalog.add_component(SERVICE, "pypi", PACKAGE, "2.0.0")
        self.catalog.add_component(SERVICE, "pypi", PACKAGE, "1.0.0")
        # 2.0.0 -> 1.0.0，同一 PyPI 包的两个版本处于同一服务内。
        self.catalog.add_dependency(
            SERVICE, "pypi", PACKAGE, "2.0.0",
            SERVICE, "pypi", PACKAGE, "1.0.0",
        )
        # 首次导入：两个版本都直接受同一漏洞、同一命中包影响，等级 high。
        self.assertEqual(
            self.catalog.import_osv(SOURCE, osv_doc(["1.0.0", "2.0.0"])), 1
        )

    def tearDown(self) -> None:
        self.catalog.close()

    # -- 辅助 -------------------------------------------------------------

    def records_for(self, version):
        """服务范围 impact 中属于 pkg 某版本的全部 nvd/CVE-9001 记录。"""
        return [
            record for record in self.catalog.impact(service=SERVICE)
            if record["component"] == identity(version)
            and record["vulnerability"] == VULN
            and record["matched_name"] == PACKAGE
            and record["source"] == SOURCE
        ]

    def sole_record(self, version):
        records = self.records_for(version)
        self.assertEqual(
            len(records), 1,
            f"pkg {version} 对同一组件/漏洞/来源/命中包必须只有一条记录，"
            f"实际 {len(records)} 条",
        )
        return records[0]

    def assert_explanation(self, record, *, direct, conditions, path_versions):
        self.assertEqual(record["component"], identity(path_versions[0]))
        self.assertEqual(record["vulnerability"], VULN)
        self.assertEqual(record["source"], SOURCE)
        self.assertEqual(record["matched_name"], PACKAGE)
        self.assertEqual(record["severity"], "high")
        self.assertEqual(record["severity_basis"], "declared")
        self.assertEqual(record["direct"], direct)
        self.assertEqual(record["matched_conditions"], conditions)
        self.assertEqual(
            [node["version"] for node in record["path"]], path_versions
        )
        self.assertEqual(
            [node["name"] for node in record["path"]],
            [PACKAGE] * len(path_versions),
        )
        # 路径上的每个节点都带全身份（service/ecosystem/name/version）。
        for node in record["path"]:
            self.assertEqual(node, identity(node["version"]))

    def assert_request_unchanged(self):
        """替换解释不允许改写申请范围、批准时等级或处理历史。"""
        request = self.catalog.get_exemption(REQUEST_ID)
        self.assertEqual(request["id"], REQUEST_ID)
        self.assertEqual(request["status"], "approved")
        self.assertEqual(request["scope"], {
            "service": SERVICE,
            "ecosystem": "pypi",
            "name": PACKAGE,
            "version": "2.0.0",
            "vulnerability": VULN,
            "matched_name": PACKAGE,
            "source": SOURCE,
        })
        self.assertEqual(request["applicant"], "alice")
        self.assertEqual(request["reason"], "accept risk")
        self.assertEqual(request["expires_at"], "2030-01-01T00:00:00.000000Z")
        self.assertEqual(request["approver"], "bob")
        self.assertEqual(request["decision_note"], "controls verified")
        self.assertEqual(request["approved_severity"], "high")
        self.assertIsNotNone(request["decided_at"])
        # 解释变化不自动追加审批事件：历史仍是 request + approve 两条。
        self.assertEqual(
            [(event["action"], event["actor"], event["from_status"],
              event["to_status"]) for event in request["events"]],
            [
                ("request", "alice", None, "pending"),
                ("approve", "bob", "pending", "approved"),
            ],
        )
        return request

    def replace_to_100_only(self):
        """整体替换 nvd：同编号、同包名、同 high，只命中 1.0.0。"""
        return self.catalog.import_osv(SOURCE, osv_doc(["1.0.0"]))

    # -- 第一阶段：两个版本都直接命中 -------------------------------------

    def test_200_is_direct_once_with_self_only_path_before_replacement(
        self,
    ) -> None:
        # 全目录与服务范围都给出同样的两条当前影响记录。
        all_impact = self.catalog.impact()
        service_impact = self.catalog.impact(service=SERVICE)
        self.assertEqual(len(all_impact), 2)
        self.assertEqual(len(service_impact), 2)

        # 2.0.0 必须是直接命中：路径只有它自己，命中条件只解释 2.0.0。
        direct = self.sole_record("2.0.0")
        self.assert_explanation(
            direct, direct=True, conditions=["==2.0.0"],
            path_versions=["2.0.0"],
        )
        # 1.0.0 同理直接命中，条件只解释 1.0.0。
        self.assert_explanation(
            self.sole_record("1.0.0"), direct=True,
            conditions=["==1.0.0"], path_versions=["1.0.0"],
        )
        # 完整组件身份查询与服务范围查询对 2.0.0 的解释一致。
        identity_query = self.catalog.impact(
            service=SERVICE, ecosystem="pypi", name=PACKAGE, version="2.0.0"
        )
        self.assertEqual(identity_query, [direct])

    def test_200_never_gets_a_second_indirect_record_via_100(self) -> None:
        # 虽然 2.0.0 沿依赖能到达另一个受影响版本 1.0.0，也不能为同一
        # （组件, 漏洞, 来源, 命中包）重复产生一条间接记录。
        records = self.records_for("2.0.0")
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["direct"])
        self.assertEqual(
            [node["version"] for node in records[0]["path"]], ["2.0.0"]
        )

    def test_100_record_is_not_exempted_by_200_approval(self) -> None:
        # 为 2.0.0 的直接命中记录申请并批准一个尚未到期的豁免。
        self.catalog.request_exemption(
            REQUEST_ID, SERVICE, "pypi", PACKAGE, "2.0.0",
            VULN, PACKAGE, SOURCE,
            "alice", "accept risk", EXPIRES, submitted_at=SUBMITTED,
        )
        approved = self.catalog.approve_exemption(
            REQUEST_ID, "bob", "controls verified", decided_at=DECIDED
        )
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approved_severity"], "high")

        report = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVALUATED
        )
        # 目录中只有这两个版本和该来源：报告始终只有两条影响记录。
        self.assertEqual(report["impact_count"], 2)
        # 2.0.0 已豁免，1.0.0 未豁免：未处理组件数 1，最高未处理等级 high。
        self.assertEqual(report["unhandled_component_count"], 1)
        self.assertEqual(report["highest_severity"], "high")

        (entry_200,) = [
            entry for entry in report["impacts"]
            if entry["component"]["version"] == "2.0.0"
        ]
        (entry_100,) = [
            entry for entry in report["impacts"]
            if entry["component"]["version"] == "1.0.0"
        ]
        self.assertTrue(entry_200["exempted"])
        self.assertEqual(entry_200["exemption_request"], REQUEST_ID)
        self.assertIsNone(entry_200["not_exempt_reason"])
        # 豁免针对具体记录：另一个版本（即使同名同漏洞同来源）仍未豁免。
        self.assertFalse(entry_100["exempted"])
        self.assertIsNone(entry_100["exemption_request"])
        self.assertIsNone(entry_100["not_exempt_reason"])

    # -- 第二阶段：来源替换后 2.0.0 仅经依赖命中 --------------------------

    def test_replacement_flips_200_to_indirect_with_100_conditions(self) -> None:
        self.catalog.request_exemption(
            REQUEST_ID, SERVICE, "pypi", PACKAGE, "2.0.0",
            VULN, PACKAGE, SOURCE,
            "alice", "accept risk", EXPIRES, submitted_at=SUBMITTED,
        )
        self.catalog.approve_exemption(
            REQUEST_ID, "bob", "controls verified", decided_at=DECIDED
        )
        events_before = list(
            self.catalog.get_exemption(REQUEST_ID)["events"]
        )

        # 豁免有效期内替换同一来源：漏洞现在只影响 1.0.0。
        self.assertEqual(self.replace_to_100_only(), 1)

        # 2.0.0 仍保留唯一一条 nvd/CVE-9001/pkg 记录，但转为间接命中。
        indirect = self.sole_record("2.0.0")
        self.assert_explanation(
            indirect, direct=False, conditions=["==1.0.0"],
            path_versions=["2.0.0", "1.0.0"],
        )
        # 完整身份查询与服务范围查询给出完全相同的当前解释。
        identity_query = self.catalog.impact(
            service=SERVICE, ecosystem="pypi", name=PACKAGE, version="2.0.0"
        )
        self.assertEqual(identity_query, [indirect])
        # 全目录 impact（此目录只有一个服务）同样是两条记录。
        self.assertEqual(len(self.catalog.impact()), 2)

        # 1.0.0 仍是直接命中、自身条件、自环路径。
        self.assert_explanation(
            self.sole_record("1.0.0"), direct=True,
            conditions=["==1.0.0"], path_versions=["1.0.0"],
        )

        # 解释随当前数据变化，但申请范围、批准时等级、历史均保持原样。
        self.assert_request_unchanged()
        # 替换本身没有写入任何新事件。
        self.assertEqual(
            self.catalog.get_exemption(REQUEST_ID)["events"], events_before
        )

    def test_report_keeps_same_path_flag_conditions_after_replacement(
        self,
    ) -> None:
        self.catalog.request_exemption(
            REQUEST_ID, SERVICE, "pypi", PACKAGE, "2.0.0",
            VULN, PACKAGE, SOURCE,
            "alice", "accept risk", EXPIRES, submitted_at=SUBMITTED,
        )
        self.catalog.approve_exemption(
            REQUEST_ID, "bob", "controls verified", decided_at=DECIDED
        )
        self.replace_to_100_only()

        report = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVALUATED
        )
        # 只有这两个版本和该来源：报告始终包含两条影响记录。
        self.assertEqual(report["impact_count"], 2)
        self.assertEqual(report["unhandled_component_count"], 1)
        self.assertEqual(report["highest_severity"], "high")

        entries = {
            entry["component"]["version"]: entry
            for entry in report["impacts"]
        }
        indirect = entries["2.0.0"]
        # 风险报告保留相同路径、标记与命中条件——与 impact 的当前解释一致。
        self.assertFalse(indirect["direct"])
        self.assertEqual(indirect["matched_conditions"], ["==1.0.0"])
        self.assertEqual(
            [node["version"] for node in indirect["path"]],
            ["2.0.0", "1.0.0"],
        )
        # 它继续关联原申请并被豁免，没有任何“未豁免原因”。
        self.assertTrue(indirect["exempted"])
        self.assertEqual(indirect["exemption_request"], REQUEST_ID)
        self.assertIsNone(indirect["not_exempt_reason"])
        self.assertEqual(indirect["severity"], "high")

        direct = entries["1.0.0"]
        self.assertTrue(direct["direct"])
        self.assertEqual(direct["matched_conditions"], ["==1.0.0"])
        self.assertEqual(
            [node["version"] for node in direct["path"]], ["1.0.0"]
        )
        self.assertFalse(direct["exempted"])
        self.assertIsNone(direct["exemption_request"])

        # impact 与 risk-report 对 2.0.0 的当前解释（路径/标记/条件）一致。
        impact_record = self.sole_record("2.0.0")
        for field in ("direct", "matched_conditions", "path", "severity",
                      "severity_basis", "matched_name", "source",
                      "vulnerability"):
            self.assertEqual(indirect[field], impact_record[field])

    def test_another_source_same_id_package_cannot_borrow_exemption(self) -> None:
        self.catalog.request_exemption(
            REQUEST_ID, SERVICE, "pypi", PACKAGE, "2.0.0",
            VULN, PACKAGE, SOURCE,
            "alice", "accept risk", EXPIRES, submitted_at=SUBMITTED,
        )
        self.catalog.approve_exemption(
            REQUEST_ID, "bob", "controls verified", decided_at=DECIDED
        )
        self.replace_to_100_only()

        # 另一个来源提供同编号、同包名的 high 漏洞（同样只命中 1.0.0）。
        self.catalog.import_osv(
            OTHER_SOURCE, osv_doc(["1.0.0"], severity="high")
        )

        report = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVALUATED
        )
        # 每个来源各两条：nvd 两条（2.0.0 被豁免），ghsa 两条（全部 live）。
        self.assertEqual(report["impact_count"], 4)
        # 2.0.0 仍有 ghsa 未豁免记录 → 计入未处理组件；1.0.0 本来就 live。
        self.assertEqual(report["unhandled_component_count"], 2)
        self.assertEqual(report["highest_severity"], "high")

        def find(version, source):
            matches = [
                entry for entry in report["impacts"]
                if entry["component"]["version"] == version
                and entry["source"] == source
            ]
            self.assertEqual(len(matches), 1)
            return matches[0]

        nvd_200 = find("2.0.0", SOURCE)
        ghsa_200 = find("2.0.0", OTHER_SOURCE)
        # 原豁免只覆盖来源 nvd 的具体记录，不能借给另一来源。
        self.assertTrue(nvd_200["exempted"])
        self.assertEqual(nvd_200["exemption_request"], REQUEST_ID)
        self.assertFalse(ghsa_200["exempted"])
        self.assertIsNone(ghsa_200["exemption_request"])
        self.assertIsNone(ghsa_200["not_exempt_reason"])
        self.assertFalse(ghsa_200["direct"])
        self.assertEqual(
            [node["version"] for node in ghsa_200["path"]],
            ["2.0.0", "1.0.0"],
        )
        # 两个来源对 2.0.0 的当前解释除来源与豁免链接外完全一致。
        for field in ("direct", "matched_conditions", "path", "severity"):
            self.assertEqual(nvd_200[field], ghsa_200[field])

        # 另一来源的加入不改变原申请的任何内容。
        self.assert_request_unchanged()

    def test_scope_occupation_and_history_survive_path_change(self) -> None:
        self.catalog.request_exemption(
            REQUEST_ID, SERVICE, "pypi", PACKAGE, "2.0.0",
            VULN, PACKAGE, SOURCE,
            "alice", "accept risk", EXPIRES, submitted_at=SUBMITTED,
        )
        self.catalog.approve_exemption(
            REQUEST_ID, "bob", "controls verified", decided_at=DECIDED
        )
        self.replace_to_100_only()

        # 路径/直接标记不属于豁免范围：同一记录转间接后，该七元组范围仍被
        # 未到期的已批准申请占用，新的（直接/间接语义不同的）申请必须冲突。
        with self.assertRaises(ValueError):
            self.catalog.request_exemption(
                "EXM-OTHER", SERVICE, "pypi", PACKAGE, "2.0.0",
                VULN, PACKAGE, SOURCE,
                "carol", "second request", EXPIRES,
            )
        # 重复同一编号、同一内容只是确认原申请，且不新增事件、不重检影响。
        confirmed = self.catalog.request_exemption(
            REQUEST_ID, SERVICE, "pypi", PACKAGE, "2.0.0",
            VULN, PACKAGE, SOURCE,
            "alice", "accept risk", EXPIRES,
        )
        self.assertEqual(confirmed["status"], "approved")
        self.assertEqual(
            [event["seq"] for event in confirmed["events"]], [1, 2]
        )
        self.assert_request_unchanged()

    def test_explanation_consistency_between_all_three_query_shapes(self) -> None:
        self.replace_to_100_only()
        expected = self.sole_record("2.0.0")
        # 目录级、服务级、完整身份级三种查询对 2.0.0 必须给出相同解释。
        directory = [
            record for record in self.catalog.impact()
            if record["component"] == identity("2.0.0")
        ]
        scoped = self.records_for("2.0.0")
        full = self.catalog.impact(
            service=SERVICE, ecosystem="pypi", name=PACKAGE, version="2.0.0"
        )
        self.assertEqual([expected], directory)
        self.assertEqual([expected], scoped)
        self.assertEqual(full, [expected])

    def test_summary_counts_stay_two_components_one_vuln(self) -> None:
        summary = self.catalog.summary()
        self.assertEqual(summary.components, 2)
        self.assertEqual(summary.affected_components, 2)
        self.assertEqual(summary.vulnerabilities, 1)
        self.assertEqual(summary.highest_severity, "high")
        self.replace_to_100_only()
        summary = self.catalog.summary()
        # 替换后 2.0.0 仍（间接）受影响：两个受影响组件、一个漏洞、high。
        self.assertEqual(summary.components, 2)
        self.assertEqual(summary.affected_components, 2)
        self.assertEqual(summary.vulnerabilities, 1)
        self.assertEqual(summary.highest_severity, "high")

    def test_approved_exemption_resumes_on_the_indirect_100_route(self) -> None:
        # 先把 nvd 清空再恢复成只命中 1.0.0 的情形：影响记录一度消失后
        # 又以间接形式复现，只要审批、等级与期限仍成立，豁免即恢复。
        self.catalog.request_exemption(
            REQUEST_ID, SERVICE, "pypi", PACKAGE, "2.0.0",
            VULN, PACKAGE, SOURCE,
            "alice", "accept risk", EXPIRES, submitted_at=SUBMITTED,
        )
        self.catalog.approve_exemption(
            REQUEST_ID, "bob", "controls verified", decided_at=DECIDED
        )
        # 记录消失期间报告里没有 nvd 记录，但申请与历史仍可查询。
        self.catalog.import_osv(SOURCE, [])
        self.assertEqual(
            [r for r in self.catalog.impact(service=SERVICE)
             if r["source"] == SOURCE],
            [],
        )
        self.assertEqual(self.catalog.get_exemption(REQUEST_ID)["status"],
                         "approved")
        # 同范围以间接形态复现，豁免恢复关联。
        self.assertEqual(self.replace_to_100_only(), 1)
        report = self.catalog.risk_report(
            service=SERVICE, evaluated_at=EVALUATED
        )
        (entry_200,) = [
            entry for entry in report["impacts"]
            if entry["component"]["version"] == "2.0.0"
        ]
        self.assertFalse(entry_200["direct"])
        self.assertTrue(entry_200["exempted"])
        self.assertEqual(entry_200["exemption_request"], REQUEST_ID)
        self.assertEqual(
            [node["version"] for node in entry_200["path"]],
            ["2.0.0", "1.0.0"],
        )
        self.assert_request_unchanged()


class DirectToIndirectCliPersistenceTests(unittest.TestCase):
    """通过公开 CLI 命令走一遍完整流程，并验证重开数据库后结果可复现。"""

    def test_cli_end_to_end_and_reopen_reproduces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            both = Path(directory, "both.json")
            only_100 = Path(directory, "only-100.json")
            both.write_text(json.dumps(osv_doc(["1.0.0", "2.0.0"])))
            only_100.write_text(json.dumps(osv_doc(["1.0.0"])))

            def run(*argv):
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(io.StringIO()):
                    status = main(["--database", database, *argv])
                self.assertEqual(status, 0, output.getvalue())
                return output.getvalue()

            run("init")
            run("add-component", SERVICE, "pypi", PACKAGE, "2.0.0")
            run("add-component", SERVICE, "pypi", PACKAGE, "1.0.0")
            run("add-dependency",
                SERVICE, "pypi", PACKAGE, "2.0.0",
                SERVICE, "pypi", PACKAGE, "1.0.0")
            self.assertIn("导入漏洞记录: 1 条",
                          run("import-osv", SOURCE, str(both)))
            run("request-exemption",
                REQUEST_ID, SERVICE, "pypi", PACKAGE, "2.0.0",
                VULN, PACKAGE, SOURCE,
                "--applicant", "alice", "--reason", "accept risk",
                "--expires-at", EXPIRES)
            run("approve-exemption", REQUEST_ID,
                "--handler", "bob", "--note", "controls verified")
            run("import-osv", SOURCE, str(only_100))

            def read_impact():
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(io.StringIO()):
                    status = main(["--database", database, "impact",
                                   "--service", SERVICE])
                self.assertEqual(status, 0)
                return json.loads(output.getvalue())

            def read_report():
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(io.StringIO()):
                    status = main(["--database", database, "risk-report",
                                   "--service", SERVICE,
                                   "--at", "2026-06-01T00:00:00+00:00"])
                self.assertEqual(status, 0)
                return json.loads(output.getvalue())

            impact = read_impact()
            self.assertEqual(len(impact), 2)
            (record_200,) = [
                r for r in impact if r["component"]["version"] == "2.0.0"
            ]
            self.assertFalse(record_200["direct"])
            self.assertEqual(record_200["matched_conditions"], ["==1.0.0"])
            self.assertEqual(
                [node["version"] for node in record_200["path"]],
                ["2.0.0", "1.0.0"],
            )
            self.assertEqual(record_200["source"], SOURCE)
            self.assertEqual(record_200["matched_name"], PACKAGE)

            report = read_report()
            self.assertEqual(report["impact_count"], 2)
            self.assertEqual(report["unhandled_component_count"], 1)
            self.assertEqual(report["highest_severity"], "high")
            (entry_200,) = [
                i for i in report["impacts"]
                if i["component"]["version"] == "2.0.0"
            ]
            self.assertTrue(entry_200["exempted"])
            self.assertEqual(entry_200["exemption_request"], REQUEST_ID)
            self.assertFalse(entry_200["direct"])
            self.assertEqual(entry_200["matched_conditions"], ["==1.0.0"])
            self.assertEqual(
                [node["version"] for node in entry_200["path"]],
                ["2.0.0", "1.0.0"],
            )

            # 重开数据库：相同数据与评估时刻产生完全相同的输出，历史仍两条。
            reopened = Catalog(database)
            second_report = reopened.risk_report(
                service=SERVICE, evaluated_at="2026-06-01T00:00:00+00:00"
            )
            self.assertEqual(second_report, report)
            request = reopened.get_exemption(REQUEST_ID)
            self.assertEqual(request["status"], "approved")
            self.assertEqual(request["approved_severity"], "high")
            self.assertEqual(
                [event["action"] for event in request["events"]],
                ["request", "approve"],
            )
            reopened.close()


if __name__ == "__main__":
    unittest.main()
