"""Regression tests for dependency-path selection among equal-length routes.

One OSV record (source ``nvd``, id ``CVE-2026-4400``, package ``lib``)
declares five ECOSYSTEM ranges, so five different ``lib`` versions are
directly hit by the *same* impact group (same source, same vulnerability id,
same matched package name), each with its own distinguishable matched
condition:

* ``lib 1.0.0``  -> ``>=1.0.0,<1.5.0``
* ``lib 2.0.0``  -> ``>=2.0.0,<2.5.0``
* ``lib 3.0.0``  -> ``>=3.0.0,<3.5.0``
* ``lib 9.0.0``  -> ``>=9.0.0,<9.5.0``
* ``lib 10.0.0`` -> ``>=10.0.0,<10.5.0``

Upstream components reach two of these terminals through different
intermediate components, so every upstream component shows exactly one impact
record for the group and its path must explain *why* it is affected. The
selection rule under test (Catalog._reconstruct_path):

1. fewest dependency edges wins, always;
2. among equal-length routes the paths are compared from the upstream
   component downwards, and at the first differing node the smaller
   (ecosystem, name, version) stored-text identity wins — the shared prefix
   above the divergence plays no role, and version compares as text here
   (whether a version is *hit* stays a PEP 440 comparison);
3. the shown matched conditions come from the terminal of the chosen path,
   never mixed with the conditions another route would have hit.

The fixture deliberately puts the identity order and the terminal-version
order in opposition, so the mutations these tests exist to catch change the
answer:

* comparing only the vulnerable component's version (or only the endpoint
  identity) picks ``lib 1.0.0`` where the rule picks the route through the
  smaller intermediate ``mid-a``/``mid-c`` towards ``lib 2.0.0``;
* keeping the first registered route instead of the identity minimum makes
  the result depend on registration order, which the order-permutation test
  rejects;
* comparing versions as PEP 440 in the tie-break picks ``lib 9.0.0`` where
  the stored-text rule picks ``lib 10.0.0`` (``"10.0.0" < "9.0.0"`` as text).

The same catalog data is queried four ways — directory-wide impact,
service-scoped impact, the full-identity impact query and the risk report —
and every way must show the same path, the same matched conditions and the
same source/vulnerability/direct flags for each component.

Two boundaries of the same rule are pinned as well: a strictly shorter route
wins even when the longer route's intermediate identity is smaller, and an
upstream component that is itself directly hit by the group shows the
self-only path with its own conditions, ignoring the routes it has to other
hit versions.
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from supply_guard.catalog import Catalog
from supply_guard.cli import main

SERVICE = "api"
ECOSYSTEM = "pypi"
OSV_SOURCE = "nvd"
CVE = "CVE-2026-4400"
LIB = "lib"
EVAL_AT = "2026-06-01T00:00:00+00:00"

COND_1 = [">=1.0.0,<1.5.0"]
COND_2 = [">=2.0.0,<2.5.0"]
COND_3 = [">=3.0.0,<3.5.0"]
COND_9 = [">=9.0.0,<9.5.0"]
COND_10 = [">=10.0.0,<10.5.0"]

# (name, version); every non-lib component carries version 1.0.0.
COMPONENTS = [
    ("app", "1.0.0"),
    ("mid-a", "1.0.0"),
    ("mid-b", "1.0.0"),
    ("top", "1.0.0"),
    ("gate", "1.0.0"),
    ("mid-c", "1.0.0"),
    ("mid-d", "1.0.0"),
    ("web", "1.0.0"),
    ("mid", "1.0.0"),
    ("direct", "1.0.0"),
    ("aaa", "1.0.0"),
    (LIB, "1.0.0"),
    (LIB, "2.0.0"),
    (LIB, "3.0.0"),
    (LIB, "9.0.0"),
    (LIB, "10.0.0"),
]

# ((dependent name, version), (dependency name, version)).
EDGES = [
    # app reaches lib 2.0.0 via mid-a and lib 1.0.0 via mid-b: the smaller
    # intermediate identity (mid-a) leads to the *larger* terminal version.
    (("app", "1.0.0"), ("mid-a", "1.0.0")),
    (("app", "1.0.0"), ("mid-b", "1.0.0")),
    (("mid-a", "1.0.0"), (LIB, "2.0.0")),
    (("mid-b", "1.0.0"), (LIB, "1.0.0")),
    # top reaches both terminals through the shared prefix top -> gate; the
    # routes diverge only below gate, again with mid-c < mid-d opposite to
    # the terminal version order.
    (("top", "1.0.0"), ("gate", "1.0.0")),
    (("gate", "1.0.0"), ("mid-c", "1.0.0")),
    (("gate", "1.0.0"), ("mid-d", "1.0.0")),
    (("mid-c", "1.0.0"), (LIB, "2.0.0")),
    (("mid-d", "1.0.0"), (LIB, "1.0.0")),
    # web's two routes share the intermediate mid and differ only at the
    # terminal version: text order ("10.0.0" < "9.0.0") decides, not PEP 440.
    (("web", "1.0.0"), ("mid", "1.0.0")),
    (("mid", "1.0.0"), (LIB, "9.0.0")),
    (("mid", "1.0.0"), (LIB, "10.0.0")),
    # direct has a one-edge route to lib 2.0.0 and a two-edge route through
    # aaa (identity smaller than lib) to lib 1.0.0: the shorter route wins.
    (("direct", "1.0.0"), (LIB, "2.0.0")),
    (("direct", "1.0.0"), ("aaa", "1.0.0")),
    (("aaa", "1.0.0"), (LIB, "1.0.0")),
    # lib 3.0.0 is itself directly hit and also depends on lib 1.0.0: its
    # record is the self-only direct hit, not the route to lib 1.0.0.
    ((LIB, "3.0.0"), (LIB, "1.0.0")),
]


def osv_records() -> list[dict]:
    """One record hitting five lib versions with distinct conditions."""
    return [
        {
            "id": CVE,
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": LIB},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": introduced},
                                {"fixed": fixed},
                            ],
                        }
                        for introduced, fixed in (
                            ("1.0.0", "1.5.0"),
                            ("2.0.0", "2.5.0"),
                            ("3.0.0", "3.5.0"),
                            ("9.0.0", "9.5.0"),
                            ("10.0.0", "10.5.0"),
                        )
                    ],
                }
            ],
            "database_specific": {"severity": "high"},
        }
    ]


def build_catalog(reverse: bool = False) -> Catalog:
    """The fixture catalog; ``reverse`` flips every registration order."""
    catalog = Catalog()
    components = list(reversed(COMPONENTS)) if reverse else COMPONENTS
    edges = list(reversed(EDGES)) if reverse else EDGES
    for name, version in components:
        catalog.add_component(SERVICE, ECOSYSTEM, name, version)
    for (name, version), (dep_name, dep_version) in edges:
        catalog.add_dependency(
            SERVICE, ECOSYSTEM, name, version,
            SERVICE, ECOSYSTEM, dep_name, dep_version,
        )
    catalog.import_osv(OSV_SOURCE, osv_records())
    return catalog


def node(name: str, version: str = "1.0.0") -> dict:
    return {
        "service": SERVICE,
        "ecosystem": ECOSYSTEM,
        "name": name,
        "version": version,
    }


def expected_record(
    name: str,
    version: str,
    *,
    direct: bool,
    path: list[tuple[str, str]],
    conditions: list[str],
) -> dict:
    """The one impact record the component must show for the group."""
    return {
        "component": node(name, version),
        "vulnerability": CVE,
        "source": OSV_SOURCE,
        "matched_name": LIB,
        "severity": "high",
        "severity_basis": "declared",
        "direct": direct,
        "matched_conditions": conditions,
        "path": [node(step, step_version) for step, step_version in path],
    }


# The complete expected answer, keyed by (component name, version). Every
# indirect path ends at the terminal whose conditions the record carries.
EXPECTED = {
    ("app", "1.0.0"): expected_record(
        "app", "1.0.0", direct=False,
        path=[("app", "1.0.0"), ("mid-a", "1.0.0"), (LIB, "2.0.0")],
        conditions=COND_2,
    ),
    ("mid-a", "1.0.0"): expected_record(
        "mid-a", "1.0.0", direct=False,
        path=[("mid-a", "1.0.0"), (LIB, "2.0.0")],
        conditions=COND_2,
    ),
    ("mid-b", "1.0.0"): expected_record(
        "mid-b", "1.0.0", direct=False,
        path=[("mid-b", "1.0.0"), (LIB, "1.0.0")],
        conditions=COND_1,
    ),
    ("top", "1.0.0"): expected_record(
        "top", "1.0.0", direct=False,
        path=[
            ("top", "1.0.0"), ("gate", "1.0.0"),
            ("mid-c", "1.0.0"), (LIB, "2.0.0"),
        ],
        conditions=COND_2,
    ),
    ("gate", "1.0.0"): expected_record(
        "gate", "1.0.0", direct=False,
        path=[("gate", "1.0.0"), ("mid-c", "1.0.0"), (LIB, "2.0.0")],
        conditions=COND_2,
    ),
    ("mid-c", "1.0.0"): expected_record(
        "mid-c", "1.0.0", direct=False,
        path=[("mid-c", "1.0.0"), (LIB, "2.0.0")],
        conditions=COND_2,
    ),
    ("mid-d", "1.0.0"): expected_record(
        "mid-d", "1.0.0", direct=False,
        path=[("mid-d", "1.0.0"), (LIB, "1.0.0")],
        conditions=COND_1,
    ),
    ("web", "1.0.0"): expected_record(
        "web", "1.0.0", direct=False,
        path=[("web", "1.0.0"), ("mid", "1.0.0"), (LIB, "10.0.0")],
        conditions=COND_10,
    ),
    ("mid", "1.0.0"): expected_record(
        "mid", "1.0.0", direct=False,
        path=[("mid", "1.0.0"), (LIB, "10.0.0")],
        conditions=COND_10,
    ),
    ("direct", "1.0.0"): expected_record(
        "direct", "1.0.0", direct=False,
        path=[("direct", "1.0.0"), (LIB, "2.0.0")],
        conditions=COND_2,
    ),
    ("aaa", "1.0.0"): expected_record(
        "aaa", "1.0.0", direct=False,
        path=[("aaa", "1.0.0"), (LIB, "1.0.0")],
        conditions=COND_1,
    ),
    (LIB, "1.0.0"): expected_record(
        LIB, "1.0.0", direct=True,
        path=[(LIB, "1.0.0")],
        conditions=COND_1,
    ),
    (LIB, "2.0.0"): expected_record(
        LIB, "2.0.0", direct=True,
        path=[(LIB, "2.0.0")],
        conditions=COND_2,
    ),
    (LIB, "3.0.0"): expected_record(
        LIB, "3.0.0", direct=True,
        path=[(LIB, "3.0.0")],
        conditions=COND_3,
    ),
    (LIB, "9.0.0"): expected_record(
        LIB, "9.0.0", direct=True,
        path=[(LIB, "9.0.0")],
        conditions=COND_9,
    ),
    (LIB, "10.0.0"): expected_record(
        LIB, "10.0.0", direct=True,
        path=[(LIB, "10.0.0")],
        conditions=COND_10,
    ),
}


def by_component(records: list[dict]) -> dict:
    """Key impact records by (name, version); one record per component here."""
    return {
        (record["component"]["name"], record["component"]["version"]): record
        for record in records
    }


class PathSelectionTests(unittest.TestCase):
    """The directory-wide answer pins every chosen path and its conditions."""

    def setUp(self) -> None:
        self.catalog = build_catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_directory_impact_matches_the_expected_paths(self) -> None:
        records = by_component(self.catalog.impact())
        self.assertEqual(records, EXPECTED)

    def test_intermediate_identity_wins_over_terminal_version_order(self) -> None:
        # mid-a < mid-b as identities, but the mid-a route ends at the
        # *larger* terminal version 2.0.0. Choosing by the vulnerable
        # component's version (or by endpoint identity) would walk through
        # mid-b to lib 1.0.0 instead.
        record = by_component(self.catalog.impact())[("app", "1.0.0")]
        self.assertEqual(
            [step["name"] for step in record["path"]], ["app", "mid-a", LIB]
        )
        self.assertEqual(record["path"][-1]["version"], "2.0.0")
        # The shown conditions belong to the chosen path's terminal only;
        # the other route's ==1.0.0-range condition must not leak in.
        self.assertEqual(record["matched_conditions"], COND_2)
        self.assertNotIn(COND_1[0], record["matched_conditions"])

    def test_divergence_after_a_common_prefix_compares_only_the_branch(self) -> None:
        # top -> gate is shared by both routes; the comparison happens at
        # mid-c vs mid-d, unaffected by the shared prefix above them.
        record = by_component(self.catalog.impact())[("top", "1.0.0")]
        self.assertEqual(
            [step["name"] for step in record["path"]],
            ["top", "gate", "mid-c", LIB],
        )
        self.assertEqual(record["path"][-1]["version"], "2.0.0")
        self.assertEqual(record["matched_conditions"], COND_2)

    def test_terminal_version_tie_break_compares_text_not_pep440(self) -> None:
        # "10.0.0" < "9.0.0" as stored text, the reverse of the PEP 440
        # order; both versions are still *matched* per PEP 440 (each keeps
        # its own direct record below).
        records = by_component(self.catalog.impact())
        self.assertEqual(records[("web", "1.0.0")]["path"][-1], node(LIB, "10.0.0"))
        self.assertEqual(records[("web", "1.0.0")]["matched_conditions"], COND_10)
        self.assertEqual(records[("mid", "1.0.0")]["path"][-1], node(LIB, "10.0.0"))

    def test_each_directly_hit_version_keeps_its_own_record(self) -> None:
        records = by_component(self.catalog.impact())
        for version, conditions in (
            ("1.0.0", COND_1),
            ("2.0.0", COND_2),
            ("3.0.0", COND_3),
            ("9.0.0", COND_9),
            ("10.0.0", COND_10),
        ):
            record = records[(LIB, version)]
            self.assertTrue(record["direct"])
            self.assertEqual(record["path"], [node(LIB, version)])
            self.assertEqual(record["matched_conditions"], conditions)

    def test_shorter_route_wins_over_smaller_intermediate_identity(self) -> None:
        # aaa < lib as identities, but the aaa route is one edge longer:
        # hop count is judged before any identity comparison.
        record = by_component(self.catalog.impact())[("direct", "1.0.0")]
        self.assertEqual(
            record["path"], [node("direct"), node(LIB, "2.0.0")]
        )
        self.assertEqual(record["matched_conditions"], COND_2)

    def test_directly_hit_upstream_shows_only_itself(self) -> None:
        # lib 3.0.0 depends on lib 1.0.0 but is itself hit by the group:
        # distance zero means a self-only path with its own conditions.
        record = by_component(self.catalog.impact())[(LIB, "3.0.0")]
        self.assertTrue(record["direct"])
        self.assertEqual(record["path"], [node(LIB, "3.0.0")])
        self.assertEqual(record["matched_conditions"], COND_3)


class QueryConsistencyTests(unittest.TestCase):
    """All four query shapes explain every component identically."""

    def setUp(self) -> None:
        self.catalog = build_catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def test_service_and_identity_queries_match_the_directory_answer(self) -> None:
        directory = by_component(self.catalog.impact())
        service = by_component(self.catalog.impact(service=SERVICE))
        self.assertEqual(service, EXPECTED)
        self.assertEqual(service, directory)

        for (name, version), expected in EXPECTED.items():
            identity_records = self.catalog.impact(
                service=SERVICE, ecosystem=ECOSYSTEM, name=name, version=version
            )
            # Exactly one record for the one group, identical to the
            # directory-wide and service-scoped record of this component.
            self.assertEqual(identity_records, [expected], (name, version))

    def test_risk_report_carries_the_same_paths_and_conditions(self) -> None:
        for report_service in (None, SERVICE):
            report = self.catalog.risk_report(
                service=report_service, evaluated_at=EVAL_AT
            )
            entries = by_component(report["impacts"])
            self.assertEqual(set(entries), set(EXPECTED))
            for key, expected in EXPECTED.items():
                entry = entries[key]
                for field in (
                    "component", "vulnerability", "source", "matched_name",
                    "severity", "severity_basis", "direct",
                    "matched_conditions", "path",
                ):
                    self.assertEqual(entry[field], expected[field], (key, field))
                self.assertFalse(entry["exempted"])
                self.assertIsNone(entry["exemption_request"])
                self.assertIsNone(entry["not_exempt_reason"])

    def test_cli_impact_and_risk_report_print_the_same_records(self) -> None:
        # A file database so each main() call is a separate CLI invocation.
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory, "catalog.db"))
            file_catalog = Catalog(database)
            for name, version in COMPONENTS:
                file_catalog.add_component(SERVICE, ECOSYSTEM, name, version)
            for (name, version), (dep_name, dep_version) in EDGES:
                file_catalog.add_dependency(
                    SERVICE, ECOSYSTEM, name, version,
                    SERVICE, ECOSYSTEM, dep_name, dep_version,
                )
            file_catalog.import_osv(OSV_SOURCE, osv_records())
            file_catalog.close()

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main([
                    "--database", database, "impact",
                    "--service", SERVICE, "--ecosystem", ECOSYSTEM,
                    "--name", "app", "--version", "1.0.0",
                ])
            self.assertEqual(status, 0)
            self.assertEqual(
                json.loads(stdout.getvalue()), [EXPECTED[("app", "1.0.0")]]
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main([
                    "--database", database, "risk-report",
                    "--service", SERVICE, "--at", EVAL_AT,
                ])
            self.assertEqual(status, 0)
            report = json.loads(stdout.getvalue())
            entries = by_component(report["impacts"])
            self.assertEqual(
                entries[("app", "1.0.0")]["path"],
                EXPECTED[("app", "1.0.0")]["path"],
            )
            self.assertEqual(
                entries[("app", "1.0.0")]["matched_conditions"], COND_2
            )


class RegistrationOrderTests(unittest.TestCase):
    """Registration order of components and edges never changes the answer.

    A path rule that keeps the first registered route (or otherwise follows
    insertion order) flips the app's path when the same components and
    relationships are registered in reverse; the identity-minimum rule is
    order-independent, so both registrations must produce byte-identical
    business results.
    """

    def test_reversed_registration_gives_identical_results(self) -> None:
        forward_catalog = build_catalog()
        reverse_catalog = build_catalog(reverse=True)
        try:
            forward_impact = forward_catalog.impact()
            reverse_impact = reverse_catalog.impact()
            self.assertEqual(reverse_impact, forward_impact)
            self.assertEqual(by_component(forward_impact), EXPECTED)

            self.assertEqual(
                reverse_catalog.impact(service=SERVICE),
                forward_catalog.impact(service=SERVICE),
            )
            for name, version in COMPONENTS:
                self.assertEqual(
                    reverse_catalog.impact(
                        service=SERVICE, ecosystem=ECOSYSTEM,
                        name=name, version=version,
                    ),
                    forward_catalog.impact(
                        service=SERVICE, ecosystem=ECOSYSTEM,
                        name=name, version=version,
                    ),
                )
            self.assertEqual(
                reverse_catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT),
                forward_catalog.risk_report(service=SERVICE, evaluated_at=EVAL_AT),
            )
        finally:
            forward_catalog.close()
            reverse_catalog.close()


if __name__ == "__main__":
    unittest.main()
