"""Regression tests for choosing one dependency path among equal-length routes.

An upstream component may reach two directly hit versions of the same PyPI
package through different middle components. Under one source, one
vulnerability id and one matched package name the upstream still gets a
single impact record; the chosen path must explain *why* it is affected, and
its hit condition must come from the terminal component at the end of that
path alone - the other route's condition must never mix in.

Path selection has two levels:

1. fewest dependency edges first - a shorter route wins even when the longer
   route runs through an identity-smaller middle component;
2. when two routes are equally long, compare them from the upstream end and,
   at the first node where they differ, compare the stored texts of
   ecosystem, package name and version in that order and keep the smaller
   identity. A shared prefix never changes how the later branch is compared.

Version ordering at that comparison is textual - ``"10.0.0" < "9.0.0"`` -
while whether a version is actually hit still follows PEP 440. Two diamonds
with opposite wirings are therefore both tested:

* middle ``maaa`` -> ``lib 9.0.0`` and middle ``mzzz`` -> ``lib 10.0.0``:
  the smaller middle reaches the text-LARGER terminal, so the middle-name
  order is opposite to the terminal version text order (and agrees with the
  PEP 440 order) - a rule that wrongly compared only terminal identities or
  terminal versions as text would take the other route;
* middle ``maaa`` -> ``lib 10.0.0`` and middle ``mzzz`` -> ``lib 9.0.0``:
  the smaller middle reaches the PEP 440-LARGER terminal, so a rule that
  wrongly compared terminal versions as PEP 440 would take the other route.

Between them the two diamonds reject every "compare the terminal instead of
the first diverging node" mutation, regardless of which version order such
a mutation uses. The tests additionally pin:

* the same comparison after a shared prefix;
* the two directly hit versions keeping their own records and conditions;
* identical answers from all four queries (directory-wide impact, the
  service query, the full-identity query and the risk report), preserving
  source, vulnerability id, matched package and the direct/indirect flag;
* independence from component/relationship registration order (a
  first-registered-route rule fails on the reversed and shuffled seeds);
* the shortest-route-wins and upstream-self-direct boundaries.
"""

import unittest

from supply_guard.catalog import Catalog

SERVICE = "api"
ECOSYSTEM = "pypi"
PACKAGE = "lib"
CVE = "CVE-2026-5001"
SOURCE = "nvd"
V9 = "9.0.0"
V10 = "10.0.0"
UPSTREAM = "app"


def osv_records(*versions: str, extra_affected: list[dict] | None = None) -> list[dict]:
    """One OSV record for PACKAGE hitting each of ``versions`` explicitly."""
    affected = [
        {
            "package": {"ecosystem": "PyPI", "name": PACKAGE},
            "versions": list(versions),
        }
    ]
    if extra_affected:
        affected.extend(extra_affected)
    return [
        {
            "id": CVE,
            "affected": affected,
            "database_specific": {"severity": "high"},
        }
    ]


def node(name: str, version: str) -> dict:
    return {
        "service": SERVICE,
        "ecosystem": ECOSYSTEM,
        "name": name,
        "version": version,
    }


def path_signature(path: list[dict]) -> list[tuple[str, str]]:
    return [(item["name"], item["version"]) for item in path]


# Two equal-length diamonds. The identity-smaller middle "maaa" is wired to
# SMALL_MIDDLE_TERMINAL; the expected upstream path always runs through
# "maaa", regardless of how its terminal's version orders against the other
# terminal's.
DIAMOND_TEXT_REVERSED = (V9, V10)      # maaa -> 9.0.0 (text-larger), mzzz -> 10.0.0
DIAMOND_PEP440_REVERSED = (V10, V9)    # maaa -> 10.0.0 (PEP 440-larger), mzzz -> 9.0.0


def register_diamond(
    catalog: Catalog,
    small_terminal: str,
    large_terminal: str,
    shared_prefix: bool = False,
) -> None:
    """Register app -> {maaa,mzzz} -> {lib small_terminal, lib large_terminal}.

    The smaller middle ``maaa`` always leads to ``small_terminal`` and the
    larger middle ``mzzz`` to ``large_terminal``. With ``shared_prefix`` the
    routes first share ``app -> pivot`` and only diverge at the middles.
    """
    components: list[tuple[str, str]] = [
        (UPSTREAM, "1.0.0"),
        ("maaa", "1.0.0"),
        ("mzzz", "1.0.0"),
        (PACKAGE, small_terminal),
        (PACKAGE, large_terminal),
    ]
    if shared_prefix:
        components.append(("pivot", "1.0.0"))
    for name, version in components:
        catalog.add_component(SERVICE, ECOSYSTEM, name, version)

    if shared_prefix:
        catalog.add_dependency(
            SERVICE, ECOSYSTEM, UPSTREAM, "1.0.0",
            SERVICE, ECOSYSTEM, "pivot", "1.0.0",
        )
        catalog.add_dependency(
            SERVICE, ECOSYSTEM, "pivot", "1.0.0",
            SERVICE, ECOSYSTEM, "maaa", "1.0.0",
        )
        catalog.add_dependency(
            SERVICE, ECOSYSTEM, "pivot", "1.0.0",
            SERVICE, ECOSYSTEM, "mzzz", "1.0.0",
        )
    else:
        catalog.add_dependency(
            SERVICE, ECOSYSTEM, UPSTREAM, "1.0.0",
            SERVICE, ECOSYSTEM, "maaa", "1.0.0",
        )
        catalog.add_dependency(
            SERVICE, ECOSYSTEM, UPSTREAM, "1.0.0",
            SERVICE, ECOSYSTEM, "mzzz", "1.0.0",
        )
    catalog.add_dependency(
        SERVICE, ECOSYSTEM, "maaa", "1.0.0",
        SERVICE, ECOSYSTEM, PACKAGE, small_terminal,
    )
    catalog.add_dependency(
        SERVICE, ECOSYSTEM, "mzzz", "1.0.0",
        SERVICE, ECOSYSTEM, PACKAGE, large_terminal,
    )
    catalog.import_osv(SOURCE, osv_records(small_terminal, large_terminal))


def expected_indirect_explanation(terminal_version: str) -> dict:
    return {
        "path": [
            node(UPSTREAM, "1.0.0"),
            node("maaa", "1.0.0"),
            node(PACKAGE, terminal_version),
        ],
        "matched_conditions": [f"=={terminal_version}"],
        "direct": False,
        "source": SOURCE,
        "vulnerability": CVE,
        "matched_name": PACKAGE,
        "severity": "high",
        "severity_basis": "declared",
    }


def pick_app(records: list[dict], *, expect_one: bool = True) -> dict:
    matches = [
        record
        for record in records
        if record["component"] == node(UPSTREAM, "1.0.0")
    ]
    if expect_one:
        assert len(matches) == 1, f"expected one upstream record, got {len(matches)}"
        return matches[0]
    return matches


class EqualLengthPathSelectionTests(unittest.TestCase):
    """The first-diverging-node identity rule on equal-length routes."""

    def setUp(self) -> None:
        self.catalog = Catalog()

    def tearDown(self) -> None:
        self.catalog.close()

    def assertAppExplainedBy(
        self, record: dict, terminal_version: str, prefix: bool = False
    ) -> None:
        if prefix:
            expected_path = [
                node(UPSTREAM, "1.0.0"),
                node("pivot", "1.0.0"),
                node("maaa", "1.0.0"),
                node(PACKAGE, terminal_version),
            ]
        else:
            expected_path = expected_indirect_explanation(terminal_version)["path"]
        self.assertFalse(record["direct"])
        self.assertEqual(record["path"], expected_path)
        # The hit condition belongs to the chosen terminal only; the other
        # route's condition must never mix in.
        self.assertEqual(record["matched_conditions"], [f"=={terminal_version}"])
        self.assertEqual(record["source"], SOURCE)
        self.assertEqual(record["vulnerability"], CVE)
        self.assertEqual(record["matched_name"], PACKAGE)
        self.assertEqual(record["severity"], "high")
        self.assertEqual(record["severity_basis"], "declared")

    def test_middle_identity_decides_when_terminal_text_order_is_opposite(self) -> None:
        # maaa (identity-smaller) reaches lib 9.0.0, whose stored text
        # "9.0.0" is LARGER than "10.0.0" on the other route. The middle
        # name decides; comparing only the terminal identity or the terminal
        # version as text would wrongly take mzzz -> 10.0.0.
        register_diamond(self.catalog, *DIAMOND_TEXT_REVERSED)
        record = pick_app(self.catalog.impact())
        self.assertAppExplainedBy(record, V9)

    def test_middle_identity_decides_when_terminal_pep440_order_is_opposite(self) -> None:
        # The mirrored wiring: maaa reaches lib 10.0.0, PEP 440-LARGER than
        # the other route's 9.0.0. Comparing terminal versions under PEP 440
        # would wrongly take mzzz -> 9.0.0; the first diverging node still
        # decides.
        register_diamond(self.catalog, *DIAMOND_PEP440_REVERSED)
        record = pick_app(self.catalog.impact())
        self.assertAppExplainedBy(record, V10)

    def test_divergence_after_shared_prefix_compares_branch_nodes(self) -> None:
        # Both routes share app -> pivot before diverging; the shared prefix
        # must not shift the comparison onto the terminals.
        register_diamond(self.catalog, *DIAMOND_TEXT_REVERSED, shared_prefix=True)
        record = pick_app(self.catalog.impact())
        self.assertAppExplainedBy(record, V9, prefix=True)

    def test_shared_prefix_with_mirrored_wiring(self) -> None:
        register_diamond(self.catalog, *DIAMOND_PEP440_REVERSED, shared_prefix=True)
        record = pick_app(
            self.catalog.impact(
                service=SERVICE, ecosystem=ECOSYSTEM,
                name=UPSTREAM, version="1.0.0",
            )
        )
        self.assertEqual(
            path_signature(record["path"]),
            [
                (UPSTREAM, "1.0.0"),
                ("pivot", "1.0.0"),
                ("maaa", "1.0.0"),
                (PACKAGE, V10),
            ],
        )
        self.assertEqual(record["matched_conditions"], [f"=={V10}"])

    def test_directly_hit_versions_keep_their_own_records_and_conditions(self) -> None:
        register_diamond(self.catalog, *DIAMOND_TEXT_REVERSED)
        for terminal_version in (V9, V10):
            records = self.catalog.impact(
                service=SERVICE,
                ecosystem=ECOSYSTEM,
                name=PACKAGE,
                version=terminal_version,
            )
            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertTrue(record["direct"])
            self.assertEqual(record["path"], [node(PACKAGE, terminal_version)])
            self.assertEqual(
                record["matched_conditions"], [f"=={terminal_version}"]
            )

        # All five components carry exactly one CVE-5001/lib record each.
        records = self.catalog.impact(service=SERVICE)
        self.assertEqual(len(records), 5)
        terminal_records = [
            record for record in records if record["component"]["name"] == PACKAGE
        ]
        self.assertEqual(len(terminal_records), 2)
        for record in terminal_records:
            self.assertTrue(record["direct"])
        for name in ("maaa", "mzzz", UPSTREAM):
            (record,) = (
                record for record in records if record["component"]["name"] == name
            )
            self.assertFalse(record["direct"])
        # Each middle is explained by its own terminal's condition.
        middle_conditions = {
            record["component"]["name"]: record["matched_conditions"]
            for record in records
            if record["component"]["name"] in ("maaa", "mzzz")
        }
        self.assertEqual(middle_conditions["maaa"], [f"=={V9}"])
        self.assertEqual(middle_conditions["mzzz"], [f"=={V10}"])

    def test_four_query_shapes_report_the_same_path_and_explanation(self) -> None:
        register_diamond(self.catalog, *DIAMOND_TEXT_REVERSED)

        all_records = self.catalog.impact()
        service_records = self.catalog.impact(service=SERVICE)
        identity_records = self.catalog.impact(
            service=SERVICE, ecosystem=ECOSYSTEM, name=UPSTREAM, version="1.0.0"
        )
        report = self.catalog.risk_report()
        service_report = self.catalog.risk_report(service=SERVICE)
        self.assertEqual(len(identity_records), 1)

        expected = expected_indirect_explanation(V9)
        for label, picked in (
            ("impact()", pick_app(all_records)),
            ("impact(service)", pick_app(service_records)),
            ("impact(identity)", identity_records[0]),
            ("risk-report", pick_app(report["impacts"])),
            ("risk-report(service)", pick_app(service_report["impacts"])),
        ):
            with self.subTest(query=label):
                for field, value in expected.items():
                    self.assertEqual(picked[field], value, f"{label}: {field}")

        # The same agreement must hold for the mirrored wiring (whose chosen
        # terminal is PEP 440-larger), across all four query shapes too.
        mirror = Catalog()
        try:
            register_diamond(mirror, *DIAMOND_PEP440_REVERSED)
            mirror_expected = expected_indirect_explanation(V10)
            mirror_identity = mirror.impact(
                service=SERVICE, ecosystem=ECOSYSTEM,
                name=UPSTREAM, version="1.0.0",
            )
            mirror_report = [
                entry
                for entry in mirror.risk_report(service=SERVICE)["impacts"]
                if entry["component"] == node(UPSTREAM, "1.0.0")
            ]
            self.assertEqual(len(mirror_identity), 1)
            self.assertEqual(len(mirror_report), 1)
            for label, picked in (
                ("impact()", pick_app(mirror.impact())),
                ("impact(service)", pick_app(mirror.impact(service=SERVICE))),
                ("impact(identity)", mirror_identity[0]),
                ("risk-report", pick_app(mirror.risk_report()["impacts"])),
                ("risk-report(service)", mirror_report[0]),
            ):
                with self.subTest(query=f"mirror:{label}"):
                    for field, value in mirror_expected.items():
                        self.assertEqual(picked[field], value, f"{label}: {field}")
        finally:
            mirror.close()

        # With one service the directory and service reports agree.
        self.assertEqual(report["impact_count"], 5)
        self.assertEqual(report["unhandled_component_count"], 5)
        self.assertEqual(service_report["unhandled_component_count"], 5)
        self.assertEqual(report["highest_severity"], "high")
        self.assertEqual(service_report["highest_severity"], "high")

    def test_registration_order_does_not_change_the_result(self) -> None:
        # The same directory built in three registration orders must always
        # explain the upstream through maaa -> lib 9.0.0; a first-registered
        # route rule takes mzzz on the reversed and shuffled seeds.
        expected_path = [(UPSTREAM, "1.0.0"), ("maaa", "1.0.0"), (PACKAGE, V9)]
        base_components = [
            (UPSTREAM, "1.0.0"),
            ("maaa", "1.0.0"),
            ("mzzz", "1.0.0"),
            (PACKAGE, V9),
            (PACKAGE, V10),
        ]
        # (dependent, dependency, terminal version for a lib endpoint)
        base_edges = [
            (UPSTREAM, "maaa", V9),
            ("maaa", PACKAGE, V9),
            (UPSTREAM, "mzzz", V10),
            ("mzzz", PACKAGE, V10),
        ]

        def reversed_order(items: list) -> list:
            return list(reversed(items))

        orders = (
            ("forward", None, None),
            ("reverse", reversed_order, reversed_order),
            # The mzzz edges and the 10.0.0 terminal are registered before
            # the maaa ones, so insertion order and identity order disagree.
            (
                "shuffled",
                lambda items: [items[i] for i in (4, 0, 3, 1, 2)],
                lambda items: [items[i] for i in (3, 0, 2, 1)],
            ),
        )

        for label, component_order, edge_order in orders:
            with self.subTest(order=label):
                catalog = Catalog()
                try:
                    components = (
                        base_components
                        if component_order is None
                        else component_order(base_components)
                    )
                    for name, version in components:
                        catalog.add_component(SERVICE, ECOSYSTEM, name, version)
                    edges = (
                        base_edges if edge_order is None else edge_order(base_edges)
                    )
                    for dependent, dependency, terminal_version in edges:
                        dependency_version = (
                            terminal_version
                            if dependency == PACKAGE
                            else "1.0.0"
                        )
                        catalog.add_dependency(
                            SERVICE, ECOSYSTEM, dependent, "1.0.0",
                            SERVICE, ECOSYSTEM, dependency, dependency_version,
                        )
                    catalog.import_osv(SOURCE, osv_records(V9, V10))

                    via_all = pick_app(catalog.impact())
                    via_identity = catalog.impact(
                        service=SERVICE, ecosystem=ECOSYSTEM,
                        name=UPSTREAM, version="1.0.0",
                    )
                    via_report = pick_app(
                        catalog.risk_report(service=SERVICE)["impacts"]
                    )
                    self.assertEqual(len(via_identity), 1)
                    for picked in (via_all, via_identity[0], via_report):
                        self.assertEqual(
                            path_signature(picked["path"]), expected_path
                        )
                        self.assertEqual(picked["matched_conditions"], [f"=={V9}"])
                        self.assertFalse(picked["direct"])
                        self.assertEqual(picked["source"], SOURCE)
                        self.assertEqual(picked["vulnerability"], CVE)
                        self.assertEqual(picked["matched_name"], PACKAGE)
                finally:
                    catalog.close()

    def test_shorter_route_wins_over_identity_smaller_long_route(self) -> None:
        # A direct app -> lib 9.0.0 edge is one edge long; the alternative
        # runs app -> aaa -> zzz -> lib 10.0.0 through the identity-smallest
        # middle "aaa", yet length dominates identity.
        for name, version in [
            (UPSTREAM, "1.0.0"),
            ("aaa", "1.0.0"),
            ("zzz", "1.0.0"),
            (PACKAGE, V9),
            (PACKAGE, V10),
        ]:
            self.catalog.add_component(SERVICE, ECOSYSTEM, name, version)
        self.catalog.add_dependency(
            SERVICE, ECOSYSTEM, UPSTREAM, "1.0.0",
            SERVICE, ECOSYSTEM, PACKAGE, V9,
        )
        self.catalog.add_dependency(
            SERVICE, ECOSYSTEM, UPSTREAM, "1.0.0",
            SERVICE, ECOSYSTEM, "aaa", "1.0.0",
        )
        self.catalog.add_dependency(
            SERVICE, ECOSYSTEM, "aaa", "1.0.0",
            SERVICE, ECOSYSTEM, "zzz", "1.0.0",
        )
        self.catalog.add_dependency(
            SERVICE, ECOSYSTEM, "zzz", "1.0.0",
            SERVICE, ECOSYSTEM, PACKAGE, V10,
        )
        self.catalog.import_osv(SOURCE, osv_records(V9, V10))
        record = pick_app(self.catalog.impact())
        self.assertFalse(record["direct"])
        self.assertEqual(
            path_signature(record["path"]),
            [(UPSTREAM, "1.0.0"), (PACKAGE, V9)],
        )
        self.assertEqual(record["matched_conditions"], [f"=={V9}"])

    def test_upstream_directly_hit_gets_self_only_path_and_own_condition(self) -> None:
        # The upstream itself is directly hit by the same vulnerability id:
        # that record is the self-only path with its own condition; the lib
        # group still has its separate indirect record through the diamond.
        register_diamond(self.catalog, *DIAMOND_TEXT_REVERSED)
        self.catalog.import_osv(
            SOURCE,
            osv_records(
                V9,
                V10,
                extra_affected=[
                    {
                        "package": {"ecosystem": "PyPI", "name": UPSTREAM},
                        "versions": ["1.0.0"],
                    }
                ],
            ),
        )
        records = self.catalog.impact(
            service=SERVICE, ecosystem=ECOSYSTEM,
            name=UPSTREAM, version="1.0.0",
        )
        self.assertEqual(len(records), 2)
        by_matched = {record["matched_name"]: record for record in records}

        direct = by_matched[UPSTREAM]
        self.assertTrue(direct["direct"])
        self.assertEqual(direct["path"], [node(UPSTREAM, "1.0.0")])
        self.assertEqual(direct["matched_conditions"], ["==1.0.0"])

        indirect = by_matched[PACKAGE]
        self.assertFalse(indirect["direct"])
        self.assertEqual(
            path_signature(indirect["path"]),
            [(UPSTREAM, "1.0.0"), ("maaa", "1.0.0"), (PACKAGE, V9)],
        )
        self.assertEqual(indirect["matched_conditions"], [f"=={V9}"])


class EqualLengthEcosystemFieldTests(unittest.TestCase):
    """Ecosystem is the first field compared at the diverging node.

    The two middle nodes differ in both ecosystem and package name with
    opposite orders: ``npm/zzz`` has the smaller ecosystem text
    (``"npm" < "pypi"``) but the larger package name, so the ecosystem leg
    selects the npm route even though the package name prefers the pypi
    route. The selected route ends at ``lib 9.0.0`` (the text-larger
    terminal), proving ecosystem ordering at the first diverging node is
    what decides.
    """

    def test_ecosystem_at_diverging_node_compared_before_name(self) -> None:
        catalog = Catalog()
        try:
            for ecosystem, name, version in [
                (ECOSYSTEM, UPSTREAM, "1.0.0"),
                ("npm", "zzz", "1.0.0"),
                (ECOSYSTEM, "aaa", "1.0.0"),
                (ECOSYSTEM, PACKAGE, V9),
                (ECOSYSTEM, PACKAGE, V10),
            ]:
                catalog.add_component(SERVICE, ecosystem, name, version)
            catalog.add_dependency(
                SERVICE, ECOSYSTEM, UPSTREAM, "1.0.0",
                SERVICE, "npm", "zzz", "1.0.0",
            )
            catalog.add_dependency(
                SERVICE, "npm", "zzz", "1.0.0",
                SERVICE, ECOSYSTEM, PACKAGE, V9,
            )
            catalog.add_dependency(
                SERVICE, ECOSYSTEM, UPSTREAM, "1.0.0",
                SERVICE, ECOSYSTEM, "aaa", "1.0.0",
            )
            catalog.add_dependency(
                SERVICE, ECOSYSTEM, "aaa", "1.0.0",
                SERVICE, ECOSYSTEM, PACKAGE, V10,
            )
            catalog.import_osv(SOURCE, osv_records(V9, V10))
            records = catalog.impact(
                service=SERVICE, ecosystem=ECOSYSTEM,
                name=UPSTREAM, version="1.0.0",
            )
            self.assertEqual(len(records), 1)
            self.assertEqual(
                [
                    (item["ecosystem"], item["name"], item["version"])
                    for item in records[0]["path"]
                ],
                [
                    (ECOSYSTEM, UPSTREAM, "1.0.0"),
                    ("npm", "zzz", "1.0.0"),
                    (ECOSYSTEM, PACKAGE, V9),
                ],
            )
            self.assertEqual(records[0]["matched_conditions"], [f"=={V9}"])
        finally:
            catalog.close()


class EqualLengthVersionTextFieldTests(unittest.TestCase):
    """The tie-break compares the *stored text* of the diverging version.

    The middle nodes share one package name but carry distinct versions, so
    the first-diverging comparison reaches the version field. It is a text
    comparison: ``"10.0.0" < "9.0.0"`` although PEP 440 ranks 10.0.0 above
    9.0.0. The hit test itself stays PEP 440.
    """

    def test_version_field_at_diverging_node_compared_as_text(self) -> None:
        catalog = Catalog()
        try:
            for name, version in [
                (UPSTREAM, "1.0.0"),
                ("mid", V10),
                ("mid", V9),
                (PACKAGE, "2.0.0"),
            ]:
                catalog.add_component(SERVICE, ECOSYSTEM, name, version)
            # Both routes diverge at the two "mid" versions and converge on
            # the same directly hit terminal, so the terminal cannot decide.
            catalog.add_dependency(
                SERVICE, ECOSYSTEM, UPSTREAM, "1.0.0",
                SERVICE, ECOSYSTEM, "mid", V10,
            )
            catalog.add_dependency(
                SERVICE, ECOSYSTEM, UPSTREAM, "1.0.0",
                SERVICE, ECOSYSTEM, "mid", V9,
            )
            catalog.add_dependency(
                SERVICE, ECOSYSTEM, "mid", V10,
                SERVICE, ECOSYSTEM, PACKAGE, "2.0.0",
            )
            catalog.add_dependency(
                SERVICE, ECOSYSTEM, "mid", V9,
                SERVICE, ECOSYSTEM, PACKAGE, "2.0.0",
            )
            catalog.import_osv(SOURCE, osv_records("2.0.0"))
            records = catalog.impact(
                service=SERVICE, ecosystem=ECOSYSTEM,
                name=UPSTREAM, version="1.0.0",
            )
            self.assertEqual(len(records), 1)
            # Text order picks mid 10.0.0 ("10.0.0" < "9.0.0"); a PEP 440
            # comparison at that node would wrongly pick mid 9.0.0.
            self.assertEqual(
                path_signature(records[0]["path"]),
                [(UPSTREAM, "1.0.0"), ("mid", V10), (PACKAGE, "2.0.0")],
            )
            self.assertEqual(records[0]["matched_conditions"], ["==2.0.0"])
        finally:
            catalog.close()


if __name__ == "__main__":
    unittest.main()
