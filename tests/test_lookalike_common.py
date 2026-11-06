"""
tests/test_lookalike_common.py — unit tests for layer1/_lookalike_common.py.

Covers the pure, no-AI building blocks shared by both lookalike producers
(layer1/brand_protection and layer1/newly_registered_domains):

1. score()           — the MX-dominated internal risk ranking.
2. map_sev_platform() — the SEV1 to SEV5 mapping (the team's decision table),
                        including the SEV1-reserved-for-live-clone rule and the
                        mail+signal escalation to SEV2.
3. fuzzy_brand_match()/brand_label() — the openSquat-style matcher used by the
                        CT/NRD discovery.
4. cluster_campaigns() — infrastructure pivoting, including that info-severity
                        findings are excluded and singletons are not clustered.
"""
from __future__ import annotations

from layer1 import _lookalike_common as lc


def test_brand_label_strips_public_suffix():
    assert lc.brand_label("shop.acme.co.uk") == "acme"
    assert lc.brand_label("acme.com") == "acme"
    assert lc.brand_label("acme") == "acme"


def test_fuzzy_brand_match_substring_and_edit_distance():
    labels = {"acme"}
    assert lc.fuzzy_brand_match("acme-login.com", labels) == "acme"   # prefix
    assert lc.fuzzy_brand_match("acrne.com", labels, 2) == "acme"      # rn -> m
    assert lc.fuzzy_brand_match("acme.com", labels) == "acme"          # exact
    assert lc.fuzzy_brand_match("totallyunrelated.com", labels) is None
    # labels under 4 chars are ignored to avoid matching everything
    assert lc.fuzzy_brand_match("abc-bank.com", {"abc"}) is None


def test_score_mail_dominates():
    sev, reasons = lc.score(
        mx=["mx1"], a=["1.2.3.4"], ns=[], legit_ns=set(),
        age_days=10, registered=True,
    )
    assert sev == "high"                       # mx3 + a1 + recent2 = 6
    assert any("mail" in r.lower() for r in reasons)


def test_score_dormant_and_unregistered():
    assert lc.score(mx=[], a=[], ns=[], legit_ns=set(),
                    age_days=None, registered=False)[0] == "info"
    assert lc.score(mx=[], a=["1.2.3.4"], ns=[], legit_ns=set(),
                    age_days=None, registered=True)[0] == "low"


def test_score_generic_label_tld_swap_is_info():
    sev, _ = lc.score(
        mx=["mx1"], a=["1.2.3.4"], ns=[], legit_ns=set(),
        age_days=5, registered=True, fuzzer="tld-swap", distinctive_brand=False,
    )
    assert sev == "info"


def test_map_sev_platform_rules():
    # SEV1 reserved for a confirmed live clone.
    assert lc.map_sev_platform(
        "high", mail_capable=True, serves_login=True, visual_match=True) == "SEV1"
    # mail + one strong signal escalates to at least SEV2.
    assert lc.map_sev_platform(
        "medium", mail_capable=True, favicon_match=True) == "SEV2"
    # plain medium with no strong signals maps by the base table.
    assert lc.map_sev_platform("medium") == "SEV3"
    assert lc.map_sev_platform("info") == "SEV5"
    assert lc.map_sev_platform("low") == "SEV4"


def test_cluster_campaigns_groups_shared_infra():
    findings = [
        {"value": "a.com", "data": {"severity": "high",
                                    "dns_a": ["5.5.5.5"], "dns_ns": ["ns1.foo.net"]}},
        {"value": "b.com", "data": {"severity": "medium",
                                    "dns_a": ["5.5.5.5"], "dns_ns": []}},
        {"value": "c.com", "data": {"severity": "low", "dns_a": ["9.9.9.9"]}},
        {"value": "d.com", "data": {"severity": "info", "dns_a": ["5.5.5.5"]}},
    ]
    campaigns = lc.cluster_campaigns(findings)
    assert len(campaigns) == 1                       # only a+b share an IP
    assert findings[0]["data"]["cluster_id"] == findings[1]["data"]["cluster_id"]
    assert "cluster_id" not in findings[2]["data"]   # singleton, not clustered
    assert "cluster_id" not in findings[3]["data"]   # info severity excluded
    assert campaigns[0]["shared_ips"] == ["5.5.5.5"]
