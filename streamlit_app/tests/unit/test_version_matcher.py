import pytest

from vulnerability.cvss import cvss3_base, normalize_label, severity_from_score
from vulnerability.version_matcher import (VersionError, assess_advisory, cmp_maven, cmp_pep440, cmp_semver, compare,
                                           describe_range, evaluate_range)


def test_semver_not_lexicographic():
    assert cmp_semver("1.10.0", "1.9.0") > 0  # lexicographic would say <
    assert cmp_semver("v1.2.3", "1.2.3") == 0
    assert cmp_semver("1.0.0-alpha", "1.0.0") < 0
    assert cmp_semver("1.0.0-alpha.1", "1.0.0-alpha.beta") < 0
    assert cmp_semver("1.0.0-rc.1", "1.0.0-beta.11") > 0
    assert cmp_semver("1.0.0+build1", "1.0.0+build2") == 0
    assert cmp_semver("0.0.0-20190101-abc", "0.0.0-20180101-abc") > 0
    with pytest.raises(VersionError):
        cmp_semver("banana", "1.0.0")


def test_pep440_rules_differ_from_semver():
    assert cmp_pep440("1.0.post1", "1.0") > 0
    assert cmp_pep440("1.0rc1", "1.0") < 0
    assert cmp_pep440("2.0.dev1", "2.0a1") < 0
    assert cmp_pep440("1.0", "1.0.0") == 0
    assert cmp_pep440("0.12.2", "0.12.10") < 0
    with pytest.raises(VersionError):
        cmp_pep440("not a version", "1.0")


def test_maven_rules():
    assert cmp_maven("1.0", "1.0.0") == 0
    assert cmp_maven("1.0-alpha", "1.0") < 0
    assert cmp_maven("1.0-SNAPSHOT", "1.0") < 0
    assert cmp_maven("1.0-rc1", "1.0-beta2") > 0
    assert cmp_maven("1.0-sp1", "1.0") > 0
    assert cmp_maven("1.0.ga", "1.0") == 0
    assert cmp_maven("2.14.1", "2.15.0") < 0
    assert cmp_maven("31.0-jre", "31.0.1-jre") < 0
    assert cmp_maven("1.10", "1.9") > 0


def test_ecosystem_dispatch_and_unknown():
    assert compare("PyPI", "1.0.post1", "1.0") > 0
    assert compare("npm", "1.0.0-rc.1", "1.0.0") < 0
    assert compare("Packagist", "2.0.0", "2.0.0-beta1") > 0
    with pytest.raises(VersionError):
        compare("Debian", "1", "2")


def r(*events, type="ECOSYSTEM"):
    return {"type": type, "events": list(events)}


def test_evaluate_range_basic():
    rg = r({"introduced": "3.7.0"}, {"fixed": "4.17.19"}, type="SEMVER")
    assert evaluate_range("npm", rg, "4.17.15") is True
    assert evaluate_range("npm", rg, "4.17.19") is False
    assert evaluate_range("npm", rg, "3.6.9") is False
    assert evaluate_range("npm", rg, "4.17.100") is False  # numeric, not lexicographic
    assert evaluate_range("npm", rg, "garbage") is None


def test_evaluate_range_zero_last_affected_and_multi_interval():
    assert evaluate_range("PyPI", r({"introduced": "0"}, {"fixed": "2.20.0"}), "2.19.1") is True
    assert evaluate_range("PyPI", r({"introduced": "0"}, {"last_affected": "1.5"}), "1.5") is True
    assert evaluate_range("PyPI", r({"introduced": "0"}, {"last_affected": "1.5"}), "1.5.1") is False
    multi = r({"introduced": "1.0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"fixed": "2.3"})
    assert [evaluate_range("PyPI", multi, v) for v in ("0.9", "1.1", "1.5", "2.1", "2.3")] == [False, True, False, True, False]
    # events given out of order are sorted
    shuffled = r({"fixed": "2.20.0"}, {"introduced": "0"})
    assert evaluate_range("PyPI", shuffled, "2.19.1") is True


def test_git_ranges_unknown():
    assert evaluate_range("npm", {"type": "GIT", "events": [{"introduced": "abc"}]}, "1.0.0") is None
    assert evaluate_range("npm", {"type": "SEMVER", "events": []}, "1.0.0") is None


def adv(entries):
    return {"id": "X-1", "affected": entries}


def test_assess_confirmed_with_fix_and_branches():
    vuln = adv([{"package": {"ecosystem": "npm", "name": "minimist"},
                 "ranges": [r({"introduced": "0"}, {"fixed": "0.2.1"}, {"introduced": "1.0.0"}, {"fixed": "1.2.3"}, type="SEMVER")]}])
    a = assess_advisory("npm", "minimist", "0.0.8", vuln)
    assert a["status"] == "confirmed_affected"
    assert a["fixed_versions"] == ["0.2.1", "1.2.3"] and a["recommended_fix"] == "0.2.1"
    assert assess_advisory("npm", "minimist", "1.2.5", vuln)["status"] == "not_affected"
    assert assess_advisory("npm", "minimist", "1.2.5", vuln)["recommended_fix"] is None


def test_assess_name_identity_and_ecosystem():
    vuln = adv([{"package": {"ecosystem": "PyPI", "name": "Flask"}, "ranges": [r({"introduced": "0"}, {"fixed": "1.0"})]}])
    assert assess_advisory("PyPI", "flask", "0.12.2", vuln)["status"] == "confirmed_affected"  # PEP 503 normalization
    # same name in a different ecosystem must not match
    assert assess_advisory("npm", "flask", "0.12.2", vuln)["status"] == "unknown"
    # a different package never matches
    assert assess_advisory("PyPI", "flask-cors", "0.12.2", vuln)["status"] == "unknown"


def test_assess_versions_list_only():
    vuln = adv([{"package": {"ecosystem": "Maven", "name": "g:a"}, "versions": ["1.0", "1.1"]}])
    assert assess_advisory("Maven", "g:a", "1.1", vuln)["status"] == "confirmed_affected"
    assert assess_advisory("Maven", "g:a", "1.2", vuln)["status"] == "not_affected"


def test_assess_unknown_when_unevaluable_and_no_fix_invented():
    vuln = adv([{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]}]}])
    a = assess_advisory("npm", "x", "1.0.0", vuln)
    assert a["status"] == "unknown" and a["fixed_versions"] == [] and a["recommended_fix"] is None
    nofix = adv([{"package": {"ecosystem": "npm", "name": "x"}, "ranges": [r({"introduced": "0"}, type="SEMVER")]}])
    b = assess_advisory("npm", "x", "1.0.0", nofix)
    assert b["status"] == "confirmed_affected" and b["fixed_versions"] == []


def test_assess_ignores_distro_suffix_ecosystems_and_purl_match():
    vuln = adv([{"package": {"ecosystem": "Debian:11", "name": "x"}, "ranges": [r({"introduced": "0"})]}])
    assert assess_advisory("npm", "x", "1.0.0", vuln)["status"] == "unknown"
    v2 = adv([{"package": {"ecosystem": "npm", "name": "other", "purl": "pkg:npm/x"}, "ranges": [r({"introduced": "0"}, {"fixed": "2"}, type="SEMVER")]}])
    assert assess_advisory("npm", "x", "1.0.0", v2, purl="pkg:npm/x@1.0.0")["status"] == "confirmed_affected"


def test_describe_range():
    assert describe_range(r({"introduced": "0"}, {"fixed": "2.0"})) == ">= 0, < 2.0"
    assert "no fix" in describe_range(r({"introduced": "1.0"}))


def test_cvss3():
    assert cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H") == 7.4
    assert cvss3_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N") == 7.2
    assert cvss3_base("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss3_base("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert cvss3_base("junk") is None
    assert severity_from_score(9.8) == "CRITICAL" and severity_from_score(7.4) == "HIGH"
    assert severity_from_score(0.0) is None and severity_from_score(None) is None
    assert normalize_label("moderate") == "MEDIUM" and normalize_label("weird") is None
