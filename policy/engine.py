"""Policy-as-code: declarative YAML rules evaluated over the Guardian's findings, producing a pass/fail gate with the violating evidence.

Policy file (see ``policies/default.yaml``)::

    name: default
    rules:
      - id: no-known-exploited
        description: ...
        when: {kind: vulnerability, kev: true}          # all conditions must match (AND)
        action: block                                    # block | warn | info
    exceptions:                                          # optional, time-boxed waivers
      - {rule: epss-high, subject: "lodash@4.17.4", reason: "...", expires: "2027-01-31"}

Condition operators: ``field: value`` (equality), ``field: [a, b]`` (any of), ``field_gte/_lte/_gt/_lt: number``, ``license_any: [...]``,
and ``unless: {...}`` to exclude. A *block* violation fails the gate; *warn* and *info* are reported only. Analyst decisions stored in memory
(accepted risk / false positive / suppress, with expiry) waive matching findings - waived items stay visible.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

import yaml

ACTIONS = ("block", "warn", "info")
KNOWN_KEYS = {"kind", "severity", "kev", "epss", "verdict", "reachability", "dependency_type", "ecosystem", "fix_available", "priority", "risk", "confirmed", "rule_id", "category", "third_party",
              "classification", "strength", "scope", "install_script", "deprecated", "integrity", "licenses", "published_age_days", "name", "confidence"}
POLICY_DIR = Path(__file__).resolve().parent.parent / "policies"


class PolicyError(ValueError):
    pass


def load_policy(name_or_path: str) -> dict:
    p = Path(name_or_path)
    if not p.exists():
        p = POLICY_DIR / (name_or_path if name_or_path.endswith((".yaml", ".yml")) else name_or_path + ".yaml")
    if not p.exists():
        raise PolicyError(f"policy '{name_or_path}' not found (looked in {POLICY_DIR})")
    return parse_policy(p.read_text(encoding="utf-8"), p.stem)


def parse_policy(text: str, default_name: str = "custom") -> dict:
    try:
        d = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise PolicyError(f"invalid YAML: {e}") from e
    if not isinstance(d, dict) or not isinstance(d.get("rules"), list) or not d["rules"]:
        raise PolicyError("a policy needs a non-empty `rules:` list")
    seen = set()
    for r in d["rules"]:
        if not isinstance(r, dict) or not r.get("id") or not isinstance(r.get("when"), dict):
            raise PolicyError("every rule needs `id` and a `when:` mapping")
        if r["id"] in seen:
            raise PolicyError(f"duplicate rule id '{r['id']}'")
        seen.add(r["id"])
        if r.get("action", "block") not in ACTIONS:
            raise PolicyError(f"rule '{r['id']}': action must be one of {ACTIONS}")
        for blk in (r["when"], r.get("unless") or {}):
            for k in blk:
                base = k.rsplit("_", 1)[0] if k.endswith(("_gte", "_lte", "_gt", "_lt")) else k
                if base not in KNOWN_KEYS and k != "license_any":
                    raise PolicyError(f"rule '{r['id']}': unknown condition '{k}' (known: {sorted(KNOWN_KEYS)})")
    d.setdefault("name", default_name)
    return d


def _num(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _match_block(fact: dict, cond: dict) -> bool:
    for k, v in cond.items():
        if k == "license_any":
            lic = [str(x).lower() for x in (fact.get("licenses") or [])]
            want = [str(x).lower() for x in (v if isinstance(v, list) else [v])]
            if not any(any(w == l or w in l for w in want) for l in lic):
                return False
            continue
        op = None
        for suf, name in (("_gte", "gte"), ("_lte", "lte"), ("_gt", "gt"), ("_lt", "lt")):
            if k.endswith(suf):
                k, op = k[:-len(suf)], name
                break
        have = fact.get(k)
        if op:
            a, b = _num(have), _num(v)
            if a is None or b is None or not {"gte": a >= b, "lte": a <= b, "gt": a > b, "lt": a < b}[op]:
                return False
        elif isinstance(v, list):
            if have not in v:
                return False
        elif have != v:
            return False
    return True


def matches(fact: dict, rule: dict) -> bool:
    return _match_block(fact, rule["when"]) and not (rule.get("unless") and _match_block(fact, rule["unless"]))


def facts_from_result(r: dict, waivers: Optional[dict[str, dict]] = None) -> list[dict]:
    """Flatten a scan result into evaluable facts (one per finding / component)."""
    risks = {a["finding_id"]: a for a in r.get("risk_assessments", [])}
    fps = (r.get("memory") or {}).get("fingerprints") or {}
    inv = r.get("investigations") or {}
    out: list[dict] = []
    for f in r.get("vulnerabilities", []):
        a = risks.get(f["finding_id"], {})
        out.append({"kind": "vulnerability", "id": f["finding_id"], "subject": f"{f['package_name']}@{f['installed_version']} {f['primary_id']}", "severity": f["severity"], "kev": bool(f["kev"]),
                    "epss": f.get("epss"), "verdict": f.get("verdict"), "reachability": (f.get("reachability") or {}).get("status"), "dependency_type": f["dependency_type"], "ecosystem": f["ecosystem"],
                    "fix_available": bool(f["fixed_versions"]), "priority": a.get("priority"), "risk": a.get("label"), "confirmed": f["affected_status"] == "confirmed_affected", "name": f["package_name"],
                    "confidence": (a.get("confidence") or {}).get("label"), "evidence_ids": (inv.get(f["finding_id"]) or {}).get("evidence_ids", []), "fingerprint": fps.get(f["finding_id"])})
    for kind, lst in (("pipeline", (r.get("pipeline") or {}).get("findings", [])), ("package_risk", (r.get("package_risk") or {}).get("findings", []))):
        for f in lst:
            a = risks.get(f["finding_id"], {})
            out.append({"kind": kind, "id": f["finding_id"], "subject": f"{f['rule_id']} {f['title']}" + (f" ({f['file']})" if kind == "pipeline" else ""), "severity": f["severity"], "rule_id": f["rule_id"],
                        "category": f.get("category"), "third_party": bool((f.get("extra") or {}).get("third_party")), "ecosystem": f.get("ecosystem"), "priority": a.get("priority"), "risk": a.get("label"),
                        "evidence_ids": [f["evidence_id"]] if f.get("evidence_id") else [], "fingerprint": fps.get(f["finding_id"])})
    for t in r.get("typosquatting", []):
        out.append({"kind": "typosquatting", "id": t["finding_id"], "subject": f"{t['package_name']} resembles {t['similar_to']}", "strength": t["evidence_strength"], "ecosystem": t["ecosystem"],
                    "risk": risks.get(t["finding_id"], {}).get("label"), "fingerprint": fps.get(t["finding_id"]), "evidence_ids": []})
    for c in r.get("lockfile_changes", []):
        out.append({"kind": "lockfile_change", "id": c["finding_id"], "subject": f"{c['change_type']} {c['package_name']} ({c['file']})", "classification": c["classification"], "strength": c["evidence_strength"],
                    "ecosystem": c["ecosystem"], "risk": risks.get(c["finding_id"], {}).get("label"), "fingerprint": fps.get(c["finding_id"]), "evidence_ids": []})
    scan_ts = (r.get("repo") or {}).get("scan_timestamp", "")
    for c in r.get("components", []):
        if c.get("is_self") or c.get("type") in ("file", "container"):
            continue
        age = None
        if c.get("published_at") and scan_ts:
            try:
                age = (time.mktime(time.strptime(scan_ts, "%Y-%m-%dT%H:%M:%SZ")) - time.mktime(time.strptime(c["published_at"][:19], "%Y-%m-%dT%H:%M:%S"))) / 86400
            except ValueError:
                age = None
        out.append({"kind": "component", "id": c["bom_ref"], "subject": f"{c['name']}@{c['version']}", "name": c["name"], "ecosystem": c.get("ecosystem"), "licenses": c.get("licenses") or [], "scope": c.get("scope"),
                    "install_script": bool(c.get("install_script")), "deprecated": bool(c.get("deprecated")), "integrity": (c.get("integrity") or {}).get("status"), "published_age_days": age,
                    "evidence_ids": [], "fingerprint": None})
    return out


def evaluate(policy: dict, result: dict, waivers: Optional[dict[str, dict]] = None, today: Optional[str] = None) -> dict[str, Any]:
    """Evaluate ``policy`` against a scan result. ``waivers``: fingerprint -> active memory decision."""
    waivers = waivers or {}
    today = today or time.strftime("%Y-%m-%d", time.gmtime())
    exc = [e for e in policy.get("exceptions") or [] if isinstance(e, dict) and (not e.get("expires") or str(e["expires"]) >= today)]
    facts = facts_from_result(result)
    violations, waived = [], []
    for rule in policy["rules"]:
        action = rule.get("action", "block")
        for f in facts:
            if f["kind"] != rule["when"].get("kind", f["kind"]) and "kind" in rule["when"] and not isinstance(rule["when"]["kind"], list):
                continue
            if not matches(f, rule):
                continue
            v = {"rule_id": rule["id"], "action": action, "description": rule.get("description", ""), "finding_id": f["id"], "kind": f["kind"], "subject": f["subject"], "evidence_ids": f.get("evidence_ids", [])}
            wf = waivers.get(f.get("fingerprint") or "")
            fe = next((e for e in exc if e.get("rule") == rule["id"] and (not e.get("subject") or e["subject"] in f["subject"])), None)
            if wf or fe:
                v["waiver"] = {"source": "analyst decision" if wf else "policy exception", "reason": (wf or fe).get("reason", ""), "expires": (wf or fe).get("expires_at") or (wf or fe).get("expires")}
                waived.append(v)
            else:
                violations.append(v)
    blocking = [v for v in violations if v["action"] == "block"]
    by_rule: dict[str, int] = {}
    for v in violations:
        by_rule[v["rule_id"]] = by_rule.get(v["rule_id"], 0) + 1
    return {"policy": policy.get("name"), "description": policy.get("description", ""), "passed": not blocking, "blocking": len(blocking), "warnings": sum(1 for v in violations if v["action"] == "warn"),
            "info": sum(1 for v in violations if v["action"] == "info"), "waived": len(waived), "violations": violations, "waived_items": waived, "by_rule": by_rule,
            "rules_evaluated": len(policy["rules"]), "facts_evaluated": len(facts), "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def to_rego(policy: dict) -> str:
    """Illustrative Rego (OPA/Conftest) export of the same rules over the flattened facts. The YAML engine remains authoritative."""
    def cond(k, v):
        for suf, op in (("_gte", ">="), ("_lte", "<="), ("_gt", ">"), ("_lt", "<")):
            if k.endswith(suf):
                return f"f.{k[:-len(suf)]} {op} {v}"
        if k == "license_any":
            return "some l in f.licenses; some w in " + str([str(x).lower() for x in v]) + "; contains(lower(l), w)"
        if isinstance(v, list):
            return f"f.{k} in {v!r}".replace("'", '"')
        return f"f.{k} == " + (str(v).lower() if isinstance(v, bool) else f'"{v}"' if isinstance(v, str) else str(v))
    lines = ["package guardian", "", "import rego.v1", "", "# Generated from policies/*.yaml - input.facts is the flattened findings/components list.", ""]
    for action in ("block", "warn", "info"):
        lines.append(f"{'deny' if action == 'block' else action} contains msg if {{" if False else "")
    for r in policy["rules"]:
        name = {"block": "deny", "warn": "warn", "info": "info"}[r.get("action", "block")]
        body = [f"    some f in input.facts"] + [f"    {cond(k, v)}" for k, v in r["when"].items()]
        lines.append(f"{name} contains msg if {{")
        lines += body
        lines.append(f'    msg := sprintf("{r["id"]}: %v", [f.subject])')
        lines.append("}")
        lines.append("")
    return "\n".join(lines)
