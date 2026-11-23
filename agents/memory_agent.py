"""Memory Agent: compares this scan with the repository's history and records it (deterministic, SQLite-backed)."""
from __future__ import annotations

from agents.runtime import Runtime
from agents.specialists import ScanState
from storage.memory import Memory, fingerprint, title


class MemoryAgent:
    name = "Memory Agent"

    def run(self, st: ScanState, rt: Runtime) -> None:
        with rt.step("memory", "Comparing with previous scans of this repository and recording finding history") as b:
            mem = Memory(st.ctx.db)
            labels = {a["finding_id"]: a["label"] for a in st.risk["assessments"]}
            typos = [f.model_dump() for f in st.typo["findings"]]
            locks = [c for c in st.lres["findings"] if c["classification"] != "insufficient_baseline"]
            items = ([("vulnerability", f, labels.get(f["finding_id"])) for f in st.vulns] + [("typosquatting", f, labels.get(f["finding_id"])) for f in typos]
                     + [("pipeline", f, labels.get(f["finding_id"])) for f in st.pipe["findings"]]
                     + [("package_risk", f, labels.get(f["finding_id"])) for f in st.pkgrisk["findings"]]
                     + [("lockfile_change", f, labels.get(f["finding_id"])) for f in locks])
            diff = mem.record_scan(st.info.url, st.info.scan_id, st.info.scan_timestamp, items)
            fps = {f["finding_id"]: fingerprint(k, f) for k, f, _ in items}
            titles = {f["finding_id"]: title(k, f) for k, f, _ in items}
            seen = mem.record_packages(st.info.url, {(c.ecosystem or "", c.name) for c in st.components if not c.is_self and c.type != "file" and c.ecosystem})
            typo_seen = {f["package_name"]: seen[(f["ecosystem"], f["package_name"])] for f in typos if (f["ecosystem"], f["package_name"]) in seen}
            st.result["memory"] = {"diff": diff, "fingerprints": fps, "titles": titles, "packages_seen_in_other_repos": len(seen), "typosquat_candidates_seen_elsewhere": typo_seen}
            c = diff["counts"]
            if diff["baseline"]:
                rt.observe("memory", "First scan of this repository: no history to compare; this scan becomes the baseline.")
            else:
                rt.observe("memory", f"Compared with the previous state: {c['new']} new, {c['persisting']} persisting, {c['fixed']} fixed, {c['regressed']} reappeared.")
                if c["regressed"]:
                    rt.decide("memory", f"Flag {c['regressed']} finding(s) that were fixed before and are back", reason="A previously fixed finding reappeared - likely a reverted upgrade.", agent="Supervisor")
            if typo_seen:
                rt.observe("memory", f"{len(typo_seen)} suspicious package name(s) were also seen in other scanned repositories: " + ", ".join(sorted(typo_seen)[:5]))
            b["message"] = ("baseline recorded" if diff["baseline"] else f"{c['new']} new / {c['fixed']} fixed / {c['persisting']} persisting")
