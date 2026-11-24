"""Fix Validation & Verification (stages 4-5).

Takes one *approved* remediation proposal from a stored scan, applies it in a disposable sandbox, builds/tests it, regenerates the
SBOM, rescans, compares before and after, records integrity/provenance evidence and issues a final, evidence-backed verdict.

This package runs after a scan, on demand. It is not a node of the scan graph and never changes the scan result schema:
it only *reads* stored scans and remediation items, and writes its own files under ``artifacts/validation/``.

Modules
  contracts     typed inputs/outputs (the hand-off with the remediation engine lives in ``ApprovedRemediation.from_item``)
  comparison    pure before/after diff of two scan results
  verdict       pure verdict rules
  provenance    digests and an in-toto / SLSA-shaped provenance statement
  report        writes before_after_comparison.json, validation_report.json, final_assessment.json
  fix_validator the end-to-end flow (sandbox -> rescan -> compare -> verdict -> reports)
"""
