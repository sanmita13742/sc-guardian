"""One adapter per SBOM producer. This is the single normalisation boundary of the project.

Each adapter exposes:
  NAME                        scanner id (``syft`` | ``trivy`` | ``builtin``)
  canonicalize(raw) -> dict   CycloneDX document in the canonical shape every later stage consumes (raw input is never mutated)
  locations(component) -> list[str]   file paths that evidence the component (as written by the tool)
  found_by(component) -> str|None     tool-specific cataloger / package type

Downstream code (graph, OSV, detectors, reports) only ever sees the canonical document / ``Component`` models.
"""
from __future__ import annotations

from sbom.adapters import builtin, syft, trivy

ADAPTERS = {a.NAME: a for a in (syft, trivy, builtin)}


def get_adapter(name: str):
    return ADAPTERS.get(name, syft)
