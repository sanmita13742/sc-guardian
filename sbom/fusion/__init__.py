"""Metadata fusion: field-level, provenance-tracked reconciliation of everything we know about each component.

Sources, in the order they are consulted (see ``engine.py``): lockfile (native) -> manifest -> SBOM scanner -> registry (deps.dev,
ecosystem registries). A value from a more trusted source is never overwritten; disagreements are recorded as conflicts.
"""
