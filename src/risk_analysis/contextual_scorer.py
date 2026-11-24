"""Contextual Vulnerability Risk Scoring Engine v2.0.

Implements the four-factor linear contextual risk model:
    R = 0.15*C + 0.20*A + 0.35*P + 0.30*I

Where:
    C: CVSS Severity (0-100)
    A: Application Code Reachability (0-100)
    P: Production Code Reachability (0-100)
    I: Function-Level Application Impact (0-100)

Follows strict missing-evidence handling: Unknown is not zero.
Threat intelligence (CISA KEV, EPSS) is maintained as an independent prioritization dimension.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class FunctionImpactBreakdown:
    """Breakdown of the 5 sub-factors comprising Dimension I."""
    function_criticality_F: float = 25.0  # F: 0-100 (weight 0.25)
    data_sensitivity_S: float = 30.0      # S: 0-100 (weight 0.25)
    privilege_boundary_B: float = 30.0    # B: 0-100 (weight 0.20)
    downstream_impact_D: float = 35.0     # D: 0-100 (weight 0.20)
    production_exposure_X: float = 40.0   # X: 0-100 (weight 0.10)
    composite_score_I: float = 30.0       # 0-100
    rationale: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DimensionScore:
    """Detailed score and evidence audit for a single scoring dimension."""
    dimension: str  # "C", "A", "P", "I"
    name: str
    weight: float
    raw_value: Any
    normalized_score: Optional[float]  # None if unknown / missing
    status: str  # "confirmed", "potential", "unreachable", "unknown", etc.
    weighted_contribution: float
    evidence: list[str] = field(default_factory=list)
    confidence: str = "medium"  # "high", "medium", "low", "none"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ContextualRiskResult:
    """Complete assessment result from ContextualScorer."""
    finding_id: str
    score: float  # Final score 0-100 (or provisional score)
    rounded_score: int
    label: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    priority: str  # P0, P1, P2, P3
    is_provisional: bool
    formula: str
    weights: dict[str, float]
    dimensions: dict[str, DimensionScore]
    impact_breakdown: Optional[FunctionImpactBreakdown] = None
    missing_dimensions: list[str] = field(default_factory=list)
    missing_evidence_reasons: list[str] = field(default_factory=list)
    threat_intel_escalations: list[str] = field(default_factory=list)
    factors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.impact_breakdown:
            data["impact_breakdown"] = self.impact_breakdown.to_dict()
        data["dimensions"] = {k: v.to_dict() for k, v in self.dimensions.items()}
        return data


class ContextualScorer:
    """Calculates contextual risk using the v2.0 model with missing-evidence awareness."""

    DEFAULT_WEIGHTS = {
        "C": 0.15,
        "A": 0.20,
        "P": 0.35,
        "I": 0.30,
    }

    DEFAULT_THRESHOLDS = {
        "CRITICAL": 70.0,
        "HIGH": 45.0,
        "MEDIUM": 25.0,
        "LOW": 10.0,
    }

    def __init__(
        self,
        weights: Optional[dict[str, float]] = None,
        thresholds: Optional[dict[str, float]] = None,
    ):
        self.weights = dict(weights or self.DEFAULT_WEIGHTS)
        self.thresholds = dict(thresholds or self.DEFAULT_THRESHOLDS)
        self._validate_weights()

    def _validate_weights(self) -> None:
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-4:
            raise ValueError(f"Contextual scoring weights must sum to 1.0; got {total:.4f} ({self.weights})")
        for k in ("C", "A", "P", "I"):
            if k not in self.weights:
                raise ValueError(f"Missing weight for dimension '{k}'")
            if self.weights[k] < 0:
                raise ValueError(f"Weight for '{k}' cannot be negative: {self.weights[k]}")

    def label_for(self, score: float) -> str:
        for lab in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if score >= self.thresholds[lab]:
                return lab
        return "INFORMATIONAL"

    def calculate_priority(
        self,
        risk_score: float,
        label: str,
        dim_a: DimensionScore,
        dim_p: DimensionScore,
        kev: bool = False,
        epss: Optional[float] = None,
    ) -> tuple[str, list[str]]:
        """Calculate operational priority P0-P3 with decoupled threat intelligence."""
        reasons = []
        is_kev_active = bool(kev)
        high_epss = (epss or 0.0) >= 0.20
        app_reachable = dim_a.normalized_score is not None and dim_a.normalized_score >= 60.0
        prod_reachable = dim_p.normalized_score is not None and dim_p.normalized_score >= 70.0
        test_only = dim_p.status == "test_only" or (dim_p.normalized_score is not None and dim_p.normalized_score == 0.0)
        unimported = dim_a.status == "unreachable" or (dim_a.normalized_score is not None and dim_a.normalized_score == 0.0)

        if is_kev_active:
            reasons.append("Active exploitation in CISA KEV catalog")
        if high_epss:
            reasons.append(f"High exploitation probability (EPSS {epss:.1%})")

        # Deprioritization if verified test-only or completely unimported without active KEV
        if (test_only or unimported) and not is_kev_active:
            if label in ("CRITICAL", "HIGH", "MEDIUM"):
                return "P2", ["Deprioritized: zero production/application runtime exposure (no active KEV)"]
            return "P3", ["Deprioritized: zero production/application runtime exposure"]

        # Escalation rules
        if risk_score >= self.thresholds["CRITICAL"] or (is_kev_active and app_reachable) or (risk_score >= self.thresholds["HIGH"] and prod_reachable):
            if is_kev_active and app_reachable:
                reasons.append("Escalated to P0 due to active CISA KEV with verified application reachability")
            elif prod_reachable and risk_score >= self.thresholds["HIGH"]:
                reasons.append("Escalated to P0 due to high contextual risk in confirmed production path")
            return "P0", reasons

        if risk_score >= self.thresholds["HIGH"] or (risk_score >= self.thresholds["MEDIUM"] and prod_reachable) or (is_kev_active):
            if is_kev_active:
                reasons.append("Escalated to P1 due to active CISA KEV")
            elif prod_reachable:
                reasons.append("Escalated to P1 due to medium contextual risk with strong production path")
            return "P1", reasons

        if risk_score >= self.thresholds["MEDIUM"]:
            return "P2", reasons

        return "P3", reasons

    def score(
        self,
        finding_id: str,
        dim_c: DimensionScore,
        dim_a: DimensionScore,
        dim_p: DimensionScore,
        dim_i: DimensionScore,
        impact_breakdown: Optional[FunctionImpactBreakdown] = None,
        kev: bool = False,
        epss: Optional[float] = None,
    ) -> ContextualRiskResult:
        """Execute the 4-factor scoring calculation."""
        dims = {"C": dim_c, "A": dim_a, "P": dim_p, "I": dim_i}
        missing_dims: list[str] = []
        missing_reasons: list[str] = []
        factors: list[dict[str, Any]] = []

        available_weights = 0.0
        weighted_sum = 0.0

        for key, dim in dims.items():
            # Clamp raw normalized score if present
            if dim.normalized_score is not None:
                dim.normalized_score = max(0.0, min(100.0, float(dim.normalized_score)))
                contrib = self.weights[key] * dim.normalized_score
                dim.weighted_contribution = round(contrib, 2)
                weighted_sum += contrib
                available_weights += self.weights[key]
                factors.append({
                    "factor": f"Dimension {key} ({dim.name})",
                    "points": round(contrib, 1),
                    "normalized": round(dim.normalized_score, 1),
                    "weight": f"{int(self.weights[key] * 100)}%",
                    "detail": f"{dim.status}: {'; '.join(dim.evidence[:2]) if dim.evidence else 'Score ' + str(round(dim.normalized_score, 1))}",
                })
            else:
                dim.weighted_contribution = 0.0
                missing_dims.append(key)
                reason = f"Dimension {key} ({dim.name}) is unknown or missing evidence."
                missing_reasons.append(reason)
                factors.append({
                    "factor": f"Dimension {key} ({dim.name})",
                    "points": 0.0,
                    "normalized": "Unknown",
                    "weight": f"{int(self.weights[key] * 100)}%",
                    "detail": "Missing or unassessed evidence; treated as provisional (NOT zero).",
                })

        is_provisional = len(missing_dims) > 0

        # Calculate final or provisional score
        if available_weights > 0.0:
            if is_provisional:
                # Re-normalize over available weights
                final_score = weighted_sum / available_weights
            else:
                final_score = weighted_sum
        else:
            final_score = 50.0  # Complete uncertainty baseline

        final_score = max(0.0, min(100.0, final_score))
        label = self.label_for(final_score)
        priority, escalations = self.calculate_priority(
            final_score, label, dim_a, dim_p, kev=kev, epss=epss
        )

        formula_str = f"R = {self.weights['C']:.2f}*C + {self.weights['A']:.2f}*A + {self.weights['P']:.2f}*P + {self.weights['I']:.2f}*I"

        return ContextualRiskResult(
            finding_id=finding_id,
            score=round(final_score, 1),
            rounded_score=int(round(final_score)),
            label=label,
            priority=priority,
            is_provisional=is_provisional,
            formula=formula_str,
            weights=dict(self.weights),
            dimensions=dims,
            impact_breakdown=impact_breakdown,
            missing_dimensions=missing_dims,
            missing_evidence_reasons=missing_reasons,
            threat_intel_escalations=escalations,
            factors=factors,
        )
