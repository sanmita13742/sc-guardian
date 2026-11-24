"""Function-Level Application Impact Evaluation for Contextual Risk Scoring v2.0.

Implements Dimension I:
    I = 0.25*F + 0.25*S + 0.20*B + 0.20*D + 0.10*X

Where:
    F: Function responsibility & criticality (0-100)
    S: Sensitivity of data handled (0-100)
    B: Privilege-boundary significance (0-100)
    D: Downstream application impact (0-100)
    X: Production execution exposure (0-100)
"""
from __future__ import annotations

import re
from typing import Any, Optional

from risk_analysis.contextual_scorer import DimensionScore, FunctionImpactBreakdown

# Keywords identifying security-critical functions and modules
SECURITY_CRITICAL_KEYWORDS = {
    "auth", "authentication", "authorize", "authorization", "crypto", "cryptography",
    "jwt", "token", "password", "session", "login", "oauth", "saml", "secret",
    "signature", "sign", "verify", "permission", "rbac", "acl", "tls", "ssl", "cipher"
}

TRANSACTIONAL_KEYWORDS = {
    "pay", "payment", "billing", "checkout", "order", "invoice", "transfer",
    "account", "bank", "credit", "charge", "subscription", "cart", "transaction"
}

DATA_SENSITIVITY_KEYWORDS = {
    "password", "secret", "token", "key", "credential", "private", "card",
    "ssn", "pii", "identity", "email", "phone", "dob", "address", "salt"
}

NETWORK_INGRESS_KEYWORDS = {
    "route", "endpoint", "api", "handler", "request", "webhook", "controller",
    "ingress", "listener", "server", "http", "graphql", "rest"
}

# Downstream impact classification based on vulnerability summaries, CWEs, or descriptions
RCE_CWE = {"CWE-78", "CWE-89", "CWE-94", "CWE-502", "CWE-434", "CWE-120", "CWE-79"}
AUTH_BYPASS_CWE = {"CWE-287", "CWE-269", "CWE-918", "CWE-862", "CWE-863", "CWE-306"}
INFO_LEAK_CWE = {"CWE-200", "CWE-209", "CWE-352", "CWE-532", "CWE-601"}
DOS_CWE = {"CWE-400", "CWE-770", "CWE-1333", "CWE-835", "CWE-674"}


class FunctionImpactAnalyzer:
    """Evaluates the 5 sub-factors of function-level application impact."""

    def evaluate_function_impact(
        self,
        package_name: str,
        vulnerable_symbols: Optional[list[str]] = None,
        advisory_summary: Optional[str] = None,
        advisory_details: Optional[str] = None,
        app_file_locations: Optional[list[str]] = None,
        dim_p_score: Optional[float] = None,
        is_dev: bool = False,
    ) -> tuple[DimensionScore, FunctionImpactBreakdown]:
        """Compute Dimension I and return both the DimensionScore and the sub-factor breakdown."""
        dim_name = "Function-Level Application Impact"
        weight = 0.30

        text_corpus = f"{package_name} {' '.join(vulnerable_symbols or [])} {' '.join(app_file_locations or [])}".lower()
        adv_corpus = f"{advisory_summary or ''} {advisory_details or ''}".lower()

        rationale: dict[str, str] = {}

        # 1. Sub-factor F: Function Responsibility & Criticality (0-100)
        if any(k in text_corpus for k in SECURITY_CRITICAL_KEYWORDS):
            score_F = 100.0
            rationale["F"] = "Security-critical functionality: package or call-site handles authentication, crypto, or access control."
        elif any(k in text_corpus for k in TRANSACTIONAL_KEYWORDS):
            score_F = 75.0
            rationale["F"] = "Core transactional logic: package operates within financial, payment, or order processing flows."
        elif any(k in text_corpus for k in ("db", "database", "sql", "orm", "redis", "mongo", "queue", "kafka")):
            score_F = 50.0
            rationale["F"] = "Supporting business infrastructure: package manages data persistence or messaging queues."
        elif any(k in text_corpus for k in ("log", "logger", "format", "string", "util", "helper", "math")):
            score_F = 25.0
            rationale["F"] = "Auxiliary/utility logic: package provides non-critical utility, formatting, or helper functions."
        else:
            score_F = 35.0
            rationale["F"] = "General application component: standard application functionality."

        # 2. Sub-factor S: Sensitivity of Data Handled (0-100)
        if any(k in text_corpus for k in DATA_SENSITIVITY_KEYWORDS):
            score_S = 100.0
            rationale["S"] = "Highly sensitive data: call sites handle credentials, cryptographic keys, PII, or tokens."
        elif any(k in text_corpus for k in ("user", "profile", "account", "customer", "tenant")):
            score_S = 60.0
            rationale["S"] = "Internal business state: package processes user profiles or tenant data."
        elif any(k in text_corpus for k in ("req", "request", "param", "query", "body", "input")):
            score_S = 30.0
            rationale["S"] = "Public/untrusted input: package processes external request parameters or query data."
        else:
            score_S = 20.0
            rationale["S"] = "No direct sensitive data handling identified."

        # 3. Sub-factor B: Privilege-Boundary Significance (0-100)
        if any(k in text_corpus for k in NETWORK_INGRESS_KEYWORDS):
            score_B = 100.0
            rationale["B"] = "External network trust boundary: package executes in public HTTP/API request ingress paths."
        elif any(k in text_corpus for k in ("rpc", "grpc", "service", "client", "worker", "agent")):
            score_B = 70.0
            rationale["B"] = "Service/process boundary: package executes in inter-service RPC or worker boundaries."
        else:
            score_B = 30.0
            rationale["B"] = "Internal execution context: package executes within isolated process boundaries."

        # 4. Sub-factor D: Downstream Application Impact (0-100)
        if any(term in adv_corpus for term in ("remote code execution", "rce", "command injection", "sql injection", "arbitrary code", "deserialization")):
            score_D = 100.0
            rationale["D"] = "Critical downstream impact: vulnerability allows Remote Code Execution, command injection, or SQLi."
        elif any(term in adv_corpus for term in ("bypass", "privilege escalation", "ssrf", "authentication bypass", "unauthorized")):
            score_D = 85.0
            rationale["D"] = "High downstream impact: vulnerability enables authentication bypass or privilege escalation."
        elif any(term in adv_corpus for term in ("information disclosure", "leak", "sensitive data", "csrf", "spoof")):
            score_D = 60.0
            rationale["D"] = "Moderate downstream impact: vulnerability causes sensitive information disclosure or cross-site request forgery."
        elif any(term in adv_corpus for term in ("denial of service", "dos", "crash", "infinite loop", "resource exhaustion")):
            score_D = 35.0
            rationale["D"] = "Bounded downstream impact: vulnerability results in service degradation or Denial of Service."
        else:
            score_D = 40.0
            rationale["D"] = "Moderate downstream impact based on standard advisory classification."

        # 5. Sub-factor X: Production Execution Exposure (0-100)
        if is_dev:
            score_X = 0.0
            rationale["X"] = "Zero production exposure: development-only dependency."
        elif dim_p_score is not None:
            # Correlate exposure with production reachability score
            score_X = dim_p_score
            rationale["X"] = f"Production exposure directly aligned with production reachability ({dim_p_score:.0f}/100)."
        elif any(k in text_corpus for k in ("server", "app", "main", "service")):
            score_X = 80.0
            rationale["X"] = "High production exposure: active in core server runtime loop."
        else:
            score_X = 40.0
            rationale["X"] = "Intermittent/standard execution exposure."

        # Compute Dimension I = 0.25*F + 0.25*S + 0.20*B + 0.20*D + 0.10*X
        composite_I = round(
            0.25 * score_F +
            0.25 * score_S +
            0.20 * score_B +
            0.20 * score_D +
            0.10 * score_X,
            1
        )
        composite_I = max(0.0, min(100.0, composite_I))

        breakdown = FunctionImpactBreakdown(
            function_criticality_F=score_F,
            data_sensitivity_S=score_S,
            privilege_boundary_B=score_B,
            downstream_impact_D=score_D,
            production_exposure_X=score_X,
            composite_score_I=composite_I,
            rationale=rationale,
        )

        evidence = [
            f"Composite Impact: {composite_I:.1f}/100 (F:{score_F:.0f}, S:{score_S:.0f}, B:{score_B:.0f}, D:{score_D:.0f}, X:{score_X:.0f})",
            rationale["F"],
            rationale["D"],
        ]

        dim_score = DimensionScore(
            dimension="I",
            name=dim_name,
            weight=weight,
            raw_value=breakdown.to_dict(),
            normalized_score=composite_I,
            status="assessed",
            weighted_contribution=round(weight * composite_I, 2),
            evidence=evidence,
            confidence="high",
        )

        return dim_score, breakdown
