"""T-126 / NFR-02: reconciliation and risk scoring for 50,000 assets in under 60 s.

Certificates are the only claims that do not pool (an algorithm is one asset with
many occurrences, OQ-18), so 50,000 distinct certificates is the honest way to get
50,000 assets. The ceiling is the PRD's 60 s; the measured figure is printed and
recorded in NOTE.md rather than asserted tight, since CI hardware varies.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from qavach_core.context import parse_systems_csv
from qavach_core.model import CertificateFacts, ConfidenceTier, NetworkLocus
from qavach_core.pipeline import ClaimInput, artefact_lifetime_of, assemble
from qavach_core.risk import AssetRiskInput, ScoreMemo, score_asset

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
_spec = importlib.util.spec_from_file_location("demo", ROOT / "scripts/demo.py")
assert _spec and _spec.loader
demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(demo)

KNOWLEDGE, POLICY, _PQC = demo.load_knowledge()
NOW = datetime(2026, 9, 20, 9, 0, tzinfo=UTC)
N = 50_000


def _claims(n: int) -> list[ClaimInput]:
    out = []
    for i in range(n):
        ca = i % 50 == 0
        facts = CertificateFacts(
            sha256_fingerprint=f"{i:064x}",
            spki_sha256=f"{i:064x}",
            subject=f"CN=host{i}",
            issuer=f"CN=host{i}" if ca else "CN=root",
            not_before=NOW - timedelta(days=1),
            not_after=NOW + timedelta(days=365 * (20 if ca else 1) - 1 + i % 300),
            is_ca=ca,
            self_signed=ca,
        )
        out.append(
            ClaimInput(
                name="RSA",
                primitive="signature",
                parameter_set="2048",
                certificate=facts,
                locus=NetworkLocus(host=f"host{i}", port=443, sni=f"host{i}", protocol="TLSv1.3"),
                collector="tls.endpoint",
                tool_version="0",
                confidence=ConfidenceTier.RUNTIME,
                detection_method="runtime",
                raw_ref="r",
                observed_at=NOW,
            )
        )
    return out


def test_nfr02_reconcile_and_score_fifty_thousand_assets_under_sixty_seconds() -> None:
    claims = _claims(N)
    system = parse_systems_csv(
        (ROOT / "tests/fixtures/demo/systems.csv").read_text(), POLICY
    ).systems[0]
    as_of = date(2026, 9, 20)

    t0 = time.perf_counter()
    assets = assemble(claims, KNOWLEDGE).assets
    t_assemble = time.perf_counter() - t0
    assert len(assets) == N  # nothing pooled, nothing dropped (I4, I8)

    t0 = time.perf_counter()
    memo = ScoreMemo()
    scored = [
        score_asset(
            AssetRiskInput(
                identity=a.identity,
                finding_class=a.finding_class,
                also_quantum_vulnerable=False,
                function=a.function,
                authority=a.migration_authority,
                loci=tuple(o.locus for o in a.occurrences),
                system=system,
                artefact_lifetime_years=artefact_lifetime_of(a, as_of),
            ),
            policy=POLICY,
            as_of=as_of,
            explain=False,
            memo=memo,
        )
        for a in assets
    ]
    t_score = time.perf_counter() - t0
    total = t_assemble + t_score
    print(  # noqa: T201
        f"\nNFR-02, {N:,} assets: reconcile {t_assemble:.1f}s + score {t_score:.1f}s = {total:.1f}s"
    )
    assert len(scored) == N
    assert total < 60, f"{total:.1f}s exceeds NFR-02's 60 s"
