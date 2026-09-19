"""Replacement selection and hybrid guidance. T-082 / ARCH.md 8 / FR-410.

Table-driven from `pqc_alternatives.yaml`, never hardcoded, so the answer and
its standardisation status always come from the same audited file. Rules:

* **Only `final` standards are ever the answer.** Non-final entries (HQC,
  FN-DSA) appear in `watch` with their exact status text, never in `primary`
  or `also_consider`. (`PqcKnowledge` also refuses to load a non-final entry
  marked usable, so this cannot be broken by a data edit.)
* **Only quantum-relevant classes get a PQC recommendation (I1).** A
  `GROVER_AFFECTED` finding gets "prefer 256-bit" as *information*; a
  `CLASSICAL_WEAK` one gets its classical fix and is explicitly *not* a
  quantum finding; `QUANTUM_SAFE` needs nothing; `UNKNOWN` cannot be advised on
  (I8). A weak asset that is *also* quantum-vulnerable (RSA-1024) gets both.
* **Hybrid is contextual, not universal (ARCH.md 8.2).** Each applicable
  context yields its own advice with its own reason and citation; where a regime
  has a position (CNSA 2.0), the regime's position is stated, and an unverified
  source is flagged as such rather than quietly trusted.
* **The size cost is quantified, not adjectival.** For signature-size-sensitive
  cases the ratio comes from `performance.yaml`; if either figure is `None`
  it says "not available" instead of estimating.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from qavach_core.model.enums import CryptoFunction, FindingClass
from qavach_core.recommend.knowledge import Alternative, ClassicalFix, PqcKnowledge

_CONFIDENTIALITY = frozenset(
    {
        CryptoFunction.KEY_ENCAPSULATION,
        CryptoFunction.KEY_AGREEMENT,
        CryptoFunction.ENCRYPTION,
    }
)
_INCUMBENT_SIGNATURE_ROW = {
    "ECDSA": "signature.ECDSA-P-256",
    "EdDSA": "signature.Ed25519",
    "RSASSA-PKCS1": "signature.RSA-2048",
    "RSASSA-PSS": "signature.RSA-2048",
}
_CLASSICAL_FIX_BY_FAMILY = {
    "MD5": "hash-md5-sha1",
    "SHA-1": "hash-md5-sha1",
    "DES": "symmetric-weak",
    "3DES": "symmetric-weak",
    "RC4": "symmetric-weak",
    "Blowfish": "symmetric-weak",
}


@dataclass(frozen=True, slots=True)
class Constraints:
    regimes: frozenset[str] = frozenset()
    tls_in_transit: bool = False
    signature_size_constrained: bool = False
    firmware_or_boot_signing: bool = False
    stateful_signatures_acceptable: bool = False
    want_lattice_diversity: bool = False
    long_term_archival_confidentiality: bool = False


@dataclass(frozen=True, slots=True)
class AlternativeRef:
    name: str
    standard: str | None
    status: str
    status_text: str
    verified_on: str | None
    unverified_reason: str | None
    source_url: str
    note: str | None = None

    @staticmethod
    def of(alt: Alternative) -> AlternativeRef:
        text = {
            "final": f"Final ({alt.standard}, {alt.status_date})",
            "selected-not-published": (
                f"Selected for standardisation {alt.status_date}; standard not yet published. "
                "Not a compliance claim."
            ),
            "in-development": (
                "In development; not a published standard. Do not recommend as final."
            ),
        }[alt.status]
        return AlternativeRef(
            name=alt.name,
            standard=alt.standard,
            status=alt.status,
            status_text=text,
            verified_on=alt.verified_on.isoformat() if alt.verified_on else None,
            unverified_reason=alt.unverified_reason,
            source_url=alt.source_url,
            note=alt.note,
        )


@dataclass(frozen=True, slots=True)
class HybridAdvice:
    context: str
    position: str
    reason: str
    recommend: str | None
    verified: bool
    unverified_reason: str | None
    source_url: str


@dataclass(frozen=True, slots=True)
class SizeCost:
    incumbent: str
    replacement: str
    incumbent_signature_bytes: int | None
    replacement_signature_bytes: int | None
    ratio: float | None
    """`None` when either figure is unavailable - never estimated."""


@dataclass(frozen=True, slots=True)
class Recommendation:
    applicable: bool
    kind: str
    """`pqc`, `classical-fix`, `informational`, `none` or `cannot-advise`."""
    reason: str
    primary: AlternativeRef | None = None
    also_consider: tuple[AlternativeRef, ...] = ()
    watch: tuple[AlternativeRef, ...] = ()
    classical_fix: str | None = None
    hybrid: tuple[HybridAdvice, ...] = ()
    size_cost: SizeCost | None = None
    notes: tuple[str, ...] = field(default=())


def _alt(knowledge: PqcKnowledge, key: str) -> Alternative:
    return knowledge.alternatives[key]


def _fix_ref(fix: ClassicalFix) -> str:
    return f"{fix.name} ({fix.standard})"


def _hybrid_advice(
    knowledge: PqcKnowledge, key: str, *, recommend: str | None = None
) -> HybridAdvice:
    g = knowledge.hybrid[key]
    return HybridAdvice(
        context=g.context,
        position=g.position,
        reason=g.reason,
        recommend=recommend or g.recommend,
        verified=g.verified_on is not None,
        unverified_reason=g.unverified_reason,
        source_url=g.source_url,
    )


def _size_cost(
    knowledge: PqcKnowledge, family: str | None, replacement_row: str
) -> SizeCost | None:
    incumbent_row = _INCUMBENT_SIGNATURE_ROW.get(family or "")
    if incumbent_row is None:
        return None
    inc = knowledge.performance.get(incumbent_row)
    rep = knowledge.performance.get(replacement_row)
    inc_bytes = inc.figures.get("signature_bytes") if inc else None
    rep_bytes = rep.figures.get("signature_bytes") if rep else None
    ratio = round(rep_bytes / inc_bytes, 1) if inc_bytes and rep_bytes else None
    return SizeCost(
        incumbent=incumbent_row.split(".", 1)[1],
        replacement=replacement_row.split(".", 1)[1],
        incumbent_signature_bytes=inc_bytes,
        replacement_signature_bytes=rep_bytes,
        ratio=ratio,
    )


def recommend(
    *,
    finding_class: FindingClass,
    also_quantum_vulnerable: bool,
    function: CryptoFunction | None,
    algorithm_family: str | None,
    knowledge: PqcKnowledge,
    constraints: Constraints | None = None,
) -> Recommendation:
    c = constraints or Constraints()

    if finding_class is FindingClass.UNKNOWN:
        return Recommendation(
            False,
            "cannot-advise",
            "the asset could not be classified, so no replacement can be advised (I8)",
        )
    if finding_class is FindingClass.QUANTUM_SAFE:
        return Recommendation(False, "none", "already quantum-safe: confirm and record")
    if finding_class is FindingClass.GROVER_AFFECTED:
        fix = knowledge.classical_fixes["grover-prefer-256"]
        return Recommendation(
            True,
            "informational",
            "Grover halves symmetric strength but does not break it: prefer 256-bit for "
            "data with a long shelf life. This is information, never a migrate-now finding.",
            classical_fix=_fix_ref(fix),
            notes=(fix.note,) if fix.note else (),
        )

    quantum_relevant = finding_class is FindingClass.QUANTUM_VULNERABLE or also_quantum_vulnerable
    notes: list[str] = []
    fix_text: str | None = None
    if finding_class is FindingClass.CLASSICAL_WEAK:
        key = _CLASSICAL_FIX_BY_FAMILY.get(algorithm_family or "")
        if key:
            fix_text = _fix_ref(knowledge.classical_fixes[key])
        notes.append(
            "Broken today, independent of quantum: replace now. This is not a quantum finding."
        )
        if not quantum_relevant:
            return Recommendation(
                fix_text is not None,
                "classical-fix" if fix_text else "cannot-advise",
                "classically weak: " + (fix_text or "no catalogued replacement for this algorithm"),
                classical_fix=fix_text,
                notes=tuple(notes),
            )

    if function is None:
        return Recommendation(
            False,
            "cannot-advise",
            "the cryptographic function is unknown, so a replacement cannot be chosen (I8)",
            classical_fix=fix_text,
            notes=tuple(notes),
        )

    nss = "nss" in c.regimes
    also: list[str] = []
    watch: list[str] = []
    replacement_row = ""
    if function in _CONFIDENTIALITY:
        primary_key = "ml-kem-1024" if nss else "ml-kem-768"
        watch.append("hqc")
        reason = "key establishment: ML-KEM (FIPS 203)"
    elif function is CryptoFunction.SIGNATURE:
        if c.firmware_or_boot_signing and c.stateful_signatures_acceptable:
            primary_key = "lms-xmss"
            reason = (
                "firmware/boot signing where stateful signatures are acceptable: "
                "LMS/XMSS (SP 800-208)"
            )
            also += ["ml-dsa-65"]
        else:
            primary_key = "ml-dsa-87" if nss else "ml-dsa-65"
            reason = "signing: ML-DSA (FIPS 204)"
            also += ["slh-dsa"] if c.want_lattice_diversity else []
            replacement_row = "signature.ML-DSA-65"
        if c.signature_size_constrained:
            watch.append("fn-dsa")
    else:
        return Recommendation(
            False,
            "none",
            f"{function.value} is not changed by Shor's algorithm; no PQC replacement applies",
            classical_fix=fix_text,
            notes=tuple(notes),
        )

    hybrid: list[HybridAdvice] = []
    if nss:
        hybrid.append(_hybrid_advice(knowledge, "national-security"))
    elif c.tls_in_transit and function in _CONFIDENTIALITY:
        hybrid.append(_hybrid_advice(knowledge, "tls-transition"))
    if c.long_term_archival_confidentiality and function in _CONFIDENTIALITY:
        hybrid.append(_hybrid_advice(knowledge, "archival-confidentiality"))

    size_cost = None
    if c.signature_size_constrained and function is CryptoFunction.SIGNATURE:
        hybrid.append(_hybrid_advice(knowledge, "size-constrained"))
        size_cost = _size_cost(
            knowledge, algorithm_family, replacement_row or "signature.ML-DSA-65"
        )

    return Recommendation(
        True,
        "pqc",
        reason,
        primary=AlternativeRef.of(_alt(knowledge, primary_key)),
        also_consider=tuple(AlternativeRef.of(_alt(knowledge, k)) for k in also),
        watch=tuple(AlternativeRef.of(_alt(knowledge, k)) for k in watch),
        classical_fix=fix_text,
        hybrid=tuple(hybrid),
        size_cost=size_cost,
        notes=tuple(notes),
    )
