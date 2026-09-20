"""What a certificate contributes to risk beyond its key algorithm (OQ-20, I2).

Two certificates with the same RSA-2048 key are the same *algorithm* but not the
same *risk*: an ephemeral TLS leaf that expires next month has nothing left for a
future forger to exploit, while a root CA that anchors trust for another two
decades has everything. The difference is entirely in these facts - who the
certificate is (`role`) and how long it stays trusted (`not_after`) - so they are
carried on the asset and consumed by scoring, never guessed.

Pure data, stdlib only (packages/core purity).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Literal

Role = Literal["leaf", "intermediate", "root"]
_DAYS_PER_YEAR = 365.25


@dataclass(frozen=True, slots=True)
class CertificateFacts:
    sha256_fingerprint: str
    spki_sha256: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    is_ca: bool
    self_signed: bool

    def __post_init__(self) -> None:
        if self.not_before.tzinfo is None or self.not_after.tzinfo is None:
            raise ValueError("certificate validity must be timezone-aware")

    @property
    def role(self) -> Role:
        if self.is_ca and self.self_signed:
            return "root"
        return "intermediate" if self.is_ca else "leaf"

    def remaining_years(self, as_of: date) -> float:
        """How long this certificate stays trusted from `as_of` - the artefact
        lifetime `x_integ` is derived from (ARCH.md §7.2). Never negative: an
        expired certificate has nothing left to forge (an expired *root* is worth
        reporting, but that is a hygiene finding, not a quantum-urgency one)."""
        end = self.not_after.astimezone(UTC).date()
        return max(0.0, (end - as_of).days / _DAYS_PER_YEAR)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256_fingerprint": self.sha256_fingerprint,
            "spki_sha256": self.spki_sha256,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "is_ca": self.is_ca,
            "self_signed": self.self_signed,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> CertificateFacts:
        def when(value: str) -> datetime:
            parsed = datetime.fromisoformat(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

        return CertificateFacts(
            sha256_fingerprint=data["sha256_fingerprint"],
            spki_sha256=data["spki_sha256"],
            subject=data["subject"],
            issuer=data["issuer"],
            not_before=when(data["not_before"]),
            not_after=when(data["not_after"]),
            is_ca=bool(data["is_ca"]),
            self_signed=bool(data["self_signed"]),
        )
