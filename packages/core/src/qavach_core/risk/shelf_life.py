"""ARCH.md §7.2 - `X`, how long the protected thing must stay secure. T-061.

**This is the invariant-I2 module.** One `X` for everything is the mistake
almost every implementation makes. `X` is two quantities:

* `x_conf` - how long data must stay *confidential*. Harvest-now-decrypt-later
  applies, and late migration is unrecoverable (ciphertext already captured
  cannot be un-captured). Taken from the system's retention.
* `x_integ` - how long a signature/MAC must stay *unforgeable* ("trust now,
  forge later"). HNDL does not apply, late migration is recoverable
  (re-sign or re-timestamp before the deadline). Taken from the artefact's
  trust lifetime, not from retention - except that an archival artefact
  (RFC 3161 timestamp, audit log) passes its retention as the lifetime.

An ephemeral TLS server certificate is `x_integ = 0`; an offline root CA is
10-25 years. Same algorithm, same key size, opposite urgency - that divergence
is the demonstration that the risk model does real work, and the property test
in `tests/core/test_shelf_life.py` pins it.

Aggregation direction (`ARCH.md §7.2`'s asymmetry, which "will be implemented
backwards at least once"): shelf life aggregates with `max()` **upward** along a
derivation chain - a root secret inherits the maximum of everything beneath it,
a child inherits nothing from its parent. Deadlines aggregate the other way.

An unresolved input never becomes a comfortable zero (I8): a derived key with no
known consumers, or an asset whose function is unknown, returns
`complete=False`, and unknown function is scored at its worst plausible reading.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from qavach_core.model.enums import CryptoFunction
from qavach_core.model.system import System
from qavach_core.policy import PolicySnapshot
from qavach_core.risk.explain import Explanation, refs

CONFIDENTIALITY_FUNCTIONS = frozenset(
    {
        CryptoFunction.KEY_ENCAPSULATION,
        CryptoFunction.KEY_AGREEMENT,
        CryptoFunction.ENCRYPTION,
    }
)
AUTHENTICITY_FUNCTIONS = frozenset(
    {CryptoFunction.SIGNATURE, CryptoFunction.MAC, CryptoFunction.HASH}
)
DERIVED_FUNCTIONS = frozenset({CryptoFunction.KDF, CryptoFunction.DRBG})

_EPHEMERAL_PATH = "scoring.mosca.ephemeral_artefact_max_years"


@dataclass(frozen=True, slots=True)
class ShelfLife:
    x_conf: float
    x_integ: float
    basis: str
    complete: bool
    """False when the value could not be established (unknown function, or a
    derived key with no known consumer). Never read `x == 0` as "safe" without
    checking this."""
    explanation: Explanation

    @property
    def x(self) -> float:
        """What Mosca consumes: max(x_conf, x_integ). The two keep separate
        rationale and separate mitigations (`ARCH.md §7.2`)."""
        return max(self.x_conf, self.x_integ)


def shelf_life_years(
    function: CryptoFunction | None,
    *,
    system: System,
    policy: PolicySnapshot,
    artefact_lifetime_years: float | None = None,
    consumers: Sequence[ShelfLife] = (),
) -> ShelfLife:
    """`artefact_lifetime_years` is how long the signed/MACed artefact must
    remain trusted (certificate `notAfter`, firmware support window); `None`
    means unknown-or-ephemeral and is treated as ephemeral. For an archival
    artefact pass the retention period, not `None`."""
    threshold_node = policy.node(_EPHEMERAL_PATH)
    threshold = float(threshold_node.value)
    inputs: dict[str, object] = {
        "function": function.value if function else None,
        "retention_years": system.retention_years,
        "retention_inferred": system.retention_inferred,
        "artefact_lifetime_years": artefact_lifetime_years,
        "consumers": len(consumers),
    }

    def build(
        x_conf: float,
        x_integ: float,
        basis: str,
        complete: bool,
        formula: str,
        steps: tuple[str, ...],
    ) -> ShelfLife:
        return ShelfLife(
            x_conf=x_conf,
            x_integ=x_integ,
            basis=basis,
            complete=complete,
            explanation=Explanation(
                name="shelf_life",
                formula=formula,
                inputs=inputs,
                policy=refs([threshold_node]),
                steps=steps,
            ),
        )

    if function is None:
        integ = artefact_lifetime_years or 0.0
        return build(
            system.retention_years,
            integ,
            "unknown-function:worst-case",
            False,
            "x_conf = retention_years; x_integ = artefact lifetime "
            "(function unknown: both channels assumed)",
            ("the function is unknown, so it is scored at its worst plausible reading (I8)",),
        )

    if function in CONFIDENTIALITY_FUNCTIONS:
        return build(
            system.retention_years,
            0.0,
            "hndl:data-retention",
            True,
            "x_conf = retention_years; x_integ = 0",
            ("confidentiality function: HNDL applies, so X is the data retention",),
        )

    if function in AUTHENTICITY_FUNCTIONS:
        if artefact_lifetime_years is None or artefact_lifetime_years <= threshold:
            return build(
                0.0,
                0.0,
                "authenticity:ephemeral",
                True,
                "x_conf = 0; x_integ = 0 when artefact lifetime <= ephemeral threshold",
                (
                    "authenticity function on an ephemeral artefact: a forged signature is useless "
                    "once the artefact has expired, and HNDL does not apply to signatures",
                ),
            )
        return build(
            0.0,
            artefact_lifetime_years,
            "tnfl:long-lived-artefact",
            True,
            "x_conf = 0; x_integ = artefact lifetime when it exceeds the ephemeral threshold",
            ("long-lived artefact: trust-now-forge-later, X is how long it must stay unforgeable",),
        )

    return derive_from_consumers(
        consumers, policy=policy, inputs=inputs, threshold_node=threshold_node
    )


def derive_from_consumers(
    consumers: Sequence[ShelfLife],
    *,
    policy: PolicySnapshot,
    inputs: dict[str, object] | None = None,
    threshold_node: object | None = None,
) -> ShelfLife:
    """KDF/DRBG/master secrets: `max()` over consumers, per channel, upward only."""
    node = policy.node(_EPHEMERAL_PATH)
    base_inputs = inputs if inputs is not None else {"consumers": len(consumers)}
    if not consumers:
        return ShelfLife(
            0.0,
            0.0,
            "derived:no-known-consumers",
            False,
            Explanation(
                name="shelf_life",
                formula="x_conf = x_integ = max over consumers (none known)",
                inputs=base_inputs,
                policy=refs([node]),
                steps=("no known consumer: this is NOT safe, it is a coverage gap (I8)",),
            ),
        )
    return ShelfLife(
        max(c.x_conf for c in consumers),
        max(c.x_integ for c in consumers),
        "derived:max-over-consumers",
        all(c.complete for c in consumers),
        Explanation(
            name="shelf_life",
            formula="x_conf = max(consumer.x_conf); x_integ = max(consumer.x_integ)",
            inputs=base_inputs,
            policy=refs([node]),
            steps=(
                "derived key material inherits the maximum of everything beneath it, upward only",
            ),
        ),
    )
