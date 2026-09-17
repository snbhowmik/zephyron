"""ARCH.md §4.2, A-13 — the data-quality queue. T-016b.

"A modulus length outside the plausible set for its family goes to the
data-quality queue, not to a chart. Implausible values are a collector bug
and must be visible as one." Regression fixtures are drawn directly from
IDEATION.md §2.2b's documented competitor failure modes: 0-bit keys,
2450-bit/281-bit "RSA" (no such key size exists), and filenames captured
as algorithm names.
"""

from __future__ import annotations

from dataclasses import dataclass

# Every historically-real bit-length for these families, from genuinely
# ancient/weak (512) through current (15360) — deliberately wide, so this
# flags nonsense like "2450" or "281" (IDEATION.md §2.2b), not merely weak
# keys (that's classify.py's job, not this one's).
PLAUSIBLE_MODULUS_BITS: dict[str, frozenset[int]] = {
    "RSASSA-PKCS1": frozenset({512, 768, 1024, 1536, 2048, 3072, 4096, 7680, 8192, 15360}),
    "RSASSA-PSS": frozenset({512, 768, 1024, 1536, 2048, 3072, 4096, 7680, 8192, 15360}),
    "RSAES-PKCS1": frozenset({512, 768, 1024, 1536, 2048, 3072, 4096, 7680, 8192, 15360}),
    "RSAES-OAEP": frozenset({512, 768, 1024, 1536, 2048, 3072, 4096, 7680, 8192, 15360}),
    "RSA-X931": frozenset({512, 768, 1024, 1536, 2048, 3072, 4096, 7680, 8192, 15360}),
    "DSA": frozenset({512, 768, 1024, 2048, 3072}),
    "FFDH": frozenset({512, 768, 1024, 1536, 2048, 3072, 4096}),
    "AES": frozenset({128, 192, 256}),
}

_FILENAME_EXTENSIONS = (
    ".exe",
    ".dll",
    ".so",
    ".jar",
    ".dylib",
    ".zip",
    ".tar",
    ".gz",
    ".apk",
    ".deb",
    ".rpm",
    ".msi",
)


@dataclass(frozen=True, slots=True)
class DataQualityIssue:
    kind: str  # "zero_bit_key" | "implausible_modulus" | "filename_shaped_name"
    detail: str


def check_modulus_plausibility(family: str, parameter_set: str | None) -> DataQualityIssue | None:
    """None means "nothing to flag" — either the family isn't one this
    table has an opinion on (e.g. ML-DSA's parameter sets are names like
    "44", not bit-lengths — checking those against a bit-length table
    would itself be a bug), or the modulus is plausible."""
    plausible = PLAUSIBLE_MODULUS_BITS.get(family)
    if plausible is None or parameter_set is None:
        return None

    try:
        size = int(parameter_set)
    except ValueError:
        return None  # not a bit-length claim at all — not this function's concern

    if size == 0:
        return DataQualityIssue(
            kind="zero_bit_key",
            detail=(
                f"{family} reported a 0-bit key — IDEATION.md §2.2b: almost certainly "
                "a non-RSA-shaped key (e.g. Ed25519 or a PQC key) forced into a bit-length field"
            ),
        )
    if size not in plausible:
        return DataQualityIssue(
            kind="implausible_modulus",
            detail=(
                f"{family} reported {size}-bit, not one of the plausible sizes {sorted(plausible)}"
            ),
        )
    return None


def check_filename_shaped_name(name: str | None) -> DataQualityIssue | None:
    """IDEATION.md §2.2c: 'SHA reference in sublime_text...' captured as an
    algorithm name. Deterministic string checks, not a regex (SECURITY.md
    §9's preference)."""
    if name is None:
        return None
    lowered = name.lower()
    looks_like_a_path = "/" in name or "\\" in name
    looks_like_a_filename = lowered.endswith(_FILENAME_EXTENSIONS)
    if looks_like_a_path or looks_like_a_filename:
        return DataQualityIssue(
            kind="filename_shaped_name",
            detail=f"{name!r} looks like a file path or filename, not an algorithm name",
        )
    return None
