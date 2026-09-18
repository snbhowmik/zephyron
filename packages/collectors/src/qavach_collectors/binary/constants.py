"""Well-known algorithm constant tables, searched for in a binary's bytes.
T-036b.

Every table is **computed from its defining mathematics**, not typed in, so a
transcription error is impossible and the source of each is checkable:

* AES S-box — FIPS 197 §5.1.1 (multiplicative inverse in GF(2^8) then the
  affine transform).
* SHA-256 `K` — FIPS 180-4 §4.2.2: first 32 fractional bits of the cube roots
  of the first 64 primes. SHA-512 `K` (§4.2.3): first 64 bits, first 80 primes.
* MD5 `T[i]` — RFC 1321 §3.4: `floor(2^32 * abs(sin(i + 1)))`.

**A hit means these bytes are present, nothing more.** Tables can be linked in
from a library that never runs, or be data in an unrelated file. Reported at
`PATTERN` confidence, and only long, distinctive prefixes are searched (a
short constant matches noise). SHA-256's table is shared by SHA-224, and
SHA-512's by SHA-384 — the parameter reported is the table's width class.
"""

from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass
from functools import cache
from pathlib import Path

_SCAN_MAX_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ConstantHit:
    name: str
    parameter_set: str | None
    primitive: str
    offset: int


def _primes(count: int) -> list[int]:
    found: list[int] = []
    candidate = 2
    while len(found) < count:
        if all(candidate % p for p in found if p * p <= candidate):
            found.append(candidate)
        candidate += 1
    return found


def _icbrt(n: int) -> int:
    low, high = 0, 1 << ((n.bit_length() // 3) + 2)
    while low < high:
        mid = (low + high + 1) // 2
        if mid**3 <= n:
            low = mid
        else:
            high = mid - 1
    return low


def _rotl8(x: int, s: int) -> int:
    return ((x << s) | (x >> (8 - s))) & 0xFF


@cache
def aes_sbox() -> bytes:
    sbox = bytearray(256)
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return bytes(sbox)


@cache
def sha256_k() -> tuple[int, ...]:
    return tuple(_icbrt(p << 96) & 0xFFFFFFFF for p in _primes(64))


@cache
def sha512_k() -> tuple[int, ...]:
    return tuple(_icbrt(p << 192) & 0xFFFFFFFFFFFFFFFF for p in _primes(80))


@cache
def md5_t() -> tuple[int, ...]:
    import math

    return tuple(int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64))


def _words(values: tuple[int, ...], count: int, width: int) -> tuple[bytes, bytes]:
    fmt = "I" if width == 32 else "Q"
    head = values[:count]
    return (
        struct.pack("<" + fmt * count, *head),
        struct.pack(">" + fmt * count, *head),
    )


@cache
def _patterns() -> tuple[tuple[str, str | None, str, bytes], ...]:
    """(name, parameter_set, primitive, needle). Eight 32-bit words / four
    64-bit words is 32 bytes — distinctive, far longer than chance."""
    out: list[tuple[str, str | None, str, bytes]] = [("AES", None, "block-cipher", aes_sbox())]
    for needle in _words(sha256_k(), 8, 32):
        out.append(("SHA-2", "256", "hash", needle))
    for needle in _words(sha512_k(), 4, 64):
        out.append(("SHA-2", "512", "hash", needle))
    for needle in _words(md5_t(), 8, 32):
        out.append(("MD5", None, "hash", needle))
    return tuple(out)


def find_constants(path: Path) -> tuple[list[ConstantHit], str | None]:
    """First match per (algorithm, parameter). Returns hits and a note when
    the file was too large to scan."""
    try:
        size = path.stat().st_size
        if size == 0:
            return [], None
        if size > _SCAN_MAX_BYTES:
            return [], f"larger than {_SCAN_MAX_BYTES} bytes, constants not scanned"
        with (
            path.open("rb") as handle,
            mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data,
        ):
            hits: list[ConstantHit] = []
            seen: set[tuple[str, str | None]] = set()
            for name, parameter_set, primitive, needle in _patterns():
                if (name, parameter_set) in seen:
                    continue
                offset = data.find(needle)
                if offset != -1:
                    seen.add((name, parameter_set))
                    hits.append(ConstantHit(name, parameter_set, primitive, offset))
            return hits, None
    except (OSError, ValueError):
        return [], "could not be read for constants"
