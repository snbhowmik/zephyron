"""Java / JCA compound algorithm names -> the algorithms they are made of.

Source: "Java Security Standard Algorithm Names" (Oracle, Java SE 21),
https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html
- fetched 2026-09-20. That specification does not enumerate every name; it *defines
how names are composed*, so this is a small grammar, not a table (a table of every
combination would be both huge and always incomplete):

* `<digest>with<signature>` [`and<mgf>`]  ->  SHA256withRSA, SHA1withDSA, SHA384withECDSA
* `PBEWith<prf>And<cipher>`               ->  PBEWithMD5AndDES, PBEWithHmacSHA256AndAES_128
* `PBKDF2With<prf>`                       ->  PBKDF2WithHmacSHA256
* `Hmac<digest>`                          ->  HmacSHA256, HmacSHA512/256
* `<cipher>/<mode>/<padding>`  ->  AES/CBC/PKCS5Padding, RSA/ECB/OAEPWithSHA-256AndMGF1Padding

Why decompose: one Java name carries several independent security facts. `PBEWithMD5AndDES`
is a broken hash *and* a broken cipher, and they must be findings of their own (I1),
not one opaque, unresolved string. Every component is a spelling the alias table /
registry already resolves, so nothing here invents a family. A name this grammar
does not recognise returns `None` and stays UNKNOWN (I8) - never a guess.

Pure, stdlib only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_DIGESTS = {
    "md2": "MD2",
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha224": "SHA-224",
    "sha-224": "SHA-224",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha-384": "SHA-384",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
    "sha512/224": "SHA-512/224",
    "sha-512/224": "SHA-512/224",
    "sha512/256": "SHA-512/256",
    "sha-512/256": "SHA-512/256",
    "sha3-224": "SHA3-224",
    "sha3-256": "SHA3-256",
    "sha3-384": "SHA3-384",
    "sha3-512": "SHA3-512",
}
# name -> (spelling the resolver knows, parameter_set)
# output size in bits: the parameter a MAC/KDF is classified by (ARCH.md 7.1: "HMAC over
# those" - the quantum posture of HMAC(D) follows D's output size, not D's collision resistance)
_BITS = {
    "MD2": "128", "MD5": "128", "SHA-1": "160", "SHA-224": "224", "SHA-256": "256",
    "SHA-384": "384", "SHA-512": "512", "SHA-512/224": "224", "SHA-512/256": "256",
    "SHA3-224": "224", "SHA3-256": "256", "SHA3-384": "384", "SHA3-512": "512",
}  # fmt: skip
_SIGNATURES = {"rsa": ("RSA", None), "dsa": ("DSA", None), "ecdsa": ("ECDSA", None)}
_CIPHERS = {
    "des": ("DES", None),
    "desede": ("3DES", None),
    "tripledes": ("3DES", None),
    "rc2": ("RC2", None),
    "rc4": ("RC4", None),
    "arcfour": ("RC4", None),
    "aes": ("AES", None),
    "blowfish": ("Blowfish", None),
    "rsa": ("RSA", None),
}
_SIZED = re.compile(r"^(rc2|rc4|aes)_(\d{2,3})$")
_OAEP = re.compile(r"^oaepwith(.+?)andmgf1padding$")


@dataclass(frozen=True, slots=True)
class JcaComponent:
    name: str
    """A spelling the alias table / registry resolves."""
    primitive: str | None = None
    parameter_set: str | None = None
    mode: str | None = None
    padding: str | None = None


def _digest(token: str) -> str | None:
    return _DIGESTS.get(token.lower())


def _cipher(token: str) -> tuple[str, str | None] | None:
    t = token.lower()
    sized = _SIZED.match(t)
    if sized:
        base, bits = sized.groups()
        return _CIPHERS[base][0], bits
    return _CIPHERS.get(t)


def _prf(token: str) -> str | None:
    """A PBE pseudo-random function: a bare digest (PBES1) or `Hmac<digest>` (PBES2)."""
    t = token.lower()
    return _digest(token) or (_digest(t[4:]) if t.startswith("hmac") else None)


def decompose_jca(name: str) -> tuple[JcaComponent, ...] | None:
    """The components of a JCA compound name, or `None` if `name` is not one."""
    n = name.strip()
    low = n.lower()

    # <digest>with<signature>[and<mgf>]
    m = re.fullmatch(r"(.+?)with(rsa|dsa|ecdsa)(?:and(mgf1)|/pss)?", low)
    if m:
        d = "NONE" if m.group(1) == "none" else _digest(m.group(1))
        if d is not None:
            sig = (
                "RSASSA-PSS" if (m.group(3) or low.endswith("/pss")) else _SIGNATURES[m.group(2)][0]
            )
            out = [JcaComponent(sig, "signature")]
            if d != "NONE":
                out.append(JcaComponent(d, "hash"))
            return tuple(out)

    # PBEWith<prf>And<cipher>
    m = re.fullmatch(r"pbewith(.+?)and(.+)", n, re.IGNORECASE)
    if m:
        prf, cipher = _prf(m.group(1)), _cipher(m.group(2))
        if prf is not None and cipher is not None:
            kind = "block-cipher" if cipher[0] != "RC4" else "stream-cipher"
            if _digest(m.group(1)):  # PBES1 (PKCS#5 v1.5): a bare digest; both halves are weak
                return (
                    JcaComponent("PBES1", "kdf"),
                    JcaComponent(prf, "hash"),
                    JcaComponent(cipher[0], kind, cipher[1]),
                )
            return (  # PBES2: `Hmac<digest>` is the PRF, classified by its output size
                JcaComponent("PBES2", "kdf", _BITS[prf]),
                JcaComponent(cipher[0], kind, cipher[1]),
            )

    # PBKDF2With<prf>
    m = re.fullmatch(r"pbkdf2with(.+)", n, re.IGNORECASE)
    if m and _prf(m.group(1)):
        return (JcaComponent("PBKDF2", "kdf", _BITS[_prf(m.group(1)) or ""]),)

    # Hmac<digest>
    m = re.fullmatch(r"hmac(.+)", n, re.IGNORECASE)
    if m and _digest(m.group(1)):
        return (JcaComponent("HMAC", "mac", _BITS[_digest(m.group(1)) or ""]),)

    # <cipher>/<mode>/<padding>
    parts = n.split("/")
    if len(parts) == 3:
        cipher = _cipher(parts[0])
        if cipher is not None:
            mode, pad = parts[1].upper(), parts[2]
            oaep = _OAEP.match(pad.lower())
            if cipher[0] == "RSA":
                if oaep:
                    d = _digest(oaep.group(1))
                    comps = [JcaComponent("RSAES-OAEP", "pke", mode=mode)]
                    return tuple(comps + ([JcaComponent(d, "hash")] if d else []))
                return (JcaComponent("RSAES-PKCS1", "pke", mode=mode, padding=pad),)
            return (JcaComponent(cipher[0], "block-cipher", cipher[1], mode=mode, padding=pad),)
    return None
