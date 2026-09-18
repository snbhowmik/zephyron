"""ARCH.md §2.2: 'QAVACH owns... chain reconstruction on top' of
certfinder. T-036.

certfinder (and `pkcs7.py`) report individual certificates per file or
keystore entry — never a pre-assembled trust chain, since a chain's
members are frequently scattered across several files on a real host
(a leaf cert here, an intermediate bundled elsewhere, a root in the OS
trust store). This module links them by subject/issuer DN matching,
purely from what was actually discovered on this host — an issuer DN
that matches nothing found here means the chain is genuinely incomplete
from this scan, which is real, useful signal, not a bug to paper over
with a placeholder.
"""

from __future__ import annotations

from dataclasses import dataclass

from qavach_collectors.tls.store import DiscoveredCertificate

_MAX_CHAIN_LENGTH = 16
"""A defensive bound against a cyclic issuer graph (two certs whose
issuer DNs happen to reference each other, neither self-signed) —
real chains are never this long; this only prevents an infinite loop on
malformed/adversarial input."""


@dataclass(frozen=True, slots=True)
class CertificateChain:
    certificates: tuple[DiscoveredCertificate, ...]
    """Ordered leaf-first. The last entry is either self-signed (a
    complete chain to a root found on this host) or has an issuer DN
    that matched nothing else discovered (an incomplete chain — its
    issuer exists somewhere QAVACH didn't look, e.g. the OS trust
    store)."""

    @property
    def is_complete(self) -> bool:
        return self.certificates[-1].self_signed


def reconstruct_chains(certificates: list[DiscoveredCertificate]) -> list[CertificateChain]:
    """One chain per leaf certificate — a certificate that is nobody
    else's issuer among the discovered set. A cert that *is* someone
    else's issuer only appears as a link inside that leaf's chain, never
    as its own separate top-level chain, so the same intermediate/root
    isn't double-reported as a standalone entry."""
    by_subject: dict[str, DiscoveredCertificate] = {}
    for cert in certificates:
        by_subject.setdefault(cert.subject, cert)

    # "Issuer of somebody else" — a self-signed certificate naming itself
    # must not count here, or a root with real children would look like a
    # leaf and be emitted both as its own chain and inside its leaf's.
    issuers_of_others = {cert.issuer for cert in certificates if cert.issuer != cert.subject}
    leaves = [cert for cert in certificates if cert.subject not in issuers_of_others]

    chains = []
    for leaf in leaves:
        chains.append(CertificateChain(certificates=tuple(_walk_chain(leaf, by_subject))))
    return chains


def _walk_chain(
    leaf: DiscoveredCertificate, by_subject: dict[str, DiscoveredCertificate]
) -> list[DiscoveredCertificate]:
    chain = [leaf]
    current = leaf
    seen_subjects = {leaf.subject}
    while not current.self_signed and len(chain) < _MAX_CHAIN_LENGTH:
        issuer = by_subject.get(current.issuer)
        if issuer is None or issuer.subject in seen_subjects:
            break
        chain.append(issuer)
        seen_subjects.add(issuer.subject)
        current = issuer
    return chain
