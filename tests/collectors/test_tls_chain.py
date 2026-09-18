"""T-036 — `tls/chain.py`. Pure logic over `DiscoveredCertificate`
values, so these are ordinary unit tests: no binary, no filesystem, no
network. The interesting cases are the ones a real host actually
produces — a chain whose root was never found, a pile of unrelated
self-signed certs, and the same intermediate shared by two leaves."""

from __future__ import annotations

from qavach_collectors.tls import DiscoveredCertificate, reconstruct_chains


def _cert(subject: str, issuer: str, *, path: str = "/etc/ssl/cert.pem") -> DiscoveredCertificate:
    return DiscoveredCertificate(
        path=path,
        subject=subject,
        issuer=issuer,
        public_key_algorithm="RSA",
        public_key_bits=2048,
        public_key_curve=None,
        signature_algorithm="SHA256-RSA",
        sha256_fingerprint=f"fp-{subject}",
        spki_sha256=f"spki-{subject}",
        self_signed=subject == issuer,
    )


def test_single_self_signed_certificate_is_a_complete_one_link_chain() -> None:
    root = _cert("CN=Root", "CN=Root")
    chains = reconstruct_chains([root])
    assert len(chains) == 1
    assert chains[0].certificates == (root,)
    assert chains[0].is_complete


def test_full_three_link_chain_is_reconstructed_leaf_first() -> None:
    root = _cert("CN=Root", "CN=Root")
    intermediate = _cert("CN=Intermediate", "CN=Root")
    leaf = _cert("CN=leaf.example", "CN=Intermediate")

    chains = reconstruct_chains([intermediate, root, leaf])  # deliberately unordered input
    assert len(chains) == 1
    assert [c.subject for c in chains[0].certificates] == [
        "CN=leaf.example",
        "CN=Intermediate",
        "CN=Root",
    ]
    assert chains[0].is_complete


def test_chain_with_a_missing_root_is_reported_incomplete() -> None:
    """The intermediate's issuer wasn't found on this host — real signal
    that the chain terminates outside what was scanned (an OS trust
    store, most often), not an error to paper over."""
    intermediate = _cert("CN=Intermediate", "CN=Root Not On This Host")
    leaf = _cert("CN=leaf.example", "CN=Intermediate")

    chains = reconstruct_chains([leaf, intermediate])
    assert len(chains) == 1
    assert [c.subject for c in chains[0].certificates] == ["CN=leaf.example", "CN=Intermediate"]
    assert not chains[0].is_complete


def test_two_leaves_sharing_one_intermediate_produce_two_chains() -> None:
    root = _cert("CN=Root", "CN=Root")
    intermediate = _cert("CN=Intermediate", "CN=Root")
    leaf_a = _cert("CN=a.example", "CN=Intermediate")
    leaf_b = _cert("CN=b.example", "CN=Intermediate")

    chains = reconstruct_chains([root, intermediate, leaf_a, leaf_b])
    assert len(chains) == 2
    leaf_subjects = {chain.certificates[0].subject for chain in chains}
    assert leaf_subjects == {"CN=a.example", "CN=b.example"}
    assert all(chain.is_complete for chain in chains)
    assert all(len(chain.certificates) == 3 for chain in chains)


def test_intermediates_are_not_also_reported_as_their_own_chains() -> None:
    """An intermediate appears inside its leaf's chain, never as a
    separate top-level entry — otherwise the same certificate would be
    counted twice in any aggregate built from this output."""
    root = _cert("CN=Root", "CN=Root")
    intermediate = _cert("CN=Intermediate", "CN=Root")
    leaf = _cert("CN=leaf.example", "CN=Intermediate")

    chains = reconstruct_chains([root, intermediate, leaf])
    assert len(chains) == 1


def test_unrelated_self_signed_certificates_are_separate_chains() -> None:
    a = _cert("CN=self-a", "CN=self-a")
    b = _cert("CN=self-b", "CN=self-b")
    chains = reconstruct_chains([a, b])
    assert len(chains) == 2
    assert all(len(chain.certificates) == 1 for chain in chains)


def test_cyclic_issuer_references_terminate() -> None:
    """Two non-self-signed certs naming each other as issuer — malformed
    or adversarial input that must not loop forever."""
    a = _cert("CN=a", "CN=b")
    b = _cert("CN=b", "CN=a")
    chains = reconstruct_chains([a, b])
    for chain in chains:
        assert len(chain.certificates) <= 16


def test_empty_input_produces_no_chains() -> None:
    assert reconstruct_chains([]) == []
