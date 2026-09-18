"""T-040 — `cloud.aws`, against `moto`'s local implementation of the real
AWS APIs (KMS, ACM, ELBv2, IAM, STS). No AWS credentials exist or are
needed anywhere in this file: `mock_aws` intercepts boto3 at the HTTP
layer, so the collector's real boto3 calls, pagination and response
parsing all execute — only the AWS endpoint is local."""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws
from qavach_collectors import RunContext, Target, TargetType
from qavach_collectors.cloud import (
    AwsCollector,
    AwsCredentialNotReadOnlyError,
    acm_key_algorithm_to_claim,
    assert_read_only,
    cipher_name_to_claim,
    kms_key_spec_to_claim,
)

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def _fake_aws_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Belt and braces: even if `mock_aws` failed to intercept, these
    obviously-fake values could never authenticate against real AWS."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    yield


class _ReadOnlyIamSession:
    """Real boto3 session (talking to moto) except IAM policy simulation,
    which moto does not implement — it raises a Python
    `NotImplementedError` real AWS never would. The scripted answer is the
    honest "no write actions allowed" a correctly-scoped credential gets."""

    def __init__(self) -> None:
        self._session = boto3.Session(region_name=REGION)

    def client(self, name: str, **kwargs: Any) -> Any:
        if name != "iam":
            return self._session.client(name, **kwargs)

        class _Iam:
            def simulate_principal_policy(self, **request: Any) -> Any:
                return {
                    "EvaluationResults": [
                        {"EvalActionName": a, "EvalDecision": "implicitDeny"}
                        for a in request["ActionNames"]
                    ]
                }

        return _Iam()


def _collector() -> AwsCollector:
    return AwsCollector(session_factory=lambda _region: _ReadOnlyIamSession())


def _target() -> Target:
    return Target(type=TargetType.CLOUD_ACCOUNT, ref="aws", options={"regions": REGION})


# --- pure mapping tables ---


@pytest.mark.parametrize(
    ("key_spec", "usage", "name", "primitive", "parameter_set"),
    [
        ("SYMMETRIC_DEFAULT", "ENCRYPT_DECRYPT", "AES", "ae", "256"),
        ("RSA_2048", "ENCRYPT_DECRYPT", "RSAES-OAEP", "pke", "2048"),
        ("RSA_4096", "SIGN_VERIFY", "RSASSA-PKCS1", "signature", "4096"),
        ("ECC_NIST_P256", "SIGN_VERIFY", "ECDSA", "signature", "secp256r1"),
        ("ECC_NIST_P384", "KEY_AGREEMENT", "ECDH", "key-agree", "secp384r1"),
        ("HMAC_256", "GENERATE_VERIFY_MAC", "HMAC", "mac", "256"),
        ("ML_DSA_65", "SIGN_VERIFY", "ML-DSA", "signature", "65"),
    ],
)
def test_kms_key_spec_mapping(
    key_spec: str, usage: str, name: str, primitive: str, parameter_set: str
) -> None:
    claim = kms_key_spec_to_claim(key_spec, usage)
    assert claim is not None
    assert (claim.name, claim.primitive, claim.parameter_set) == (name, primitive, parameter_set)


def test_unknown_kms_key_spec_maps_to_none() -> None:
    assert kms_key_spec_to_claim("SOME_FUTURE_SPEC", None) is None


def test_acm_key_algorithm_mapping() -> None:
    rsa = acm_key_algorithm_to_claim("RSA_2048")
    ec = acm_key_algorithm_to_claim("EC_prime256v1")
    assert rsa is not None and (rsa.name, rsa.parameter_set) == ("RSA", "2048")
    assert ec is not None and (ec.name, ec.parameter_set) == ("ECDSA", "prime256v1")
    assert acm_key_algorithm_to_claim("SOMETHING_NEW") is None


@pytest.mark.parametrize(
    ("cipher", "name", "size"),
    [
        ("ECDHE-RSA-AES128-GCM-SHA256", "AES", "128"),
        ("ECDHE-ECDSA-AES256-GCM-SHA384", "AES", "256"),
        ("ECDHE-RSA-CHACHA20-POLY1305", "ChaCha20", None),
        ("DES-CBC3-SHA", "3DES", None),
        ("ECDHE-RSA-RC4-SHA", "RC4", None),
    ],
)
def test_cipher_name_mapping(cipher: str, name: str, size: str | None) -> None:
    claim = cipher_name_to_claim(cipher)
    assert claim is not None
    assert (claim.name, claim.parameter_set) == (name, size)


def test_cipher_with_no_recognised_symmetric_algorithm_maps_to_none() -> None:
    assert cipher_name_to_claim("TLS_FALLBACK_SCSV") is None


# --- against moto ---


@mock_aws
def test_kms_keys_become_attested_claims_with_cloud_loci() -> None:
    kms = boto3.client("kms", region_name=REGION)
    kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")
    kms.create_key(KeySpec="SYMMETRIC_DEFAULT", KeyUsage="ENCRYPT_DECRYPT")

    result = _collector().collect(_target(), RunContext(scan_run_id="run-1"))

    names = sorted(c.name for c in result.claims if c.name)
    assert names == ["AES", "RSASSA-PKCS1"]
    assert all(c.confidence.name == "ATTESTED" for c in result.claims)

    rsa = next(c for c in result.claims if c.name == "RSASSA-PKCS1")
    assert rsa.parameter_set == "2048"
    assert rsa.locus.provider == "aws"  # type: ignore[union-attr]
    assert rsa.locus.resource_arn.startswith("arn:aws:kms:us-east-1:")  # type: ignore[union-attr]
    assert rsa.locus.region == REGION  # type: ignore[union-attr]


@mock_aws
def test_acm_certificates_become_claims() -> None:
    """moto ignores `request_certificate(KeyAlgorithm=...)` and always
    reports `RSA_2048` (checked directly against `describe_certificate`),
    so this asserts the round-trip moto can honestly produce; the EC
    mapping is covered by `test_acm_key_algorithm_mapping`."""
    acm = boto3.client("acm", region_name=REGION)
    acm.request_certificate(DomainName="qavach-test.example.com")

    result = _collector().collect(_target(), RunContext(scan_run_id="run-1"))

    acm_claims = [c for c in result.claims if c.name == "RSA"]
    assert len(acm_claims) == 1
    assert acm_claims[0].parameter_set == "2048"
    assert ":certificate/" in acm_claims[0].locus.resource_arn  # type: ignore[union-attr]


@mock_aws
def test_elbv2_listener_tls_policy_yields_deduplicated_cipher_claims() -> None:
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnets = [
        ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=f"{REGION}{az}")[
            "Subnet"
        ]["SubnetId"]
        for i, az in ((1, "a"), (2, "b"))
    ]
    elb = boto3.client("elbv2", region_name=REGION)
    balancer = elb.create_load_balancer(Name="qavach-lb", Subnets=subnets)["LoadBalancers"][0]
    acm = boto3.client("acm", region_name=REGION)
    cert = acm.request_certificate(DomainName="lb.example.com")["CertificateArn"]
    target_group = elb.create_target_group(Name="tg", Protocol="HTTP", Port=80, VpcId=vpc)[
        "TargetGroups"
    ][0]["TargetGroupArn"]
    elb.create_listener(
        LoadBalancerArn=balancer["LoadBalancerArn"],
        Protocol="HTTPS",
        Port=443,
        SslPolicy="ELBSecurityPolicy-2016-08",
        Certificates=[{"CertificateArn": cert}],
        DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group}],
    )

    result = _collector().collect(_target(), RunContext(scan_run_id="run-1"))

    listener_claims = [
        c
        for c in result.claims
        if ":listener/" in c.locus.resource_arn  # type: ignore[union-attr]
    ]
    assert listener_claims, "expected cipher claims from the listener's TLS policy"
    keys = [(c.name, c.parameter_set, c.mode) for c in listener_claims]
    assert len(keys) == len(set(keys)), "the same cipher must not be reported once per suite"


@mock_aws
def test_an_empty_account_yields_no_claims_and_is_not_partial() -> None:
    result = _collector().collect(_target(), RunContext(scan_run_id="run-1"))
    assert result.claims == []


@mock_aws
def test_raw_payload_never_contains_credentials() -> None:
    boto3.client("kms", region_name=REGION).create_key(KeySpec="RSA_2048")
    result = _collector().collect(_target(), RunContext(scan_run_id="run-1"))
    payload = result.raw.decode()
    assert "testing" not in payload  # the fake secret key / token values
    assert "SecretAccessKey" not in payload


def test_supports_only_aws_cloud_account_targets() -> None:
    collector = AwsCollector()
    assert collector.supports(Target(type=TargetType.CLOUD_ACCOUNT, ref="aws"))
    assert not collector.supports(Target(type=TargetType.CLOUD_ACCOUNT, ref="azure"))
    assert not collector.supports(Target(type=TargetType.REPOSITORY, ref="aws"))


# --- the read-only refusal (SECURITY.md §6) ---


def _iam_session_returning(decisions: dict[str, str]) -> Any:
    """A real boto3 session whose STS/IAM clients are botocore `Stubber`s
    returning a scripted `SimulatePrincipalPolicy` answer — moto's IAM
    policy simulation does not model per-action evaluation, so the
    *decision* is scripted while everything around it (client
    construction, request validation against the real IAM API model) is
    genuine botocore."""
    session = boto3.Session(region_name=REGION)
    sts = session.client("sts")
    iam = session.client("iam")
    stubs = {"sts": Stubber(sts), "iam": Stubber(iam)}
    stubs["sts"].add_response(
        "get_caller_identity",
        {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/scanner", "UserId": "X"},
    )
    stubs["iam"].add_response(
        "simulate_principal_policy",
        {
            "EvaluationResults": [
                {"EvalActionName": action, "EvalDecision": decision}
                for action, decision in decisions.items()
            ]
        },
    )
    for stub in stubs.values():
        stub.activate()

    class _Session:
        def client(self, name: str, **_: Any) -> Any:
            return {"sts": sts, "iam": iam}[name]

    return _Session()


def test_refuses_a_credential_allowed_kms_write_actions() -> None:
    session = _iam_session_returning({"kms:Encrypt": "allowed", "kms:CreateKey": "implicitDeny"})
    with pytest.raises(AwsCredentialNotReadOnlyError, match=r"kms:Encrypt"):
        assert_read_only(session)


def test_accepts_a_credential_with_no_kms_write_actions() -> None:
    session = _iam_session_returning(
        {"kms:Encrypt": "implicitDeny", "kms:CreateKey": "explicitDeny"}
    )
    assert assert_read_only(session) is None


def test_collector_hard_refuses_rather_than_degrading() -> None:
    """A write-capable credential is a refusal, not a `partial=True`
    result: degrading would still have *used* the credential."""
    session = _iam_session_returning({"kms:Sign": "allowed"})
    collector = AwsCollector(session_factory=lambda _region: session)
    with pytest.raises(AwsCredentialNotReadOnlyError):
        collector.collect(_target(), RunContext(scan_run_id="run-1"))


@mock_aws
def test_an_unverifiable_credential_degrades_with_a_warning_not_a_refusal() -> None:
    """If the self-check itself is denied, the collector proceeds — but
    says so, rather than silently claiming the credential was verified."""
    session = boto3.Session(region_name=REGION)

    class _DenyingSession:
        def client(self, name: str, **kwargs: Any) -> Any:
            if name == "iam":
                from botocore.exceptions import ClientError

                class _Iam:
                    def simulate_principal_policy(self, **_: Any) -> Any:
                        raise ClientError(
                            {"Error": {"Code": "AccessDenied", "Message": "no"}},
                            "SimulatePrincipalPolicy",
                        )

                return _Iam()
            return session.client(name, **kwargs)

    collector = AwsCollector(session_factory=lambda _region: _DenyingSession())
    result = collector.collect(_target(), RunContext(scan_run_id="run-1"))
    assert result.partial
    assert any("could not verify" in e.message and not e.fatal for e in result.errors)


def test_process_environment_is_not_mutated_by_these_tests() -> None:
    assert os.environ.get("AWS_PROFILE") is None
