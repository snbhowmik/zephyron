"""ARCH.md §2.2 `cloud.aws` — read-only AWS crypto inventory. T-040.

KMS `ListKeys`/`DescribeKey` -> `KeySpec`, ACM `ListCertificates`/
`DescribeCertificate`, ELBv2 listener TLS policies. `ATTESTED` tier: the
cloud provider's own API is stating the key/certificate properties, not
QAVACH inferring them.

**Read-only by contract** (`SECURITY.md §6`): the exact minimum policy is
`docs/iam/aws-readonly.json`. Before scanning, `assert_read_only` asks IAM
to *simulate* KMS write actions against the credential it was handed and
refuses to run if any is allowed — a scanner holding write access to key
material is a misconfiguration worth failing loudly on, not tolerating.

Credentials come from the standard boto3 chain (environment variables in a
sandboxed run, `SECURITY.md §6`) — never a constructor argument, never
logged, never written into a `RawClaim` or the retained `raw` payload.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from qavach_core.model import CloudLocus, ConfidenceTier

from qavach_collectors.base import (
    CollectorError,
    CollectorResult,
    RawClaim,
    RawFormat,
    RunContext,
    Target,
    TargetType,
    ToolIdentity,
)

KMS_WRITE_ACTIONS = (
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:ReEncryptFrom",
    "kms:ReEncryptTo",
    "kms:Sign",
    "kms:GenerateDataKey",
    "kms:GenerateMac",
    "kms:CreateKey",
    "kms:CreateGrant",
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
    "kms:PutKeyPolicy",
    "kms:ImportKeyMaterial",
)


class AwsCredentialNotReadOnlyError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class KmsKeySpecClaim:
    name: str
    primitive: str
    parameter_set: str | None = None
    mode: str | None = None


def kms_key_spec_to_claim(key_spec: str, key_usage: str | None) -> KmsKeySpecClaim | None:
    """Maps a KMS `KeySpec` (+ `KeyUsage`) to the algorithm family it
    represents. Returns `None` for a spec this table does not know —
    the caller reports that as an unnamed claim so it becomes UNKNOWN
    downstream (invariant I8) instead of being dropped."""
    if key_spec == "SYMMETRIC_DEFAULT":
        # AWS documents SYMMETRIC_DEFAULT as AES-256-GCM.
        return KmsKeySpecClaim("AES", "ae", "256", "GCM")
    if key_spec.startswith("RSA_"):
        bits = key_spec.removeprefix("RSA_")
        if key_usage == "ENCRYPT_DECRYPT":
            return KmsKeySpecClaim("RSAES-OAEP", "pke", bits)
        return KmsKeySpecClaim("RSASSA-PKCS1", "signature", bits)
    ecc_curves = {
        "ECC_NIST_P256": "secp256r1",
        "ECC_NIST_P384": "secp384r1",
        "ECC_NIST_P521": "secp521r1",
        "ECC_SECG_P256K1": "secp256k1",
    }
    if key_spec in ecc_curves:
        if key_usage == "KEY_AGREEMENT":
            return KmsKeySpecClaim("ECDH", "key-agree", ecc_curves[key_spec])
        return KmsKeySpecClaim("ECDSA", "signature", ecc_curves[key_spec])
    if key_spec == "ECC_NIST_EDWARDS25519":
        return KmsKeySpecClaim("EdDSA", "signature", "Ed25519")
    if key_spec.startswith("HMAC_"):
        return KmsKeySpecClaim("HMAC", "mac", key_spec.removeprefix("HMAC_"))
    if key_spec == "SM2":
        return KmsKeySpecClaim("SM2", "signature")
    if key_spec.startswith("ML_DSA_"):
        return KmsKeySpecClaim("ML-DSA", "signature", key_spec.removeprefix("ML_DSA_"))
    return None


_ACM_EC_CURVES = {
    "EC_prime256v1": "prime256v1",
    "EC_secp384r1": "secp384r1",
    "EC_secp521r1": "secp521r1",
}


def acm_key_algorithm_to_claim(key_algorithm: str) -> KmsKeySpecClaim | None:
    if key_algorithm.startswith("RSA_"):
        return KmsKeySpecClaim("RSA", "signature", key_algorithm.removeprefix("RSA_"))
    if key_algorithm in _ACM_EC_CURVES:
        return KmsKeySpecClaim("ECDSA", "signature", _ACM_EC_CURVES[key_algorithm])
    return None


# ELBv2 policies name ciphers in OpenSSL form, e.g. `ECDHE-RSA-AES128-GCM-SHA256`.
# A fixed token table, compared with `==` on `split("-")` parts — no regex
# (SECURITY.md §9). Only the *symmetric* algorithm is extracted; that is the
# part that differentiates a modern policy from one that still offers 3DES/RC4.
_CIPHER_TOKENS: dict[str, tuple[str, str | None]] = {
    "AES128": ("AES", "128"),
    "AES256": ("AES", "256"),
    "CHACHA20": ("ChaCha20", None),
    "3DES": ("3DES", None),
    "CBC3": ("3DES", None),
    "RC4": ("RC4", None),
    "DES": ("DES", None),
}


def cipher_name_to_claim(cipher: str) -> KmsKeySpecClaim | None:
    parts = cipher.split("-")
    # 3DES first: OpenSSL names it `DES-CBC3-*`, so a plain left-to-right
    # scan would match the `DES` token and misclassify 3DES as single DES.
    if "CBC3" in parts or "3DES" in parts:
        return KmsKeySpecClaim("3DES", "block-cipher", None, "CBC")
    for part in parts:
        if part in _CIPHER_TOKENS:
            name, size = _CIPHER_TOKENS[part]
            mode = (
                "GCM"
                if "GCM" in parts
                else ("CBC" if "SHA" in parts or "SHA256" in parts else None)
            )
            return KmsKeySpecClaim(name, "ae" if mode == "GCM" else "block-cipher", size, mode)
    return None


def assert_read_only(session: Any) -> str | None:
    """Simulates KMS write actions against the caller's principal and
    raises `AwsCredentialNotReadOnlyError` if any is allowed. Returns a
    warning string when the check itself could not run (the policy lacks
    `iam:SimulatePrincipalPolicy`), `None` when it ran and passed."""
    try:
        identity = session.client("sts").get_caller_identity()
        principal = _simulation_principal(identity["Arn"], identity["Account"])
        response = session.client("iam").simulate_principal_policy(
            PolicySourceArn=principal, ActionNames=list(KMS_WRITE_ACTIONS)
        )
    except (ClientError, BotoCoreError) as exc:
        return (
            "could not verify the AWS credential is read-only "
            f"(self-check failed: {type(exc).__name__}); attach iam:SimulatePrincipalPolicy "
            "per docs/iam/aws-readonly.json to enable it"
        )

    allowed = [
        result["EvalActionName"]
        for result in response.get("EvaluationResults", [])
        if result.get("EvalDecision") == "allowed"
    ]
    if allowed:
        raise AwsCredentialNotReadOnlyError(
            f"refusing to scan: this credential is allowed KMS write actions {allowed}. "
            "cloud.aws is read-only by contract — use the policy in docs/iam/aws-readonly.json"
        )
    return None


def _simulation_principal(arn: str, account: str) -> str:
    """`SimulatePrincipalPolicy` accepts a user/role ARN, not the
    `assumed-role/<role>/<session>` ARN STS reports for a role session."""
    if ":assumed-role/" in arn:
        role = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        return f"arn:aws:iam::{account}:role/{role}"
    return arn


class AwsCollector:
    name = "cloud.aws"
    version = "1.0.0"
    default_confidence = ConfidenceTier.ATTESTED
    requires_sandbox = False
    requires_network = True

    def __init__(self, *, session_factory: Callable[[str], Any] | None = None) -> None:
        self._session_factory = session_factory or (
            lambda region: boto3.Session(region_name=region)
        )

    def supports(self, target: Target) -> bool:
        return target.type is TargetType.CLOUD_ACCOUNT and target.ref.startswith("aws")

    def collect(self, target: Target, ctx: RunContext) -> CollectorResult:
        start = time.monotonic()
        regions = [r for r in target.options.get("regions", "us-east-1").split(",") if r]
        tool = ToolIdentity(
            name=self.name,
            version=self.version,
            invocation=("boto3", "kms/acm/elbv2", ",".join(regions)),
            exit_code=None,
            duration_seconds=0.0,
        )
        claims: list[RawClaim] = []
        errors: list[CollectorError] = []
        inventory: dict[str, list[dict[str, Any]]] = {"kms": [], "acm": [], "elbv2": []}

        for index, region in enumerate(regions):
            session = self._session_factory(region)
            if index == 0:
                warning = assert_read_only(session)  # raises: a hard refusal, not a degraded run
                if warning:
                    errors.append(CollectorError(message=warning, fatal=False))
            account = session.client("sts").get_caller_identity()["Account"]

            for scan in (_scan_kms, _scan_acm, _scan_elbv2):
                try:
                    scan(session, account, region, claims, inventory, self.default_confidence)
                except (ClientError, BotoCoreError) as exc:
                    errors.append(
                        CollectorError(
                            message=f"{scan.__name__} in {region}: {type(exc).__name__}: {exc}",
                            fatal=False,
                        )
                    )

        return CollectorResult(
            raw=json.dumps(inventory, default=str).encode(),
            raw_format=RawFormat.QAVACH_NATIVE,
            claims=claims,
            tool=ToolIdentity(
                name=tool.name,
                version=tool.version,
                invocation=tool.invocation,
                exit_code=0,
                duration_seconds=time.monotonic() - start,
            ),
            errors=errors,
            partial=bool(errors),
        )


def _locus(account: str, region: str, arn: str) -> CloudLocus:
    return CloudLocus(provider="aws", account=account, region=region, resource_arn=arn)


def _claim(
    spec: KmsKeySpecClaim | None, *, locus: CloudLocus, confidence: ConfidenceTier
) -> RawClaim:
    if spec is None:
        # Unrecognised spec: a locus with no name/OID -> UNKNOWN downstream (I8).
        return RawClaim(locus=locus, name=None, detection_method="attested", confidence=confidence)
    return RawClaim(
        locus=locus,
        name=spec.name,
        primitive=spec.primitive,
        parameter_set=spec.parameter_set,
        mode=spec.mode,
        detection_method="attested",
        confidence=confidence,
    )


def _scan_kms(
    session: Any,
    account: str,
    region: str,
    claims: list[RawClaim],
    inventory: dict[str, list[dict[str, Any]]],
    confidence: ConfidenceTier,
) -> None:
    kms = session.client("kms")
    for page in kms.get_paginator("list_keys").paginate():
        for key in page["Keys"]:
            metadata = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            inventory["kms"].append(
                {k: metadata.get(k) for k in ("Arn", "KeySpec", "KeyUsage", "KeyManager", "Origin")}
            )
            spec = metadata.get("KeySpec") or metadata.get("CustomerMasterKeySpec") or ""
            claims.append(
                _claim(
                    kms_key_spec_to_claim(spec, metadata.get("KeyUsage")),
                    locus=_locus(account, region, metadata["Arn"]),
                    confidence=confidence,
                )
            )


def _scan_acm(
    session: Any,
    account: str,
    region: str,
    claims: list[RawClaim],
    inventory: dict[str, list[dict[str, Any]]],
    confidence: ConfidenceTier,
) -> None:
    acm = session.client("acm")
    for page in acm.get_paginator("list_certificates").paginate():
        for summary in page["CertificateSummaryList"]:
            arn = summary["CertificateArn"]
            certificate = acm.describe_certificate(CertificateArn=arn)["Certificate"]
            inventory["acm"].append(
                {
                    k: certificate.get(k)
                    for k in ("CertificateArn", "KeyAlgorithm", "SignatureAlgorithm")
                }
            )
            claims.append(
                _claim(
                    acm_key_algorithm_to_claim(certificate.get("KeyAlgorithm", "")),
                    locus=_locus(account, region, arn),
                    confidence=confidence,
                )
            )


def _scan_elbv2(
    session: Any,
    account: str,
    region: str,
    claims: list[RawClaim],
    inventory: dict[str, list[dict[str, Any]]],
    confidence: ConfidenceTier,
) -> None:
    elb = session.client("elbv2")
    policy_ciphers: dict[str, list[str]] = {}
    for page in elb.get_paginator("describe_load_balancers").paginate():
        for balancer in page["LoadBalancers"]:
            listeners = elb.describe_listeners(LoadBalancerArn=balancer["LoadBalancerArn"])
            for listener in listeners.get("Listeners", []):
                policy = listener.get("SslPolicy")
                if not policy:
                    continue
                if policy not in policy_ciphers:
                    described = elb.describe_ssl_policies(Names=[policy])["SslPolicies"]
                    policy_ciphers[policy] = [
                        c["Name"] for p in described for c in p.get("Ciphers", [])
                    ]
                inventory["elbv2"].append(
                    {"ListenerArn": listener["ListenerArn"], "SslPolicy": policy}
                )
                locus = _locus(account, region, listener["ListenerArn"])
                seen: set[tuple[str, str | None, str | None]] = set()
                for cipher in policy_ciphers[policy]:
                    spec = cipher_name_to_claim(cipher)
                    if spec is None:
                        continue
                    key = (spec.name, spec.parameter_set, spec.mode)
                    if key not in seen:
                        seen.add(key)
                        claims.append(_claim(spec, locus=locus, confidence=confidence))
