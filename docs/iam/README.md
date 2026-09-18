# AWS IAM policy for the QAVACH cloud collector

`aws-readonly.json` is the **exact minimum** policy `cloud.aws` needs, and
QAVACH requires nothing more (`SECURITY.md §6`). It grants inventory reads
only — no `kms:Encrypt`, `Decrypt`, `Sign`, `CreateKey`, `ScheduleKeyDeletion`
or any other action that touches key material or changes state.

`sts:GetCallerIdentity` and `iam:SimulatePrincipalPolicy` are for the
collector's own self-check: before scanning it simulates KMS write actions
against the credential it was handed and **refuses to run** if any are
allowed, because a scanner holding write access to KMS is a misconfiguration
worth failing loudly on. If the self-check itself is denied (the policy above
was attached without those two actions) the collector proceeds but records a
non-fatal error saying it could not verify the credential is read-only.
