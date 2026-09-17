# Sandbox seccomp profile

`scanner.json` is Docker's own default seccomp profile, vendored verbatim
from the primary source:

- Repo: <https://github.com/moby/profiles>
- Path: `seccomp/default.json`
- Branch: `main` (fetched 2026-09-18)
- License: Apache-2.0

This is the same profile `dockerd`/`containerd` apply automatically when no
`--security-opt seccomp=` is given at all — QAVACH pins it explicitly rather
than relying on the container engine's built-in default so the sandbox's
security posture is checked into the repo, reviewable, and identical across
Docker and Podman rather than depending on each engine's own bundled copy
possibly drifting out of sync with each other.

**Why not a smaller, hand-rolled allowlist?** A custom, more-restrictive
profile would need to be verified against the real syscall footprint of
every scanner QAVACH shells out to (Node.js/npm for cdxgen, JVM for
CBOMkit-theia, Python for Syft plugins, Go binaries for Syft/Opengrep/
Certipy) — five different language runtimes' worth of subprocess, mmap and
threading behaviour. Getting that allowlist wrong fails closed (a scanner
mysteriously dies mid-run with `EPERM`, produced no output, and QAVACH has
no way to distinguish "the target is hostile" from "the seccomp list is
missing `pipe2`"). Docker's default profile is already the actually-verified
baseline the entire Docker/Kubernetes ecosystem runs untrusted-ish workloads
under — `SCMP_ACT_ERRNO` default (deny-by-default), 446 syscalls allowlisted,
`ptrace`, `keyctl`, `mount`, `reboot`, `add_key`, kernel-module and most
namespace-creation syscalls excluded. It is the defensible baseline; a
tighter one is a `SECURITY.md` follow-up (`NOTE.md §6`), not something to
invent under this task.

Do not hand-edit this file. Re-vendor by re-fetching the URL above.
