"""ARCH.md §3a: 'packaged as a single-file bundle (PyInstaller or
equivalent) so it runs on a host with no Python of its own.' T-031a.

Two subcommands, matching the enrollment/poll split in the module docstrings
of `enrollment.py` and `runtime.py`:

  qavach-agent enroll --backend-url URL --token TOKEN --ca-bundle PATH \
      --credential-out PATH
  qavach-agent run --backend-url URL --credential PATH [--poll-interval N]

No real agent-side collector exists yet (`tls.store` etc. are still-open
Phase 3 tasks — T-036, T-036a, T-041, T-042), so `run` currently polls and
reports with an empty `CollectorRegistry`; it will pick up real collectors
the moment `apps/agent` imports them (`CLAUDE.md §3`'s "no
`packages/collectors/host/`" rule — this entrypoint is the thin shell that
is meant to import them directly)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from qavach_collectors import CollectorRegistry

from qavach_agent.enrollment import AgentCredential, EnrollmentError, enroll
from qavach_agent.runtime import RunForeverConfig, run_forever
from qavach_agent.transport import AgentTransport

logger = logging.getLogger("qavach_agent")


def _cmd_enroll(args: argparse.Namespace) -> int:
    try:
        credential = enroll(
            backend_url=args.backend_url,
            enrollment_token=args.token,
            ca_bundle_path=args.ca_bundle,
        )
    except EnrollmentError as exc:
        logger.error("enrollment failed: %s", exc)
        return 1

    out_path = Path(args.credential_out)
    out_path.write_text(json.dumps(credential.to_json_dict()))
    out_path.chmod(0o600)
    logger.info("enrolled as %s, credential written to %s", credential.agent_id, out_path)
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    credential = AgentCredential.from_json_dict(json.loads(Path(args.credential).read_text()))
    registry = CollectorRegistry()
    config = RunForeverConfig(poll_interval_seconds=args.poll_interval)

    with AgentTransport(backend_url=args.backend_url, credential=credential) as client:
        outcomes = run_forever(
            client=client, agent_id=credential.agent_id, registry=registry, config=config
        )
    for outcome in outcomes:
        if not outcome.ok:
            logger.warning("poll cycle error: %s", outcome.error)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qavach-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    enroll_parser = subparsers.add_parser(
        "enroll", help="exchange an enrollment token for a credential"
    )
    enroll_parser.add_argument("--backend-url", required=True)
    enroll_parser.add_argument("--token", required=True)
    enroll_parser.add_argument("--ca-bundle", required=True)
    enroll_parser.add_argument("--credential-out", required=True)
    enroll_parser.set_defaults(func=_cmd_enroll)

    run_parser = subparsers.add_parser("run", help="run the outbound poll loop")
    run_parser.add_argument("--backend-url", required=True)
    run_parser.add_argument("--credential", required=True)
    run_parser.add_argument("--poll-interval", type=float, default=30.0)
    run_parser.set_defaults(func=_cmd_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
