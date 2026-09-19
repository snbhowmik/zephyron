"""ARCH.md §3a: 'packaged as a single-file bundle (PyInstaller or
equivalent) so it runs on a host with no Python of its own.' T-031a.

Two subcommands, matching the enrollment/poll split in the module docstrings
of `enrollment.py` and `runtime.py`:

  qavach-agent enroll --backend-url URL --token TOKEN --ca-bundle PATH \
      --credential-out PATH
  qavach-agent run --backend-url URL --credential PATH [--poll-interval N]

`run` registers the real agent-side collectors via `registry.build_registry`
(T-031d); this entrypoint stays a thin shell that imports them directly
(`CLAUDE.md §3`'s "no `packages/collectors/host/`" rule)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from qavach_agent.enrollment import AgentCredential, EnrollmentError, enroll
from qavach_agent.parser_worker import parse_worker_main
from qavach_agent.registry import build_registry
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
    built = build_registry(config_dir=Path(args.config_dir) if args.config_dir else None)
    for name, reason in built.skipped.items():
        logger.warning("collector %s not registered: %s", name, reason)
    registry = built.registry
    config = RunForeverConfig(poll_interval_seconds=args.poll_interval)

    with AgentTransport(backend_url=args.backend_url, credential=credential) as client:
        outcomes = run_forever(
            client=client, agent_id=credential.agent_id, registry=registry, config=config
        )
    for outcome in outcomes:
        if not outcome.ok:
            logger.warning("poll cycle error: %s", outcome.error)
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Prints what this build can actually do, as JSON: which collectors are
    registered, which were skipped and why, and where config/binaries were
    found. Exit 1 if nothing is registered. Used to verify a frozen bundle."""
    from qavach_agent.registry import default_config_dir, locate_binary

    built = build_registry(config_dir=Path(args.config_dir) if args.config_dir else None)
    report = {
        "registered": sorted(c.name for c in built.registry),
        "skipped": built.skipped,
        "config_dir": str(Path(args.config_dir) if args.config_dir else default_config_dir()),
        "binaries": {
            name: (str(found) if (found := locate_binary(name)) else None)
            for name in ("certfinder", "cbomkit-theia")
        },
        "frozen": bool(getattr(sys, "frozen", False)),
    }
    print(json.dumps(report, indent=2))
    return 0 if report["registered"] else 1


def _cmd_parse_worker(args: argparse.Namespace) -> int:
    result: int = parse_worker_main(args.parse_entrypoint)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qavach-agent")
    # `metavar` overrides the auto-generated `{enroll,run,_parse-worker}`
    # choices display in the usage line. Omitting `help=` on the
    # `_parse-worker` subparser itself (not passing `argparse.SUPPRESS`,
    # which was tried first and confirmed live to print the literal string
    # "==SUPPRESS==" instead of hiding the line) keeps it out of the
    # per-item listing too. It remains fully parseable either way — this
    # only changes what --help prints.
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="{enroll,run,doctor}")

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
    run_parser.add_argument(
        "--config-dir", help="knowledge tables (default: bundled, or QAVACH_CONFIG_DIR)"
    )
    run_parser.set_defaults(func=_cmd_run)

    # Internal: re-exec target for parser_worker.run_in_worker (ARCH.md
    # §3a's resource-limited parsing worker, T-031b). Not a user-facing
    # command — hidden from --help.
    doctor_parser = subparsers.add_parser("doctor", help="report what this build can run")
    doctor_parser.add_argument("--config-dir")
    doctor_parser.set_defaults(func=_cmd_doctor)

    worker_parser = subparsers.add_parser("_parse-worker")
    worker_parser.add_argument("parse_entrypoint")
    worker_parser.set_defaults(func=_cmd_parse_worker)

    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
