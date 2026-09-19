"""T-081 - fails the build if any knowledge-base entry was last verified more
than 180 days ago, forcing a re-check against NIST CSRC / the RFC Editor.

    uv run python scripts/check_knowledge_freshness.py [--today YYYY-MM-DD]

Exit 1 on any stale entry. Entries with `verified_on: null` are listed as
warnings (they carry an `unverified_reason` and the UI says so) but do not fail
the build - failing on "not yet verified" would only push people to fake a date.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

import yaml
from qavach_core.recommend import MAX_AGE_DAYS, PqcKnowledge

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--today", type=date.fromisoformat, default=date.today())
    args = parser.parse_args()
    knowledge = PqcKnowledge.from_documents(
        yaml.safe_load((ROOT / "config/knowledge/pqc_alternatives.yaml").read_text()),
        yaml.safe_load((ROOT / "config/knowledge/performance.yaml").read_text()),
    )
    for name in knowledge.unverified():
        print(f"warning: {name} is UNVERIFIED (see its unverified_reason)")
    stale = knowledge.stale(args.today)
    for name, age in stale:
        print(f"STALE: {name} was last verified {age} days ago (limit {MAX_AGE_DAYS})")
    if stale:
        print("Re-verify against the primary source, then update `verified_on`.")
        return 1
    print(f"knowledge base fresh as of {args.today}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
