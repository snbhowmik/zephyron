#!/usr/bin/env python3
"""T-006. Pull every image in config/scanners.yaml's `container_images`
section by digest — never by tag (SECURITY.md §3). Invoked by
`make scanners-pull`.

`qavach_built_images` entries are skipped with a clear message naming the
task that builds them (NOTE.md §4.4's "honest stub" rule) — there is
nothing to pull for an image QAVACH hasn't built yet.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCANNERS_YAML = REPO_ROOT / "config" / "scanners.yaml"
ENGINE = os.environ.get("ENGINE", "docker")


def main() -> int:
    config = yaml.safe_load(SCANNERS_YAML.read_text())

    failures = 0
    for name, spec in config.get("container_images", {}).items():
        ref = f"{spec['image']}@{spec['digest']}"
        print(f"[{name}] pulling {ref}")
        result = subprocess.run([ENGINE, "pull", ref])
        if result.returncode != 0:
            failures += 1
            print(f"[{name}] FAILED to pull {ref}", file=sys.stderr)

    for name, spec in config.get("qavach_built_images", {}).items():
        task = spec.get("built_by", "an unassigned task")
        print(f"[{name}] not yet built — see TASK.md {task}. Nothing to pull.")

    for name in config.get("agent_artifacts", {}):
        print(
            f"[{name}] agent-side artefact, not a container — pinned by checksum, not pulled here."
        )

    if failures:
        print(f"\n{failures} image(s) failed to pull.", file=sys.stderr)
        return 1
    print("\nAll published scanner images pulled and verified against their pinned digest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
