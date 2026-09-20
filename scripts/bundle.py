"""`make bundle` (T-123): an offline tarball to carry into an air-gapped site.

Contents: every image QAVACH runs (`docker save`, one archive so shared layers are
stored once), the knowledge base and policy (`config/`), the pinned-scanner manifest,
a `MANIFEST.json` and `SHA256SUMS`, and `load.sh`, which verifies the checksums and
`docker load`s the images.

Images are identified by content, not by name: `docker load` restores an image but not
its `repo@sha256:` name, and under the containerd image store the image ID *is* the
registry digest, so QAVACH resolves a pinned reference to the bare `sha256:<digest>` on
such a host (`qavach_worker.registry.resolve_local_ref`). QAVACH-built images have no
registry digest and are pinned by their image ID.

    uv run python scripts/bundle.py [--out dist/bundle] [--dry-run] [--only SUBSTRING]

Not included: Python wheels and node modules (build those on a connected machine, e.g.
`uv build` / a container image of the API), and the theia/certfinder agent binaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

LOAD_SH = """#!/bin/sh
# Verify, then load. Run from the unpacked bundle directory.
set -eu
cd "$(dirname "$0")"
sha256sum -c SHA256SUMS
docker load -i images.tar
echo "loaded. Start with: make dev   (or make demo-ui)"
"""


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def image_refs() -> dict[str, str]:
    """name -> reference to save. Upstream images by pinned digest, built ones by tag."""
    from qavach_collectors.container.theia import THEIA_IMAGE
    from qavach_collectors.sbom.syft import SYFT_IMAGE
    from qavach_collectors.source_scan.cdxgen import CDXGEN_IMAGE

    refs = {
        "source_scan.cdxgen": CDXGEN_IMAGE,
        "sbom.syft": SYFT_IMAGE,
        "container.theia": THEIA_IMAGE,
        "source_scan.opengrep": "qavach/opengrep:dev",
        "runtime.tracebom": "qavach/tracebom:dev",
        "source_scan.cbomkit": "qavach/cbomkit-lib:dev",
        "ad.adcs": "qavach/certipy:dev",
    }
    for service in yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"].values():
        refs[f"infra.{service['image'].split('/')[-1].split(':')[0]}"] = service["image"]
    return refs


def image_id(ref: str) -> str | None:
    proc = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", ref],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    ident = proc.stdout.strip()
    return ident if proc.returncode == 0 and ident.startswith("sha256:") else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "bundle")
    parser.add_argument("--dry-run", action="store_true", help="list what would be bundled")
    parser.add_argument("--only", help="only images whose name or ref contains this")
    args = parser.parse_args()

    refs = {n: r for n, r in image_refs().items() if not args.only or args.only in n + r}
    present: dict[str, str] = {}
    missing: list[str] = []
    for name, ref in refs.items():
        ident = image_id(ref)
        (present.__setitem__(name, ident) if ident else missing.append(f"{name} ({ref})"))
    for name, ident in present.items():
        print(f"  ok       {name:<24} {ident[:19]}  {refs[name]}")
    for m in missing:
        print(f"  MISSING  {m}")
    if missing:
        print(
            "\nbuild or pull the missing images first (`make build-images`, `make scanners-pull`)"
        )
        return 1
    if args.dry_run:
        return 0

    out = args.out
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    print("\nsaving images (this is large)...")
    subprocess.run(
        ["docker", "save", "-o", str(out / "images.tar"), *sorted(set(refs.values()))], check=True
    )
    shutil.copytree(ROOT / "config", out / "config")
    (out / "load.sh").write_text(LOAD_SH)
    (out / "load.sh").chmod(0o755)
    manifest = {
        "created": datetime.now(UTC).isoformat(),
        "git_commit": subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=ROOT, check=False
        ).stdout.strip(),
        "images": {n: {"ref": refs[n], "id": present[n]} for n in sorted(present)},
    }  # fmt: skip
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    files = sorted(p for p in out.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    (out / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.relative_to(out)}\n" for p in files))
    archive = out.parent / f"qavach-bundle-{datetime.now(UTC):%Y%m%d}.tar"
    with tarfile.open(archive, "w") as tar:
        tar.add(out, arcname="qavach-bundle")
    print(f"\nwrote {archive} ({archive.stat().st_size / 1e9:.1f} GB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
