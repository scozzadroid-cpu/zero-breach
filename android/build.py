#!/usr/bin/env python3
"""Build the installable module zip.

  python3 android/build.py

The zip holds android/module/ plus the audited upstream scanner, taken straight
from the git tag named in android/UPSTREAM_TAG (not from the working tree), with a
MANIFEST.sha256 of every bundled upstream file. The output is deterministic: the
same tag and module sources always give the same zip.
"""

import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MODULE = os.path.join(HERE, "module")
UPSTREAM_PATHS = ["scan/adint_scan", "scan/update-iocs.py", "iocs/adfection_iocs.txt",
                  "iocs/adfection_iocs.txt.sha256", "iocs/LICENSE.md", "LICENSE", "NOTICE"]
SKIP = {"__pycache__", "data.js", "data.js.tmp"}
EPOCH = (2026, 10, 28, 0, 0, 0)


def git(*args):
    return subprocess.run(["git", "-C", ROOT] + list(args), check=True,
                          capture_output=True).stdout


def prop(name):
    with open(os.path.join(MODULE, "module.prop"), encoding="utf-8") as fh:
        return re.search(r"^{}=(.*)$".format(name), fh.read(), re.M).group(1).strip()


def main():
    with open(os.path.join(HERE, "UPSTREAM_TAG"), encoding="utf-8") as fh:
        tag = fh.read().strip()
    commit = git("rev-parse", tag + "^{commit}").decode().strip()

    files = {}  # zip path -> (bytes, mode)
    for dirpath, dirs, names in os.walk(MODULE):
        dirs[:] = sorted(d for d in dirs if d not in SKIP)
        for name in sorted(names):
            if name in SKIP or name.endswith((".pyc", ".tmp")):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, MODULE).replace(os.sep, "/")
            with open(full, "rb") as fh:
                files[rel] = (fh.read(), 0o755 if name.endswith(".sh") else 0o644)

    tar = git("archive", "--format=tar", tag, *UPSTREAM_PATHS)
    manifest = []
    with tarfile.open(fileobj=io.BytesIO(tar)) as tf:
        for member in sorted(tf.getmembers(), key=lambda m: m.name):
            if not member.isfile() or "__pycache__" in member.name:
                continue
            data = tf.extractfile(member).read()
            rel = "upstream/" + member.name
            files["zb/" + rel] = (data, 0o644)
            manifest.append("{}  {}".format(hashlib.sha256(data).hexdigest(), rel))
    files["zb/MANIFEST.sha256"] = (("\n".join(sorted(manifest, key=lambda l: l.split("  ", 1)[1])) + "\n").encode(), 0o644)
    files["zb/UPSTREAM_TAG"] = ((tag + "\n").encode(), 0o644)
    files["zb/UPSTREAM_COMMIT"] = ((commit + "\n").encode(), 0o644)

    out_dir = os.path.join(HERE, "dist")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "zero-breach-nightly-{}.zip".format(prop("version")))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in sorted(files):
            data, mode = files[rel]
            info = zipfile.ZipInfo(rel, EPOCH)
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    digest = hashlib.sha256(open(out, "rb").read()).hexdigest()
    print("{}\nbundled Zero Breach {} ({})\nsha256 {}".format(out, tag, commit[:12], digest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
