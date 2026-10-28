#!/usr/bin/env python3
"""Is there a newer Zero Breach release than the one this module bundles?

Asks the GitHub releases API of the upstream project (read-only, one request).
Never downloads or installs anything: the bundled scanner is audited and pinned,
and moving to a new release is a deliberate step (rebuild the module from a
reviewed tag, see android/README.md).

  check_update.py          print the status; exit 0 up to date, 10 newer release, 1 error
"""

import json
import os
import re
import ssl
import sys
import urllib.request

CODE = os.path.dirname(os.path.abspath(__file__))
UPSTREAM = "interplains/zero-breach"
API = "https://api.github.com/repos/{}/".format(UPSTREAM)
TAG_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def parse(tag):
    m = TAG_RE.match((tag or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


def pinned():
    with open(os.path.join(CODE, "UPSTREAM_TAG"), encoding="utf-8") as fh:
        return fh.read().strip()


def _get(path, timeout=20):
    req = urllib.request.Request(API + path, headers={
        "User-Agent": "zero-breach-android-update-check",
        "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
        return json.load(resp)


def latest():
    """(tag, url) of the newest stable release; falls back to the highest tag."""
    try:
        rel = _get("releases/latest")
        if parse(rel.get("tag_name")):
            return rel["tag_name"], rel.get("html_url", "")
    except Exception:  # noqa: BLE001 - e.g. 404 when only tags exist
        pass
    tags = [t["name"] for t in _get("tags?per_page=100") if parse(t["name"])]
    if not tags:
        raise ValueError("no release or version tag found")
    best = max(tags, key=parse)
    return best, "https://github.com/{}/releases/tag/{}".format(UPSTREAM, best)


def check():
    """Returns {"pinned", "latest", "url", "newer"}; raises on network errors."""
    have = pinned()
    tag, url = latest()
    return {"pinned": have, "latest": tag, "url": url,
            "newer": (parse(tag) or ()) > (parse(have) or ())}


def main():
    try:
        res = check()
    except Exception as exc:  # noqa: BLE001
        print("update check failed: {}".format(exc), file=sys.stderr)
        return 1
    if res["newer"]:
        print("NEW RELEASE: Zero Breach {} is out (bundled: {}) - {}".format(
            res["latest"], res["pinned"], res["url"]))
        return 10
    print("up to date: bundled {} is the latest release ({})".format(res["pinned"], res["latest"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
