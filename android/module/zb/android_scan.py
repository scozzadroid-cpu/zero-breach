#!/usr/bin/env python3
"""Android front end for the pinned Zero Breach scanner (see UPSTREAM_TAG).

Upstream knows only desktop browser locations. This script points its own
browser module at the Chromium profiles Android apps keep under /data/data
(Chrome and the WebView of every app), adds the app HTTP-cache and hosts-file
checks that the desktop layout cannot reach, and reuses upstream's indicator
matcher, evidence grading, verdict and report unchanged. Read-only; the scan
runs inside upstream's no-network guard.

Needs root (reads other apps' data). Exit codes as upstream: 0 nothing found,
2 an indicator matched, 1 the scan could not be set up.

  android_scan.py [--iocs PATH] [--json PATH]
  android_scan.py --self-check      verify the bundled upstream code, then exit
"""

import argparse
import datetime
import hashlib
import io
import os
import re
import sys
import time

CODE = os.path.dirname(os.path.abspath(__file__))
DATA = "/data/adb/zero-breach"
sys.path.insert(0, os.path.join(CODE, "upstream", "scan"))

from adint_scan.context import ScanContext  # noqa: E402
from adint_scan.iocs import IocError, load  # noqa: E402
from adint_scan.localpaths import local_temp_dir, path_problem, walk_local  # noqa: E402
from adint_scan.modules import browser, host  # noqa: E402
from adint_scan.netguard import no_network  # noqa: E402
from adint_scan.report import V_HITS, build_document, render_human, write_json  # noqa: E402
from adint_scan.result import (EV_CONFIGURED, EV_CONTACTED, EV_REFERENCED,  # noqa: E402
                               Hit, ModuleResult)

CHROME_PKG = "com.android.chrome"
HOSTS_FILE = "/system/etc/hosts"
MANIFEST = os.path.join(CODE, "MANIFEST.sha256")

# cache/ subfolders that hold web content or HTTP responses. Image and media
# caches are left out on purpose: they hold pictures, not origins.
CACHE_DIR_RE = re.compile(
    r"^(webview|cache|code cache|http[-_ ]?cache|net_cache|cronet.*|okhttp.*|"
    r".*\.http-cache|volley)$", re.I)

FULL_MAX = 256 * 1024     # smaller cache files are searched whole
HEAD_BYTES = 16 * 1024    # larger ones: the start (URL key) ...
TAIL_BYTES = 32 * 1024    # ... and the end (HTTP response headers)
CACHE_BUDGET_S = 40 * 60  # stop walking caches after this long, reported as a gap

SIMPLE_CACHE_MAGIC = b"\x30\x5c\x72\xa7\x1b\x6d\xfb\xfc"  # Chromium simple cache
ISOLATION_PREFIX = "1/0/_dk_"  # key: <prefix><top site> <frame site> <url>
OWNER_RE = re.compile(r"^/data/(?:data|user/\d+)/([^/]+)/")


def _be_nice():
    """Run at low priority and be the first thing lmkd kills under memory
    pressure, so a night scan never costs an app its place."""
    try:
        os.nice(10)
    except OSError:
        pass
    try:
        with open("/proc/self/oom_score_adj", "w") as fh:
            fh.write("800")
    except OSError:
        pass


def default_iocs():
    working = os.path.join(DATA, "iocs", "adfection_iocs.txt")
    if os.path.exists(working):
        return working
    return os.path.join(CODE, "upstream", "iocs", "adfection_iocs.txt")


def data_bases():
    """App data roots: the owner (/data/data, a real directory) plus any extra
    user such as Xiaomi's dual apps (/data/user/N). /data/user/0 is a symlink
    to /data/data and upstream refuses symlinks, so it is skipped."""
    bases = ["/data/data"]
    try:
        for name in sorted(os.listdir("/data/user")):
            if name.isdigit() and name != "0":
                bases.append("/data/user/" + name)
    except OSError:
        pass
    return [b for b in bases if os.path.isdir(b) and not path_problem(b)]


def chromium_roots(bases):
    """(label, user-data root, display name) for Chrome and every app WebView:
    any <pkg>/app_* folder that holds a Chromium 'Default' profile."""
    roots = []
    for base in bases:
        try:
            pkgs = sorted(os.listdir(base))
        except OSError:
            continue
        for pkg in pkgs:
            pdir = os.path.join(base, pkg)
            try:
                names = sorted(os.listdir(pdir))
            except OSError:
                continue
            for name in names:
                if not name.startswith("app_"):
                    continue
                root = os.path.join(pdir, name)
                if not os.path.isdir(os.path.join(root, "Default")):
                    continue
                if pkg == CHROME_PKG:
                    roots.append(("chrome", root, ""))
                else:
                    extra = "" if name in ("app_webview", "app_chrome") else " " + name
                    roots.append(("webview", root, pkg + extra))
    return roots


# --- adapting upstream's browser module to Android --------------------------

def _android_note(path, exc):
    """Upstream words every PermissionError as 'the browser was running'. Here a
    lock is a lock and anything else is reported with its real error (the same
    distinction upstream issue #16 / PR #17 asks for)."""
    leftover = getattr(exc, "snapshot_leftover", "")
    tail = (" WARNING: temporary snapshot cleanup failed; a copy of app data may "
            "remain at {}.".format(leftover)) if leftover else ""
    text = str(exc).lower()
    if "locked" in text or "busy" in text:
        m = OWNER_RE.match(path)
        return "{} was in use, so a database was locked and could not be checked ({}).".format(
            m.group(1) if m else "the app", os.path.basename(path)) + tail
    return "could not read {}: {}".format(path, exc) + tail


def _install_android_roots(roots):
    """Point upstream's browser module at the Android profiles. Upstream's own
    tests patch the same attributes the same way."""
    browser.CHROMIUM_ROOTS = [(label, root) for label, root, _ in roots]
    browser.FIREFOX_ROOTS = []
    display = {root: name for _, root, name in roots if name}
    original = browser._chromium_profile_names

    def names(user_data):
        out = original(user_data)
        if user_data in display:
            # every app's profile folder is "Default"; the package name is what
            # tells the reader whose data a finding came from
            out = {"Default": display[user_data], "Guest Profile": display[user_data]}
        return out

    browser._chromium_profile_names = names
    browser._locked_note = _android_note

    # LevelDB's zero-byte LOCK file is held exclusively while an app runs;
    # reading it fails and would be reported as a gap although it never holds
    # data (upstream issue #18).
    walk = browser.walk_local

    def walk_without_lock(root, onerror=None):
        for dirpath, dirs, files in walk(root, onerror=onerror):
            yield dirpath, dirs, [f for f in files if f != "LOCK"]

    browser.walk_local = walk_without_lock


# --- extra checks: app HTTP caches and hosts file ---------------------------

def _simple_cache_url(head):
    """(resource url, top-level site) from a Chromium simple-cache entry header,
    or None. The key sits at offset 24 and is the request the cache answered."""
    if head[:8] != SIMPLE_CACHE_MAGIC or len(head) < 24:
        return None
    length = int.from_bytes(head[12:16], "little")
    if not 0 < length <= HEAD_BYTES - 24:
        return None
    key = head[24:24 + length].decode("utf-8", "replace").lower()
    if key.startswith(ISOLATION_PREFIX):
        parts = key[len(ISOLATION_PREFIX):].split(" ")
        if len(parts) >= 3:
            return parts[2], parts[0]
    return key, ""


def _scan_cache_file(ctx, r, path, owner, stats):
    try:
        size = os.stat(path).st_size
        with io.open(path, "rb") as fh:
            if size <= FULL_MAX:
                chunks = [fh.read()]
            else:
                head = fh.read(HEAD_BYTES)
                fh.seek(max(size - TAIL_BYTES, HEAD_BYTES))
                chunks = [head, fh.read(TAIL_BYTES)]
                stats["partial"] += 1
    except FileNotFoundError:
        stats["vanished"] += 1  # the app evicted it while we were walking its cache
        return
    except OSError as exc:
        r.skipped += 1
        stats["unreadable"].append("{}: {}".format(path, exc))
        return
    r.checked += 1
    stats["files"] += 1

    contacted = None
    keyed = _simple_cache_url(chunks[0])
    if keyed:
        url, top = keyed
        contacted = browser._host_matches(browser._host_of(url), ctx.iocs)
        if contacted is not None:
            r.add_hit(Hit(
                indicator=contacted.value, location=path,
                detail="HTTP cache holds a response fetched from {}{}".format(
                    url[:160], " while on " + top if top else ""),
                tier=contacted.tier, confidence=contacted.confidence,
                source=contacted.source, evidence=EV_CONTACTED, profile=owner))
    for chunk in chunks:
        for ind in ctx.iocs.most_specific(ctx.iocs.search_bytes(chunk.lower())):
            if contacted is not None and ind.value == contacted.value:
                continue
            key = (path, ind.value)
            if key in stats["seen"]:
                continue
            stats["seen"].add(key)
            r.add_hit(Hit(
                indicator=ind.value, location=path,
                detail="binary match in an app cache; raw bytes do not show "
                       "whether this is a request or saved page content",
                tier=ind.tier, confidence=ind.confidence, source=ind.source,
                evidence=EV_REFERENCED, profile=owner))


def _scan_caches(ctx, r, bases):
    started = time.time()
    stats = {"files": 0, "partial": 0, "vanished": 0, "unreadable": [], "seen": set()}
    failures = []
    dirs = 0

    def onerror(exc):
        failures.append("could not enumerate {}: {}".format(
            getattr(exc, "filename", "?"), exc))

    for base in bases:
        try:
            pkgs = sorted(os.listdir(base))
        except OSError as exc:
            r.could_not_run("app-cache:" + base, str(exc))
            continue
        for pkg in pkgs:
            cache = os.path.join(base, pkg, "cache")
            try:
                subs = [n for n in sorted(os.listdir(cache)) if CACHE_DIR_RE.match(n)]
            except OSError:
                continue
            for sub in subs:
                dirs += 1
                for dirpath, _dirs, files in walk_local(os.path.join(cache, sub), onerror=onerror):
                    for fn in files:
                        _scan_cache_file(ctx, r, os.path.join(dirpath, fn), pkg, stats)
                    if time.time() - started > CACHE_BUDGET_S:
                        r.could_not_run(
                            "app-cache",
                            "time budget of {} min reached after {:,} files; the "
                            "remaining cache folders were not searched".format(
                                CACHE_BUDGET_S // 60, stats["files"]))
                        return stats
    r.submetrics["cache_files"] = stats["files"]
    r.submetrics["cache_folders"] = dirs
    problems = failures + stats["unreadable"]
    if problems:
        r.could_not_run("app-cache", "{} item(s) could not be read, e.g. {}".format(
            len(problems), "; ".join(problems[:3])))
    elif dirs:
        r.ran("app-cache")
    else:
        r.could_not_run("app-cache", "no app cache folders were found")
    if stats["vanished"]:
        r.note("app-cache: {:,} cache files were removed by their app during the scan".format(
            stats["vanished"]))
    if stats["partial"]:
        r.note("app-cache: {:,} cache entries larger than {} KB were searched at "
               "their start (request URL) and end (response headers) only".format(
                   stats["partial"], FULL_MAX // 1024))
    return stats


def _scan_hosts(ctx, r):
    problem = path_problem(HOSTS_FILE)
    if problem:
        r.could_not_run("hosts-file", problem)
        return
    try:
        with io.open(HOSTS_FILE, encoding="utf-8", errors="replace") as fh:
            lines = [ln.strip() for ln in fh
                     if ln.strip() and not ln.strip().startswith("#")]
    except OSError as exc:
        r.could_not_run("hosts-file", "could not read {}: {}".format(HOSTS_FILE, exc))
        return
    blocked = 0
    for line in lines:
        found = ctx.iocs.most_specific(ctx.iocs.search(line.lower()))
        if not found:
            continue
        addr = line.split()[0]
        if addr in host._SINK_ADDRESSES:
            blocked += 1  # a block entry is protective, never a finding
            continue
        for ind in found:
            r.add_hit(Hit(
                indicator=ind.value, location=HOSTS_FILE,
                detail="mapped in the hosts file to {} (line: {})".format(addr, line[:160]),
                tier=ind.tier, confidence=ind.confidence, source=ind.source,
                evidence=EV_CONFIGURED))
    r.checked += len(lines)
    r.ran("hosts-file")
    if blocked:
        r.note("hosts-file: {} entries block indicator names (protective, not findings)"
               .format(blocked))


def android_module(ctx, bases):
    r = ModuleResult("android")
    ctx.partial = r
    _scan_caches(ctx, r, bases)
    _scan_hosts(ctx, r)
    r.could_not_run(
        "dns-history",
        "Android keeps no DNS query history, so lookups made in the past cannot "
        "be checked from this device")
    r.could_not_run(
        "native-app-traffic",
        "Android does not record which hosts native (non-web) app code contacted; "
        "only browser and WebView artifacts and app HTTP caches can be searched")
    return r


def hash_not_applicable():
    r = ModuleResult("hash")
    r.could_not_run(
        "file-fingerprints",
        "not applicable on Android: the published file hashes identify a Windows "
        "implant and a Windows driver, which cannot exist as such on this device")
    return r


# --- self check ------------------------------------------------------------

def verify_manifest():
    """Hash every bundled upstream file against MANIFEST.sha256 (written at build
    time from the audited release tag). Returns a list of problems."""
    try:
        with io.open(MANIFEST, encoding="utf-8") as fh:
            entries = [ln.rstrip("\n").split("  ", 1) for ln in fh if ln.strip()]
    except OSError as exc:
        return ["manifest unreadable: {}".format(exc)]
    problems, listed = [], set()
    for digest, rel in entries:
        listed.add(rel)
        try:
            with io.open(os.path.join(CODE, rel), "rb") as fh:
                got = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            problems.append("missing: " + rel)
            continue
        if got != digest:
            problems.append("modified: " + rel)
    upstream = os.path.join(CODE, "upstream")
    for dirpath, dirs, files in os.walk(upstream):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fn in files:
            rel = os.path.relpath(os.path.join(dirpath, fn), CODE)
            if rel not in listed:
                problems.append("unexpected: " + rel)
    return problems


def self_check():
    problems = verify_manifest()
    try:
        with io.open(os.path.join(CODE, "UPSTREAM_TAG"), encoding="utf-8") as fh:
            tag = fh.read().strip()
    except OSError:
        tag = "?"
        problems.append("UPSTREAM_TAG missing")
    print("bundled Zero Breach {}: {}".format(
        tag, "files match the manifest" if not problems else "{} integrity problem(s)".format(len(problems))))
    for p in problems[:10]:
        print("  - " + p)
    try:
        iocs = load(default_iocs())
        print("indicators: {} ({})".format(len(iocs), default_iocs()))
    except IocError as exc:
        problems.append("indicator file: {}".format(exc))
        print("indicators: ERROR {}".format(exc))
    if os.geteuid() != 0:
        problems.append("not running as root")
    roots = chromium_roots(data_bases())
    print("root: {}; Chromium profile folders found: {}; python {}".format(
        "yes" if os.geteuid() == 0 else "NO", len(roots), sys.version.split()[0]))
    if not roots:
        problems.append("no Chromium profile folders found")
    try:
        print("temp dir: " + local_temp_dir())
    except PermissionError as exc:
        problems.append("temp dir: {}".format(exc))
    print("SELF-CHECK " + ("FAILED" if problems else "OK"))
    return 1 if problems else 0


# --- orchestration (same shape as upstream cli._run_modules) ----------------

def _guarded(name, ctx, fn):
    ctx.emit("[*] running check: " + name)
    started = time.time()
    ctx.partial = None
    try:
        result = fn()
    except Exception as exc:  # a module must never take the whole scan down
        partial = ctx.partial
        result = partial if isinstance(partial, ModuleResult) and partial.name == name \
            else ModuleResult(name)
        result.could_not_run(name, "module error: {}: {}".format(type(exc).__name__, exc))
    finally:
        ctx.partial = None
    result.duration_s = time.time() - started
    ctx.emit("[*]   {} finished in {:.0f}s".format(name, result.duration_s))
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description="Zero Breach scan of this Android device.")
    p.add_argument("--iocs", default=default_iocs())
    p.add_argument("--json", metavar="PATH", help="also write the machine-readable report")
    p.add_argument("--self-check", action="store_true",
                   help="verify the bundled upstream code and the environment, then exit")
    args = p.parse_args(argv)

    if args.self_check:
        return self_check()
    try:
        iocs = load(args.iocs)
    except IocError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1
    if os.geteuid() != 0:
        print("error: root is required to read other apps' data", file=sys.stderr)
        return 1

    _be_nice()
    started = datetime.datetime.now()
    ctx = ScanContext(iocs=iocs, quick=True)
    bases = data_bases()
    roots = chromium_roots(bases)
    ctx.emit("[*] {} Chromium profile folder(s) in {} app data root(s)".format(
        len(roots), len(bases)))
    _install_android_roots(roots)

    with no_network():
        results = [
            _guarded(browser.NAME, ctx, lambda: browser.run(ctx)),
            _guarded("android", ctx, lambda: android_module(ctx, bases)),
            hash_not_applicable(),
        ]

    document = build_document(iocs, results, started)
    print(render_human(document))
    if args.json:
        try:
            write_json(document, args.json)
        except OSError as exc:
            print("could not write JSON report to {}: {}".format(args.json, exc),
                  file=sys.stderr)
    return 2 if document["verdict"]["status"] == V_HITS else 0


if __name__ == "__main__":
    raise SystemExit(main())
