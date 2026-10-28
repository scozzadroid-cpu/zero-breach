# Zero Breach Nightly (Android / KernelSU module)

An **unofficial** Android wrapper for [Zero Breach](../README.md): a root module that
runs the project's read-only AdFection / Candiru indicator check on the phone itself,
on a schedule (default: every weekday at 03:30), and keeps the results on a web page
you open from the root manager.

It adds no detection logic of its own. The scanner's indicator matcher, evidence
grading and report come from the audited upstream release bundled in the module;
this directory only adapts *where* it looks (Android app data instead of a desktop
profile) and *when* it runs. Not affiliated with or endorsed by the upstream project
or the researchers it cites.

> **A clean result is not a clean bill of health.** The scan searches for published
> traces of one campaign in the places an Android phone leaves them. It cannot see
> native-app network traffic, DNS history (Android keeps none) or an implant that
> leaves no such trace. If you have a concrete reason to think you are targeted, ask
> the [Access Now Digital Security Helpline](https://www.accessnow.org/help/) or
> [Amnesty International's Security Lab](https://securitylab.amnesty.org/).

## What it checks

| Where | What |
| --- | --- |
| Chrome and **every app's WebView** (`/data/data/<app>/app_*/Default`) | history, cookies, favicons, connection and HSTS records, Local/Session Storage, Service Worker caches — upstream's browser module, pointed at the Android profiles |
| App HTTP caches (`cache/`, `WebView`, `http-cache`, `okhttp*`, …) | request URLs and bytes of cached responses. A cached response *fetched from* an indicator host is graded `contacted`; a name merely appearing in cached content is `referenced` |
| `/system/etc/hosts` | indicator names mapped to a real address (block entries are protective, not findings) |

Reported as gaps, never as clean: file fingerprints (the published hashes are Windows
files), DNS history, and native-app traffic.

Findings keep upstream's evidence grades. For example a news site's consent-manager
vendor list that names an ad-tech company is `referenced` — a mention, not contact.

## Requirements

* Root with a module manager that runs `service.sh` (KernelSU, ReSukiSU, Magisk). The
  web page needs a manager with WebUI support (KernelSU and forks).
* [Termux](https://termux.dev) with Python: `pkg install python` (3.13 tested). The
  module uses Termux's interpreter; nothing is installed system-wide.
* Developed on a Xiaomi Mi 11 Ultra (HyperOS, Android 14, ReSukiSU).

**Status: pre-release.** Scanning, scheduling, notifications and page generation were
run end to end on that phone from a root shell. Not yet confirmed there: the manager
starting `service.sh` at boot, and the page rendering inside the manager's WebUI (it was
rendered against the real scan data with a DOM stub only).

## Install

1. Build or download `zero-breach-nightly-<version>.zip` and flash it from the
   manager (or `python3 android/build.py` to build it from this checkout).
2. Reboot, or press **Action** on the module once to start the service now.

## Use

* **Web page** — open the module's WebUI button: last result, history, findings
  grouped per file, what could not be checked, the full report, next run, whether a
  newer Zero Breach exists, and a *Scan now* button. The same page is written as
  one self-contained file, `index.html`, next to `latest.txt` in `SHARE_DIR`.
* **Notifications** — only when *new* findings appear, a scan fails, a night is skipped,
  or a new Zero Breach release is out. The same unchanged finding is not repeated every
  night. They are posted through `cmd notification`, i.e. as the Android **Shell** app, and
  the module checks that each one actually appeared. Some ROMs block that app: then the
  web page shows a warning and alerts remain visible only on the page and in the module
  description until you enable *Settings → Apps → Shell → Notifications*.
* **Action button** — starts the service if it is not running, otherwise runs a scan now.
* **Module description** — shows the last result and the next run.

Settings can be changed from the **Settings** card of the web page (time, days, charging
rule, notifications, list update, version check, late window, time limit) or by editing
`config.sh`; both are picked up without a reboot. The page only sends a fixed set of keys
and value shapes, and `set_config.py` checks them again before touching `config.sh`.
`SHARE_DIR` is deliberately file-only. The charging rule applies to scheduled scans; *run now*
always runs.

Settings in `config.sh`:

| Key | Default | Meaning |
| --- | --- | --- |
| `TIME` | `0330` | local start time |
| `DAYS` | `1 2 3 4 5` | active days, 1 = Monday … 7 = Sunday |
| `LATE_H` | `4` | if the phone was off/asleep, still run up to this many hours late, then skip |
| `ONLY_CHARGING` | `1` | start the scheduled scan only while a charger is connected; if it is not, retry every 30 minutes until the late window closes, then skip that night (and say so) |
| `NOTIFY` | `1` | notifications |
| `UPDATE_IOCS` | `1` | refresh the indicator list before each scan (see below) |
| `CHECK_UPSTREAM` | `1` | look for a newer Zero Breach release (notify only) |
| `TIMEOUT_MIN` | `90` | maximum scan time |
| `SHARE_DIR` | `/storage/emulated/0/Download/zero-breach` | where `latest.txt` and `index.html` are written |

A full scan takes about 15 minutes at low CPU priority (and as the first thing the
low-memory killer would take). Data, reports (last 30), state and the log live in
`/data/adb/zero-breach/` and survive module updates.

## How it stays awake and on time

The scheduler sleeps on a `CLOCK_BOOTTIME_ALARM` timer, which wakes the SoC from
suspend at the scheduled moment, holds a kernel wake lock only while a scan runs, and
re-checks the local time at least every six hours (DST, clock changes). No wake lock is
held while idle.

## Trust model

The module runs third-party code as root, so the bundled code is pinned and checkable:

* `android/UPSTREAM_TAG` names the upstream release (`v0.1.8`). `build.py` takes the
  scanner from that git tag, not from the working tree, and writes `MANIFEST.sha256`.
* Before every scan, `android_scan.py --self-check` hashes the bundled upstream files
  against the manifest; on any mismatch the scan is not started and you are notified.
* I verified `v0.1.8` before pinning it: `python build/build.py` on the tag reproduces
  the signed `zero-breach.py` (SHA-256 `74740af2…ef44`), its detached signatures verify
  against the project's published key (fingerprint
  `C24E C92B 12D6 670A 2516 065F 9B4D 5754 99AF A53C`, matching
  <https://archivegenocide.com/verify.html>), and the upstream test suite passes on
  Termux's Python 3.13.
* The scanner runs inside upstream's no-network guard. The only network use is the two
  small, separate steps below; both fail soft.
* `update-iocs.py` (upstream's own updater: HTTPS, published SHA-256, must parse as a
  valid non-empty list, atomic replace, previous copy kept as `.prev`) refreshes the
  indicator list. This is **data**, not code, and is not covered by the release
  signature (see upstream `SIGNING.md`). Set `UPDATE_IOCS=0` to stay on the bundled list.
* The version check asks GitHub's API for the latest upstream release and only
  *tells you*. Updating means: review the new tag, change `android/UPSTREAM_TAG`, run
  `python3 android/build.py`, flash.
* The web page shows scanned strings as text only (no `innerHTML`), under a strict
  Content-Security-Policy, with indicators defanged (`example[.]com`). The WebUI can run
  root commands, so hostile content in a cache must never become markup.

## Changes on top of upstream's v0.1.8 behaviour

Taken from issues and forks of the project:

* skip LevelDB's always-empty `LOCK` file, which otherwise shows up as a false gap while
  an app is running (upstream issue #18);
* describe a locked database as locked and any other read error as what it is, instead
  of "the browser was running" (upstream issue #16 / PR #17);
* a `--self-check` before every run (idea from upstream issue #18).

## Layout

```
android/
  UPSTREAM_TAG      audited upstream release bundled by build.py
  build.py          deterministic zip builder
  module/
    module.prop config.sh common.sh service.sh action.sh customize.sh uninstall.sh
    webroot/        the report page (index.html, app.js, style.css; data.js is generated)
    zb/             android_scan.py  scheduler.py  report_page.py  check_update.py  set_config.py
```

Apache-2.0, like the project this is forked from.
