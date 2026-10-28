#!/usr/bin/env python3
"""Nightly scheduler for the Android Zero Breach scan.

Started as root by the module's service.sh. It sleeps on a CLOCK_BOOTTIME_ALARM
timerfd, which wakes the phone from suspend, so the scan runs at the configured
time even if the device is asleep. Settings come from the module's config.sh and
are re-read every cycle.

SIGUSR1 runs a scan now (the module's Action button and the web page send it).
SIGHUP re-reads config.sh and rewrites the web page (set_config.py sends it).
SIGUSR2 sends a test notification and records whether it was shown.
A scheduled scan only starts while a charger is connected when ONLY_CHARGING=1; it
keeps waiting for one until the late window closes, then the night is skipped.
"""

import datetime
import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

CODE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CODE)

import check_update  # noqa: E402
import report_page  # noqa: E402

MODDIR = os.path.dirname(CODE)
WEBROOT = os.path.join(MODDIR, "webroot")
PROP = os.path.join(MODDIR, "module.prop")
DATA = "/data/adb/zero-breach"
REPORTS = os.path.join(DATA, "reports")
STATE = os.path.join(DATA, "state.json")
LOG = os.path.join(DATA, "log.txt")
IOCS = os.path.join(DATA, "iocs", "adfection_iocs.txt")
SCAN = os.path.join(CODE, "android_scan.py")
UPDATER = os.path.join(CODE, "upstream", "scan", "update-iocs.py")
WAKELOCK = "zero_breach"
CLOCK_BOOTTIME_ALARM = 9
CLOCK_BOOTTIME = 7
KEEP_REPORTS = 30
LOG_MAX = 256 * 1024
STEM_RE = re.compile(r"^\d{4}-\d\d-\d\d_\d{4}$")

DEFAULTS = {"TIME": "0330", "DAYS": "1 2 3 4 5", "LATE_H": "4", "NOTIFY": "1",
            "ONLY_CHARGING": "1", "UPDATE_IOCS": "1", "CHECK_UPSTREAM": "1", "TIMEOUT_MIN": "90",
            "SHARE_DIR": "/storage/emulated/0/Download/zero-breach"}
DAY_NAMES = {1: "Mon", 2: "Tue", 3: "Wed", 4: "Thu", 5: "Fri", 6: "Sat", 7: "Sun"}


class RunNow(Exception):
    """Raised by SIGUSR1 while the scheduler is waiting."""


class Reload(Exception):
    """Raised by SIGHUP while the scheduler is waiting."""


class TestNotify(Exception):
    """Raised by SIGUSR2 while the scheduler is waiting."""


_waiting = False


def _on_usr1(_sig, _frame):
    if _waiting:
        raise RunNow()


def _on_hup(_sig, _frame):
    if _waiting:
        raise Reload()


def _on_usr2(_sig, _frame):
    if _waiting:
        raise TestNotify()


def _on_term(_sig, _frame):
    wakelock(False)
    raise SystemExit(0)


# --- small helpers -----------------------------------------------------------

def log(msg):
    try:
        if os.path.exists(LOG) and os.path.getsize(LOG) > LOG_MAX:
            os.replace(LOG, LOG + ".1")
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write("{} {}\n".format(time.strftime("%m-%d %H:%M:%S"), msg))
    except OSError:
        pass


def wakelock(on):
    try:
        with open("/sys/power/wake_lock" if on else "/sys/power/wake_unlock", "w") as fh:
            fh.write(WAKELOCK)
    except OSError as exc:
        if on:
            log("WARNING: wake lock not taken: {}".format(exc))


def config():
    cfg = dict(DEFAULTS)
    try:
        with open(os.path.join(MODDIR, "config.sh"), encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"""\s*([A-Z_]+)=(?:"([^"]*)"|'([^']*)'|([^\s#]*))""", line)
                if m:
                    cfg[m.group(1)] = next(g for g in m.groups()[1:] if g is not None)
    except OSError:
        pass
    return cfg


def local_now():
    """Naive local datetime from Android's own date(1), which knows the phone's
    timezone; Termux's Python has no system tz database to ask."""
    out = subprocess.run(["/system/bin/date", "+%Y-%m-%d %H:%M:%S"], capture_output=True,
                         text=True, timeout=10, check=True).stdout.strip()
    return datetime.datetime.strptime(out, "%Y-%m-%d %H:%M:%S")


def alarm_sleep(seconds):
    """Block for `seconds`, waking the SoC from suspend when it expires."""
    global _waiting
    try:
        fd = os.timerfd_create(CLOCK_BOOTTIME_ALARM)
    except OSError as exc:
        log("WARNING: no wake-alarm timer ({}); falling back to a plain timer, the "
            "scan may start late if the phone is asleep".format(exc))
        fd = os.timerfd_create(CLOCK_BOOTTIME)
    try:
        os.timerfd_settime(fd, initial=max(seconds, 0.5))
        _waiting = True
        os.read(fd, 8)
    finally:
        _waiting = False
        os.close(fd)


def load_state():
    try:
        with open(STATE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(state):
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=1)
    os.replace(tmp, STATE)


def set_desc(text):
    """Dynamic module description, shown in the root manager."""
    try:
        with open(PROP, encoding="utf-8") as fh:
            lines = [ln.rstrip("\n") for ln in fh if not ln.startswith("description=")]
        lines.append("description=" + text)
        tmp = PROP + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, PROP)
    except OSError as exc:
        log("module.prop not updated: {}".format(exc))


LAST_NOTIFY = {"ok": None}
SHELL_UID = 2000


def _drop_to_shell():
    """preexec for the notification command: become the Shell user. Termux's Python
    is built without os.setuid and subprocess' user=/group=, so use libc directly."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    for call, args in ((libc.setgroups, (0, None)),
                       (libc.setresgid, (SHELL_UID,) * 3),
                       (libc.setresuid, (SHELL_UID,) * 3)):
        if call(*args) != 0:
            raise OSError(ctypes.get_errno(), "cannot become the Shell user")


def notify(title, text):
    """Post a notification and check it really appeared.

    `cmd notification post` posts on behalf of the calling package. Run as root it
    asks for a package called "root", which does not exist, and the notification
    service drops the request without telling the caller. So the command is run
    as the Shell user (uid 2000), which posts as com.android.shell. The result is
    verified in the active-notification listing (the post is asynchronous)."""
    as_shell = {"preexec_fn": _drop_to_shell} if os.geteuid() == 0 else {}
    try:
        subprocess.run(["/system/bin/cmd", "notification", "post", "-S", "bigtext",
                        "-t", title, "zero_breach", text],
                       capture_output=True, timeout=30, check=True, **as_shell)
        for _ in range(8):
            time.sleep(0.5)
            listing = subprocess.run(["/system/bin/cmd", "notification", "list"],
                                     capture_output=True, text=True, timeout=30).stdout
            if "|zero_breach|" in listing:
                LAST_NOTIFY["ok"] = True
                return True
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        err = (getattr(exc, "stderr", None) or b"")[-300:]
        log("notification failed: {}{}".format(
            str(exc)[:200], " | " + err.decode("utf-8", "replace").strip() if err else ""))
    LAST_NOTIFY["ok"] = False
    log("notification NOT shown (check that notifications are allowed for the Shell app and see logcat NotificationService)")
    return False


_shell_block = {"at": 0.0, "value": None}


def shell_notifications_blocked(max_age=600):
    """Passive check, without posting anything (cached for ten minutes)."""
    if time.time() - _shell_block["at"] < max_age:
        return _shell_block["value"]
    try:
        dump = subprocess.run(["/system/bin/dumpsys", "notification", "--noredact"],
                              capture_output=True, text=True, timeout=60).stdout
        _shell_block["value"] = bool(re.search(
            r"AppSettings: com\.android\.shell \(2000\) importance=NONE", dump))
    except (OSError, subprocess.SubprocessError):
        _shell_block["value"] = None
    _shell_block["at"] = time.time()
    return _shell_block["value"]


def send_test_notification():
    ok = notify("Zero Breach: notifications work",
                "Test message from the module. If you can read this, alerts will reach you.")
    state = load_state()
    state["notify_test"] = {"when": local_now().isoformat(timespec="seconds"), "ok": bool(ok)}
    state["notify_failed"] = not ok
    save_state(state)
    log("test notification: {}".format("shown" if ok else "NOT shown"))


def on_charger(base="/sys/class/power_supply/", suspend_file="/sys/class/qcom-battery/input_suspend"):
    """True while a charger is connected, also when another tool has paused the
    charging current (input_suspend). If nothing can be read, assume yes: a
    phone we cannot judge should still be scanned."""
    def read(path):
        try:
            with open(path) as fh:
                return fh.read().strip()
        except OSError:
            return None

    seen = []
    for name in ("usb", "ac", "wireless", "dc", "main"):
        seen.append(read(base + name + "/online"))
    seen.append(read(base + "battery/status"))
    suspended = read(suspend_file)
    if "1" in seen[:5] or suspended == "1" or seen[5] in ("Charging", "Full"):
        return True
    return all(v is None for v in seen) and suspended is None


EDITABLE = ("TIME", "DAYS", "LATE_H", "TIMEOUT_MIN", "ONLY_CHARGING", "NOTIFY", "UPDATE_IOCS", "CHECK_UPSTREAM")


def fmt_day(dt):
    return "{} {}".format(DAY_NAMES[dt.isoweekday()], dt.strftime("%d %b %H:%M"))


def share_label(cfg):
    return re.sub(r"^/(storage/emulated/0|sdcard)/", "", cfg["SHARE_DIR"].rstrip("/"))


def max_gap_hours(cfg):
    """Longest wait between two scheduled scans, so the page knows when a scan is overdue."""
    days = sorted({int(d) for d in cfg["DAYS"].split() if d.isdigit()})
    if len(days) < 2:
        return 7 * 24
    return max(((days[(i + 1) % len(days)] - days[i]) % 7 or 7) for i in range(len(days))) * 24


def schedule_text(cfg):
    days = sorted(int(d) for d in cfg["DAYS"].split() if d.isdigit())
    names = [DAY_NAMES[d] for d in days if d in DAY_NAMES]
    if days == [1, 2, 3, 4, 5]:
        names = ["Mon-Fri"]
    return "{} at {}:{}".format(", ".join(names) or "no day selected", cfg["TIME"][:2], cfg["TIME"][2:4])


# --- scheduling --------------------------------------------------------------

def pick_slot(now, cfg, last_slot):
    """First configured night slot that is not done yet and not too late."""
    hh, mm = int(cfg["TIME"][:2]), int(cfg["TIME"][2:4])
    days = set(cfg["DAYS"].split())
    late = datetime.timedelta(hours=float(cfg["LATE_H"]))
    for add in range(-1, 9):
        day = now.date() + datetime.timedelta(days=add)
        slot = datetime.datetime.combine(day, datetime.time(hh, mm))
        if str(slot.isoweekday()) not in days or day.isoformat() == last_slot:
            continue
        if now > slot + late:
            continue
        return slot
    return None


def child_env():
    return {"PATH": "/system/bin:/system/xbin", "HOME": DATA,
            "TMPDIR": os.path.join(DATA, "tmp"), "LANG": "C.UTF-8",
            "LD_LIBRARY_PATH": os.path.join(os.path.dirname(os.path.dirname(sys.executable)), "lib")}


def py(*args, **kw):
    return subprocess.run([sys.executable, "-I", "-B", "-X", "utf8"] + list(args),
                          capture_output=True, text=True, env=child_env(), **kw)


def refresh_iocs():
    try:
        shutil.copy2(IOCS, IOCS + ".prev")
        p = py(UPDATER, "--apply", "--local", IOCS, timeout=180)
        lines = [ln for ln in (p.stdout + p.stderr).splitlines() if ln.strip()]
        summary = next((ln for ln in lines if ln.startswith(("change since", "Your indicator", "error"))),
                       lines[-1] if lines else "no output")
        log("IOC refresh rc={}: {}".format(p.returncode, summary))
    except (OSError, subprocess.SubprocessError) as exc:
        log("IOC refresh skipped: {}".format(exc))


def check_upstream(state):
    """Look for a newer Zero Breach release; tell the user once per new version."""
    try:
        res = check_update.check()
    except Exception as exc:  # noqa: BLE001 - never block the scan on this
        log("upstream check failed: {}".format(exc))
        return
    state.update(upstream_latest=res["latest"], upstream_url=res["url"],
                 upstream_newer=res["newer"], upstream_checked=local_now().isoformat(timespec="seconds"))
    log("upstream check: bundled {}, latest {}{}".format(
        res["pinned"], res["latest"], " (NEWER)" if res["newer"] else ""))
    if res["newer"] and state.get("upstream_notified") != res["latest"]:
        state["upstream_notified"] = res["latest"]
        return res
    return None


def prune_reports():
    stems = sorted({f.rsplit(".", 1)[0] for f in os.listdir(REPORTS)
                    if STEM_RE.match(f.rsplit(".", 1)[0])})
    for stem in stems[:-KEEP_REPORTS]:
        for f in os.listdir(REPORTS):
            if f.rsplit(".", 1)[0] == stem:
                os.remove(os.path.join(REPORTS, f))


def publish_text(cfg, txt_path, header):
    """Readable copy of the latest report where the user keeps their files."""
    try:
        os.makedirs(cfg["SHARE_DIR"], exist_ok=True)
        with open(txt_path, encoding="utf-8", errors="replace") as src, \
                open(os.path.join(cfg["SHARE_DIR"], "latest.txt"), "w", encoding="utf-8") as dst:
            dst.write(header + "\n\n" + src.read())
    except OSError as exc:
        log("report not copied to shared storage: {}".format(exc))


def pinned_tag():
    try:
        return check_update.pinned()
    except OSError:
        return "?"


def compose_desc(state, nxt):
    parts = []
    if state.get("last_desc"):
        parts.append(state["last_desc"])
    if state.get("upstream_newer"):
        parts.append("⬆️ Zero Breach {} available".format(state.get("upstream_latest")))
    if nxt:
        parts.append("⏳ next scan " + nxt)
    return " · ".join(parts)


def refresh_page(cfg, state, nxt):
    """Rewrite the web page data (WebUI) and its standalone copy."""
    meta = {
        "generated": local_now().isoformat(timespec="seconds"),
        "pinned": pinned_tag(),
        "latest": state.get("upstream_latest"),
        "newer": bool(state.get("upstream_newer")),
        "update_url": state.get("upstream_url", ""),
        "next": nxt,
        "schedule": schedule_text(cfg),
        "running": state.get("running"),
        "last_error": state.get("last_error"),
        "last_skip": state.get("last_skip"),
        "waiting_for_charger": bool(state.get("deferred_slot")),
        "shell_blocked": bool(shell_notifications_blocked()),
        "notify_failed": bool(state.get("notify_failed")),
        "notify_test": state.get("notify_test"),
        "max_gap_h": max_gap_hours(cfg),
        "config": {k: cfg[k] for k in EDITABLE},
        "set_cmd": "{} -I -B -X utf8 {}".format(sys.executable, os.path.join(CODE, "set_config.py")),
    }
    try:
        report_page.refresh(WEBROOT, REPORTS, cfg["SHARE_DIR"], meta)
    except Exception as exc:  # noqa: BLE001 - the page is never worth a crash
        log("web page not refreshed: {!r}".format(exc))


# --- the scan ------------------------------------------------------------------

def run_scan(slot, cfg, manual):
    now = local_now()
    stem = os.path.join(REPORTS, now.strftime("%Y-%m-%d_%H%M"))
    txt, js, err = stem + ".txt", stem + ".json", stem + ".err"
    state = load_state()
    late = "" if manual or now - slot < datetime.timedelta(minutes=5) else ", late by {}".format(now - slot)
    log("scan start ({}{})".format("manual" if manual else "scheduled " + fmt_day(slot), late))
    state["running"] = now.isoformat(timespec="seconds")
    state["deferred_slot"] = None
    save_state(state)
    refresh_page(cfg, state, None)
    t0 = time.time()
    wakelock(True)
    rc, reason, newer = None, "", None
    try:
        if cfg["UPDATE_IOCS"] == "1":
            refresh_iocs()
        if cfg["CHECK_UPSTREAM"] == "1":
            newer = check_upstream(state)
        try:
            chk = py(SCAN, "--self-check", timeout=120)
            if chk.returncode != 0:
                tail = [ln for ln in chk.stdout.splitlines() if ln.strip()]
                reason = "self-check failed: " + (tail[-2] if len(tail) > 1 else "see log")
                log("self-check failed:\n" + chk.stdout[-800:])
            else:
                with open(txt, "w", encoding="utf-8") as out, open(err, "w", encoding="utf-8") as errf:
                    proc = subprocess.Popen(
                        [sys.executable, "-I", "-B", "-X", "utf8", SCAN, "--iocs", IOCS, "--json", js],
                        stdin=subprocess.DEVNULL, stdout=out, stderr=errf, env=child_env())
                    try:
                        rc = proc.wait(timeout=float(cfg["TIMEOUT_MIN"]) * 60)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                        reason = "stopped after {} min".format(cfg["TIMEOUT_MIN"])
        except (OSError, subprocess.SubprocessError) as exc:
            reason = str(exc)
    finally:
        wakelock(False)
    secs = int(time.time() - t0)

    doc = None
    if rc in (0, 2):
        try:
            with open(js, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            reason = "unreadable report: {}".format(exc)
    elif not reason:
        reason = "exit code {}".format(rc)

    when = now.strftime("%d %b %H:%M")
    state["running"] = None
    if doc is None:
        log("scan FAILED after {}s: {}".format(secs, reason))
        state["last_error"] = {"when": now.isoformat(timespec="seconds"), "reason": reason}
        desc = "⚠️ {} scan failed: {}".format(when, reason)
        if cfg["NOTIFY"] == "1":
            notify("Zero Breach: nightly scan failed",
                   "{}. Details: {}/log.txt".format(reason, DATA))
    else:
        hits = [h for m in doc["modules"].values() for h in m["hits"]]
        serious = [h for h in hits if h["evidence"] != "referenced"]
        prints = sorted({"{}|{}|{}".format(h["indicator"], h["location"], h["evidence"]) for h in hits})
        new = set(prints) - set(state.get("hits", []))
        gaps = len(doc["verdict"]["gaps"])
        age = doc["ioc_set"]["age_days"]
        log("scan done in {}s: {} hit(s), {} serious, {} new, {} gap(s), {} IOCs".format(
            secs, len(hits), len(serious), len(new), gaps, doc["ioc_set"]["count"]))
        state.update(hits=prints, last_ok=now.isoformat(timespec="seconds"), last_error=None)
        header = "Zero Breach {}: scan of {} ({} s) - {} indicators, list is {} days old".format(
            doc["tool"]["version"], now.strftime("%Y-%m-%d %H:%M"), secs, doc["ioc_set"]["count"],
            "?" if age is None else age)
        publish_text(cfg, txt, header)
        label = share_label(cfg)
        if serious:
            desc = "🔴 {} ALERT: {} serious findings - read {}/latest.txt".format(when, len(serious), label)
        elif hits:
            desc = "🟢 {} no threat found; {} harmless mentions in saved content (not an all-clear)".format(when, len(hits))
        else:
            desc = "🟢 {} no known threat found ({} known gaps, not an all-clear)".format(when, gaps)
        if new and cfg["NOTIFY"] == "1":
            if serious:
                notify("Zero Breach: {} findings to review".format(len(serious)),
                       "Scan of {}: {} new findings, {} of them serious. Report: {}/latest.txt".format(
                           when, len(new), len(serious), label))
            else:
                notify("Zero Breach: new mentions",
                       "Scan of {}: {} new mentions in saved content (they do not show contact). "
                       "Report: {}/latest.txt".format(when, len(new), label))
    if newer and cfg["NOTIFY"] == "1":
        notify("Zero Breach: new version {}".format(newer["latest"]),
               "The module bundles {}. It does not update itself: review the release and rebuild the module. {}".format(
                   newer["pinned"], newer["url"]))
    if slot is not None and not manual:
        state["last_slot"] = slot.date().isoformat()
    state["last_desc"] = desc
    if LAST_NOTIFY["ok"] is not None:
        state["notify_failed"] = not LAST_NOTIFY["ok"]
    set_desc(compose_desc(state, None))
    save_state(state)
    refresh_page(cfg, state, None)
    prune_reports()


def main():
    os.makedirs(REPORTS, exist_ok=True)
    os.makedirs(os.path.join(DATA, "tmp"), exist_ok=True)
    os.makedirs(os.path.dirname(IOCS), exist_ok=True)
    if not os.path.exists(IOCS):  # first run: start from the list bundled with the module
        shutil.copy2(os.path.join(CODE, "upstream", "iocs", "adfection_iocs.txt"), IOCS)
    lock = open(os.path.join(DATA, "scheduler.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("scheduler already running", file=sys.stderr)
        return 3
    lock.write(str(os.getpid()))
    lock.flush()
    with open(os.path.join(DATA, "scheduler.pid"), "w") as fh:
        fh.write(str(os.getpid()))
    signal.signal(signal.SIGUSR1, _on_usr1)
    signal.signal(signal.SIGHUP, _on_hup)
    signal.signal(signal.SIGUSR2, _on_usr2)
    signal.signal(signal.SIGTERM, _on_term)
    try:
        with open("/proc/self/oom_score_adj", "w") as fh:
            fh.write("-500")
    except OSError:
        pass
    log("scheduler up (pid {}, python {}, bundled Zero Breach {})".format(
        os.getpid(), sys.version.split()[0], pinned_tag()))
    state = load_state()
    if state.get("running"):  # the previous scheduler died mid-scan
        state["running"] = None
    if shell_notifications_blocked():
        log("WARNING: notifications from the Shell app are blocked on this phone; alerts will only show on the web page and in the module description")
    save_state(state)

    while True:
        cfg = config()
        try:
            now = local_now()
            state = load_state()
            slot = pick_slot(now, cfg, state.get("last_slot"))
            skip_if_window_closed(state, slot, cfg)
            if slot is None:
                set_desc("⏸️ no active day in config.sh")
                refresh_page(cfg, state, None)
                alarm_sleep(3600)
                continue
            wait = (slot - now).total_seconds()
            if wait > 1:
                nxt = fmt_day(slot)
                set_desc(compose_desc(state, nxt))
                refresh_page(cfg, state, nxt)
                alarm_sleep(min(wait, 6 * 3600))
                continue
            if cfg["ONLY_CHARGING"] == "1" and not on_charger():
                if state.get("deferred_slot") != slot.date().isoformat():
                    state["deferred_slot"] = slot.date().isoformat()
                    save_state(state)
                    log("slot {} reached but the phone is not charging; retrying every 30 min until the window closes".format(fmt_day(slot)))
                set_desc("🔌 waiting for a charger to run the {} scan".format(fmt_day(slot)))
                refresh_page(cfg, state, None)
                alarm_sleep(1800)
                continue
            run_scan(slot, cfg, False)
        except RunNow:
            log("manual run requested")
            try:
                run_scan(None, config(), True)
            except Exception as exc:  # noqa: BLE001 - keep the scheduler alive
                log("manual run error: {!r}".format(exc))
        except Reload:
            log("settings changed, reloading")
        except TestNotify:
            send_test_notification()
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001 - keep the scheduler alive
            log("loop error: {!r}".format(exc))
            time.sleep(60)


def skip_if_window_closed(state, slot, cfg):
    """A night whose slot was deferred (not charging) and whose late window has
    now closed is skipped: say so once, in the log, on the page and by notification."""
    day = state.get("deferred_slot")
    if not day or (slot is not None and slot.date().isoformat() == day):
        return
    state["deferred_slot"] = None
    state["last_slot"] = day
    when = datetime.date.fromisoformat(day).strftime("%d %b")
    state["last_skip"] = {"when": day + "T" + cfg["TIME"][:2] + ":" + cfg["TIME"][2:4] + ":00",
                          "reason": "the phone was never on a charger during the window"}
    state["last_desc"] = "⚠️ scan of {} skipped: phone not charging".format(when)
    log("night of {} skipped: never on a charger during the window".format(day))
    if cfg["NOTIFY"] == "1":
        notify("Zero Breach: scan of {} skipped".format(when),
               "The phone was not charging during the night window (ONLY_CHARGING=1). It will try again at the next scheduled night.")
    if LAST_NOTIFY["ok"] is not None:
        state["notify_failed"] = not LAST_NOTIFY["ok"]
    save_state(state)


if __name__ == "__main__":
    raise SystemExit(main())
