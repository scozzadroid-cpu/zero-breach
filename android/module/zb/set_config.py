#!/usr/bin/env python3
"""Change settings in the module's config.sh (used by the web page).

  set_config.py KEY=VALUE [KEY=VALUE ...]

Only the keys and value shapes listed in RULES are accepted, whatever the caller
sends, because the web page that calls this runs as root through the manager.
Comments in config.sh are kept; the running scheduler is told to reload (SIGHUP).
Exit codes: 0 saved, 2 rejected (nothing is written).
"""

import os
import re
import signal
import sys

CODE = os.path.dirname(os.path.abspath(__file__))
MODDIR = os.path.dirname(CODE)
CONFIG = os.path.join(MODDIR, "config.sh")
PIDFILE = "/data/adb/zero-breach/scheduler.pid"

RULES = {
    "TIME": r"([01]\d|2[0-3])[0-5]\d",
    "DAYS": r"[1-7]( [1-7])*",
    "LATE_H": r"\d|1[0-2]",
    "TIMEOUT_MIN": r"[1-9]\d?|1[0-7]\d|180",
    "ONLY_CHARGING": r"[01]",
    "NOTIFY": r"[01]",
    "UPDATE_IOCS": r"[01]",
    "CHECK_UPSTREAM": r"[01]",
}
QUOTED = {"DAYS"}


def parse(args):
    changes = {}
    for arg in args:
        key, sep, value = arg.partition("=")
        rule = RULES.get(key)
        if not sep or rule is None or not re.fullmatch(rule, value):
            raise ValueError("rejected: {}".format(arg[:40]))
        if key == "DAYS":
            value = " ".join(sorted(set(value.split())))
        changes[key] = value
    if not changes:
        raise ValueError("nothing to change")
    return changes


def apply(changes):
    with open(CONFIG, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    for key, value in changes.items():
        text = '{}="{}"'.format(key, value) if key in QUOTED else "{}={}".format(key, value)
        pattern = re.compile(r'^{}=(?:"[^"]*"|\S*)'.format(key))
        for i, line in enumerate(lines):
            if pattern.match(line):
                lines[i] = pattern.sub(lambda _m: text, line, count=1)
                break
        else:
            lines.append(text)
    tmp = CONFIG + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    os.chmod(tmp, 0o644)
    os.replace(tmp, CONFIG)


def main(argv):
    try:
        changes = parse(argv)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    apply(changes)
    try:
        with open(PIDFILE) as fh:
            os.kill(int(fh.read().strip()), signal.SIGHUP)
    except (OSError, ValueError):
        pass  # scheduler not running: it reads config.sh when it starts
    print("ok " + " ".join("{}={}".format(k, v) for k, v in changes.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
