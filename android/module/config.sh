# Editable without a reboot (re-read every cycle). Times are HHMM, local time.
TIME=0330          # scan start time
DAYS="1 2 3 4 5"   # active days (1=Mon ... 7=Sun); default Mon-Fri, no Saturday or Sunday
LATE_H=4           # phone off/asleep at the scheduled time: still run up to this many hours late, then skip
ONLY_CHARGING=1    # scheduled scans start only while a charger is connected; otherwise wait for one until the late window closes, then skip the night
NOTIFY=1           # notify on NEW findings, failed scans and new Zero Breach releases
UPDATE_IOCS=1      # refresh the indicator list from GitHub before each scan (validated, never blocking)
CHECK_UPSTREAM=1   # look for a newer Zero Breach release before each scan (notification only, nothing is updated)
TIMEOUT_MIN=90     # maximum scan time
SHARE_DIR=/storage/emulated/0/Download/zero-breach   # where latest.txt and index.html (standalone page) are written
