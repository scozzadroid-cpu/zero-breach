#!/system/bin/sh
# Zero Breach Nightly: starts the scheduler of the nightly scan (see config.sh).
# The scheduler sleeps on an alarm that wakes the phone, so no wake lock is held while idle.
MODDIR=${0%/*}
. $MODDIR/common.sh
mkdir -p $ZB
running && exit 0   # already running (for example started from Action)

set_desc "⏳ waiting for boot to finish"
# Python lives in Termux's storage, which stays encrypted until the first unlock after boot
until [ "$(getprop sys.boot_completed)" = 1 ] && [ "$(getprop sys.user.0.ce_available)" = true ] && [ -x $PY ]; do sleep 10; done

export HOME=$ZB TMPDIR=$ZB/tmp LANG=C.UTF-8
while true; do
  $PY -I -B -X utf8 $CODE/scheduler.py >> $ZB/daemon.out 2>&1
  rc=$?
  [ $rc = 3 ] && exit 0   # another scheduler is already running
  log "scheduler exited (rc=$rc), restarting in 60s"
  sleep 60
done
