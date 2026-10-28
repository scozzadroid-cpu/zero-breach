# Zero Breach Nightly: shared paths and helpers for service.sh and action.sh (needs MODDIR)
ZB=/data/adb/zero-breach          # data: reports, state, log, indicator list
CODE=$MODDIR/zb
PY=/data/data/com.termux/files/usr/bin/python3
LOG=$ZB/log.txt
PROP=$MODDIR/module.prop

log() { echo "$(date '+%m-%d %H:%M:%S') $*" >> $LOG; }

# only used before the scheduler (which then maintains the description itself) has started
set_desc() {
  grep -qxF "description=$*" $PROP && return
  { grep -v '^description=' $PROP; echo "description=$*"; } > $PROP.tmp && mv -f $PROP.tmp $PROP
}

running() { [ -s $ZB/scheduler.pid ] && kill -0 "$(cat $ZB/scheduler.pid)" 2>/dev/null; }
