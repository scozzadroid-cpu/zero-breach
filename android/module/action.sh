#!/system/bin/sh
# Zero Breach Nightly - Action button: start the service if it is not running, otherwise run a scan NOW
MODDIR=${0%/*}
. $MODDIR/common.sh
mkdir -p $ZB

if ! running; then
  setsid sh $MODDIR/service.sh </dev/null >/dev/null 2>&1 &
  sleep 3
  if running; then echo "- Service was not running: started now."; else echo "- Service is starting (waiting for Termux's Python)."; fi
  echo "  Press Action again to run a scan right away."
else
  kill -USR1 "$(cat $ZB/scheduler.pid)" && echo "- Scan started now, in the background."
  echo "  It takes about 15 minutes. The result appears on the module's web page (WebUI) and in latest.txt;"
  echo "  the module description is updated when it ends."
fi
sed -n 's/^description=/- /p' $PROP
