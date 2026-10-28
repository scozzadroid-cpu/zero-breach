echo zero_breach > /sys/power/wake_unlock 2>/dev/null
[ -s /data/adb/zero-breach/scheduler.pid ] && kill "$(cat /data/adb/zero-breach/scheduler.pid)" 2>/dev/null
# data, reports and log stay in /data/adb/zero-breach (delete by hand if not needed)
