SKIPUNZIP=0
set_perm $MODPATH/service.sh 0 0 0755
set_perm $MODPATH/action.sh 0 0 0755
ui_print "- Zero Breach Nightly: nightly check for the AdFection/Candiru indicators (see config.sh)"
[ -x /data/data/com.termux/files/usr/bin/python3 ] || ui_print "! Termux's Python not found: run 'pkg install python' in Termux"
ui_print "- After a reboot, the report page is the module's WebUI button"
