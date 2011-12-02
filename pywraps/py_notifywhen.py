# -----------------------------------------------------------------------
# Standalone and testing code
import sys
try:
    import pywraps
    pywraps_there = True
    print "Using pywraps"
except:
    pywraps_there = False
    print "Not using pywraps"

try:
    import _idaapi
except:
    print "Please try me from inside IDA"
    sys.exit(0)

import struct

if pywraps_there:
    _idaapi.notify_when = pywraps.notify_when

# -----------------------------------------------------------------------
#<pycode(py_idaapi)>
# The general callback format of notify_when() is:
#    def notify_when_callback(nw_code)
# In the case of NW_OPENIDB, the callback is:
#    def notify_when_callback(nw_code, is_old_database)
NW_OPENIDB    = 0x0001
"""Notify when the database is opened. Its callback is of the form: def notify_when_callback(nw_code, is_old_database)"""
NW_CLOSEIDB   = 0x0002
"""Notify when the database is closed. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_INITIDA    = 0x0004
"""Notify when the IDA starts. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_TERMIDA    = 0x0008
"""Notify when the IDA terminates. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_REMOVE     = 0x0010
"""Use this flag with other flags to uninstall a notifywhen callback"""

#</pycode(py_idaapi)>
# -----------------------------------------------------------------------

def nw_openidb(code, old):
    print "Open IDB, old=", old

def nw_closeidb(code):
    print "Close IDB"

def nw_openclose(code, old = None):
    if code == NW_CLOSEIDB:
        print "openclose: Close IDB"
    elif code == NW_OPENIDB:
        print "openclose: Open IDB, old=", old

def nw_closeida(code):
    import ctypes
    user32 = ctypes.windll.user32
    user32.MessageBoxA(0, "Close IDA", "Info", 0)

print "registering nw_openidb->", _idaapi.notify_when(NW_OPENIDB, nw_openidb)
print "registering nw_closeidb->", _idaapi.notify_when(NW_CLOSEIDB, nw_closeidb)
print "registering nw_openclose->", _idaapi.notify_when(NW_OPENIDB|NW_CLOSEIDB, nw_openclose)
print "registering nw_closeida->", _idaapi.notify_when(NW_TERMIDA, nw_closeida)
