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

if pywraps_there:
    _idaapi.execute_sync = pywraps.py_execute_sync
    _idaapi.add_hotkey   = pywraps.py_add_hotkey
    _idaapi.del_hotkey   = pywraps.py_del_hotkey

# -----------------------------------------------------------------------
#<pycode(py_kernwin)>
DP_LEFT           = 0x0001
DP_TOP            = 0x0002
DP_RIGHT          = 0x0004
DP_BOTTOM         = 0x0008
DP_INSIDE         = 0x0010
# if not before, then it is after
# (use DP_INSIDE | DP_BEFORE to insert a tab before a given tab)
# this flag alone cannot be used to determine orientation
DP_BEFORE         = 0x0020
# used with combination of other flags
DP_RAW            = 0x0040
DP_FLOATING       = 0x0080

# ----------------------------------------------------------------------
def load_custom_icon(file_name=None, data=None, format=None):
    """
    Loads a custom icon and returns an identifier that can be used with other APIs

    If file_name is passed then the other two arguments are ignored.

    @param file_name: The icon file name
    @param data: The icon data
    @param format: The icon data format

    @return: Icon id or 0 on failure.
             Use free_custom_icon() to free it
    """
    if file_name is not None:
       return _idaapi.py_load_custom_icon_fn(file_name)
    elif not (data is None and format is None):
       return _idaapi.py_load_custom_icon_data(data, format)
    else:
      return 0

# ----------------------------------------------------------------------
def asklong(defval, format):
    res, val = _idaapi._asklong(defval, format)

    if res == 1:
        return val
    else:
        return None

# ----------------------------------------------------------------------
def askaddr(defval, format):
    res, ea = _idaapi._askaddr(defval, format)

    if res == 1:
        return ea
    else:
        return None

# ----------------------------------------------------------------------
def askseg(defval, format):
    res, sel = _idaapi._askseg(defval, format)

    if res == 1:
        return sel
    else:
        return None

#</pycode(py_kernwin)>

# ----------------------------------------------------------------------
from threading import Thread
import time

# ----------------------------------------------------------------------
def myfunction(cnt):
    i = 1
    while i <= cnt:
        print "i=", i
        i += 1
        time.sleep(1)

    print "done!"

def test_thread():
    t = Thread(target=myfunction, args=(2,))

    t.start()
    t.join()

# ----------------------------------------------------------------------
def hotkey_func1():
    print "Hello from hotkey handler in Python!"
