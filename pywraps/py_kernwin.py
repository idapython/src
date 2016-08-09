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
DP_TAB            = 0x0040
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
       return _ida_kernwin.py_load_custom_icon_fn(file_name)
    elif not (data is None and format is None):
       return _ida_kernwin.py_load_custom_icon_data(data, format)
    else:
      return 0

# ----------------------------------------------------------------------
def asklong(defval, format):
    res, val = _ida_kernwin._asklong(defval, format)

    if res == 1:
        return val
    else:
        return None

# ----------------------------------------------------------------------
def askaddr(defval, format):
    res, ea = _ida_kernwin._askaddr(defval, format)

    if res == 1:
        return ea
    else:
        return None

# ----------------------------------------------------------------------
def askseg(defval, format):
    res, sel = _ida_kernwin._askseg(defval, format)

    if res == 1:
        return sel
    else:
        return None

# ----------------------------------------------------------------------
class action_handler_t(object):
    def __init__(self):
        pass

    def activate(self, ctx):
	return 0

    def update(self, ctx):
        pass

#</pycode(py_kernwin)>
