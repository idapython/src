from __future__ import print_function
# -----------------------------------------------------------------------
try:
    import pywraps
    pywraps_there = True
except:
    pywraps_there = False

import _ida_idaapi
import random
import operator
import datetime

#<pycode(py_idaapi)>

__EA64__ = BADADDR == 0xFFFFFFFFFFFFFFFF

import struct
import traceback
import os
import sys
import bisect
try:
    import __builtin__ as builtins
    # This basically mimics six's features (it's not ok to ask the IDAPython runtime to rely on six)
    integer_types = (int, long)
    string_types = (str, unicode)
    long_type = long
except:
    import builtins
    integer_types = (int,)
    string_types = (str,)
    long_type = int
import re

def require(modulename, package=None):
    """
    Load, or reload a module.

    When under heavy development, a user's tool might consist of multiple
    modules. If those are imported using the standard 'import' mechanism,
    there is no guarantee that the Python implementation will re-read
    and re-evaluate the module's Python code. In fact, it usually doesn't.
    What should be done instead is 'reload()'-ing that module.

    This is a simple helper function that will do just that: In case the
    module doesn't exist, it 'import's it, and if it does exist,
    'reload()'s it.

    The importing module (i.e., the module calling require()) will have
    the loaded module bound to its globals(), under the name 'modulename'.
    (If require() is called from the command line, the importing module
    will be '__main__'.)

    For more information, see: <http://www.hexblog.com/?p=749>.
    """
    import inspect
    frame_obj, filename, line_number, function_name, lines, index = inspect.stack()[1]
    importer_module = inspect.getmodule(frame_obj)
    if importer_module is None: # No importer module; called from command line
        importer_module = sys.modules['__main__']
    if modulename in sys.modules.keys():
        m = sys.modules[modulename]
        if sys.version_info.major >= 3:
            import importlib
            importlib.reload(m)
        else:
            reload(m)
        m = sys.modules[modulename]
    else:
        import importlib
        m = importlib.import_module(modulename, package)
        sys.modules[modulename] = m
    setattr(importer_module, modulename, m)

def _replace_module_function(replacement):
    name = replacement.__name__
    modname = replacement.__module__
    assert(name)
    assert(modname)
    mod = sys.modules[modname]
    orig = getattr(mod, name)
    replacement.__doc__ = orig.__doc__
    replacement.__name__ = name
    replacement.__dict__["orig"] = orig
    setattr(mod, name, replacement)

def replfun(func):
    _replace_module_function(func)
    return func


# -----------------------------------------------------------------------

# Seek constants
SEEK_SET = 0 # from the file start
SEEK_CUR = 1 # from the current position
SEEK_END = 2 # from the file end

# Plugin constants
PLUGIN_MOD   = 0x0001
PLUGIN_DRAW  = 0x0002
PLUGIN_SEG   = 0x0004
PLUGIN_UNL   = 0x0008
PLUGIN_HIDE  = 0x0010
PLUGIN_DBG   = 0x0020
PLUGIN_PROC  = 0x0040
PLUGIN_FIX   = 0x0080
PLUGIN_MULTI = 0x0100
PLUGIN_SKIP  = 0
PLUGIN_OK    = 1
PLUGIN_KEEP  = 2

# PyIdc conversion object IDs
PY_ICID_INT64  = 0
"""int64 object"""
PY_ICID_BYREF  = 1
"""byref object"""
PY_ICID_OPAQUE = 2
"""opaque object"""

# Step trace options (used with set_step_trace_options())
ST_OVER_DEBUG_SEG  = 0x01
"""step tracing will be disabled when IP is in a debugger segment"""

ST_OVER_LIB_FUNC    = 0x02
"""step tracing will be disabled when IP is in a library function"""

# -----------------------------------------------------------------------
class pyidc_opaque_object_t(object):
    """This is the base class for all Python<->IDC opaque objects"""
    __idc_cvt_id__ = PY_ICID_OPAQUE

# -----------------------------------------------------------------------
class py_clinked_object_t(pyidc_opaque_object_t):
    """
    This is a utility and base class for C linked objects
    """
    def __init__(self, lnk = None):
        # static link: if a link was provided
        self.__static_clink__ = True if lnk else False

        # Create link if it was not provided
        self.__clink__ = lnk if lnk else self._create_clink()

    def __del__(self):
        """Delete the link upon object destruction (only if not static)"""
        self._free()

    def _free(self):
        """Explicitly delete the link (only if not static)"""
        if not self.__static_clink__ and self.__clink__ is not None:
            self._del_clink(self.__clink__)
            self.__clink__ = None

    def copy(self):
        """Returns a new copy of this class"""

        # Create an unlinked instance
        inst = self.__class__()

        # Assign self to the new instance
        inst.assign(self)

        return inst

    #
    # Methods to be overwritten
    #
    def _create_clink(self):
        """
        Overwrite me.
        Creates a new clink
        @return: PyCapsule representing the C link
        """
        pass

    def _del_clink(self, lnk):
        """
        Overwrite me.
        This method deletes the link
        """
        pass

    def _get_clink_ptr(self):
        """
        Overwrite me.
        Returns the C link pointer as a 64bit number
        """
        pass

    def assign(self, other):
        """
        Overwrite me.
        This method allows you to assign an instance contents to anothers
        @return: Boolean
        """
        pass

    clink = property(lambda self: self.__clink__)
    """Returns the C link as a PyObject"""

    clink_ptr = property(lambda self: self._get_clink_ptr())
    """Returns the C link pointer as a number"""

# -----------------------------------------------------------------------
class object_t(object):
    """Helper class used to initialize empty objects"""
    def __init__(self, **kwds):
        self.__dict__ = kwds

    def __getitem__(self, idx):
        """Allow access to object attributes by index (like dictionaries)"""
        return getattr(self, idx)

# -----------------------------------------------------------------------
def _qvector_front(self):
    return self.at(0)

# -----------------------------------------------------------------------
def _qvector_back(self):
    return self.at((self.size() - 1) if self.size() else 0)

# -----------------------------------------------------------------------
def _bounded_getitem_iterator(self):
    """Helper function, to be set as __iter__ method for qvector-, or array-based classes."""
    for i in range(len(self)):
        yield self[i]

# -----------------------------------------------------------------------
class plugin_t(pyidc_opaque_object_t):
    """Base class for all scripted plugins."""
    def run(self, arg): pass
    def term(self): pass

# -----------------------------------------------------------------------
class plugmod_t(pyidc_opaque_object_t):
    """Base class for all scripted multi-plugins."""
    pass

# -----------------------------------------------------------------------
class pyidc_cvt_helper__(object):
    """
    This is a special helper object that helps detect which kind
    of object is this python object wrapping and how to convert it
    back and from IDC.
    This object is characterized by its special attribute and its value
    """
    def __init__(self, cvt_id, value):
        self.__idc_cvt_id__ = cvt_id
        self.value = value

    def __set_value(self, v):
        self.__idc_cvt_value__ = v
    def __get_value(self):
        return self.__idc_cvt_value__
    value = property(__get_value, __set_value)

# -----------------------------------------------------------------------
class PyIdc_cvt_int64__(pyidc_cvt_helper__):
    """Helper class for explicitly representing VT_INT64 values"""

    def __init__(self, v):
        # id = 0 = int64 object
        super(self.__class__, self).__init__(PY_ICID_INT64, v)

    # operation table
    __op_table = \
    {
        0: lambda a, b: a + b,
        1: lambda a, b: a - b,
        2: lambda a, b: a * b,
        3: lambda a, b: a / b
    }
    # carries the operation given its number
    def __op(self, op_n, other, rev=False):
        a = self.value
        # other operand of same type? then take its value field
        if type(other) == type(self):
            b = other.value
        else:
            b = other
        if rev:
            t = a
            a = b
            b = t
        # construct a new object and return as the result
        return self.__class__(self.__op_table[op_n](a, b))

    # overloaded operators
    def __add__(self, other):  return self.__op(0, other)
    def __sub__(self, other):  return self.__op(1, other)
    def __mul__(self, other):  return self.__op(2, other)
    def __div__(self, other):  return self.__op(3, other)
    def __radd__(self, other): return self.__op(0, other, True)
    def __rsub__(self, other): return self.__op(1, other, True)
    def __rmul__(self, other): return self.__op(2, other, True)
    def __rdiv__(self, other): return self.__op(3, other, True)

# -----------------------------------------------------------------------
class PyIdc_cvt_refclass__(pyidc_cvt_helper__):
    """Helper class for representing references to immutable objects"""
    def __init__(self, v):
        # id = one = byref object
        super(self.__class__, self).__init__(PY_ICID_BYREF, v)

    def cstr(self):
        """Returns the string as a C string (up to the zero termination)"""
        return as_cstr(self.value)

# -----------------------------------------------------------------------
def as_cstr(val):
    """
    Returns a C str from the passed value. The passed value can be of type refclass (returned by a call to buffer() or byref())
    It scans for the first \\x00 and returns the string value up to that point.
    """
    if isinstance(val, PyIdc_cvt_refclass__):
        val = val.value

    n = val.find('\x00')
    return val if n == -1 else val[:n]

# -----------------------------------------------------------------------
def as_UTF16(s):
    """Convenience function to convert a string into appropriate unicode format"""
    # use UTF16 big/little endian, depending on the environment?
    import _ida_ida
    if sys.version_info.major >= 3:
        if type(s) == bytes:
            s = s.decode("UTF-8")
    else:
        s = unicode(s)
    return s.encode("UTF-16" + ("BE" if _ida_ida.cvar.inf.is_be() else "LE"))
as_unicode = as_UTF16

# -----------------------------------------------------------------------
def as_uint32(v):
    """Returns a number as an unsigned int32 number"""
    return v & 0xffffffff

# -----------------------------------------------------------------------
def as_int32(v):
    """Returns a number as a signed int32 number"""
    return as_signed(v, 32)

# -----------------------------------------------------------------------
def as_signed(v, nbits = 32):
    """
    Returns a number as signed. The number of bits are specified by the user.
    The MSB holds the sign.
    """
    return -(( ~v & ((1 << nbits)-1) ) + 1) if v & (1 << nbits-1) else v & ((1 << nbits)-1)

# ----------------------------------------------------------------------
def TRUNC(ea):
    """ Truncate EA for the current application bitness"""
    import _ida_ida
    return (ea & 0xFFFFFFFFFFFFFFFF) if _ida_ida.inf_is_64bit() else (ea & 0xFFFFFFFF)

# ----------------------------------------------------------------------
def copy_bits(v, s, e=-1):
    """
    Copy bits from a value
    @param v: the value
    @param s: starting bit (0-based)
    @param e: ending bit
    """
    # end-bit not specified? use start bit (thus extract one bit)
    if e == -1:
        e = s
    # swap start and end if start > end
    if s > e:
        e, s = s, e

    mask = ~(((1 << (e-s+1))-1) << s)

    return (v & mask) >> s

# ----------------------------------------------------------------------
__struct_unpack_table = {
  1: ('b', 'B'),
  2: ('h', 'H'),
  4: ('l', 'L'),
  8: ('q', 'Q')
}

# ----------------------------------------------------------------------
def struct_unpack(buffer, signed = False, offs = 0):
    """
    Unpack a buffer given its length and offset using struct.unpack_from().
    This function will know how to unpack the given buffer by using the lookup table '__struct_unpack_table'
    If the buffer is of unknown length then None is returned. Otherwise the unpacked value is returned.
    """
    # Supported length?
    n = len(buffer)
    if n not in __struct_unpack_table:
        return None
    # Conver to number
    signed = 1 if signed else 0

    # Unpack
    return struct.unpack_from(__struct_unpack_table[n][signed], buffer, offs)[0]

# ------------------------------------------------------------
def IDAPython_ExecSystem(cmd):
    """
    Executes a command with popen().
    """
    try:
        f = os.popen(cmd, "r")
        s = ''.join(f.readlines())
        f.close()
        return s
    except Exception as e:
        return "%s\n%s" % (str(e), traceback.format_exc())

# ------------------------------------------------------------
def IDAPython_FormatExc(etype, value=None, tb=None, limit=None):
    """
    This function is used to format an exception given the
    values returned by a PyErr_Fetch()
    """
    import traceback
    try:
        return ''.join(traceback.format_exception(etype, value, tb, limit))
    except:
        parts = [str(value)]
        if tb:
            try:
                parts.append("".join(traceback.format_tb(tb)))
            finally:
                pass
        return "\n".join(parts)


# ------------------------------------------------------------
def IDAPython_ExecScript(path, g, print_error=True):
    """
    Run the specified script.

    This function is used by the low-level plugin code.
    """
    path_dir = os.path.dirname(path)
    if len(path_dir) and path_dir not in sys.path:
        sys.path.append(path_dir)

    argv = sys.argv
    sys.argv = [path]

    # Adjust the __file__ path in the globals we pass to the script
    FILE_ATTR = "__file__"
    has__file__ = FILE_ATTR in g
    if has__file__:
        old__file__ = g[FILE_ATTR]
    g[FILE_ATTR] = path

    try:
        if sys.version_info.major >= 3:
            with open(path, "rb") as fin:
                raw = fin.read()
            encoding = "UTF-8" # UTF-8 by default: https://www.python.org/dev/peps/pep-3120/

            # Look for a 'coding' comment
            encoding_pat = re.compile(r'\s*#.*coding[:=]\s*([-\w.]+).*')
            for line in raw.decode("ASCII", errors='replace').split("\n"):
                match = encoding_pat.match(line)
                if match:
                    encoding = match.group(1)
                    break

            code = compile(raw.decode(encoding), path, 'exec')
            exec(code, g)
        else:
            execfile(path, g)
        PY_COMPILE_ERR = None
    except Exception as e:
        PY_COMPILE_ERR = "%s\n%s" % (str(e), traceback.format_exc())
        if print_error:
            print(PY_COMPILE_ERR)
    finally:
        # Restore state
        if has__file__:
            g[FILE_ATTR] = old__file__
        else:
            del g[FILE_ATTR]
        sys.argv = argv

    return PY_COMPILE_ERR

# ------------------------------------------------------------
def IDAPython_LoadProcMod(path, g, print_error=True):
    """
    Load processor module.
    """
    pname = g['__name__'] if g and "__name__" in g else '__main__'
    parent = sys.modules[pname]
    path_dir, path_fname = os.path.split(path)
    procmod_name = os.path.splitext(path_fname)[0]
    procobj = None
    fp = None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(procmod_name, path)
        procmod = importlib.util.module_from_spec(spec)
        sys.modules[procmod_name] = procmod
        spec.loader.exec_module(procmod)
        if parent:
            setattr(parent, procmod_name, procmod)
            # export attrs from parent to processor module
            parent_attrs = getattr(parent, '__all__',
                                   (attr for attr in dir(parent) if not attr.startswith('_')))
            for pa in parent_attrs:
                setattr(procmod, pa, getattr(parent, pa))
            # instantiate processor object
            if getattr(procmod, 'PROCESSOR_ENTRY', None):
                procobj = procmod.PROCESSOR_ENTRY()
        PY_COMPILE_ERR = None
    except Exception as e:
        PY_COMPILE_ERR = "%s\n%s" % (str(e), traceback.format_exc())
        if print_error:
            print(PY_COMPILE_ERR)

    return (PY_COMPILE_ERR, procobj)

# ------------------------------------------------------------
def IDAPython_UnLoadProcMod(script, g, print_error=True):
    """
    Unload processor module.
    """
    pname = g['__name__'] if g and "__name__" in g else '__main__'
    parent = sys.modules[pname]

    script_fname = os.path.split(script)[1]
    procmod_name = os.path.splitext(script_fname)[0]
    if getattr(parent, procmod_name, None):
        delattr(parent, procmod_name)
        del sys.modules[procmod_name]
    PY_COMPILE_ERR = None
    return PY_COMPILE_ERR

# ----------------------------------------------------------------------
class __IDAPython_Completion_Util(object):
    """Internal utility class for auto-completion support"""
    def __init__(self):
        pass

    def debug(self, *args):
        try:
            msg = args[0] % args[1:]
            print("IDAPython_Completion_Util: %s" % msg)
        except Exception as e:
            print("debug() got exception during debug(*args=%s):\n%s" % (
                str(args),
                traceback.format_exc()))

    def dir_namespace(self, m, prefix):
        return [x for x in dir(m) if x.startswith(prefix)]

    def maybe_extend_syntactically(self, ns, name, line, syntax_char):
        to_add = None
        try:
            attr = getattr(ns, name)
            # Is it callable?
            if callable(attr):
                if not line.startswith("?"):
                    to_add = "("
            # Is it iterable?
            elif isinstance(attr, string_types) or getattr(attr, '__iter__', False):
                to_add = "["
        except:
            # self.debug("maybe_extend_syntactically() got an exception:\n%s", traceback.format_exc())
            pass
        if to_add is not None and (syntax_char is None or to_add == syntax_char):
            name += to_add
        return name

    def get_candidates(self, qname, line, match_syntax_char):
        # self.debug("get_candidates(qname=%s, line=%s, match_syntax_char=%s)", qname, line, match_syntax_char)
        results = []
        try:
            ns = sys.modules['__main__']
            parts = qname.split('.')
            # self.debug("get_candidates() got parts: %s", parts)
            for i in range(0, len(parts) - 1):
                ns = getattr(ns, parts[i])
        except Exception as e:
            # self.debug("get_candidates() got exception:\n%s", traceback.format_exc())
            pass
        else:
            # search in the namespace
            last_token = parts[-1]
            results = self.dir_namespace(ns, last_token)
            # self.debug("get_candidates() completions for %s in %s: %s", last_token, ns, results)

            # no completion found? looking from the global scope? then try the builtins
            if not results and len(parts) == 1:
                results = self.dir_namespace(builtins, last_token)
                # self.debug("get_candidates() completions for %s in %s: %s", last_token, builtins, results)

            results = map(lambda r: self.maybe_extend_syntactically(ns, r, line, match_syntax_char), results)
            ns_parts = parts[:-1]
            results = list(map(lambda r: ".".join(ns_parts + [r]), results))
            # self.debug("get_candidates() => '%s'", str(results))
            return results

    QNAME_PAT = re.compile(r"([a-zA-Z_]([a-zA-Z0-9_\.]*)?)")

    def __call__(self, line, x):
        try:
            # self.debug("__call__(line=%s, x=%s)", line, x)
            uline = line.decode("UTF-8") if sys.version_info.major < 3 else line
            result = None

            # Kludge: if the we are past the last char, and that char is syntax:
            #    idaapi.print(
            #                 ^
            # then we want to backtrack to the previous non-syntax char,
            # and then instruct get_candidates() to not extend the match
            # with possible syntax.
            match_syntax_char = None
            if x > 0 and uline[x-1] in "[({":
                match_syntax_char = uline[x-1]
                x -= 1

            # Find what looks like an identifier (possibly qualified)
            for match in re.finditer(self.QNAME_PAT, uline):
                qname, start, end = match.group(1), match.start(1), match.end(1)
                if sys.version_info.major < 3:
                    qname = qname.encode("UTF-8")
                if x >= start and x <= end:
                    result = self.get_candidates(qname, line, match_syntax_char), start, end + (1 if match_syntax_char else 0)

            # self.debug("__call__() => '%s'", str(result))
            return result
        except Exception as e:
            # self.debug("__call__() got exception:\n%s", traceback.format_exc())
            pass

# Instantiate an IDAPython command completion object (for use with IDA's CLI bar)
IDAPython_Completion = __IDAPython_Completion_Util()

def _listify_types(*classes):
    for cls in classes:
        cls.at = cls.__getitem__ # '__getitem__' has bounds checkings
        cls.__len__ = cls.size
        cls.__iter__ = _bounded_getitem_iterator
        cls.append = cls.push_back

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


_notify_when_dispatcher = None

def notify_when(when, callback):
    """
    Register a callback that will be called when an event happens.
    @param when: one of NW_XXXX constants
    @param callback: This callback prototype varies depending on the 'when' parameter:
                     The general callback format:
                         def notify_when_callback(nw_code)
                     In the case of NW_OPENIDB:
                         def notify_when_callback(nw_code, is_old_database)
    @return: Boolean
    """
    global _notify_when_dispatcher
    import ida_idp
    if _notify_when_dispatcher is None:
        _notify_when_dispatcher = ida_idp._notify_when_dispatcher_t()
    return _notify_when_dispatcher.notify_when(when, callback)


# Since version 5.5, PyQt5 doesn't simply print the PyQt exceptions by default
# anymore: https://github.com/baoboa/pyqt5/commit/1e1d8a3ba677ef3e47b916b8a5b9c281d0f8e4b5#diff-848704a82f6a6e3a13112145ce32ac69L63
# The default behavior now is that qFatal() is called, causing the application
# to abort().
# We do not want that to happen in IDA, and simply having a sys.excepthook
# that is different from sys.__excepthook__ is enough for PyQt5 to return
# to the previous behavior
def __install_excepthook():
    real_hook = sys.excepthook
    sys.excepthook = lambda *args: real_hook(*args)
__install_excepthook()


# ------------------------------------------------------------
class IDAPython_displayhook:
    def __init__(self):
        self.orig_displayhook = sys.displayhook

    def format_seq(self, num_printer, storage, item, opn, cls):
        storage.append(opn)
        for idx, el in enumerate(item):
            if idx > 0:
                storage.append(', ')
            self.format_item(num_printer, storage, el)
        storage.append(cls)

    def format_item(self, num_printer, storage, item):
        if item is None or isinstance(item, bool):
            storage.append(repr(item))
        elif isinstance(item, string_types):
            storage.append(format_basestring(item))
        elif isinstance(item, integer_types):
            storage.append(num_printer(item))
        elif isinstance(item, list):
            self.format_seq(num_printer, storage, item, '[', ']')
        elif isinstance(item, tuple):
            self.format_seq(num_printer, storage, item, '(', ')')
        elif isinstance(item, set):
            self.format_seq(num_printer, storage, item, 'set([', '])')
        elif isinstance(item, (dict,)):
            storage.append('{')
            for idx, pair in enumerate(item.items()):
                if idx > 0:
                    storage.append(', ')
                self.format_item(num_printer, storage, pair[0])
                storage.append(": ")
                self.format_item(num_printer, storage, pair[1])
            storage.append('}')
        else:
            storage.append(str(item))

    def _print_hex(self, x):
        return hex(x)

    def displayhook(self, item):
        if item is None or type(item) is bool:
            self.orig_displayhook(item)
            return
        try:
            storage = []
            import ida_idp
            num_printer = self._print_hex
            dn = ida_idp.ph_get_flag() & ida_idp.PR_DEFNUM
            if dn == ida_idp.PRN_OCT:
                num_printer = oct
            elif dn == ida_idp.PRN_DEC:
                num_printer = str
            elif dn == ida_idp.PRN_BIN:
                num_printer = bin
            self.format_item(num_printer, storage, item)
            sys.stdout.write("%s\n" % "".join(storage))
        except:
            import traceback
            traceback.print_exc()
            self.orig_displayhook(item)

_IDAPython_displayhook = IDAPython_displayhook()
sys.displayhook = _IDAPython_displayhook.displayhook

def _make_one_time_warning_message(bad_attr, new_attr):
    warned = [False]
    def f():
        if not warned[0]:
            import traceback
            # skip two frames to get the actual line which triggered the  access
            f = sys._getframe().f_back.f_back
            traceback.print_stack(f)
            print("Please use \"%s\" instead of \"%s\" (\"%s\" is kept for backward-compatibility, and will be removed soon.)" % (new_attr, bad_attr, bad_attr))
            warned[0] = True
    return f

def _make_missed_695bwcompat_property(bad_attr, new_attr, has_setter):
    _notify_bwcompat = _make_one_time_warning_message(bad_attr, new_attr)
    def _getter(self):
        _notify_bwcompat()
        return getattr(self, new_attr)
    def _setter(self, v):
        _notify_bwcompat()
        return setattr(self, new_attr, v)
    return property(_getter, _setter if has_setter else None)



#</pycode(py_idaapi)>
