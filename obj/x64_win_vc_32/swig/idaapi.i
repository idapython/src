%module(docstring="IDA Plugin SDK API wrapper: idaapi",directors="1",threads="1") ida_idaapi
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_IDAAPI
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_IDAAPI
  #define HAS_DEP_ON_INTERFACE_IDAAPI
#endif
%include "header.i"
%{
#include <loader.hpp>
#include <diskio.hpp>
%}

%{
#include <Python.h>

#ifdef HAVE_SSIZE_T
#define _SSIZE_T_DEFINED 1
#endif

//<code(py_idaapi)>
//-------------------------------------------------------------------------
#define GET_THIS() py_customidamemo_t *_this = view_extract_this<py_customidamemo_t>(self)
#define CHK_THIS()                                                      \
  GET_THIS();                                                           \
  if ( _this == NULL )                                                  \
    return;
#define CHK_THIS_OR_NULL()                                              \
  GET_THIS();                                                           \
  if ( _this == NULL )                                                  \
    return NULL;
#define CHK_THIS_OR_NONE()                                              \
  GET_THIS();                                                           \
  if ( _this == NULL )                                                  \
    Py_RETURN_NONE


//-------------------------------------------------------------------------
void pygc_refresh(PyObject *self)
{
  CHK_THIS();
  _this->refresh();
}

//-------------------------------------------------------------------------
void pygc_set_node_info(PyObject *self, PyObject *py_node_idx, PyObject *py_node_info, PyObject *py_flags)
{
  CHK_THIS();
  _this->set_node_info(py_node_idx, py_node_info, py_flags);
}

//-------------------------------------------------------------------------
void pygc_set_nodes_infos(PyObject *self, PyObject *values)
{
  CHK_THIS();
  _this->set_nodes_infos(values);
}

//-------------------------------------------------------------------------
PyObject *pygc_get_node_info(PyObject *self, PyObject *py_node_idx)
{
  GET_THIS();
  if ( _this != NULL )
    return _this->get_node_info(py_node_idx);
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
void pygc_del_nodes_infos(PyObject *self, PyObject *py_nodes)
{
  CHK_THIS();
  _this->del_nodes_infos(py_nodes);
}

//-------------------------------------------------------------------------
PyObject *pygc_get_current_renderer_type(PyObject *self)
{
  GET_THIS();
  if ( _this != NULL )
    return _this->get_current_renderer_type();
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
void pygc_set_current_renderer_type(PyObject *self, PyObject *py_rt)
{
  CHK_THIS();
  _this->set_current_renderer_type(py_rt);
}

//-------------------------------------------------------------------------
PyObject *pygc_create_groups(PyObject *self, PyObject *groups_infos)
{
  CHK_THIS_OR_NONE();
  return _this->create_groups(groups_infos);
}

//-------------------------------------------------------------------------
PyObject *pygc_delete_groups(PyObject *self, PyObject *groups, PyObject *new_current)
{
  CHK_THIS_OR_NONE();
  return _this->delete_groups(groups, new_current);
}

//-------------------------------------------------------------------------
PyObject *pygc_set_groups_visibility(PyObject *self, PyObject *groups, PyObject *expand, PyObject *new_current)
{
  CHK_THIS_OR_NONE();
  return _this->set_groups_visibility(groups, expand, new_current);
}

//-------------------------------------------------------------------------
TWidget *pycim_get_widget(PyObject *self)
{
  CHK_THIS_OR_NULL();
  TWidget *widget = NULL;
  if ( !pycim_lookup_info.find_by_py_view(&widget, _this) )
    return NULL;
  return widget;
}

//-------------------------------------------------------------------------
void pycim_view_close(PyObject *self)
{
  CHK_THIS();
  delete _this;
}

#undef CHK_THIS_OR_NONE
#undef CHK_THIS_OR_NULL
#undef CHK_THIS
#undef GET_THIS
//</code(py_idaapi)>
%}

%constant ea_t BADADDR = ea_t(-1);
%constant sel_t BADSEL = sel_t(-1);
%constant size_t SIZE_MAX = size_t(-1);
/* %constant nodeidx_t BADNODE = nodeidx_t(-1); */

%include "typemaps.i"

%include "cstring.i"
%include "carrays.i"
%include "cpointer.i"

%pythoncode %{
#<pycode(py_idaapi)>

__EA64__ = BADADDR == 0xFFFFFFFFFFFFFFFF

import struct
import traceback
import os
import sys
import bisect
import __builtin__
import imp
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
        reload(sys.modules[modulename])
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
PLUGIN_MOD  = 0x0001
PLUGIN_DRAW = 0x0002
PLUGIN_SEG  = 0x0004
PLUGIN_UNL  = 0x0008
PLUGIN_HIDE = 0x0010
PLUGIN_DBG  = 0x0020
PLUGIN_PROC = 0x0040
PLUGIN_FIX  = 0x0080
PLUGIN_SKIP = 0
PLUGIN_OK   = 1
PLUGIN_KEEP = 2

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
        @return: PyCObject representing the C link
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
    It scans for the first \x00 and returns the string value up to that point.
    """
    if isinstance(val, PyIdc_cvt_refclass__):
        val = val.value

    n = val.find('\x00')
    return val if n == -1 else val[:n]

# -----------------------------------------------------------------------
def as_unicode(s):
    """Convenience function to convert a string into appropriate unicode format"""
    # use UTF16 big/little endian, depending on the environment?
    import _ida_ida
    return unicode(s).encode("UTF-16" + ("BE" if _ida_ida.cvar.inf.is_be() else "LE"))

# -----------------------------------------------------------------------
def as_uint32(v):
    """Returns a number as an unsigned int32 number"""
    return v & 0xffffffff

# -----------------------------------------------------------------------
def as_int32(v):
    """Returns a number as a signed int32 number"""
    return -((~v & 0xffffffff)+1)

# -----------------------------------------------------------------------
def as_signed(v, nbits = 32):
    """
    Returns a number as signed. The number of bits are specified by the user.
    The MSB holds the sign.
    """
    return -(( ~v & ((1 << nbits)-1) ) + 1) if v & (1 << nbits-1) else v

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
try:
    "".decode("UTF-8").encode("mbcs")
    has_mbcs = True
except:
    has_mbcs = False

def _utf8_native(utf8):
    if has_mbcs:
        uni = utf8.decode("UTF-8")
        return uni.encode("mbcs")
    else:
        return utf8

# ------------------------------------------------------------
def IDAPython_ExecSystem(cmd):
    """
    Executes a command with popen().
    """
    try:
        cmd = _utf8_native(cmd)
        f = os.popen(cmd, "r")
        s = ''.join(f.readlines())
        f.close()
        return s
    except Exception as e:
        return "%s\n%s" % (str(e), traceback.format_exc())

# ------------------------------------------------------------
def IDAPython_FormatExc(etype, value, tb, limit=None):
    """
    This function is used to format an exception given the
    values returned by a PyErr_Fetch()
    """
    try:
        return ''.join(traceback.format_exception(etype, value, tb, limit))
    except:
        return str(value)


# ------------------------------------------------------------
def IDAPython_ExecScript(script, g, print_error=True):
    """
    Run the specified script.
    It also addresses http://code.google.com/p/idapython/issues/detail?id=42

    This function is used by the low-level plugin code.
    """
    script = _utf8_native(script)
    scriptpath = os.path.dirname(script)
    if len(scriptpath) and scriptpath not in sys.path:
        sys.path.append(scriptpath)

    argv = sys.argv
    sys.argv = [ script ]

    # Adjust the __file__ path in the globals we pass to the script
    old__file__ = g['__file__'] if '__file__' in g else ''
    g['__file__'] = script

    try:
        execfile(script, g)
        PY_COMPILE_ERR = None
    except Exception as e:
        PY_COMPILE_ERR = "%s\n%s" % (str(e), traceback.format_exc())
        if print_error:
            print(PY_COMPILE_ERR)
    finally:
        # Restore state
        g['__file__'] = old__file__
        sys.argv = argv

    return PY_COMPILE_ERR

# ------------------------------------------------------------
def IDAPython_LoadProcMod(script, g, print_error=True):
    """
    Load processor module.
    """
    script = _utf8_native(script)
    pname = g['__name__'] if g and "__name__" in g else '__main__'
    parent = sys.modules[pname]

    scriptpath, scriptname = os.path.split(script)
    if len(scriptpath) and scriptpath not in sys.path:
        sys.path.append(scriptpath)

    procmod_name = os.path.splitext(scriptname)[0]
    procobj = None
    fp = None
    try:
        fp, pathname, description = imp.find_module(procmod_name)
        procmod = imp.load_module(procmod_name, fp, pathname, description)
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
    finally:
        if fp: fp.close()

    sys.path.remove(scriptpath)

    return (PY_COMPILE_ERR, procobj)

# ------------------------------------------------------------
def IDAPython_UnLoadProcMod(script, g, print_error=True):
    """
    Unload processor module.
    """
    script = _utf8_native(script)
    pname = g['__name__'] if g and "__name__" in g else '__main__'
    parent = sys.modules[pname]

    scriptname = os.path.split(script)[1]
    procmod_name = os.path.splitext(scriptname)[0]
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
            elif isinstance(attr, basestring) or getattr(attr, '__iter__', False):
                to_add = "["
        except:
            # self.debug("maybe_extend_syntactically() got an exception:\n%s", traceback.format_exc())
            pass
        if to_add is not None and (syntax_char is None or to_add == syntax_char):
            name += to_add
        return name

    def get_candidates(self, qname, line, match_syntax_char):
        # self.debug("get_candidates(qname=%s, line=%s, has_syntax=%s)", qname, line, has_syntax)
        results = []
        try:
            ns = sys.modules['__main__']
            parts = qname.split('.')
            # self.debug("get_candidates() got parts: %s", parts)
            for i in xrange(0, len(parts) - 1):
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
                results = self.dir_namespace(__builtin__, last_token)
                # self.debug("get_candidates() completions for %s in %s: %s", last_token, __builtin__, results)

            results = map(lambda r: self.maybe_extend_syntactically(ns, r, line, match_syntax_char), results)
            ns_parts = parts[:-1]
            results = map(lambda r: ".".join(ns_parts + [r]), results)
            # self.debug("get_candidates() => '%s'", str(results))
            return results

    QNAME_PAT = re.compile(r"([a-zA-Z_]([a-zA-Z0-9_\.]*)?)")

    def __call__(self, line, x):
        try:
            # self.debug("__call__(line=%s, x=%s)", line, x)
            uline = line.decode("UTF-8")
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
                qname, start, end = match.group(1).encode("UTF-8"), match.start(1), match.end(1)
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


# ----------------------------------- helpers for bw-compat w/ 6.95 API
class __BC695:
    def __init__(self):
        self.FIXME = "FIXME @arnaud"

    def false_p(self, *args):
        return False

    def identity(self, arg):
        return arg

    def dummy(self, *args):
        pass

    def replace_fun(self, new):
        new.__dict__["bc695redef"] = True
        _replace_module_function(new)

_BC695 = __BC695()
#</pycode(py_idaapi)>
%}


%inline %{
//<inline(py_idaapi)>


//------------------------------------------------------------------------
/*
#<pydoc>
def parse_command_line(cmdline):
    """
    Parses a space separated string (quotes and escape character are supported)
    @param cmdline: The command line to parse
    @return: A list of strings or None on failure
    """
    pass
#</pydoc>
*/
static PyObject *py_parse_command_line(const char *cmdline)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstrvec_t args;
  if ( parse_command_line(&args, NULL, cmdline, LP_PATH_WITH_ARGS) == 0 )
    Py_RETURN_NONE;
  return qstrvec2pylist(args);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_inf_structure():
    """
    Returns the global variable 'inf' (an instance of idainfo structure, see ida.hpp)
    """
    pass
#</pydoc>
*/
idainfo *get_inf_structure(void)
{
  return &inf;
}

//-------------------------------------------------------------------------
// Declarations from Python.cpp
/*
#<pydoc>
def set_script_timeout(timeout):
    """
    Changes the script timeout value. The script wait box dialog will be hidden and shown again when the timeout elapses.
    See also L{disable_script_timeout}.

    @param timeout: This value is in seconds.
                    If this value is set to zero then the script will never timeout.
    @return: Returns the old timeout value
    """
    pass
#</pydoc>
*/
idaman int ida_export set_script_timeout(int timeout);

/*
#<pydoc>
def disable_script_timeout():
    """
    Disables the script timeout and hides the script wait box.
    Calling L{set_script_timeout} will not have any effects until the script is compiled and executed again

    @return: None
    """
    pass
#</pydoc>
*/
idaman void ida_export disable_script_timeout();


/*
#<pydoc>
def enable_extlang_python(enable):
    """
    Enables or disables Python extlang.
    When enabled, all expressions will be evaluated by Python.
    @param enable: Set to True to enable, False otherwise
    """
    pass
#</pydoc>
*/
idaman void ida_export enable_extlang_python(bool enable);
idaman void ida_export enable_python_cli(bool enable);

/*
#<pydoc>
def RunPythonStatement(stmt):
    """
    This is an IDC function exported from the Python plugin.
    It is used to evaluate Python statements from IDC.
    @param stmt: The statement to evaluate
    @return: 0 - on success otherwise a string containing the error
    """
    pass
#</pydoc>
*/

//------------------------------------------------------------------------
/*
#<pydoc>
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
    pass
#</pydoc>
*/
static bool notify_when(int when, PyObject *py_callable)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return PyCallable_Check(py_callable) && add_notify_when(when, py_callable);
}

void pygc_refresh(PyObject *self);
void pygc_set_node_info(PyObject *self, PyObject *py_node_idx, PyObject *py_node_info, PyObject *py_flags);
void pygc_set_nodes_infos(PyObject *self, PyObject *values);
PyObject *pygc_get_node_info(PyObject *self, PyObject *py_node_idx);
void pygc_del_nodes_infos(PyObject *self, PyObject *py_nodes);
PyObject *pygc_get_current_renderer_type(PyObject *self);
void pygc_set_current_renderer_type(PyObject *self, PyObject *py_rt);
PyObject *pygc_create_groups(PyObject *self, PyObject *groups_infos);
PyObject *pygc_delete_groups(PyObject *self, PyObject *groups, PyObject *new_current);
PyObject *pygc_set_groups_visibility(PyObject *self, PyObject *groups, PyObject *expand, PyObject *new_current);
TWidget *pycim_get_widget(PyObject *self);
void pycim_view_close(PyObject *self);
//</inline(py_idaapi)>
%}

//-------------------------------------------------------------------------
%inline %{
//<inline(py_idaapi_loader_input)>
/*
#<pydoc>
class loader_input_t(pyidc_opaque_object_t):
    """A helper class to work with linput_t related functions.
    This class is also used by file loaders scripts.
    """
    def __init__(self):
        pass

    def close(self):
        """Closes the file"""
        pass

    def open(self, filename, remote = False):
        """Opens a file (or a remote file)
        @return: Boolean
        """
        pass

    def set_linput(self, linput):
        """Links the current loader_input_t instance to a linput_t instance"""
        pass

    @staticmethod
    def from_fp(fp):
        """A static method to construct an instance from a FILE*"""
        pass

    def open_memory(self, start, size):
        """Create a linput for process memory (By internally calling idaapi.create_memory_linput())
        This linput will use dbg->read_memory() to read data
        @param start: starting address of the input
        @param size: size of the memory range to represent as linput
                    if unknown, may be passed as 0
        """
        pass

    def seek(self, pos, whence = SEEK_SET):
        """Set input source position
        @return: the new position (not 0 as fseek!)
        """
        pass

    def tell(self):
        """Returns the current position"""
        pass

    def getz(self, sz, fpos = -1):
        """Returns a zero terminated string at the given position
        @param sz: maximum size of the string
        @param fpos: if != -1 then seek will be performed before reading
        @return: The string or None on failure.
        """
        pass

    def gets(self, len):
        """Reads a line from the input file. Returns the read line or None"""
        pass

    def read(self, size):
        """Reads from the file. Returns the buffer or None"""
        pass

    def readbytes(self, size, big_endian):
        """Similar to read() but it respect the endianness"""
        pass

    def file2base(self, pos, ea1, ea2, patchable):
        """
        Load portion of file into the database
        This function will include (ea1..ea2) into the addressing space of the
        program (make it enabled)
        @param li: pointer ot input source
        @param pos: position in the file
        @param (ea1..ea2): range of destination linear addresses
        @param patchable: should the kernel remember correspondance of
                          file offsets to linear addresses.
        @return: 1-ok,0-read error, a warning is displayed
        """
        pass

    def get_char(self):
        """Reads a single character from the file. Returns None if EOF or the read character"""
        pass

    def opened(self):
        """Checks if the file is opened or not"""
        pass
#</pydoc>
*/
class loader_input_t
{
private:
  linput_t *li;
  int own;
  qstring fn;
  enum
  {
    OWN_NONE    = 0, // li not created yet
    OWN_CREATE  = 1, // Owns li because we created it
    OWN_FROM_LI = 2, // No ownership we borrowed the li from another class
    OWN_FROM_FP = 3, // We got an li instance from an fp instance, we have to unmake_linput() on Close
  };

  //--------------------------------------------------------------------------
  void _from_cobject(PyObject *pycobject)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    this->set_linput((linput_t *)PyCObject_AsVoidPtr(pycobject));
  }

  //--------------------------------------------------------------------------
  void assign(const loader_input_t &rhs)
  {
    fn = rhs.fn;
    li = rhs.li;
    own = OWN_FROM_LI;
  }

  //--------------------------------------------------------------------------
  loader_input_t(const loader_input_t &rhs)
  {
    assign(rhs);
  }
public:
  // Special attribute that tells the pyvar_to_idcvar how to convert this
  // class from and to IDC. The value of this variable must be set to two
  int __idc_cvt_id__;
  //--------------------------------------------------------------------------
  loader_input_t(PyObject *pycobject = NULL): li(NULL), own(OWN_NONE), __idc_cvt_id__(PY_ICID_OPAQUE)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( pycobject != NULL && PyCapsule_IsValid(pycobject, VALID_CAPSULE_NAME) )
      _from_cobject(pycobject);
  }

  //--------------------------------------------------------------------------
  void close()
  {
    if ( li == NULL )
      return;

    PYW_GIL_GET;
    Py_BEGIN_ALLOW_THREADS;
    if ( own == OWN_CREATE )
      close_linput(li);
    else if ( own == OWN_FROM_FP )
      unmake_linput(li);
    Py_END_ALLOW_THREADS;
    li = NULL;
    own = OWN_NONE;
  }

  //--------------------------------------------------------------------------
  ~loader_input_t()
  {
    close();
  }

  //--------------------------------------------------------------------------
  bool open(const char *filename, bool remote = false)
  {
    close();
    PYW_GIL_GET;
    Py_BEGIN_ALLOW_THREADS;
    li = open_linput(filename, remote);
    if ( li != NULL )
    {
      // Save file name
      fn = filename;
      own = OWN_CREATE;
    }
    Py_END_ALLOW_THREADS;
    return li != NULL;
  }

  //--------------------------------------------------------------------------
  void set_linput(linput_t *linput)
  {
    close();
    own = OWN_FROM_LI;
    li = linput;
    fn.sprnt("<linput_t * %p>", linput);
  }

  //--------------------------------------------------------------------------
  static loader_input_t *from_linput(linput_t *linput)
  {
    loader_input_t *l = new loader_input_t();
    l->set_linput(linput);
    return l;
  }

  //--------------------------------------------------------------------------
  // This method can be used to pass a linput_t* from C code
  static loader_input_t *from_cobject(PyObject *pycobject)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( !PyCapsule_IsValid(pycobject, VALID_CAPSULE_NAME) )
      return NULL;
    loader_input_t *l = new loader_input_t();
    l->_from_cobject(pycobject);
    return l;
  }

  //--------------------------------------------------------------------------
  static loader_input_t *from_fp(FILE *fp)
  {
    PYW_GIL_GET;
    loader_input_t *l = NULL;
    Py_BEGIN_ALLOW_THREADS;
    linput_t *fp_li = make_linput(fp);
    if ( fp_li != NULL )
    {
      l = new loader_input_t();
      l->own = OWN_FROM_FP;
      l->fn.sprnt("<FILE * %p>", fp);
      l->li = fp_li;
    }
    Py_END_ALLOW_THREADS;
    return l;
  }

  //--------------------------------------------------------------------------
  linput_t *get_linput()
  {
    return li;
  }

  //--------------------------------------------------------------------------
  bool open_memory(ea_t start, asize_t size = 0)
  {
    PYW_GIL_GET;
    linput_t *l;
    Py_BEGIN_ALLOW_THREADS;
    l = create_memory_linput(start, size);
    if ( l != NULL )
    {
      close();
      li = l;
      fn = "<memory>";
      own = OWN_CREATE;
    }
    Py_END_ALLOW_THREADS;
    return l != NULL;
  }

  //--------------------------------------------------------------------------
  int64 seek(int64 pos, int whence = SEEK_SET)
  {
    int64 r;
    PYW_GIL_GET;
    Py_BEGIN_ALLOW_THREADS;
    r = qlseek(li, pos, whence);
    Py_END_ALLOW_THREADS;
    return r;
  }

  //--------------------------------------------------------------------------
  int64 tell()
  {
    int64 r;
    PYW_GIL_GET;
    Py_BEGIN_ALLOW_THREADS;
    r = qltell(li);
    Py_END_ALLOW_THREADS;
    return r;
  }

  //--------------------------------------------------------------------------
  PyObject *getz(size_t sz, int64 fpos = -1)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    do
    {
      char *buf = (char *) malloc(sz + 5);
      if ( buf == NULL )
        break;
      Py_BEGIN_ALLOW_THREADS;
      qlgetz(li, fpos, buf, sz);
      Py_END_ALLOW_THREADS;
      PyObject *ret = IDAPyStr_FromUTF8(buf);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  PyObject *gets(size_t len)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    do
    {
      char *buf = (char *) malloc(len + 5);
      if ( buf == NULL )
        break;
      bool ok;
      Py_BEGIN_ALLOW_THREADS;
      ok = qlgets(buf, len, li) != NULL;
      Py_END_ALLOW_THREADS;
      if ( !ok )
        buf[0] = '\0';
      PyObject *ret = IDAPyStr_FromUTF8(buf);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  PyObject *read(size_t size)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    do
    {
      char *buf = (char *) malloc(size + 5);
      if ( buf == NULL )
        break;
      ssize_t r;
      Py_BEGIN_ALLOW_THREADS;
      r = qlread(li, buf, size);
      Py_END_ALLOW_THREADS;
      if ( r == -1 )
        r = 0;
      PyObject *ret = IDAPyStr_FromUTF8AndSize(buf, r);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  bool opened()
  {
    return li != NULL;
  }

  //--------------------------------------------------------------------------
  PyObject *readbytes(size_t size, bool big_endian)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    do
    {
      char *buf = (char *) malloc(size + 5);
      if ( buf == NULL )
        break;
      int r;
      Py_BEGIN_ALLOW_THREADS;
      r = lreadbytes(li, buf, size, big_endian);
      Py_END_ALLOW_THREADS;
      if ( r == -1 )
        r = 0;
      PyObject *ret = IDAPyStr_FromUTF8AndSize(buf, r);
      free(buf);
      return ret;
    } while ( false );
    Py_RETURN_NONE;
  }

  //--------------------------------------------------------------------------
  int file2base(int64 pos, ea_t ea1, ea_t ea2, int patchable)
  {
    int rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = ::file2base(li, pos, ea1, ea2, patchable);
    Py_END_ALLOW_THREADS;
    return rc;
  }

  //--------------------------------------------------------------------------
  int64 size()
  {
    int64 rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = qlsize(li);
    Py_END_ALLOW_THREADS;
    return rc;
  }

  //--------------------------------------------------------------------------
  PyObject *filename()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    return IDAPyStr_FromUTF8(fn.c_str());
  }

  //--------------------------------------------------------------------------
  PyObject *get_char()
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    int ch;
    Py_BEGIN_ALLOW_THREADS;
    ch = qlgetc(li);
    Py_END_ALLOW_THREADS;
    if ( ch == EOF )
      Py_RETURN_NONE;
    return Py_BuildValue("c", ch);
  }
};
//</inline(py_idaapi_loader_input)>
%}
%pythoncode %{
if _BC695:
    pycim_get_tcustom_control=pycim_get_widget
    pycim_get_tform=pycim_get_widget

%}