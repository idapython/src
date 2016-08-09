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

import struct
import traceback
import os
import sys
import bisect
import __builtin__
import imp

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

    For more information, see: <http://www.hexblog.com/?p=749>.
    """
    if modulename in sys.modules.keys():
        reload(sys.modules[modulename])
    else:
        import importlib
        import inspect
        m = importlib.import_module(modulename, package)
        frame_obj, filename, line_number, function_name, lines, index = inspect.stack()[1]
        importer_module = inspect.getmodule(frame_obj)
        if importer_module is None: # No importer module; called from command line
            importer_module = sys.modules['__main__']
        setattr(importer_module, modulename, m)
        sys.modules[modulename] = m

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
    return unicode(s).encode("UTF-16" + ("BE" if _ida_ida.cvar.inf.mf else "LE"))

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
    pname = g['__name__'] if g and g.has_key("__name__") else '__main__'
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
    pname = g['__name__'] if g and g.has_key("__name__") else '__main__'
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
        self.n = 0
        self.completion = None
        self.lastmodule = None

    @staticmethod
    def parse_identifier(line, prefix, prefix_start):
        """
        Parse a line and extracts identifier
        """
        id_start = prefix_start
        while id_start > 0:
            ch = line[id_start]
            if not ch.isalpha() and ch != '.' and ch != '_':
                id_start += 1
                break
            id_start -= 1

        return line[id_start:prefix_start + len(prefix)]

    @staticmethod
    def dir_of(m, prefix):
        return [x for x in dir(m) if x.startswith(prefix)]

    @classmethod
    def get_completion(cls, id, prefix):
        try:
            m = sys.modules['__main__']

            parts = id.split('.')
            c = len(parts)

            for i in xrange(0, c-1):
                m = getattr(m, parts[i])
        except Exception as e:
            return (None, None)
        else:
            # search in the module
            completion = cls.dir_of(m, prefix)

            # no completion found? looking from the global scope? then try the builtins
            if not completion and c == 1:
                completion = cls.dir_of(__builtin__, prefix)

            return (m, completion) if completion else (None, None)

    def __call__(self, prefix, n, line, prefix_start):
        if n == 0:
            self.n = n
            id = self.parse_identifier(line, prefix, prefix_start)
            self.lastmodule, self.completion = self.get_completion(id, prefix)

        if self.completion is None or n >= len(self.completion):
            return None

        s = self.completion[n]
        try:
            attr = getattr(self.lastmodule, s)
            # Is it callable?
            if callable(attr):
                return s + ("" if line.startswith("?") else "(")
            # Is it iterable?
            elif isinstance(attr, basestring) or getattr(attr, '__iter__', False):
                return s + "["
        except:
            pass

        return s

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

# -----------------------------------------------------------------------
#                           CustomIDAMemo
# -----------------------------------------------------------------------
class CustomIDAMemo(object):
    def Refresh(self):
        """
        Refreshes the graph. This causes the OnRefresh() to be called
        """
        ida_idaapi.pygc_refresh(self)

    def GetCurrentRendererType(self):
        return ida_idaapi.pygc_get_current_renderer_type(self)

    def SetCurrentRendererType(self, rtype):
        """
        Set the current view's renderer.

        @param rtype: The renderer type. Should be one of the idaapi.TCCRT_* values.
        """
        ida_idaapi.pygc_set_current_renderer_type(self, rtype)

    def SetNodeInfo(self, node_index, node_info, flags):
        """
        Set the properties for the given node.

        Example usage (set second nodes's bg color to red):
          inst = ...
          p = idaapi.node_info_t()
          p.bg_color = 0x00ff0000
          inst.SetNodeInfo(1, p, idaapi.NIF_BG_COLOR)

        @param node_index: The node index.
        @param node_info: An idaapi.node_info_t instance.
        @param flags: An OR'ed value of NIF_* values.
        """
        ida_idaapi.pygc_set_node_info(self, node_index, node_info, flags)

    def SetNodesInfos(self, values):
        """
        Set the properties for the given nodes.

        Example usage (set first three nodes's bg color to purple):
          inst = ...
          p = idaapi.node_info_t()
          p.bg_color = 0x00ff00ff
          inst.SetNodesInfos({0 : p, 1 : p, 2 : p})

        @param values: A dictionary of 'int -> node_info_t' objects.
        """
        ida_idaapi.pygc_set_nodes_infos(self, values)

    def GetNodeInfo(self, node):
        """
        Get the properties for the given node.

        @param node: The index of the node.
        @return: A tuple (bg_color, frame_color, ea, text), or None.
        """
        return ida_idaapi.pygc_get_node_info(self, node)

    def DelNodesInfos(self, *nodes):
        """
        Delete the properties for the given node(s).

        @param nodes: A list of node IDs
        """
        return ida_idaapi.pygc_del_nodes_infos(self, nodes)

    def CreateGroups(self, groups_infos):
        """
        Send a request to modify the graph by creating a
        (set of) group(s), and perform an animation.

        Each object in the 'groups_infos' list must be of the format:
        {
          "nodes" : [<int>, <int>, <int>, ...] # The list of nodes to group
          "text" : <string>                    # The synthetic text for that group
        }

        @param groups_infos: A list of objects that describe those groups.
        @return: A [<int>, <int>, ...] list of group nodes, or None (failure).
        """
        return ida_idaapi.pygc_create_groups(self, groups_infos)

    def DeleteGroups(self, groups, new_current = -1):
        """
        Send a request to delete the specified groups in the graph,
        and perform an animation.

        @param groups: A list of group node numbers.
        @param new_current: A node to focus on after the groups have been deleted
        @return: True on success, False otherwise.
        """
        return ida_idaapi.pygc_delete_groups(self, groups, new_current)

    def SetGroupsVisibility(self, groups, expand, new_current = -1):
        """
        Send a request to expand/collapse the specified groups in the graph,
        and perform an animation.

        @param groups: A list of group node numbers.
        @param expand: True to expand the group, False otherwise.
        @param new_current: A node to focus on after the groups have been expanded/collapsed.
        @return: True on success, False otherwise.
        """
        return ida_idaapi.pygc_set_groups_visibility(self, groups, expand, new_current)

    def GetTForm(self):
        """
        Return the TForm hosting this view.

        @return: The TForm that hosts this view, or None.
        """
        return ida_idaapi.pycim_get_tform(self)

    def GetTCustomControl(self):
        """
        Return the TCustomControl underlying this view.

        @return: The TCustomControl underlying this view, or None.
        """
        return ida_idaapi.pycim_get_tcustom_control(self)

#</pycode(py_idaapi)>
