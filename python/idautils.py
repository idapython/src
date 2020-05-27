#---------------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler
#
# Copyright (c) 2004-2010 Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#---------------------------------------------------------------------
"""
idautils.py - High level utility functions for IDA
"""
import ida_bytes
import ida_dbg
import ida_entry
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idd
import ida_idp
import ida_kernwin
import ida_loader
import ida_nalt
import ida_name
import ida_netnode
import ida_segment
import ida_strlist
import ida_struct
import ida_ua
import ida_xref

import idc
import types
import os
import sys

def refs(ea, funcfirst, funcnext):
    """
    Generic reference collector - INTERNAL USE ONLY.
    """
    ref = funcfirst(ea)
    while ref != ida_idaapi.BADADDR:
        yield ref
        ref = funcnext(ea, ref)


def CodeRefsTo(ea, flow):
    """
    Get a list of code references to 'ea'

    @param ea:   Target address
    @param flow: Follow normal code flow or not
    @type  flow: Boolean (0/1, False/True)

    @return: list of references (may be empty list)

    Example::

        for ref in CodeRefsTo(get_screen_ea(), 1):
            print(ref)
    """
    if flow == 1:
        return refs(ea, ida_xref.get_first_cref_to, ida_xref.get_next_cref_to)
    else:
        return refs(ea, ida_xref.get_first_fcref_to, ida_xref.get_next_fcref_to)


def CodeRefsFrom(ea, flow):
    """
    Get a list of code references from 'ea'

    @param ea:   Target address
    @param flow: Follow normal code flow or not
    @type  flow: Boolean (0/1, False/True)

    @return: list of references (may be empty list)

    Example::

        for ref in CodeRefsFrom(get_screen_ea(), 1):
            print(ref)
    """
    if flow == 1:
        return refs(ea, ida_xref.get_first_cref_from, ida_xref.get_next_cref_from)
    else:
        return refs(ea, ida_xref.get_first_fcref_from, ida_xref.get_next_fcref_from)


def DataRefsTo(ea):
    """
    Get a list of data references to 'ea'

    @param ea:   Target address

    @return: list of references (may be empty list)

    Example::

        for ref in DataRefsTo(get_screen_ea()):
            print(ref)
    """
    return refs(ea, ida_xref.get_first_dref_to, ida_xref.get_next_dref_to)


def DataRefsFrom(ea):
    """
    Get a list of data references from 'ea'

    @param ea:   Target address

    @return: list of references (may be empty list)

    Example::

        for ref in DataRefsFrom(get_screen_ea()):
            print(ref)
    """
    return refs(ea, ida_xref.get_first_dref_from, ida_xref.get_next_dref_from)


# Xref type names table
_ref_types = {
    ida_xref.fl_U  : 'Data_Unknown',
    ida_xref.dr_O  : 'Data_Offset',
    ida_xref.dr_W  : 'Data_Write',
    ida_xref.dr_R  : 'Data_Read',
    ida_xref.dr_T  : 'Data_Text',
    ida_xref.dr_I  : 'Data_Informational',
    ida_xref.fl_CF : 'Code_Far_Call',
    ida_xref.fl_CN : 'Code_Near_Call',
    ida_xref.fl_JF : 'Code_Far_Jump',
    ida_xref.fl_JN : 'Code_Near_Jump',
    20 : 'Code_User',
    ida_xref.fl_F : 'Ordinary_Flow'
}

def XrefTypeName(typecode):
    """
    Convert cross-reference type codes to readable names

    @param typecode: cross-reference type code
    """
    assert typecode in _ref_types, "unknown reference type %d" % typecode
    return _ref_types[typecode]

def _copy_xref(xref):
    """ Make a private copy of the xref class to preserve its contents """
    class _xref(object):
        pass

    xr = _xref()
    for attr in [ 'frm', 'to', 'iscode', 'type', 'user' ]:
        setattr(xr, attr, getattr(xref, attr))
    return xr


def XrefsFrom(ea, flags=0):
    """
    Return all references from address 'ea'

    @param ea: Reference address
    @param flags: one of ida_xref.XREF_ALL (default), ida_xref.XREF_FAR, ida_xref.XREF_DATA

    Example::
           for xref in XrefsFrom(here(), 0):
               print(xref.type, XrefTypeName(xref.type), \
                         'from', hex(xref.frm), 'to', hex(xref.to))
    """
    xref = ida_xref.xrefblk_t()
    if xref.first_from(ea, flags):
        yield _copy_xref(xref)
        while xref.next_from():
            yield _copy_xref(xref)


def XrefsTo(ea, flags=0):
    """
    Return all references to address 'ea'

    @param ea: Reference address
    @param flags: one of ida_xref.XREF_ALL (default), ida_xref.XREF_FAR, ida_xref.XREF_DATA

    Example::
           for xref in XrefsTo(here(), 0):
               print(xref.type, XrefTypeName(xref.type), \
                         'from', hex(xref.frm), 'to', hex(xref.to))
    """
    xref = ida_xref.xrefblk_t()
    if xref.first_to(ea, flags):
        yield _copy_xref(xref)
        while xref.next_to():
            yield _copy_xref(xref)


def Threads():
    """Returns all thread IDs for the current debugee"""
    for i in range(0, idc.get_thread_qty()):
        yield idc.getn_thread(i)


def Heads(start=None, end=None):
    """
    Get a list of heads (instructions or data items)

    @param start: start address (default: inf.min_ea)
    @param end:   end address (default: inf.max_ea)

    @return: list of heads between start and end
    """
    if start is None: start = ida_ida.cvar.inf.min_ea
    if end is None:   end = ida_ida.cvar.inf.max_ea

    ea = start
    if not idc.is_head(ida_bytes.get_flags(ea)):
        ea = ida_bytes.next_head(ea, end)
    while ea < end and ea != ida_idaapi.BADADDR:
        yield ea
        ea = ida_bytes.next_head(ea, end)


def Functions(start=None, end=None):
    """
    Get a list of functions

    @param start: start address (default: inf.min_ea)
    @param end:   end address (default: inf.max_ea)

    @return: list of function entrypoints between start and end

    @note: The last function that starts before 'end' is included even
    if it extends beyond 'end'. Any function that has its chunks scattered
    in multiple segments will be reported multiple times, once in each segment
    as they are listed.
    """
    if start is None: start = ida_ida.cvar.inf.min_ea
    if end is None:   end = ida_ida.cvar.inf.max_ea

    # find first function head chunk in the range
    chunk = ida_funcs.get_fchunk(start)
    if not chunk:
        chunk = ida_funcs.get_next_fchunk(start)
    while chunk and chunk.start_ea < end and (chunk.flags & ida_funcs.FUNC_TAIL) != 0:
        chunk = ida_funcs.get_next_fchunk(chunk.start_ea)
    func = chunk

    while func and func.start_ea < end:
        startea = func.start_ea
        yield startea
        func = ida_funcs.get_next_func(startea)


def Chunks(start):
    """
    Get a list of function chunks

    @param start: address of the function

    @return: list of funcion chunks (tuples of the form (start_ea, end_ea))
             belonging to the function
    """
    func_iter = ida_funcs.func_tail_iterator_t( ida_funcs.get_func( start ) )
    status = func_iter.main()
    while status:
        chunk = func_iter.chunk()
        yield (chunk.start_ea, chunk.end_ea)
        status = next(func_iter)


def Modules():
    """
    Returns a list of module objects with name,size,base and the rebase_to attributes
    """
    mod = ida_idd.modinfo_t()
    result = ida_dbg.get_first_module(mod)
    while result:
        yield ida_idaapi.object_t(name=mod.name, size=mod.size, base=mod.base, rebase_to=mod.rebase_to)
        result = ida_dbg.get_next_module(mod)


def Names():
    """
    Returns a list of names

    @return: List of tuples (ea, name)
    """
    for i in range(ida_name.get_nlist_size()):
        ea   = ida_name.get_nlist_ea(i)
        name = ida_name.get_nlist_name(i)
        yield (ea, name)


def Segments():
    """
    Get list of segments (sections) in the binary image

    @return: List of segment start addresses.
    """
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if seg:
            yield seg.start_ea


def Entries():
    """
    Returns a list of entry points (exports)

    @return: List of tuples (index, ordinal, ea, name)
    """
    n = ida_entry.get_entry_qty()
    for i in range(0, n):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea      = ida_entry.get_entry(ordinal)
        name    = ida_entry.get_entry_name(ordinal)
        yield (i, ordinal, ea, name)


def FuncItems(start):
    """
    Get a list of function items (instruction or data items inside function boundaries)

    @param start: address of the function

    @return: ea of each item in the function
    """
    func = ida_funcs.get_func(start)
    if not func:
        return
    fii = ida_funcs.func_item_iterator_t()
    ok = fii.set(func)
    while ok:
        yield fii.current()
        ok = fii.next_code()


def Structs():
    """
    Get a list of structures

    @return: List of tuples (idx, sid, name)
    """
    idx  = idc.get_first_struc_idx()
    while idx != ida_idaapi.BADADDR:
        sid = idc.get_struc_by_idx(idx)
        yield (idx, sid, idc.get_struc_name(sid))
        idx = idc.get_next_struc_idx(idx)


def StructMembers(sid):
    """
    Get a list of structure members information (or stack vars if given a frame).

    @param sid: ID of the structure.

    @return: List of tuples (offset, name, size)

    @note: If 'sid' does not refer to a valid structure,
           an exception will be raised.
    @note: This will not return 'holes' in structures/stack frames;
           it only returns defined structure members.
    """
    sptr = ida_struct.get_struc(sid)
    if sptr is None:
        raise Exception("No structure with ID: 0x%x" % sid)
    for m in sptr.members:
        name = idc.get_member_name(sid, m.soff)
        if name:
            size = ida_struct.get_member_size(m)
            yield (m.soff, name, size)


def DecodePrecedingInstruction(ea):
    """
    Decode preceding instruction in the execution flow.

    @param ea: address to decode
    @return: (None or the decode instruction, farref)
             farref will contain 'true' if followed an xref, false otherwise
    """
    insn = ida_ua.insn_t()
    prev_addr, farref  = ida_ua.decode_preceding_insn(insn, ea)
    return (insn, farref) if prev_addr != ida_idaapi.BADADDR else (None, False)


def DecodePreviousInstruction(ea):
    """
    Decodes the previous instruction and returns an insn_t like class

    @param ea: address to decode
    @return: None or a new insn_t instance
    """
    insn = ida_ua.insn_t()
    prev_addr = ida_ua.decode_prev_insn(insn, ea)
    return insn if prev_addr != ida_idaapi.BADADDR else None


def DecodeInstruction(ea):
    """
    Decodes an instruction and returns an insn_t like class

    @param ea: address to decode
    @return: None or a new insn_t instance
    """
    insn = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(insn, ea)
    return insn if inslen > 0 else None


def GetDataList(ea, count, itemsize=1):
    """
    Get data list - INTERNAL USE ONLY
    """
    if itemsize == 1:
        getdata = ida_bytes.get_byte
    elif itemsize == 2:
        getdata = ida_bytes.get_word
    elif itemsize == 4:
        getdata = ida_bytes.get_dword
    elif itemsize == 8:
        getdata = ida_bytes.get_qword
    else:
        raise ValueError("Invalid data size! Must be 1, 2, 4 or 8")

    endea = ea + itemsize * count
    curea = ea
    while curea < endea:
        yield getdata(curea)
        curea += itemsize


def PutDataList(ea, datalist, itemsize=1):
    """
    Put data list - INTERNAL USE ONLY
    """
    putdata = None

    if itemsize == 1:
        putdata = ida_bytes.patch_byte
    if itemsize == 2:
        putdata = ida_bytes.patch_word
    if itemsize == 4:
        putdata = ida_bytes.patch_dword

    assert putdata, "Invalid data size! Must be 1, 2 or 4"

    for val in datalist:
        putdata(ea, val)
        ea = ea + itemsize


def MapDataList(ea, length, func, wordsize=1):
    """
    Map through a list of data words in the database

    @param ea:       start address
    @param length:   number of words to map
    @param func:     mapping function
    @param wordsize: size of words to map [default: 1 byte]

    @return: None
    """
    PutDataList(ea, map(func, GetDataList(ea, length, wordsize)), wordsize)


def GetInputFileMD5():
    """
    Return the MD5 hash of the input binary file

    @return: MD5 string or None on error
    """
    return idc.retrieve_input_file_md5()


class Strings(object):
    """
    Allows iterating over the string list. The set of strings will not be
    modified, unless asked explicitly at setup()-time. This string list also
    is used by the "String window" so it may be changed when this window is
    updated.

    Example:
        s = Strings()

        for i in s:
            print("%x: len=%d type=%d -> '%s'" % (i.ea, i.length, i.strtype, str(i)))

    """
    class StringItem(object):
        """
        Class representing each string item.
        """
        def __init__(self, si):
            self.ea = si.ea
            """String ea"""
            self.strtype = si.type
            """string type (STRTYPE_xxxxx)"""
            self.length = si.length
            """string length"""

        def is_1_byte_encoding(self):
            return ida_nalt.get_strtype_bpu(self.strtype) == 1

        def _toseq(self, as_unicode):
            strbytes = ida_bytes.get_strlit_contents(self.ea, self.length, self.strtype)
            if sys.version_info.major >= 3:
                return strbytes.decode("UTF-8", "replace") if as_unicode else strbytes
            else:
                return unicode(strbytes, "UTF-8", 'replace') if as_unicode else strbytes

        def __str__(self):
            return self._toseq(False if sys.version_info.major < 3 else True)

        def __unicode__(self):
            return self._toseq(True)

    def clear_cache(self):
        """Clears the strings list cache"""
        ida_strlist.clear_strlist()

    def __init__(self, default_setup = False):
        """
        Initializes the Strings enumeration helper class

        @param default_setup: Set to True to use default setup (C strings, min len 5, ...)
        """
        self.size = 0
        if default_setup:
            self.setup()
        else:
            # restore saved options
            ida_strlist.get_strlist_options()
        self.refresh()

        self._si = ida_strlist.string_info_t()


    def refresh(self):
        """Refreshes the strings list"""
        ida_strlist.build_strlist()
        self.size = ida_strlist.get_strlist_qty()


    def setup(self,
              strtypes = [ida_nalt.STRTYPE_C],
              minlen = 5,
              only_7bit = True,
              ignore_instructions = False,
              display_only_existing_strings = False):

        t = ida_strlist.get_strlist_options()
        t.strtypes = strtypes
        t.minlen = minlen
        t.only_7bit = only_7bit
        t.display_only_existing_strings = display_only_existing_strings
        self.refresh()


    def _get_item(self, index):
        if not ida_strlist.get_strlist_item(self._si, index):
            return None
        return Strings.StringItem(self._si)


    def __iter__(self):
        return (self._get_item(index) for index in range(0, self.size))


    def __getitem__(self, index):
        """Returns a string item or None"""
        if index >= self.size:
            raise KeyError
        else:
            return self._get_item(index)

# -----------------------------------------------------------------------
def GetIdbDir():
    """
    Get IDB directory

    This function returns directory path of the current IDB database
    """
    return os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_IDB)) + os.sep

# -----------------------------------------------------------------------
def GetRegisterList():
    """Returns the register list"""
    return ida_idp.ph_get_regnames()

# -----------------------------------------------------------------------
def GetInstructionList():
    """Returns the instruction list of the current processor module"""
    return [i[0] for i in ida_idp.ph_get_instruc() if i[0]]

# -----------------------------------------------------------------------
def _Assemble(ea, line):
    """
    Please refer to Assemble() - INTERNAL USE ONLY
    """
    if type(line) in ([bytes] + list(ida_idaapi.string_types)):
        lines = [line]
    else:
        lines = line
    ret = []
    for line in lines:
        seg = ida_segment.getseg(ea)
        if not seg:
            return (False, "No segment at ea")
        ip  = ea - (ida_segment.sel2para(seg.sel) << 4)
        buf = ida_idp.AssembleLine(ea, seg.sel, ip, seg.bitness, line)
        if not buf:
            return (False, "Assembler failed: " + line)
        ea += len(buf)
        ret.append(buf)

    if len(ret) == 1:
        ret = ret[0]
    return (True, ret)


def Assemble(ea, line):
    """
    Assembles one or more lines (does not display an message dialogs)
    If line is a list then this function will attempt to assemble all the lines
    This function will turn on batch mode temporarily so that no messages are displayed on the screen

    @param ea:       start address
    @return: (False, "Error message") or (True, asm_buf) or (True, [asm_buf1, asm_buf2, asm_buf3])
    """
    old_batch = idc.batch(1)
    ret = _Assemble(ea, line)
    idc.batch(old_batch)
    return ret

def _copy_obj(src, dest, skip_list = None):
    """
    Copy non private/non callable attributes from a class instance to another
    @param src: Source class to copy from
    @param dest: If it is a string then it designates the new class type that will be created and copied to.
                 Otherwise dest should be an instance of another class
    @return: A new instance or "dest"
    """
    if type(dest) == bytes:
        # instantiate a new destination class of the specified type name?
        dest = new.classobj(dest, (), {})
    for x in dir(src):
        # skip special and private fields
        if x.startswith("__") and x.endswith("__"):
            continue
        # skip items in the skip list
        if skip_list and x in skip_list:
            continue
        t = getattr(src, x)
        # skip callable
        if callable(t):
            continue
        setattr(dest, x, t)
    return dest

# -----------------------------------------------------------------------
class _reg_dtyp_t(object):
    """
    INTERNAL
    This class describes a register's number and dtyp.
    The equal operator is overloaded so that two instances can be tested for equality
    """
    def __init__(self, reg, dtype):
        self.reg = reg
        self.dtype = dtype

    def __eq__(self, other):
        return (self.reg == other.reg) and (self.dtype == other.dtype)

# -----------------------------------------------------------------------
class _procregs(object):
    """Utility class allowing the users to identify registers in a decoded instruction"""
    def __getattr__(self, attr):
        ri = ida_idp.reg_info_t()
        if not ida_idp.parse_reg_name(ri, attr):
            raise AttributeError()
        r = _reg_dtyp_t(ri.reg, ida_ua.get_dtype_by_size(ri.size))
        self.__dict__[attr] = r
        return r

    def __setattr__(self, attr, value):
        raise AttributeError(attr)


# -----------------------------------------------------------------------
class _cpu(object):
    "Simple wrapper around get_reg_value/set_reg_value"
    def __getattr__(self, name):
        return idc.get_reg_value(name)

    def __setattr__(self, name, value):
        return idc.set_reg_value(value, name)


# --------------------------------------------------------------------------
class __process_ui_actions_helper(object):
    def __init__(self, actions, flags = 0):
        """Expect a list or a string with a list of actions"""
        if isinstance(actions, str):
            lst = actions.split(";")
        elif isinstance(actions, (list, tuple)):
            lst = actions
        else:
            raise ValueError("Must pass a string, list or a tuple")

        # Remember the action list and the flags
        self.__action_list = lst
        self.__flags = flags

        # Reset action index
        self.__idx = 0

    def __len__(self):
        return len(self.__action_list)

    def __call__(self):
        if self.__idx >= len(self.__action_list):
            return False

        # Execute one action
        ida_kernwin.process_ui_action(
                self.__action_list[self.__idx],
                self.__flags)

        # Move to next action
        self.__idx += 1

        # Reschedule
        return True


# --------------------------------------------------------------------------
def ProcessUiActions(actions, flags=0):
    """
    @param actions: A string containing a list of actions separated by semicolon, a list or a tuple
    @param flags: flags to be passed to process_ui_action()
    @return: Boolean. Returns False if the action list was empty or execute_ui_requests() failed.
    """

    # Instantiate a helper
    helper = __process_ui_actions_helper(actions, flags)
    return False if len(helper) < 1 else ida_kernwin.execute_ui_requests((helper,))


# -----------------------------------------------------------------------
class peutils_t(object):
    """
    PE utility class. Retrieves PE information from the database.

    Constants from pe.h
    """
    PE_NODE = "$ PE header" # netnode name for PE header
    PE_ALT_DBG_FPOS   = ida_idaapi.BADADDR & -1 #  altval() -> translated fpos of debuginfo
    PE_ALT_IMAGEBASE  = ida_idaapi.BADADDR & -2 #  altval() -> loading address (usually pe.imagebase)
    PE_ALT_PEHDR_OFF  = ida_idaapi.BADADDR & -3 #  altval() -> offset of PE header
    PE_ALT_NEFLAGS    = ida_idaapi.BADADDR & -4 #  altval() -> neflags
    PE_ALT_TDS_LOADED = ida_idaapi.BADADDR & -5 #  altval() -> tds already loaded(1) or invalid(-1)
    PE_ALT_PSXDLL     = ida_idaapi.BADADDR & -6 #  altval() -> if POSIX(x86) imports from PSXDLL netnode

    def __init__(self):
        self.__penode = ida_netnode.netnode()
        self.__penode.create(peutils_t.PE_NODE)

    imagebase = property(
        lambda self: self.__penode.altval(peutils_t.PE_ALT_IMAGEBASE)
      )

    header = property(
        lambda self: self.__penode.altval(peutils_t.PE_ALT_PEHDR_OFF)
      )

    def __str__(self):
        return "peutils_t(imagebase=%s, header=%s)" % (hex(self.imagebase), hex(self.header))

    def header(self):
        """
        Returns the complete PE header as an instance of peheader_t (defined in the SDK).
        """
        return self.__penode.valobj()

# -----------------------------------------------------------------------
cpu = _cpu()
"""This is a special class instance used to access the registers as if they were attributes of this object.
For example to access the EAX register:
    print("%x" % cpu.Eax)
"""

procregs = _procregs()
"""This object is used to access the processor registers. It is useful when decoding instructions and you want to see which instruction is which.
For example:
    x = idautils.DecodeInstruction(here())
    if x[0] == procregs.Esp:
        print("This operand is the register ESP)
"""
