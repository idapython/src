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
import idaapi
import idc
import types
import os


def refs(ea, funcfirst, funcnext):
    """
    Generic reference collector - INTERNAL USE ONLY.
    """
    ref = funcfirst(ea)
    while ref != idaapi.BADADDR:
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

        for ref in CodeRefsTo(ScreenEA(), 1):
            print ref
    """
    if flow == 1:
        return refs(ea, idaapi.get_first_cref_to, idaapi.get_next_cref_to)
    else:
        return refs(ea, idaapi.get_first_fcref_to, idaapi.get_next_fcref_to)


def CodeRefsFrom(ea, flow):
    """
    Get a list of code references from 'ea'

    @param ea:   Target address
    @param flow: Follow normal code flow or not
    @type  flow: Boolean (0/1, False/True)

    @return: list of references (may be empty list)

    Example::

        for ref in CodeRefsFrom(ScreenEA(), 1):
            print ref
    """
    if flow == 1:
        return refs(ea, idaapi.get_first_cref_from, idaapi.get_next_cref_from)
    else:
        return refs(ea, idaapi.get_first_fcref_from, idaapi.get_next_fcref_from)


def DataRefsTo(ea):
    """
    Get a list of data references to 'ea'

    @param ea:   Target address

    @return: list of references (may be empty list)

    Example::

        for ref in DataRefsTo(ScreenEA()):
            print ref
    """
    return refs(ea, idaapi.get_first_dref_to, idaapi.get_next_dref_to)


def DataRefsFrom(ea):
    """
    Get a list of data references from 'ea'

    @param ea:   Target address

    @return: list of references (may be empty list)

    Example::

        for ref in DataRefsFrom(ScreenEA()):
            print ref
    """
    return refs(ea, idaapi.get_first_dref_from, idaapi.get_next_dref_from)


def XrefTypeName(typecode):
    """
    Convert cross-reference type codes to readable names

    @param typecode: cross-reference type code
    """
    ref_types = {
        0  : 'Data_Unknown',
        1  : 'Data_Offset',
        2  : 'Data_Write',
        3  : 'Data_Read',
        4  : 'Data_Text',
        5  : 'Data_Informational',
        16 : 'Code_Far_Call',
        17 : 'Code_Near_Call',
        18 : 'Code_Far_Jump',
        19 : 'Code_Near_Jump',
        20 : 'Code_User',
        21 : 'Ordinary_Flow'
        }
    assert typecode in ref_types, "unknown reference type %d" % typecode
    return ref_types[typecode]


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
    @param flags: any of idaapi.XREF_* flags

    Example::
           for xref in XrefsFrom(here(), 0):
               print xref.type, XrefTypeName(xref.type), \
                         'from', hex(xref.frm), 'to', hex(xref.to)
    """
    xref = idaapi.xrefblk_t()
    if xref.first_from(ea, flags):
        yield _copy_xref(xref)
        while xref.next_from():
            yield _copy_xref(xref)


def XrefsTo(ea, flags=0):
    """
    Return all references to address 'ea'

    @param ea: Reference address
    @param flags: any of idaapi.XREF_* flags

    Example::
           for xref in XrefsTo(here(), 0):
               print xref.type, XrefTypeName(xref.type), \
                         'from', hex(xref.frm), 'to', hex(xref.to)
    """
    xref = idaapi.xrefblk_t()
    if xref.first_to(ea, flags):
        yield _copy_xref(xref)
        while xref.next_to():
            yield _copy_xref(xref)


def Threads():
    """Returns all thread IDs"""
    for i in xrange(0, idc.GetThreadQty()):
        yield idc.GetThreadId(i)


def Heads(start=None, end=None):
    """
    Get a list of heads (instructions or data)

    @param start: start address (default: inf.minEA)
    @param end:   end address (default: inf.maxEA)

    @return: list of heads between start and end
    """
    if not start: start = idaapi.cvar.inf.minEA
    if not end:   end = idaapi.cvar.inf.maxEA

    ea = start
    if not idc.isHead(idc.GetFlags(ea)):
        ea = idaapi.next_head(ea, end)
    while ea != idaapi.BADADDR:
        yield ea
        ea = idaapi.next_head(ea, end)


def Functions(start=None, end=None):
    """
    Get a list of functions

    @param start: start address (default: inf.minEA)
    @param end:   end address (default: inf.maxEA)

    @return: list of heads between start and end

    @note: The last function that starts before 'end' is included even
    if it extends beyond 'end'. Any function that has its chunks scattered
    in multiple segments will be reported multiple times, once in each segment
    as they are listed.
    """
    if not start: start = idaapi.cvar.inf.minEA
    if not end:   end = idaapi.cvar.inf.maxEA

    # find first function head chunk in the range
    chunk = idaapi.get_fchunk(start)
    if not chunk:
        chunk = idaapi.get_next_fchunk(start)
    while chunk and chunk.startEA < end and (chunk.flags & idaapi.FUNC_TAIL) != 0:
        chunk = idaapi.get_next_fchunk(chunk.startEA)
    func = chunk

    while func and func.startEA < end:
        startea = func.startEA
        yield startea
        func = idaapi.get_next_func(startea)


def Chunks(start):
    """
    Get a list of function chunks

    @param start: address of the function

    @return: list of funcion chunks (tuples of the form (start_ea, end_ea))
             belonging to the function
    """
    func_iter = idaapi.func_tail_iterator_t( idaapi.get_func( start ) )
    status = func_iter.main()
    while status:
        chunk = func_iter.chunk()
        yield (chunk.startEA, chunk.endEA)
        status = func_iter.next()


def Modules():
    """
    Returns a list of module objects with name,size,base and the rebase_to attributes
    """
    mod = idaapi.module_info_t()
    result = idaapi.get_first_module(mod)
    while result:
        yield idaapi.object_t(name=mod.name, size=mod.size, base=mod.base, rebase_to=mod.rebase_to)
        result = idaapi.get_next_module(mod)


def Names():
    """
    Returns a list of names

    @return: List of tuples (ea, name)
    """
    for i in xrange(idaapi.get_nlist_size()):
        ea   = idaapi.get_nlist_ea(i)
        name = idaapi.get_nlist_name(i)
        yield (ea, name)


def Segments():
    """
    Get list of segments (sections) in the binary image

    @return: List of segment start addresses.
    """
    for n in xrange(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(n)
        if seg:
            yield seg.startEA


def Entries():
    """
    Returns a list of entry points

    @return: List of tuples (index, ordinal, ea, name)
    """
    n = idaapi.get_entry_qty()
    for i in xrange(0, n):
        ordinal = idaapi.get_entry_ordinal(i)
        ea      = idaapi.get_entry(ordinal)
        name    = idaapi.get_entry_name(ordinal)
        yield (i, ordinal, ea, name)


def FuncItems(start):
    """
    Get a list of function items

    @param start: address of the function

    @return: ea of each item in the function
    """
    func = idaapi.get_func(start)
    if not func:
        return
    fii = idaapi.func_item_iterator_t()
    ok = fii.set(func)
    while ok:
        yield fii.current()
        ok = fii.next_code()


def Structs():
    """
    Get a list of structures

    @return: List of tuples (idx, sid, name)
    """
    idx  = idc.GetFirstStrucIdx()
    while idx != idaapi.BADADDR:
        sid = idc.GetStrucId(idx)
        yield (idx, sid, idc.GetStrucName(sid))
        idx = idc.GetNextStrucIdx(idx)


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
    m = idc.GetFirstMember(sid)
    if m == -1:
        raise Exception("No structure with ID: 0x%x" % sid)
    while (m != idaapi.BADADDR):
        name = idc.GetMemberName(sid, m)
        if name:
            yield (m, name, idc.GetMemberSize(sid, m))
        m = idc.GetStrucNextOff(sid, m)


def DecodePrecedingInstruction(ea):
    """
    Decode preceding instruction in the execution flow.

    @param ea: address to decode
    @return: (None or the decode instruction, farref)
             farref will contain 'true' if followed an xref, false otherwise
    """
    prev_addr, farref  = idaapi.decode_preceding_insn(ea)
    if prev_addr == idaapi.BADADDR:
        return (None, False)
    else:
        return (idaapi.cmd.copy(), farref)



def DecodePreviousInstruction(ea):
    """
    Decodes the previous instruction and returns an insn_t like class

    @param ea: address to decode
    @return: None or a new insn_t instance
    """
    prev_addr = idaapi.decode_prev_insn(ea)
    if prev_addr == idaapi.BADADDR:
        return None

    return idaapi.cmd.copy()


def DecodeInstruction(ea):
    """
    Decodes an instruction and returns an insn_t like class

    @param ea: address to decode
    @return: None or a new insn_t instance
    """
    inslen = idaapi.decode_insn(ea)
    if inslen == 0:
        return None

    return idaapi.cmd.copy()


def GetDataList(ea, count, itemsize=1):
    """
    Get data list - INTERNAL USE ONLY
    """
    if itemsize == 1:
        getdata = idaapi.get_byte
    elif itemsize == 2:
        getdata = idaapi.get_word
    elif itemsize == 4:
        getdata = idaapi.get_long
    elif itemsize == 8:
        getdata = idaapi.get_qword
    else:
        raise ValueError, "Invalid data size! Must be 1, 2, 4 or 8"

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
        putdata = idaapi.patch_byte
    if itemsize == 2:
        putdata = idaapi.patch_word
    if itemsize == 4:
        putdata = idaapi.patch_long

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
    return idc.GetInputMD5()


class Strings(object):
    """
    Allows iterating over the string list. The set of strings will not be modified.
    , unless asked explicitly at setup()-time..

    Example:
        s = Strings()

        for i in s:
            print "%x: len=%d type=%d -> '%s'" % (i.ea, i.length, i.type, str(i))

    """
    class StringItem(object):
        """
        Class representing each string item.
        """
        def __init__(self, si):
            self.ea     = si.ea
            """String ea"""
            self.type   = si.type
            """string type (ASCSTR_xxxxx)"""
            self.length = si.length
            """string length"""

        def is_1_byte_encoding(self):
            return not self.is_2_bytes_encoding() and not self.is_4_bytes_encoding()

        def is_2_bytes_encoding(self):
            return (self.type & 7) in [idaapi.ASCSTR_UTF16, idaapi.ASCSTR_ULEN2, idaapi.ASCSTR_ULEN4]

        def is_4_bytes_encoding(self):
            return (self.type & 7) == idaapi.ASCSTR_UTF32

        def _toseq(self, as_unicode):
            if self.is_2_bytes_encoding():
                conv = idaapi.ACFOPT_UTF16
                pyenc = "utf-16"
            elif self.is_4_bytes_encoding():
                conv = idaapi.ACFOPT_UTF8
                pyenc = "utf-8"
            else:
                conv = idaapi.ACFOPT_ASCII
                pyenc = 'ascii'
            strbytes = idaapi.get_ascii_contents2(self.ea, self.length, self.type, conv)
            return unicode(strbytes, pyenc, 'replace') if as_unicode else strbytes

        def __str__(self):
            return self._toseq(False)

        def __unicode__(self):
            return self._toseq(True)


    STR_C       = 0x0001
    """C-style ASCII string"""
    STR_PASCAL  = 0x0002
    """Pascal-style ASCII string (length byte)"""
    STR_LEN2    = 0x0004
    """Pascal-style, length is 2 bytes"""
    STR_UNICODE = 0x0008
    """Unicode string"""
    STR_LEN4    = 0x0010
    """Pascal-style, length is 4 bytes"""
    STR_ULEN2   = 0x0020
    """Pascal-style Unicode, length is 2 bytes"""
    STR_ULEN4   = 0x0040
    """Pascal-style Unicode, length is 4 bytes"""

    def clear_cache(self):
        """Clears the strings list cache"""
        self.refresh(0, 0) # when ea1=ea2 the kernel will clear the cache

    def __init__(self, default_setup = False):
        """
        Initializes the Strings enumeration helper class

        @param default_setup: Set to True to use default setup (C strings, min len 5, ...)
        """
        self.size = 0
        if default_setup:
            self.setup()
        else:
            self.refresh()

        self._si  = idaapi.string_info_t()

    def refresh(self, ea1=None, ea2=None):
        """Refreshes the strings list"""
        if ea1 is None:
            ea1 = idaapi.cvar.inf.minEA
        if ea2 is None:
            ea2 = idaapi.cvar.inf.maxEA

        idaapi.refresh_strlist(ea1, ea2)
        self.size = idaapi.get_strlist_qty()


    def setup(self,
              strtypes = STR_C,
              minlen = 5,
              only_7bit = True,
              ignore_instructions = False,
              ea1 = None,
              ea2 = None,
              display_only_existing_strings = False):

        if ea1 is None:
            ea1 = idaapi.cvar.inf.minEA

        if ea2 is None:
            ea2 = idaapi.cvar.inf.maxEA

        t = idaapi.strwinsetup_t()
        t.strtypes = strtypes
        t.minlen = minlen
        t.only_7bit = only_7bit
        t.ea1 = ea1
        t.ea2 = ea2
        t.display_only_existing_strings = display_only_existing_strings
        idaapi.set_strlist_options(t)

        # Automatically refreshes
        self.refresh()


    def _get_item(self, index):
        if not idaapi.get_strlist_item(index, self._si):
            return None
        else:
            return Strings.StringItem(self._si)


    def __iter__(self):
        return (self._get_item(index) for index in xrange(0, self.size))


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
    return os.path.dirname(idaapi.cvar.database_idb) + os.sep

# -----------------------------------------------------------------------
def GetRegisterList():
    """Returns the register list"""
    return idaapi.ph_get_regnames()

# -----------------------------------------------------------------------
def GetInstructionList():
    """Returns the instruction list of the current processor module"""
    return [i[0] for i in idaapi.ph_get_instruc() if i[0]]

# -----------------------------------------------------------------------
def _Assemble(ea, line):
    """
    Please refer to Assemble() - INTERNAL USE ONLY
    """
    if type(line) == types.StringType:
        lines = [line]
    else:
        lines = line
    ret = []
    for line in lines:
        seg = idaapi.getseg(ea)
        if not seg:
            return (False, "No segment at ea")
        ip  = ea - (idaapi.ask_selector(seg.sel) << 4)
        buf = idaapi.AssembleLine(ea, seg.sel, ip, seg.bitness, line)
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
    old_batch = idc.Batch(1)
    ret = _Assemble(ea, line)
    idc.Batch(old_batch)
    return ret

def _copy_obj(src, dest, skip_list = None):
    """
    Copy non private/non callable attributes from a class instance to another
    @param src: Source class to copy from
    @param dest: If it is a string then it designates the new class type that will be created and copied to.
                 Otherwise dest should be an instance of another class
    @return: A new instance or "dest"
    """
    if type(dest) == types.StringType:
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
    def __init__(self, reg, dtyp):
        self.reg  = reg
        self.dtyp = dtyp

    def __eq__(self, other):
        return (self.reg == other.reg) and (self.dtyp == other.dtyp)

# -----------------------------------------------------------------------
class _procregs(object):
    """Utility class allowing the users to identify registers in a decoded instruction"""
    def __getattr__(self, attr):
        ri = idaapi.reg_info_t()
        if not idaapi.parse_reg_name(attr, ri):
            raise AttributeError()
        r = _reg_dtyp_t(ri.reg, ord(idaapi.get_dtyp_by_size(ri.size)))
        self.__dict__[attr] = r
        return r

    def __setattr__(self, attr, value):
        raise AttributeError(attr)


# -----------------------------------------------------------------------
class _cpu(object):
    "Simple wrapper around GetRegValue/SetRegValue"
    def __getattr__(self, name):
        #print "cpu.get(%s)" % name
        return idc.GetRegValue(name)

    def __setattr__(self, name, value):
        #print "cpu.set(%s)" % name
        return idc.SetRegValue(value, name)


# --------------------------------------------------------------------------
class __process_ui_actions_helper(object):
    def __init__(self, actions, flags = 0):
        """Expect a list or a string with a list of actions"""
        if isinstance(actions, str):
            lst = actions.split(";")
        elif isinstance(actions, (list, tuple)):
            lst = actions
        else:
            raise ValueError, "Must pass a string, list or a tuple"

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
        idaapi.process_ui_action(
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
    return False if len(helper) < 1 else idaapi.execute_ui_requests((helper,))


# -----------------------------------------------------------------------
class peutils_t(object):
    """
    PE utility class. Retrieves PE information from the database.

    Constants from pe.h
    """
    PE_NODE = "$ PE header" # netnode name for PE header
    PE_ALT_DBG_FPOS   = idaapi.BADADDR & -1 #  altval() -> translated fpos of debuginfo
    PE_ALT_IMAGEBASE  = idaapi.BADADDR & -2 #  altval() -> loading address (usually pe.imagebase)
    PE_ALT_PEHDR_OFF  = idaapi.BADADDR & -3 #  altval() -> offset of PE header
    PE_ALT_NEFLAGS    = idaapi.BADADDR & -4 #  altval() -> neflags
    PE_ALT_TDS_LOADED = idaapi.BADADDR & -5 #  altval() -> tds already loaded(1) or invalid(-1)
    PE_ALT_PSXDLL     = idaapi.BADADDR & -6 #  altval() -> if POSIX(x86) imports from PSXDLL netnode

    def __init__(self):
        self.__penode = idaapi.netnode()
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
    print "%x" % cpu.Eax
"""

procregs = _procregs()
"""This object is used to access the processor registers. It is useful when decoding instructions and you want to see which instruction is which.
For example:
    x = idautils.DecodeInstruction(here())
    if x[0] == procregs.Esp:
        print "This operand is the register ESP
"""
