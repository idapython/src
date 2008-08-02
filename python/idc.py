#!/usr/bin/env python
#------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler Pro
#
# Original IDC.IDC:
# Copyright (c) 1990-2008 Ilfak Guilfanov
#
# Python conversion:
# Copyright (c) 2004-2008 Gergely Erdelyi <dyce@d-dome.net> 
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#------------------------------------------------------------
# idc.py - IDC compatibility module
#------------------------------------------------------------
"""
IDC compatibility module

This file contains IDA built-in function declarations and internal bit
definitions.  Each byte of the program has 32-bit flags (low 8 bits keep 
the byte value). These 32 bits are used in GetFlags/SetFlags functions.
You may freely examine these bits using GetFlags() but the use of the
SetFlags() function is strongly discouraged.

This file is subject to change without any notice.
Future versions of IDA may use other definitions.
"""
try:
    import idaapi
except:
    print "Could not import idaapi. Running in 'pydoc mode'."

import os, struct, re

class DeprecatedIDCError(Exception):
    """
    Exception for deprecated function calls
    """
    def __init__(self, val):
        self.var = val

    def __str__(self):
        return self.val


def _IDC_GetAttr(object, map, attroffs):
    """
    Internal function to generically get object attributes
    Do not use unless you know what you are doing
    """
    if attroffs in map and hasattr(object, map[attroffs]):
        return getattr(object, map[attroffs])
    else:
        str = "attribute with offset %d not found, check the offset and report the problem" % attroffs
        raise KeyError, str


def _IDC_SetAttr(object, map, attroffs, value):
    """
    Internal function to generically set object attributes
    Do not use unless you know what you are doing
    """
    if attroffs in map and hasattr(object, map[attroffs]):
        return setattr(object, map[attroffs], value)
    else:
        str = "attribute with offset %d not found, check the offset and report the problem" % attroffs
        raise KeyError, str

 
BADADDR         = idaapi.BADADDR # Not allowed address value
BADSEL          = idaapi.BADSEL  # Not allowed selector value/number
MAXADDR         = idaapi.MAXADDR

#
#      Flag bit definitions (for GetFlags())
#
MS_VAL  = idaapi.MS_VAL             # Mask for byte value
FF_IVL  = idaapi.FF_IVL             # Byte has value ?

# Do flags contain byte value? (i.e. has the byte a value?)
# if not, the byte is uninitialized.

def hasValue(F):     return ((F & FF_IVL) != 0)     # any defined value?

# Get byte value from flags
# Get value of byte provided that the byte is initialized.
# This macro works ok only for 8-bit byte machines.

def byteValue(F):    return (F & MS_VAL)    # quick replacement for Byte()

# Is the byte initialized?

def isLoaded(ea):    hasValue(GetFlags(ea))  # any defined value?

MS_CLS   = idaapi.MS_CLS   # Mask for typing
FF_CODE  = idaapi.FF_CODE  # Code ?
FF_DATA  = idaapi.FF_DATA  # Data ?
FF_TAIL  = idaapi.FF_TAIL  # Tail ?
FF_UNK   = idaapi.FF_UNK   # Unknown ?

def isCode(F):       return ((F & MS_CLS) == FF_CODE) # is code byte?
def isData(F):       return ((F & MS_CLS) == FF_DATA) # is data byte?
def isTail(F):       return ((F & MS_CLS) == FF_TAIL) # is tail byte?
def isUnknown(F):    return ((F & MS_CLS) == FF_UNK)  # is unexplored byte?
def isHead(F):       return ((F & FF_DATA) != 0)      # is start of code/data?

#
#      Common bits
#
MS_COMM  = idaapi.MS_COMM  # Mask of common bits
FF_COMM  = idaapi.FF_COMM  # Has comment?
FF_REF   = idaapi.FF_REF   # has references?
FF_LINE  = idaapi.FF_LINE  # Has next or prev cmt lines ?
FF_NAME  = idaapi.FF_NAME  # Has user-defined name ?
FF_LABL  = idaapi.FF_LABL  # Has dummy name?
FF_FLOW  = idaapi.FF_FLOW  # Exec flow from prev instruction?
FF_VAR   = idaapi.FF_VAR   # Is byte variable ?
FF_ANYNAME = FF_LABL | FF_NAME

def isFlow(F):       return ((F & FF_FLOW) != 0)
def isVar(F):        return ((F & FF_VAR ) != 0)
def isExtra(F):      return ((F & FF_LINE) != 0)
def isRef(F):        return ((F & FF_REF)  != 0)
def hasName(F):      return ((F & FF_NAME) != 0)
def hasUserName(F):  return ((F & FF_ANYNAME) == FF_NAME)

MS_0TYPE  = idaapi.MS_0TYPE  # Mask for 1st arg typing
FF_0VOID  = idaapi.FF_0VOID  # Void (unknown)?
FF_0NUMH  = idaapi.FF_0NUMH  # Hexadecimal number?
FF_0NUMD  = idaapi.FF_0NUMD  # Decimal number?
FF_0CHAR  = idaapi.FF_0CHAR  # Char ('x')?
FF_0SEG   = idaapi.FF_0SEG   # Segment?
FF_0OFF   = idaapi.FF_0OFF   # Offset?
FF_0NUMB  = idaapi.FF_0NUMB  # Binary number?
FF_0NUMO  = idaapi.FF_0NUMO  # Octal number?
FF_0ENUM  = idaapi.FF_0ENUM  # Enumeration?
FF_0FOP   = idaapi.FF_0FOP   # Forced operand?
FF_0STRO  = idaapi.FF_0STRO  # Struct offset?
FF_0STK   = idaapi.FF_0STK   # Stack variable?

MS_1TYPE  = idaapi.MS_1TYPE  # Mask for 2nd arg typing
FF_1VOID  = idaapi.FF_1VOID  # Void (unknown)?
FF_1NUMH  = idaapi.FF_1NUMH  # Hexadecimal number?
FF_1NUMD  = idaapi.FF_1NUMD  # Decimal number?
FF_1CHAR  = idaapi.FF_1CHAR  # Char ('x')?
FF_1SEG   = idaapi.FF_1SEG   # Segment?
FF_1OFF   = idaapi.FF_1OFF   # Offset?
FF_1NUMB  = idaapi.FF_1NUMB  # Binary number?
FF_1NUMO  = idaapi.FF_1NUMO  # Octal number?
FF_1ENUM  = idaapi.FF_1ENUM  # Enumeration?
FF_1FOP   = idaapi.FF_1FOP   # Forced operand?
FF_1STRO  = idaapi.FF_1STRO  # Struct offset?
FF_1STK   = idaapi.FF_1STK   # Stack variable?

# The following macros answer questions like
#   'is the 1st (or 2nd) operand of instruction or data of the given type'?
# Please note that data items use only the 1st operand type (is...0)

def isDefArg0(F):    return ((F & MS_0TYPE) != FF_0VOID)
def isDefArg1(F):    return ((F & MS_1TYPE) != FF_1VOID)
def isDec0(F):       return ((F & MS_0TYPE) == FF_0NUMD)
def isDec1(F):       return ((F & MS_1TYPE) == FF_1NUMD)
def isHex0(F):       return ((F & MS_0TYPE) == FF_0NUMH)
def isHex1(F):       return ((F & MS_1TYPE) == FF_1NUMH)
def isOct0(F):       return ((F & MS_0TYPE) == FF_0NUMO)
def isOct1(F):       return ((F & MS_1TYPE) == FF_1NUMO)
def isBin0(F):       return ((F & MS_0TYPE) == FF_0NUMB)
def isBin1(F):       return ((F & MS_1TYPE) == FF_1NUMB)
def isOff0(F):       return ((F & MS_0TYPE) == FF_0OFF)
def isOff1(F):       return ((F & MS_1TYPE) == FF_1OFF)
def isChar0(F):      return ((F & MS_0TYPE) == FF_0CHAR)
def isChar1(F):      return ((F & MS_1TYPE) == FF_1CHAR)
def isSeg0(F):       return ((F & MS_0TYPE) == FF_0SEG)
def isSeg1(F):       return ((F & MS_1TYPE) == FF_1SEG)
def isEnum0(F):      return ((F & MS_0TYPE) == FF_0ENUM)
def isEnum1(F):      return ((F & MS_1TYPE) == FF_1ENUM)
def isFop0(F):       return ((F & MS_0TYPE) == FF_0FOP)
def isFop1(F):       return ((F & MS_1TYPE) == FF_1FOP)
def isStroff0(F):    return ((F & MS_0TYPE) == FF_0STRO)
def isStroff1(F):    return ((F & MS_1TYPE) == FF_1STRO)
def isStkvar0(F):    return ((F & MS_0TYPE) == FF_0STK)
def isStkvar1(F):    return ((F & MS_1TYPE) == FF_1STK)

#
#      Bits for DATA bytes
#
DT_TYPE  = idaapi.DT_TYPE  # Mask for DATA typing

FF_BYTE      = idaapi.FF_BYTE      # byte
FF_WORD      = idaapi.FF_WORD      # word
FF_DWRD      = idaapi.FF_DWRD      # dword
FF_QWRD      = idaapi.FF_QWRD      # qword
FF_TBYT      = idaapi.FF_TBYT      # tbyte
FF_ASCI      = idaapi.FF_ASCI      # ASCII ?
FF_STRU      = idaapi.FF_STRU      # Struct ?
FF_OWRD      = idaapi.FF_OWRD      # octaword (16 bytes)
FF_FLOAT     = idaapi.FF_FLOAT     # float
FF_DOUBLE    = idaapi.FF_DOUBLE    # double
FF_PACKREAL  = idaapi.FF_PACKREAL  # packed decimal real
FF_ALIGN     = idaapi.FF_ALIGN     # alignment directive

def isByte(F):     (isData(F) & (F & DT_TYPE) == FF_BYTE)
def isWord(F):     (isData(F) & (F & DT_TYPE) == FF_WORD)
def isDwrd(F):     (isData(F) & (F & DT_TYPE) == FF_DWRD)
def isQwrd(F):     (isData(F) & (F & DT_TYPE) == FF_QWRD)
def isOwrd(F):     (isData(F) & (F & DT_TYPE) == FF_OWRD)
def isTbyt(F):     (isData(F) & (F & DT_TYPE) == FF_TBYT)
def isFloat(F):    (isData(F) & (F & DT_TYPE) == FF_FLOAT)
def isDouble(F):   (isData(F) & (F & DT_TYPE) == FF_DOUBLE)
def isPackReal(F): (isData(F) & (F & DT_TYPE) == FF_PACKREAL)
def isASCII(F):    (isData(F) & (F & DT_TYPE) == FF_ASCI)
def isStruct(F):   (isData(F) & (F & DT_TYPE) == FF_STRU)
def isAlign(F):    (isData(F) & (F & DT_TYPE) == FF_ALIGN)

#
#      Bits for CODE bytes
#
MS_CODE  = idaapi.MS_CODE  
FF_FUNC  = idaapi.FF_FUNC  # function start?
FF_IMMD  = idaapi.FF_IMMD  # Has Immediate value ?
FF_JUMP  = idaapi.FF_JUMP  # Has jump table

#
#      Loader flags
#
NEF_SEGS   = idaapi.NEF_SEGS   # Create segments
NEF_RSCS   = idaapi.NEF_RSCS   # Load resources
NEF_NAME   = idaapi.NEF_NAME   # Rename entries
NEF_MAN    = idaapi.NEF_MAN    # Manual load
NEF_FILL   = idaapi.NEF_FILL   # Fill segment gaps
NEF_IMPS   = idaapi.NEF_IMPS   # Create imports section
NEF_TIGHT  = idaapi.NEF_TIGHT  # Don't align segments (OMF)
NEF_FIRST  = idaapi.NEF_FIRST  # This is the first file loaded
NEF_CODE   = idaapi.NEF_CODE   # for load_binary_file:
NEF_RELOAD = idaapi.NEF_RELOAD # reload the file at the same place:
NEF_FLAT   = idaapi.NEF_FLAT   # Autocreate FLAT group (PE)

#         List of built-in functions
#         --------------------------
#
# The following conventions are used in this list:
#   'ea' is a linear address
#   'success' is 0 if a function failed, 1 otherwise
#   'void' means that function returns no meaningful value (always 0)
#
#  All function parameter conversions are made automatically.
#
# ----------------------------------------------------------------------------
#                       M I S C E L L A N E O U S
# ----------------------------------------------------------------------------
def MK_FP(seg, off):
    """
    Return value of expression: ((seg<<4) + off)
    """
    return (seg << 4) + off

def form(format, *args):
    raise DeprecatedIDCError, "form() is deprecated. Use python string operations instead."

def substr(str,x1,x2):
    raise DeprecatedIDCError, "substr() is deprecated. Use python string operations instead."

def strstr(str, substr):
    raise DeprecatedIDCError, "strstr() is deprecated. Use python string operations instead."

def strlen(str):
    raise DeprecatedIDCError, "strlen() is deprecated. Use python string operations instead."

def xtol(str):
    raise DeprecatedIDCError, "xtol() is deprecated. Use python long() instead."


def atoa(ea):
    """
    Convert address value to a string
    Return address in the form 'seg000:1234'
    (the same as in line prefixes)
    
    @param ea: address to format
    """
    segname = SegName(ea)

    if segname == "":
        segname = "0"

    return "%s:%X" % (segname, ea)


def ltoa(n, radix):
    raise DeprecatedIDCError, "ltoa() is deprecated. Use python string operations instead."

def atol(str):
    raise DeprecatedIDCError, "atol() is deprecated. Use python long() instead."


def rotate_left(value, count, nbits, offset):
    """
    Rotate a value to the left (or right)

    @param x: value to rotate
    @param count: number of times to rotate. negative counter means
                  rotate to the right
    @param nbits: number of bits to rotate
    @param offset: offset of the first bit to rotate

    @return: the value with the specified field rotated
             all other bits are not modified
    """
    assert offset >= 0, "offset must be >= 0"
    assert nbits > 0, "nbits must be > 0"

    mask = 2**(offset+nbits) - 2**offset
    tmp = value & mask

    if count > 0:
        for x in xrange(count):
            if (tmp >> (offset+nbits-1)) & 1:
                tmp = (tmp << 1) | (1 << offset)
            else:
                tmp = (tmp << 1)
    else:
        for x in xrange(-count):
            if (tmp >> offset) & 1:
                tmp = (tmp >> 1) | (1 << (offset+nbits-1))
            else:
                tmp = (tmp >> 1)

    value = (value-(value&mask)) | (tmp & mask)

    return value

def rotate_dword(x, count): rotate_left(x, count, 32, 0)
def rotate_word(x, count): rotate_left(x, count, 16, 0)
def rotate_byte(x, count): rotate_left(x, count, 8, 0)


# AddHotkey return codes
IDCHK_OK        =  0   # ok
IDCHK_ARG       = -1   # bad argument(s)
IDCHK_KEY       = -2   # bad hotkey name
IDCHK_MAX       = -3   # too many IDC hotkeys

def AddHotkey(hotkey, idcfunc):
    """
    Add hotkey for IDC function
    
    @param hotkey: hotkey name ('a', "Alt-A", etc)
    @param idcfunc: IDC function name 

    @note: GUI version doesn't support hotkeys

    @return: None
    """
    return idaapi.add_idc_hotkey(hotkey, idcfunc)    


def DelHotkey(hotkey):
    """
    Delete IDC function hotkey

    @param hotkey: hotkey code to delete
    """
    return idaapi.del_idc_hotkey(hotkey)


def Jump(ea):
    """
    Move cursor to the specifed linear address

    @param ea: linear address
    """
    return idaapi.jumpto(ea)


def Wait():
    """
    Process all entries in the autoanalysis queue
    Wait for the end of autoanalysis

    @note:    This function will suspend execution of the calling script
            till the autoanalysis queue is empty.
    """
    return idaapi.autoWait()


def Compile(filename):
    """
    Compile an IDC file.

    The file being compiled should not contain functions that are
    currently executing - otherwise the behaviour of the replaced
    functions is undefined.

    @param filename: name of file to compile

    @return: 0 - ok, otherwise it returns an error message
    """
    res = idaapi.Compile(filename)

    if res:
        return res
    else:
        return 0


def Exit(code):
    """
    Stop execution of IDC program, close the database and exit to OS
    
    @param code: code to exit with.

    @return: -
    """
    idaapi.qexit(code)


def Exec(command):
    """
    Execute an OS command.

    @param command: command line to execute
    
    @return: error code from OS

    @note:
    IDA will wait for the started program to finish.
    In order to start the command in parallel, use OS methods.
    For example, you may start another program in parallel using 
    "start" command.
    """
    return os.system(command)


def RunPlugin(name, arg):
    """
    Load and run a plugin

    @param name: The plugin name is a short plugin name without an extension
    @param arg: integer argument

    @return: 0 if could not load the plugin, 1 if ok
    """
    return idaapi.load_and_run_plugin(name, arg)


def ApplySig(name):
    """
    Load (plan to apply) a FLIRT signature file

    @param name:  signature name without path and extension

    @return: 0 if could not load the signature file, !=0 otherwise
    """
    return idaapi.plan_to_apply_idasgn(name)


#----------------------------------------------------------------------------
#      C H A N G E   P R O G R A M   R E P R E S E N T A T I O N
#----------------------------------------------------------------------------


def DeleteAll():
    """
    Delete all segments, instructions, comments, i.e. everything
    except values of bytes.
    """
    ea = idaapi.cvar.inf.minEA

    # Brute-force nuke all info from all the heads
    while ea != BADADDR and ea <= idaapi.cvar.inf.maxEA:
        idaapi.del_local_name(ea)
        idaapi.del_global_name(ea)
        func = idaapi.get_func(ea)
        if func: 
            idaapi.del_func_cmt(func, False)
            idaapi.del_func_cmt(func, True)
            idaapi.del_func(ea)
        idaapi.del_hidden_area(ea)    
        seg = idaapi.getseg(ea)
        if seg:
            idaapi.del_segment_cmt(seg, False)
            idaapi.del_segment_cmt(seg, True)
            idaapi.del_segm(ea, idaapi.SEGDEL_KEEP | idaapi.SEGDEL_SILENT)

        ea = idaapi.next_head(ea, idaapi.cvar.inf.maxEA)


def MakeCode(ea):
    """
    Create an instruction at the specified address

    @param ea: linear address

    @return: 0 - can not create an instruction (no such opcode, the instruction
    would overlap with existing items, etc) otherwise returns length of the
    instruction in bytes
    """
    return idaapi.ua_code(ea)


def AnalyzeArea(sEA, eEA):
    """
    Perform full analysis of the area

    @param sEA: starting linear address
    @param eEA: ending linear address (excluded)

    @return: 1-ok, 0-Ctrl-Break was pressed.
    """
    return idaapi.analyze_area(sEA, eEA)


def MakeNameEx(ea, name, flags):
    """
    Rename an address

    @param ea: linear address
    @param name: new name of address. If name == "", then delete old name
    @param flags: combination of SN_... constants

    @return: 1-ok, 0-failure
    """
    return idaapi.set_name(ea, name, flags)

SN_CHECK      = idaapi.SN_CHECK    # Fail if the name contains invalid 
                                   # characters
                                   # If this bit is clear, all invalid chars
                                   # (those !is_ident_char()) will be replaced
                                   # by SubstChar (usually '_')
                                   # List of valid characters is defined in 
                                   # ida.cfg
SN_NOCHECK    = idaapi.SN_NOCHECK  # Replace invalid chars with SubstChar
SN_PUBLIC     = idaapi.SN_PUBLIC   # if set, make name public
SN_NON_PUBLIC = idaapi.SN_NON_PUBLIC # if set, make name non-public
SN_WEAK       = idaapi.SN_WEAK     # if set, make name weak
SN_NON_WEAK   = idaapi.SN_NON_WEAK # if set, make name non-weak
SN_AUTO       = idaapi.SN_AUTO     # if set, make name autogenerated
SN_NON_AUTO   = idaapi.SN_NON_AUTO # if set, make name non-autogenerated
SN_NOLIST     = idaapi.SN_NOLIST   # if set, exclude name from the list
                                   # if not set, then include the name into
                                   # the list (however, if other bits are set,
                                   # the name might be immediately excluded
                                   # from the list)
SN_NOWARN     = idaapi.SN_NOWARN   # don't display a warning if failed
SN_LOCAL      = idaapi.SN_LOCAL    # create local name. a function should exist.
                                   # local names can't be public or weak.
                                   # also they are not included into the list 
                                   # of names they can't have dummy prefixes

def MakeComm(ea, comment):
    """
    Set an indented regular comment of an item

    @param ea: linear address
    @param comment: comment string

    @return: None
    """
    return idaapi.set_cmt(ea, comment, 0)


def MakeRptCmt(ea, comment):
    """
    Set an indented repeatable comment of an item

    @param ea: linear address
    @param comment: comment string

    @return: None
    """
    return idaapi.set_cmt(ea, comment, 1)


def MakeArray(ea, nitems):
    """
    Create an array.

    @param ea: linear address
    @param nitems: size of array in items

    @note: This function will create an array of the items with the same type as
    the type of the item at 'ea'. If the byte at 'ea' is undefined, then
    this function will create an array of bytes.
    """
    flags = idaapi.getFlags(ea)

    if idaapi.isUnknown(flags):
        flags = idaapi.FF_BYTE

    if idaapi.isStruct(flags):
        ti = idaapi.typeinfo_t()
        assert idaapi.get_typeinfo(ea, 0, flags, ti), "get_typeinfo() failed"
        itemsize = idaapi.get_data_elsize(ea, flags, ti)
        tid = ti.tid
    else:
        itemsize = idaapi.get_item_size(ea)
        tid = BADADDR

    return idaapi.do_data_ex(ea, flags, itemsize*nitems, tid)


def MakeStr(ea, endea):
    """
    Create a string.

    This function creates a string (the string type is determined by the
    value of GetLongPrm(INF_STRTYPE))
    
    @param ea: linear address
    @param endea: ending address of the string (excluded)
        if endea == BADADDR, then length of string will be calculated
        by the kernel
    
    @return: 1-ok, 0-failure

    @note: The type of an existing string is returned by GetStringType()
    """
    return idaapi.make_ascii_string(ea, endea - ea, GetLongPrm(INF_STRTYPE))    


def MakeData(ea, flags, size, tid):
    """
    Create a data item at the specified address
    
    @param ea: linear address
    @param flags: FF_BYTE..FF_PACKREAL
    @param size: size of item in bytes
    @param tid: for FF_STRU the structure id

    @return: 1-ok, 0-failure
    """
    raise NotImplementedError


def MakeByte(ea):
    """
    Convert the current item to a byte

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doByte(ea, 1)


def MakeWord(ea):
    """
    Convert the current item to a word (2 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doWord(ea, 2)


def MakeDword(ea):
    """
    Convert the current item to a double word (4 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doDwrd(ea, 4)


def MakeQword(ea):
    """
    Convert the current item to a quadro word (8 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doQwrd(ea, 8)


def MakeOword(ea):
    """
    Convert the current item to a octa word (16 bytes)

    @param ea: linear address
    
    @return: 1-ok, 0-failure
    """
    return idaapi.doOwrd(ea, 16)


def MakeFloat(ea):
    """
    Convert the current item to a floating point (4 bytes)

    @param ea: linear address
    
    @return: 1-ok, 0-failure
    """
    return idaapi.doFloat(ea, 4)


def MakeDouble(ea):
    """
    Convert the current item to a double floating point (8 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doDouble(ea, 8)


def MakePackReal(ea):
    """
    Convert the current item to a packed real (10 or 12 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doPackReal(ea, idaapi.cvar.ph.tbyte_size)


def MakeTbyte(ea):
    """
    Convert the current item to a tbyte (10 or 12 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doTbyt(ea, idaapi.cvar.ph.tbyte_size)


def MakeStructEx(ea, size, strname):
    """
    Convert the current item to a structure instance

    @param ea: linear address
    @param size: structure size in bytes. -1 means that the size
        will be calculated automatically
    @param strname: name of a structure type

    @return: 1-ok, 0-failure
    """
    strid = idaapi.get_struc_id(strname)

    # FIXME: This should be changed to BADNODE
    if strid == 0xFFFFFFFF:
        return False

    if size == -1:
        size = idaapi.get_struc_size(strid)

    return idaapi.doStruct(ea, size, strid)    


def MakeAlign(ea, count, align):
    """
    Convert the current item to an alignment directive

    @param ea: linear address
    @param count: number of bytes to convert
    @param align: 0 or 1..32
              if it is 0, the correct alignment will be calculated
              by the kernel

    @return: 1-ok, 0-failure
    """
    return idaapi.doAlign(ea, count, align)


def MakeLocal(start, end, location, name):
    """
    Create a local variable

    @param start: start of address range for the local variable
    @param end: end of address range for the local variable
    @param location: the variable location in the "[bp+xx]" form where xx is
                     a number. The location can also be specified as a 
                     register name.
    @param name: name of the local variable

    @return: 1-ok, 0-failure

    @note: For the stack variables the end address is ignored.
           If there is no function at 'start' then this function.
           will fail.
    """
    func = idaapi.get_func(start)

    if not func:
        return 0

    # Find out if location is in the [bp+xx] form
    r = re.compile("\[([a-z]+)([-+][0-9a-fx]+)", re.IGNORECASE)
    m = r.match(location)

    if m:
        # Location in the form of [bp+xx]
        register = idaapi.str2reg(m.group(1))
        offset = int(m.group(2), 0)
        frame = idaapi.get_frame(func)

        print register, frame

        if register == -1 or not frame:
            return 0

        offset += func.frsize

        member = idaapi.get_member(frame, offset)

        if member:
            # Member already exists, rename it
            if idaapi.set_member_name(frame, offset, name):
                return 1
            else:
                return 0
        else:
            # No member at the offset, create a new one
            if idaapi.add_struc_member(frame,
                                       name,
                                       offset,
                                       idaapi.byteflag(),
                                       None, 1) == 0:
                return 1
            else:
                return 0
    else:
        # Location as simple register name
        return idaapi.add_regvar(func, start, end, location, name, None)


def MakeUnkn(ea, flags):
    """
    Convert the current item to an explored item

    @param ea: linear address
    @param flags: combination of DOUNK_* constants

    @return: None
    """
    return idaapi.do_unknown(ea, flags)


def MakeUnkn(ea, flags):
    raise NotImplementedError


def MakeUnknown(ea, size, flags):
    """
    Convert the current item to an explored item

    @param ea: linear address
    @param size: size of the range to undefine (for MakeUnknown)
    @param flags: combination of DOUNK_* constants

    @return: None
    """
    return idaapi.do_unknown_range(ea, size, flags)


DOUNK_SIMPLE   = idaapi.DOUNK_SIMPLE   # simply undefine the specified item
DOUNK_EXPAND   = idaapi.DOUNK_EXPAND   # propogate undefined items, for example
                                       # if removing an instruction removes all
                                       # references to the next instruction, then
                                       # plan to convert to unexplored the next
                                       # instruction too.
DOUNK_DELNAMES = idaapi.DOUNK_DELNAMES # delete any names at the specified address(es)


def OpBinary(ea, n):
    """
    Convert an operand of the item (instruction or data) to a binary number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands

    @return: 1-ok, 0-failure

    @note: the data items use only the type of the first operand
    """
    return idaapi.op_bin(ea, n)


def OpOctal(ea, n):
    """
    Convert an operand of the item (instruction or data) to an octal number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_oct(ea, n)


def OpDecimal(ea, n):
    """
    Convert an operand of the item (instruction or data) to a decimal number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_dec(ea, n)


def OpHex(ea, n):
    """
    Convert an operand of the item (instruction or data) to a hexadecimal number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_hex(ea, n)


def OpChr(ea, n):
    """
    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_chr(ea, n)


def OpOff(ea, n, base):
    """
    Convert operand to an offset
    (for the explanations of 'ea' and 'n' please see OpBinary())
    
    Example:
    ========

        seg000:2000 dw      1234h
    
        and there is a segment at paragraph 0x1000 and there is a data item
        within the segment at 0x1234:
        
        seg000:1234 MyString        db 'Hello, world!',0
        
        Then you need to specify a linear address of the segment base to
        create a proper offset:
        
        OpOffset(["seg000",0x2000],0,0x10000);
        
        and you will have:
        
        seg000:2000 dw      offset MyString
    
    Motorola 680x0 processor have a concept of "outer offsets".
    If you want to create an outer offset, you need to combine number
    of the operand with the following bit:

    Please note that the outer offsets are meaningful only for
    Motorola 680x0.

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    @param base: base of the offset as a linear address
        If base == BADADDR then the current operand becomes non-offset
    """
    return idaapi.set_offset(ea, n, base)


OPND_OUTER = idaapi.OPND_OUTER # outer offset base


def OpOffEx(ea, n, reftype, target, base, tdelta):
    """
    Convert operand to a complex offset expression
    This is a more powerful version of OpOff() function.
    It allows to explicitly specify the reference type (off8,off16, etc)
    and the expression target with a possible target delta.
    The complex expressions are represented by IDA in the following form:

    target + tdelta - base

    If the target is not present, then it will be calculated using

    target = operand_value - tdelta + base

    The target must be present for LOW.. and HIGH.. reference types

    @param ea: linear address of the instruction/data
    @param n: number of operand to convert (the same as in OpOff)
    @param reftype: one of REF_... constants
    @param target: an explicitly specified expression target. if you don't
              want to specify it, use -1. Please note that LOW... and
              HIGH... reference type requre the target.
    @param base: the offset base (a linear address)
    @param tdelta: a displacement from the target which will be displayed
              in the expression.

    @return: success (boolean)
    """
    return idaapi.op_offset(ea, n, reftype, target, base, tdelta)


REF_OFF8    = idaapi.REF_OFF8    # 8bit full offset
REF_OFF16   = idaapi.REF_OFF16   # 16bit full offset
REF_OFF32   = idaapi.REF_OFF32   # 32bit full offset
REF_LOW8    = idaapi.REF_LOW8    # low 8bits of 16bit offset
REF_LOW16   = idaapi.REF_LOW16   # low 16bits of 32bit offset
REF_HIGH8   = idaapi.REF_HIGH8   # high 8bits of 16bit offset
REF_HIGH16  = idaapi.REF_HIGH16  # high 16bits of 32bit offset
REF_VHIGH   = idaapi.REF_VHIGH   # high ph.high_fixup_bits of 32bit offset (processor dependent)
REF_VLOW    = idaapi.REF_VLOW    # low  (32-ph.high_fixup_bits) of 32bit offset (processor dependent)
REF_OFF64   = idaapi.REF_OFF64   # 64bit full offset
REFINFO_RVA     = 0x10 # based reference (rva)
REFINFO_PASTEND = 0x20 # reference past an item it may point to an nonexistitng
                       # do not destroy alignment dirs
REFINFO_NOBASE  = 0x80 # offset base is a number
                       # that base have be any value
                       # nb: base xrefs are created only if base
                       # points to the middle of a segment


def OpSeg(ea, n):
    """
    Convert operand to a segment expression

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_seg(ea, n)


def OpNumber(ea, n):
    """
    Convert operand to a number (with default number base, radix)

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_num(ea, n)


def OpAlt(ea, n, str):
    """
    Specify operand represenation manually.

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    @param str: a string represenation of the operand

    @note: IDA will not check the specified operand, it will simply display
    it instead of the orginal representation of the operand.
    """
    return idaapi.set_forced_operand(ea, n, str)


def OpSign(ea, n):
    """
    Change sign of the operand

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.toggle_signness(ea, n)


def OpNot(ea, n):
    """
    Toggle the bitwise not operator for the operand

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    idaapi.toggle_bnot(ea, n)
    return True


def OpEnumEx(ea, n, enumid, serial):
    """
    Convert operand to a symbolic constant

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    @param enumid: id of enumeration type
    @param serial: serial number of the constant in the enumeration
             The serial numbers are used if there are more than
             one symbolic constant with the same value in the
             enumeration. In this case the first defined constant
             get the serial number 0, then second 1, etc.
             There could be 256 symbolic constants with the same
             value in the enumeration.
    """
    return idaapi.op_enum(ea, n, enumid, serial)


def OpStroffEx(ea, n, strid, delta):
    """
    Convert operand to an offset in a structure
    
    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    @param strid: id of a structure type
    @param delta: struct offset delta. usually 0. denotes the difference
                    between the structure base and the pointer into the structure.

    """
    path = idaapi.tidArray(1)
    path[0] = strid
    return idaapi.op_stroff(ea, n, path.cast(), 1, delta)


def OpStkvar(ea, n):
    """
    Convert operand to a stack variable
    
    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_stkvar(ea, n)


def OpHigh(ea, n, target):
    """
    Convert operand to a high offset
    High offset is the upper 16bits of an offset.
    This type is used by TMS320C6 processors (and probably by other
    RISC processors too)

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    @param target: the full value (all 32bits) of the offset
    """
    return idaapi.op_offset(ea, n, idaapi.REF_HIGH16, target)


def MakeVar(ea):
    """
    Mark the location as "variable"

    @param ea: address to mark

    @return: None

    @note: All that IDA does is to mark the location as "variable". 
    Nothing else, no additional analysis is performed.
    This function may disappear in the future.
    """
    idaapi.doVar(ea, 1)


def ExtLinA(ea, n, line):
    """
    Specify an additional line to display before the generated ones.

    @param ea: linear address
    @param n: number of anterior additioal line (0..MAX_ITEM_LINES)
    @param line: the line to display

    @return: None

    @note: IDA displays additional lines from number 0 up to the first unexisting
    additional line. So, if you specify additional line #150 and there is no
    additional line #149, your line will not be displayed.  MAX_ITEM_LINES is
    defined in IDA.CFG
    """
    idaapi.ExtraUpdate(ea, line, idaapi.E_PREV + n)


def ExtLinB(ea, n, line):
    """
    Specify an additional line to display after the generated ones.

    @param ea: linear address
    @param n: number of posterior additioal line (0..MAX_ITEM_LINES)
    @param line: the line to display

    @return: None
    
    @note: IDA displays additional lines from number 0 up to the first
    unexisting additional line. So, if you specify additional line #150 
    and there is no additional line #149, your line will not be displayed. 
    MAX_ITEM_LINES is defined in IDA.CFG
    """
    idaapi.ExtraUpdate(ea, line, idaapi.E_NEXT + n)


def DelExtLnA(ea, n):
    """
    Delete an additional anterior line

    @param ea: linear address
    @param n: number of anterior additioal line (0..500)

    @return: None
    """
    idaapi.ExtraDel(ea, idaapi.E_PREV + n)


def DelExtLnB(ea, n):
    """
    Delete an additional posterior line

    @param ea: linear address
    @param n: number of posterior additioal line (0..500)

    @return: None
    """
    idaapi.ExtraDel(ea, idaapi.E_NEXT + n)


def SetManualInsn(ea, insn):
    """
    Specify instruction represenation manually.

    @param ea: linear address
    @param insn: a string represenation of the operand

    @note: IDA will not check the specified instruction, it will simply 
    display it instead of the orginal representation.
    """
    return idaapi.set_manual_insn(ea, insn)


def GetManualInsn(ea):
    """
    Get manual representation of instruction

    @param ea: linear address

    @note: This function returns value set by SetManualInsn earlier.
    """
    return idaapi.get_manual_insn(ea)


def PatchByte(ea, value):
    """
    Change value of a program byte

    @param ea: linear address
    @param value: new value of the byte

    @return: None
    """
    return idaapi.patch_byte(ea, value)


def PatchWord(ea, value):
    """
    Change value of a program word (2 bytes)

    @param ea: linear address
    @param value: new value of the word
    """
    return idaapi.patch_word(ea, value)


def PatchDword(ea, value):
    """
    Change value of a double word

    @param ea: linear address
    @param value: new value of the double word
    """
    return idaapi.patch_long(ea, value)


def SetFlags(ea, flags):
    """
    Set new value of flags
    This function should not used be used directly if possible.
    It changes properties of a program byte and if misused, may lead to
    very-very strange results.

    @param ea: adress
    @param flags: new flags value
    """
    return idaapi.setFlags(ea, flags)

_REGMAP = {
    'es' : idaapi.R_es,
    'cs' : idaapi.R_cs,
    'ss' : idaapi.R_ss,
    'ds' : idaapi.R_ds,
    'fs' : idaapi.R_fs,
    'gs' : idaapi.R_gs
}

def SetReg(ea, reg, value):
    """
    Set value of a segment register.

    @param ea: linear address
    @param reg: name of a register, like "cs", "ds", "es", etc.
    @param value: new value of the segment register.

    @note: IDA keeps tracks of all the points where segment register change their
           values. This function allows you to specify the correct value of a segment
           register if IDA is not able to find the corrent value.

    """
    if _REGMAP.has_key(reg):
        return idaapi.splitSRarea1(ea, _REGMAP[reg], value, 2)
    else:
        return False


def AutoMark2(start, end, queuetype):
    """
    Plan to perform an action in the future.
    This function will put your request to a special autoanalysis queue.
    Later IDA will retrieve the request from the queue and process
    it. There are several autoanalysis queue types. IDA will process all
    queries from the first queue and then switch to the second queue, etc.
    """
    return idaapi.auto_mark_range(start, end, queuetype)


def AutoUnmark(start, end, queuetype):
    """
    Remove range of addresses from a queue.
    """
    return autoUnmark(start, end, queuetype)
    

def AutoMark(ea,qtype):
    """
    Plan to analyze an address
    """
    return AutoMark2(ea,ea+1,qtype)

AU_UNK   = idaapi.AU_UNK   # make unknown
AU_CODE  = idaapi.AU_CODE  # convert to instruction
AU_PROC  = idaapi.AU_PROC  # make function
AU_USED  = idaapi.AU_USED  # reanalyze
AU_LIBF  = idaapi.AU_LIBF  # apply a flirt signature (the current signature!)
AU_FINAL = idaapi.AU_FINAL # coagulate unexplored items


#----------------------------------------------------------------------------
#               P R O D U C E   O U T P U T   F I L E S
#----------------------------------------------------------------------------

def GenerateFile(type, path, ea1, ea2, flags):
    """
    Generate an output file

    @param type:  type of output file. One of OFILE_... symbols. See below.
    @param path:  the output file path (will be overwritten!)
    @param ea1:   start address. For some file types this argument is ignored
    @param ea2:   end address. For some file types this argument is ignored
    @param flags: bit combination of GENFLG_...

    @returns: number of the generated lines.
                -1 if an error occured
                OFILE_EXE: 0-can't generate exe file, 1-ok
    """
    f = idaapi.fopenWT(path)

    if f:
        retval = idaapi.gen_file(type, f, ea1, ea2, flags)
        idaapi.eclose(f)
        return retval
    else:
        return -1


# output file types:
OFILE_MAP  = idaapi.OFILE_MAP  
OFILE_EXE  = idaapi.OFILE_EXE  
OFILE_IDC  = idaapi.OFILE_IDC  
OFILE_LST  = idaapi.OFILE_LST  
OFILE_ASM  = idaapi.OFILE_ASM  
OFILE_DIF  = idaapi.OFILE_DIF  

# output control flags:
GENFLG_MAPSEG  = idaapi.GENFLG_MAPSEG  # map: generate map of segments
GENFLG_MAPNAME = idaapi.GENFLG_MAPNAME # map: include dummy names
GENFLG_MAPDMNG = idaapi.GENFLG_MAPDMNG # map: demangle names
GENFLG_MAPLOC  = idaapi.GENFLG_MAPLOC  # map: include local names
GENFLG_IDCTYPE = idaapi.GENFLG_IDCTYPE # idc: gen only information about types
GENFLG_ASMTYPE = idaapi.GENFLG_ASMTYPE # asm&lst: gen information about types too
GENFLG_GENHTML = idaapi.GENFLG_GENHTML # asm&lst: generate html (gui version only)
GENFLG_ASMINC  = idaapi.GENFLG_ASMINC  # asm&lst: gen information only about types

#----------------------------------------------------------------------------
#                 C O M M O N   I N F O R M A T I O N
#----------------------------------------------------------------------------
def GetIdaDirectory ():
    """
    Get IDA directory

    This function returns the directory where IDA.EXE resides
    """
    return idaapi.idadir()


def GetInputFile():
    """
    Get input file name

    This function returns name of the file being disassembled
    """
    return idaapi.get_root_filename()


def GetInputFilePath():
    """
    Get input file path

    This function returns the full path of the file being disassembled
    """
    return idaapi.get_input_file_path()


def GetIdbPath():
    """
    Get IDB full path

    This function returns full path of the current IDB database
    """
    return idaapi.cvar.database_idb


def GetFlags(ea):
    """
    Get internal flags

    @param ea: linear address

    @return: 32-bit value of internal flags. See start of IDC.IDC file
        for explanations.
    """
    return idaapi.getFlags(ea)


def Byte(ea):
    """
    Get value of program byte

    @param ea: linear address

    @return: value of byte. If byte has no value then returns 0xFF
        If the current byte size is different from 8 bits, then the returned value
        might have more 1's.
        To check if a byte has a value, use functions hasValue(GetFlags(ea))
    """
    return idaapi.get_byte(ea)


def GetOriginalByte(ea):
    """
    Get original value of program byte

    @param ea: linear address

    @return: the original value of byte before any patch applied to it
    """
    return idaapi.get_original_byte(ea)


def Word(ea):
    """
    Get value of program word (2 bytes)

    @param ea: linear address

    @return: the value of the word. If word has no value then returns 0xFFFF
        If the current byte size is different from 8 bits, then the returned value
        might have more 1's.
    """
    return idaapi.get_word(ea)


def Dword(ea):
    """
    Get value of program double word (4 bytes)

    @param ea: linear address
    
    @return: the value of the double word. If double word has no value
        then returns 0xFFFFFFFF.
    """
    return idaapi.get_long(ea)


def GetFloat(ea):
    """
    Get value of a floating point number (4 bytes)
    
    @param ea: linear address

    @return: float
    """
    str = chr(idaapi.get_byte(ea)) + \
          chr(idaapi.get_byte(ea+1)) + \
          chr(idaapi.get_byte(ea+2)) + \
          chr(idaapi.get_byte(ea+3)) 

    return struct.unpack("f", str)[0]


def GetDouble(ea):
    """
    Get value of a floating point number (8 bytes)
    
    @param ea: linear address

    @return: double
    """
    str = chr(idaapi.get_byte(ea)) + \
          chr(idaapi.get_byte(ea+1)) + \
          chr(idaapi.get_byte(ea+2)) + \
          chr(idaapi.get_byte(ea+3)) + \
          chr(idaapi.get_byte(ea+4)) + \
          chr(idaapi.get_byte(ea+5)) + \
          chr(idaapi.get_byte(ea+6)) + \
          chr(idaapi.get_byte(ea+7))

    return struct.unpack("d", str)[0]


def LocByName(name):
    """
    Get linear address of a name

    @param name: name of program byte
    
    @return: address of the name
            badaddr - no such name
    """
    return idaapi.get_name_ea(BADADDR, name)


def LocByNameEx(fromaddr, name):
    """
    Get linear address of a name

    @param fromaddr: the referring address. Allows to retrieve local label
               addresses in functions. If a local name is not found,
               then address of a global name is returned.

    @param name: name of program byte
    
    @return: address of the name (BADADDR - no such name)
    """
    return idaapi.get_name_ea(fromaddr, name)


def SegByBase(base):
    """
    Get segment by segment base
    
    @param base: segment base paragraph or selector

    @return: linear address of the start of the segment or BADADDR 
             if no such segment
    """
    sel = idaapi.find_selector(base)
    seg = idaapi.get_segm_by_sel(sel)

    if seg:
        return seg.startEA
    else:
        return BADADDR


def ScreenEA():
    """
    Get linear address of cursor
    """
    return idaapi.get_screen_ea()


def GetCurrentLine():
    """
    Get the disassembly line at the cursor

    @return: string
    """
    return idaapi.tag_remove(idaapi.get_curline())


def SelStart():
    """
    Get start address of the selected area
    returns BADADDR - the user has not selected an area
    """
    selection, startaddr, endaddr = idaapi.read_selection()

    if selection == 1:
        return startaddr
    else:
        return BADADDR


def SelEnd():
    """
    Get end address of the selected area

    @return: BADADDR - the user has not selected an area
    """
    selection, startaddr, endaddr = idaapi.read_selection()

    if selection == 1:
        return endaddr
    else:
        return BADADDR


def GetReg(ea, reg):
    """
    Get value of segment register at the specified address

    @param ea: linear address
    @param reg: name of segment register

    @return: the value of the segment register or 0xFFFF on error

    @note: The segment registers in 32bit program usually contain selectors,
           so to get paragraph pointed by the segment register you need to 
           call AskSelector() function.
    """
    if _REGMAP.has_key(reg):
        return idaapi.getSR(ea, _REGMAP[reg]) & 0xFFFF
    else:
        return False


def NextAddr(ea):
    """
    Get next address in the program

    @param ea: linear address

    @return: BADADDR - the specified address in the last used address
    """
    return idaapi.nextaddr(ea)


def PrevAddr(ea):
    """
    Get previous address in the program

    @param ea: linear address

    @return: BADADDR - the specified address in the first address
    """
    return idaapi.prevaddr(ea)


def NextHead(ea, maxea):
    """
    Get next defined item (instruction or data) in the program

    @param ea: linear address to start search from
    @param maxea: the search will stop at the address
        maxea is not included in the search range
    
    @return: BADADDR - no (more) defined items
    """
    return idaapi.next_head(ea, maxea)


def PrevHead(ea, minea):
    """
    Get previous defined item (instruction or data) in the program

    @param ea: linear address to start search from
    @param minea: the search will stop at the address
            minea is included in the search range
    
    @return: BADADDR - no (more) defined items
    """
    return idaapi.prev_head(ea, minea)


def NextNotTail(ea):
    """
    Get next not-tail address in the program
    This function searches for the next displayable address in the program.
    The tail bytes of instructions and data are not displayable.

    @param ea: linear address
    
    @return: BADADDR - no (more) not-tail addresses
    """
    return idaapi.next_not_tail(ea)


def PrevNotTail(ea):
    """
    Get previous not-tail address in the program
    This function searches for the previous displayable address in the program.
    The tail bytes of instructions and data are not displayable.

    @param ea: linear address
    
    @return: BADADDR - no (more) not-tail addresses
    """
    return idaapi.prev_not_tail(ea)


def ItemEnd(ea):
    """
    Get address of the end of the item (instruction or data)
    
    @param ea: linear address

    @return: address past end of the item at 'ea'
    """
    return idaapi.get_item_end(ea)


def ItemSize(ea):
    """
    Get size of instruction or data item in bytes

    @param ea: linear address

    @return: 1..n
    """
    return idaapi.get_item_end(ea) - ea


def NameEx(fromaddr, ea):
    """
    Get visible name of program byte

    This function returns name of byte as it is displayed on the screen.
    If a name contains illegal characters, IDA replaces them by the
    substitution character during displaying. See IDA.CFG for the
    definition of the substitution character.

    @param fromaddr: the referring address. May be BADADDR.
               Allows to retrieve local label addresses in functions.
               If a local name is not found, then a global name is 
               returned.
    @param ea: linear address

    @return: "" - byte has no name
    """
    name = idaapi.get_name(fromaddr, ea)

    if not name:
        return ""
    else:
        return name


def GetTrueNameEx(fromaddr, ea):
    """
    Get true name of program byte

    This function returns name of byte as is without any replacements.

    @param fromaddr: the referring address. May be BADADDR.
           Allows to retrieve local label addresses in functions.
           If a local name is not found, then a global name is returned.
    @param ea: linear address

    @return: "" - byte has no name
    """
    name = idaapi.get_true_name(fromaddr, ea)

    if not name:
        return ""
    else:
        return name


def Demangle(name, disable_mask):
    """
    Demangle a name

    @param name: name to demangle
    @param disable_mask: a mask that tells how to demangle the name
            it is a good idea to get this mask using
            GetLongPrm(INF_SHORT_DN) or GetLongPrm(INF_LONG_DN)

    @return: a demangled name
        If the input name cannot be demangled, returns None
    """
    return idaapi.demangle_name(name, disable_mask)


def GetDisasm(ea):
    """
    Get disassembly line

    @param ea: linear address of instruction

    @return: "" - no instruction at the specified location

    @note: this function may not return exactly the same mnemonics 
           as you see on the screen.
    """
    text = idaapi.generate_disasm_line(ea)
    if text:
        return idaapi.tag_remove(text)
    else:
        return ""


def GetMnem(ea):
    """
    Get instruction mnemonics

    @param ea: linear address of instruction
    
    @return: "" - no instruction at the specified location

    @note: this function may not return exactly the same mnemonics
    as you see on the screen.
    """
    res = idaapi.ua_mnem(ea)

    if not res:
        return ""
    else:
        return res


def GetOpnd(ea, n):
    """
    Get operand of an instruction

    @param ea: linear address of instruction
    @param n: number of operand:
        0 - the first operand
        1 - the second operand

    @return: the current text representation of operand
    """
    res = idaapi.ua_outop(ea, n)

    if not res:
        return ""
    else:
        return idaapi.tag_remove(res)


def GetOpType(ea, n):
    """
    Get type of instruction operand

    @param ea: linear address of instruction
    @param n: number of operand:
        0 - the first operand
        1 - the second operand

    @return:
        - -1      bad operand number passed
        - 0       None
        - 1       General Register
        - 2       Memory Reference
        - 3       Base + Index
        - 4       Base + Index + Displacement
        - 5       Immediate
        - 6       Immediate Far Address (with a Segment Selector)
        - 7       Immediate Near Address
        
        B{PC:}
        
        - 8       386 Trace register
        - 9       386 Debug register
        - 10      386 Control register
        - 11      FPP register
        - 12      MMX register
        
        B{8051:}

        - 8       bit
        - 9       /bit
        - 10      bit
        
        B{80196:}

        - 8       [intmem]
        - 9       [intmem]+
        - 10      offset[intmem]
        - 11      bit
        
        B{ARM:}
        
        - 8       shifted register
        - 9       MLA operands
        - 10      register list (for LDM/STM)
        - 11      coprocessor register list (for CDP)
        - 12      coprocessor register (for LDC/STC)
        
        B{PPC:}
        
        - 8       SPR
        - 9       2 FPRs
        - 10      SH & MB & ME
        - 11      CR field
        - 12      CR bit
        
        B{TMS320C5:}
        
        - 8       bit
        - 9       bit not
        - 10      condition
        
        B{TMS320C6:}
        
        - 8       register pair (A1:A0..B15:B14)
        
        B{Z8:}
        
        - 8       @intmem
        - 9       @Rx
        
        B{Z80:}
        
        - 8       condition
    """
    inslen = idaapi.ua_code(ea)

    if inslen == 0:
        return -1

    insn = idaapi.get_current_instruction()

    if not insn:
        return -1

    op = idaapi.get_instruction_operand(insn, n)

    if not op:
        return -1

    return op.type


def GetOperandValue(ea, n):
    """
    Get number used in the operand

    This function returns an immediate number used in the operand

    @param ea: linear address of instruction
    @param n: the operand number

    @return: value
        operand is an immediate value  => immediate value
        operand has a displacement     => displacement
        operand is a direct memory ref => memory address
        operand is a register          => register number
        operand is a register phrase   => phrase number
        otherwise                      => -1
    """
    inslen = idaapi.ua_code(ea)
    if inslen == 0:
        return -1

    insn = idaapi.get_current_instruction()
    if not insn:
        return -1

    op = idaapi.get_instruction_operand(insn, n)
    if not op:
        return -1

    if op.type in [ idaapi.o_mem, idaapi.o_far, idaapi.o_near, idaapi.o_displ ]:
        value = op.addr
    elif op.type == idaapi.o_reg:
        value = op.reg
    elif op.type == idaapi.o_imm:
        value = op.value
    elif op.type == idaapi.o_phrase:
        value = op.phrase
    else:
        value = -1
    return value


def LineA(ea, num):
    """
    Get anterior line

    @param ea: linear address
    @param num: number of anterior line (0..MAX_ITEM_LINES)
          MAX_ITEM_LINES is defined in IDA.CFG
    
    @return: anterior line string
    """
    return idaapi.ExtraGet(ea, idaapi.E_PREV + num)


def LineB(ea, num):
    """
    Get posterior line

    @param ea: linear address
    @param num: number of posterior line (0..MAX_ITEM_LINES)

    @return: posterior line string
    """
    return idaapi.ExtraGet(ea, idaapi.E_NEXT + num)


def GetCommentEx(ea, repeatable):
    """
    Get regular indented comment
    
    @param ea: linear address

    @return: string or None if it fails
    """
    return idaapi.get_cmt(ea, repeatable)


def CommentEx(ea, repeatable): GetCommentEx(ea, repeatable)


def AltOp(ea, n):
    """
    Get manually entered operand string

    @param ea: linear address
    @param n: number of operand:
         0 - the first operand
         1 - the second operand

    @return: string or None if it fails
    """
    return idaapi.get_forced_operand(ea, n)


def GetString(ea, len, type):
    """
    Get string contents
    @param ea: linear address
    @param len: string length. -1 means to calculate the max string length
    @param type: the string type (one of ASCSTR_... constants)

    return: string contents or empty string
    """
    if len == -1:
        strlen = idaapi.get_max_ascii_length(ea, type)
    else:
        strlen = len

    return idaapi.get_ascii_contents(ea, strlen, type)


def GetStringType(ea):
    """
    Get string type

    @param ea: linear address

    Returns one of ASCSTR_... constants
    """
    ti = idaapi.typeinfo_t()

    if idaapi.get_typeinfo(ea, 0, GetFlags(ea), ti):
        return ti.strtype
    else:
        return None

ASCSTR_C       = idaapi.ASCSTR_TERMCHR # C-style ASCII string
ASCSTR_PASCAL  = idaapi.ASCSTR_PASCAL  # Pascal-style ASCII string (length byte)
ASCSTR_LEN2    = idaapi.ASCSTR_LEN2    # Pascal-style, length is 2 bytes
ASCSTR_UNICODE = idaapi.ASCSTR_UNICODE # Unicode string
ASCSTR_LEN4    = idaapi.ASCSTR_LEN4    # Pascal-style, length is 4 bytes
ASCSTR_ULEN2   = idaapi.ASCSTR_ULEN2   # Pascal-style Unicode, length is 2 bytes
ASCSTR_ULEN4   = idaapi.ASCSTR_ULEN4   # Pascal-style Unicode, length is 4 bytes
ASCSTR_LAST    = idaapi.ASCSTR_LAST    # Last string type


#      The following functions search for the specified byte
#          ea - address to start from
#          flag is combination of the following bits

#      returns BADADDR - not found
def FindVoid        (ea, flag): return idaapi.find_void(ea, flag)
def FindCode        (ea, flag): return idaapi.find_code(ea, flag)
def FindData        (ea, flag): return idaapi.find_data(ea, flag)
def FindUnexplored  (ea, flag): return idaapi.find_unknown(ea, flag)
def FindExplored    (ea, flag): return idaapi.find_defined(ea, flag)
def FindImmediate   (ea, flag, value): return idaapi.find_imm(ea, flag, value)

SEARCH_UP       = idaapi.SEARCH_UP       # search backward
SEARCH_DOWN     = idaapi.SEARCH_DOWN     # search forward
SEARCH_NEXT     = idaapi.SEARCH_NEXT     # search next occurence
SEARCH_CASE     = idaapi.SEARCH_CASE     # search case-sensitive
                                         # (only for bin&txt search)
SEARCH_REGEX    = idaapi.SEARCH_REGEX    # enable regular expressions (only for text)
SEARCH_NOBRK    = idaapi.SEARCH_NOBRK    # don't test ctrl-break
SEARCH_NOSHOW   = idaapi.SEARCH_NOSHOW   # don't display the search progress

def FindText(ea, flag, y, x, str):
    """
    @param ea: start address
    @param flag: combination of SEARCH_* flags
    @param y: number of text line at ea to start from (0..MAX_ITEM_LINES)
    @param x: coordinate in this line
    @param str: search string

    @return: ea of result or BADADDR if not found
    """
    return idaapi.find_text(ea, y, x, str, flag)


def FindBinary(ea, flag, str, radix=16):
    """
    @param ea: start address
    @param flag: combination of SEARCH_* flags
    @param str: a string as a user enters it for Search Text in Core
    @param radix: radix of the numbers (default=16)

    @return: ea of result or BADADDR if not found

    @note: Example: "41 42" - find 2 bytes 41h,42h (radix is 16)
    """
    endea = flag & 1 and idaapi.cvar.inf.maxEA or idaapi.cvar.inf.minEA
    return idaapi.find_binary(ea, endea, str, radix, flag)


#----------------------------------------------------------------------------
#       G L O B A L   S E T T I N G S   M A N I P U L A T I O N
#----------------------------------------------------------------------------

# The following functions allow you to set/get common parameters.
# Please note that not all parameters can be set directly.

def GetLongPrm (offset):
    """
    """
    return _IDC_GetAttr(idaapi.cvar.inf, _INFMAP, offset)


def GetShortPrm(offset):
    return GetLongPrm(offset)


def GetCharPrm (offset):
    return GetLongPrm(offset)


def SetLongPrm (offset, value):
    """
    """
    return _IDC_SetAttr(idaapi.cvar.inf, _INFMAP, offset, value)


def SetShortPrm(offset, value):
    SetLongPrm(offset, value)


def SetCharPrm (offset, value):
    SetLongPrm(offset, value)


INF_VERSION     = 3       # short;   Version of database
INF_PROCNAME    = 5       # char[8]; Name of current processor
INF_LFLAGS      = 13      # char;    IDP-dependent flags
LFLG_PC_FPP     = 0x01    #              decode floating point processor
                          #              instructions?
LFLG_PC_FLAT    = 0x02    #              Flat model?
LFLG_64BIT      = 0x04    #              64-bit program?
LFLG_DBG_NOPATH = 0x08    #              do not store input full path
LFLG_SNAPSHOT   = 0x10    #              is memory snapshot?
                          #              in debugger process options
INF_DEMNAMES    = 14      # char;    display demangled names as:
DEMNAM_CMNT  = 0          #              comments
DEMNAM_NAME  = 1          #              regular names
DEMNAM_NONE  = 2          #              don't display
INF_FILETYPE    = 15      # short;   type of input file (see ida.hpp)
FT_EXE_OLD      = 0       #              MS DOS EXE File (obsolete)
FT_COM_OLD      = 1       #              MS DOS COM File (obsolete)
FT_BIN          = 2       #              Binary File
FT_DRV          = 3       #              MS DOS Driver
FT_WIN          = 4       #              New Executable (NE)
FT_HEX          = 5       #              Intel Hex Object File
FT_MEX          = 6       #              MOS Technology Hex Object File
FT_LX           = 7       #              Linear Executable (LX)
FT_LE           = 8       #              Linear Executable (LE)
FT_NLM          = 9       #              Netware Loadable Module (NLM)
FT_COFF         = 10      #              Common Object File Format (COFF)
FT_PE           = 11      #              Portable Executable (PE)
FT_OMF          = 12      #              Object Module Format
FT_SREC         = 13      #              R-records
FT_ZIP          = 14      #              ZIP file (this file is never loaded to IDA database)
FT_OMFLIB       = 15      #              Library of OMF Modules
FT_AR           = 16      #              ar library
FT_LOADER       = 17      #              file is loaded using LOADER DLL
FT_ELF          = 18      #              Executable and Linkable Format (ELF)
FT_W32RUN       = 19      #              Watcom DOS32 Extender (W32RUN)
FT_AOUT         = 20      #              Linux a.out (AOUT)
FT_PRC          = 21      #              PalmPilot program file
FT_EXE          = 22      #              MS DOS EXE File
FT_COM          = 23      #              MS DOS COM File
FT_AIXAR        = 24      #              AIX ar library
INF_FCORESIZ    = 17
INF_CORESTART   = 21
INF_OSTYPE      = 25      # short;   FLIRT: OS type the program is for
OSTYPE_MSDOS = 0x0001
OSTYPE_WIN   = 0x0002
OSTYPE_OS2   = 0x0004
OSTYPE_NETW  = 0x0008
INF_APPTYPE     = 27      # short;   FLIRT: Application type
APPT_CONSOLE = 0x0001     #              console
APPT_GRAPHIC = 0x0002     #              graphics
APPT_PROGRAM = 0x0004     #              EXE
APPT_LIBRARY = 0x0008     #              DLL
APPT_DRIVER  = 0x0010     #              DRIVER
APPT_1THREAD = 0x0020     #              Singlethread
APPT_MTHREAD = 0x0040     #              Multithread
APPT_16BIT   = 0x0080     #              16 bit application
APPT_32BIT   = 0x0100     #              32 bit application
INF_START_SP    = 29      # long;    SP register value at the start of
                          #          program execution
INF_START_AF    = 33      # short;   Analysis flags:
AF_FIXUP        = 0x0001  #              Create offsets and segments using fixup info
AF_MARKCODE     = 0x0002  #              Mark typical code sequences as code
AF_UNK          = 0x0004  #              Delete instructions with no xrefs
AF_CODE         = 0x0008  #              Trace execution flow
AF_PROC         = 0x0010  #              Create functions if call is present
AF_USED         = 0x0020  #              Analyze and create all xrefs
AF_FLIRT        = 0x0040  #              Use flirt signatures
AF_PROCPTR      = 0x0080  #              Create function if data xref data->code32 exists
AF_JFUNC        = 0x0100  #              Rename jump functions as j_...
AF_NULLSUB      = 0x0200  #              Rename empty functions as nullsub_...
AF_LVAR         = 0x0400  #              Create stack variables
AF_TRACE        = 0x0800  #              Trace stack pointer
AF_ASCII        = 0x1000  #              Create ascii string if data xref exists
AF_IMMOFF       = 0x2000  #              Convert 32bit instruction operand to offset
AF_DREFOFF      = 0x4000  #              Create offset if data xref to seg32 exists
AF_FINAL        = 0x8000  #              Final pass of analysis
INF_START_IP    = 35      # long;    IP register value at the start of
                          #          program execution
INF_BEGIN_EA    = 39      # long;    Linear address of program entry point
INF_MIN_EA      = 43      # long;    The lowest address used
                          #          in the program
INF_MAX_EA      = 47      # long;    The highest address used
                          #          in the program - = 1
INF_OMIN_EA     = 51
INF_OMAX_EA     = 55
INF_LOW_OFF     = 59      # long;    low limit of voids
INF_HIGH_OFF    = 63      # long;    high limit of voids
INF_MAXREF      = 67      # long;    max xref depth
INF_ASCII_BREAK = 71      # char;    ASCII line break symbol
INF_WIDE_HIGH_BYTE_FIRST = 72
INF_INDENT      = 73      # char;    Indention for instructions
INF_COMMENT     = 74      # char;    Indention for comments
INF_XREFNUM     = 75      # char;    Number of references to generate
                          #          = 0 - xrefs wont be generated at all
INF_ENTAB       = 76      # char;    Use '\t' chars in the output file?
INF_SPECSEGS    = 77
INF_VOIDS       = 78      # char;    Display void marks?
INF_SHOWAUTO    = 80      # char;    Display autoanalysis indicator?
INF_AUTO        = 81      # char;    Autoanalysis is enabled?
INF_BORDER      = 82      # char;    Generate borders?
INF_NULL        = 83      # char;    Generate empty lines?
INF_GENFLAGS    = 84      # char;    General flags:
INFFL_LZERO     = 0x01    #              generate leading zeroes in numbers
INF_SHOWPREF    = 85      # char;    Show line prefixes?
INF_PREFSEG     = 86      # char;    line prefixes with segment name?
INF_ASMTYPE     = 87      # char;    target assembler number (0..n)
INF_BASEADDR    = 88      # long;    base paragraph of the program
INF_XREFS       = 92      # char;    xrefs representation:
SW_SEGXRF       = 0x01    #              show segments in xrefs?
SW_XRFMRK       = 0x02    #              show xref type marks?
SW_XRFFNC       = 0x04    #              show function offsets?
SW_XRFVAL       = 0x08    #              show xref values? (otherwise-"...")
INF_BINPREF     = 93      # short;   # of instruction bytes to show
                          #          in line prefix
INF_CMTFLAG     = 95      # char;    comments:
SW_RPTCMT       = 0x01    #              show repeatable comments?
SW_ALLCMT       = 0x02    #              comment all lines?
SW_NOCMT        = 0x04    #              no comments at all
SW_LINNUM       = 0x08    #              show source line numbers
SW_MICRO        = 0x10    #              show microcode (if implemented)
INF_NAMETYPE    = 96      # char;    dummy names represenation type
NM_REL_OFF      = 0
NM_PTR_OFF      = 1
NM_NAM_OFF      = 2
NM_REL_EA       = 3
NM_PTR_EA       = 4
NM_NAM_EA       = 5
NM_EA           = 6
NM_EA4          = 7
NM_EA8          = 8
NM_SHORT        = 9
NM_SERIAL       = 10
INF_SHOWBADS    = 97      # char;    show bad instructions?
                          #          an instruction is bad if it appears
                          #          in the ash.badworks array

INF_PREFFLAG    = 98      # char;    line prefix type:
PREF_SEGADR     = 0x01    #              show segment addresses?
PREF_FNCOFF     = 0x02    #              show function offsets?
PREF_STACK      = 0x04    #              show stack pointer?

INF_PACKBASE    = 99      # char;    pack database?

INF_ASCIIFLAGS  = 100     # uchar;   ascii flags
ASCF_GEN        = 0x01    #              generate ASCII names?
ASCF_AUTO       = 0x02    #              ASCII names have 'autogenerated' bit?
ASCF_SERIAL     = 0x04    #              generate serial names?
ASCF_COMMENT    = 0x10    #              generate auto comment for ascii references?
ASCF_SAVECASE   = 0x20    #              preserve case of ascii strings for identifiers

INF_LISTNAMES   = 101     # uchar;   What names should be included in the list?
LN_NORMAL       = 0x01    #              normal names
LN_PUBLIC       = 0x02    #              public names
LN_AUTO         = 0x04    #              autogenerated names
LN_WEAK         = 0x08    #              weak names

INF_ASCIIPREF   = 102     # char[16];ASCII names prefix
INF_ASCIISERNUM = 118     # ulong;   serial number
INF_ASCIIZEROES = 122     # char;    leading zeroes
INF_MF          = 126     # uchar;   Byte order: 1==MSB first
INF_ORG         = 127     # char;    Generate 'org' directives?
INF_ASSUME      = 128     # char;    Generate 'assume' directives?
INF_CHECKARG    = 129     # char;    Check manual operands?
INF_START_SS    = 130     # long;    value of SS at the start
INF_START_CS    = 134     # long;    value of CS at the start
INF_MAIN        = 138     # long;    address of main()
INF_SHORT_DN    = 142     # long;    short form of demangled names
INF_LONG_DN     = 146     # long;    long form of demangled names
                          #          see demangle.h for definitions
INF_DATATYPES   = 150     # long;    data types allowed in data carousel
INF_STRTYPE     = 154     # long;    current ascii string type
                          #          is considered as several bytes:
                          #      low byte:
ASCSTR_TERMCHR  = 0       #              Character-terminated ASCII string
ASCSTR_C        = 0       #              C-string, zero terminated
ASCSTR_PASCAL   = 1       #              Pascal-style ASCII string (length byte)
ASCSTR_LEN2     = 2       #              Pascal-style, length is 2 bytes
ASCSTR_UNICODE  = 3       #              Unicode string
ASCSTR_LEN4     = 4       #              Delphi string, length is 4 bytes
ASCSTR_ULEN2    = 5       #              Pascal-style Unicode, length is 2 bytes
ASCSTR_ULEN4    = 6       #              Pascal-style Unicode, length is 4 bytes

#      = 2nd byte - termination chracters for ASCSTR_TERMCHR:
#STRTERM1(strtype)       ((strtype>>8)&0xFF)
#      = 3d byte:
#STRTERM2(strtype)       ((strtype>>16)&0xFF)
                         #              The termination characters are kept in
                         #              the = 2nd and 3d bytes of string type
                         #              if the second termination character is
                         #              '\0', then it is ignored.
INF_AF2         = 158    # ushort;  Analysis flags 2
AF2_JUMPTBL     = 0x0001  # Locate and create jump tables
AF2_DODATA      = 0x0002  # Coagulate data segs in final pass
AF2_HFLIRT      = 0x0004  # Automatically hide library functions
AF2_STKARG      = 0x0008  # Propagate stack argument information
AF2_REGARG      = 0x0010  # Propagate register argument information
AF2_CHKUNI      = 0x0020  # Check for unicode strings
AF2_SIGCMT      = 0x0040  # Append a signature name comment for recognized anonymous library functions
AF2_SIGMLT      = 0x0080  # Allow recognition of several copies of the same function
AF2_FTAIL       = 0x0100  # Create function tails
AF2_DATOFF      = 0x0200  # Automatically convert data to offsets
AF2_ANORET      = 0x0400  # Perform 'no-return' analysis
AF2_VERSP       = 0x0800  # Perform full stack pointer analysis
AF2_DOCODE      = 0x1000  # Coagulate code segs at the final pass

INF_NAMELEN     = 160    # ushort;  max name length (without zero byte)
INF_MARGIN      = 162    # ushort;  max length of data lines
INF_LENXREF     = 164    # ushort;  max length of line with xrefs
INF_LPREFIX     = 166    # char[16];prefix of local names
                         #          if a new name has this prefix,
                         #          it will be automatically converted to a local name
INF_LPREFIXLEN  = 182    # uchar;   length of the lprefix
INF_COMPILER    = 183    # uchar;   compiler
COMP_MASK       = 0x0F
COMP_UNK        = 0x00      # Unknown
COMP_MS         = 0x01      # Visual C++
COMP_BC         = 0x02      # Borland C++
COMP_WATCOM     = 0x03      # Watcom C++
COMP_GNU        = 0x06      # GNU C++
COMP_VISAGE     = 0x07      # Visual Age C++
COMP_BP         = 0x08      # Delphi

INF_MODEL       = 184    # uchar;   memory model & calling convention
INF_SIZEOF_INT  = 185    # uchar;   sizeof(int)
INF_SIZEOF_BOOL = 186    # uchar;   sizeof(bool)
INF_SIZEOF_ENUM = 187    # uchar;   sizeof(enum)
INF_SIZEOF_ALGN = 188    # uchar;   default alignment
INF_SIZEOF_SHORT = 189
INF_SIZEOF_LONG  = 190
INF_SIZEOF_LLONG = 191

_INFMAP = {
INF_VERSION     : 'version',      # short;   Version of database
INF_PROCNAME    : 'procname',     # char[8]; Name of current processor
INF_LFLAGS      : 'lflags',       # char;    IDP-dependent flags
INF_DEMNAMES    : 'demnames',     # char;    display demangled names as:
INF_FILETYPE    : 'filetype',     # short;   type of input file (see ida.hpp)
INF_FCORESIZ    : 'fcoresize',
INF_CORESTART   : 'corestart',
INF_OSTYPE      : 'ostype',       # short;   FLIRT: OS type the program is for
INF_APPTYPE     : 'apptype',      # short;   FLIRT: Application type
INF_START_SP    : 'startSP',      # long;    SP register value at the start of
INF_START_AF    : 'af',           # short;   Analysis flags:
INF_START_IP    : 'startIP',      # long;    IP register value at the start of
INF_BEGIN_EA    : 'beginEA',      # long;    Linear address of program entry point
INF_MIN_EA      : 'minEA',        # long;    The lowest address used
INF_MAX_EA      : 'maxEA',        # long;    The highest address used
INF_OMIN_EA     : 'ominEA',
INF_OMAX_EA     : 'omaxEA',
INF_LOW_OFF     : 'lowoff',       # long;    low limit of voids
INF_HIGH_OFF    : 'highoff',      # long;    high limit of voids
INF_MAXREF      : 'maxref',       # long;    max xref depth
INF_ASCII_BREAK : 'ASCIIbreak',   # char;    ASCII line break symbol
INF_WIDE_HIGH_BYTE_FIRST : 'wide_high_byte_first',
INF_INDENT      : 'indent',       # char;    Indention for instructions
INF_COMMENT     : 'comment',      # char;    Indention for comments
INF_XREFNUM     : 'xrefnum',      # char;    Number of references to generate
INF_ENTAB       : 's_entab',      # char;    Use '\t' chars in the output file?
INF_SPECSEGS    : 'specsegs',
INF_VOIDS       : 's_void',       # char;    Display void marks?
INF_SHOWAUTO    : 's_showauto',   # char;    Display autoanalysis indicator?
INF_AUTO        : 's_auto',       # char;    Autoanalysis is enabled?
# FIXME: This might be incorrect
INF_BORDER      : 's_limiter',    # char;    Generate borders?
INF_NULL        : 's_null',       # char;    Generate empty lines?
INF_GENFLAGS    : 's_genflags',   # char;    General flags:
INF_SHOWPREF    : 's_showpref',   # char;    Show line prefixes?
INF_PREFSEG     : 's_prefseg',    # char;    line prefixes with segment name?
INF_ASMTYPE     : 'asmtype',      # char;    target assembler number (0..n)
INF_BASEADDR    : 'baseaddr',     # long;    base paragraph of the program
INF_XREFS       : 's_xrefflag',   # char;    xrefs representation:
INF_BINPREF     : 'binSize',      # short;   # of instruction bytes to show
INF_CMTFLAG     : 's_cmtflg',     # char;    comments:
INF_NAMETYPE    : 'nametype',     # char;    dummy names represenation type
INF_SHOWBADS    : 's_showbads',   # char;    show bad instructions?
INF_PREFFLAG    : 's_prefflag',   # char;    line prefix type:
INF_PACKBASE    : 's_packbase',   # char;    pack database?
INF_ASCIIFLAGS  : 'asciiflags',   # uchar;   ascii flags
INF_LISTNAMES   : 'listnames',    # uchar;   What names should be included in the list?
INF_ASCIIPREF   : 'ASCIIpref',    # char[16];ASCII names prefix
INF_ASCIISERNUM : 'ASCIIsernum',  # ulong;   serial number
INF_ASCIIZEROES : 'ASCIIzeroes',  # char;    leading zeroes
INF_MF          : 'mf',           # uchar;   Byte order: 1==MSB first
INF_ORG         : 's_org',        # char;    Generate 'org' directives?
INF_ASSUME      : 's_assume',     # char;    Generate 'assume' directives?
INF_CHECKARG    : 's_checkarg',   # char;    Check manual operands?
INF_START_SS    : 'start_ss',     # long;    value of SS at the start
INF_START_CS    : 'start_cs',     # long;    value of CS at the start
INF_MAIN        : 'main',         # long;    address of main()
INF_SHORT_DN    : 'short_demnames', # long;    short form of demangled names
INF_LONG_DN     : 'long_demnames', # long;    long form of demangled names
INF_DATATYPES   : 'datatypes',    # long;    data types allowed in data carousel
INF_STRTYPE     : 'strtype',      # long;    current ascii string type
INF_AF2         : 'af2',          # ushort;  Analysis flags 2
INF_NAMELEN     : 'namelen',      # ushort;  max name length (without zero byte)
INF_MARGIN      : 'margin',       # ushort;  max length of data lines
INF_LENXREF     : 'lenxref',      # ushort;  max length of line with xrefs
INF_LPREFIX     : 'lprefix',      # char[16];prefix of local names
INF_LPREFIXLEN  : 'lprefixlen',   # uchar;   length of the lprefix
INF_COMPILER    : 'cc'            # uchar;   compiler

#INF_MODEL       = 184             # uchar;   memory model & calling convention
#INF_SIZEOF_INT  = 185             # uchar;   sizeof(int)
#INF_SIZEOF_BOOL = 186             # uchar;   sizeof(bool)
#INF_SIZEOF_ENUM = 187             # uchar;   sizeof(enum)
#INF_SIZEOF_ALGN = 188             # uchar;   default alignment
#INF_SIZEOF_SHORT = 189
#INF_SIZEOF_LONG  = 190
#INF_SIZEOF_LLONG = 191
}


def SetProcessorType (processor, level):
    """
    Change current processor

    @param processor: name of processor in short form.
                      run 'ida ?' to get list of allowed processor types
    @param level: the power of request:
                  SETPROC_COMPAT - search for the processor type in the current module
                  SETPROC_ALL    - search for the processor type in all modules
                                   only if there were not calls with SETPROC_USER
                  SETPROC_USER   - search for the processor type in all modules
                                   and prohibit level SETPROC_USER
                  SETPROC_FATAL  - can be combined with previous bits.
                                   means that if the processor type can't be
                                   set, IDA should display an error message and exit.
    """
    return idaapi.set_processor_type(processor, level)

SETPROC_COMPAT = idaapi.SETPROC_COMPAT 
SETPROC_ALL    = idaapi.SETPROC_ALL    
SETPROC_USER   = idaapi.SETPROC_USER   
SETPROC_FATAL  = idaapi.SETPROC_FATAL  

def SetPrcsr(processor): return SetProcessorType(processor, SETPROC_COMPAT)


def Batch(batch):
    """
    Enable/disable batch mode of operation

    @param batch: Batch mode
            0 - ida will display dialog boxes and wait for the user input
            1 - ida will not display dialog boxes, warnings, etc.

    @return: old balue of batch flag
    """
    batch_prev = idaapi.cvar.batch
    idaapi.cvar.batch = batch
    return batch_prev


#----------------------------------------------------------------------------
#          I N T E R A C T I O N   W I T H   T H E   U S E R
#----------------------------------------------------------------------------
def AskStr(defval, prompt):
    """
    Ask the user to enter a string

    @param defval: the default string value. This value will appear
             in the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered string or 0.
    """
    return idaapi.askstr(idaapi.HIST_IDENT, defval, prompt)


def AskFile(forsave, mask, prompt):
    """
    Ask the user to choose a file

    @param forsave: 0: "Open" dialog box, 1: "Save" dialog box
    @param mask: the input file mask as "*.*" or the default file name.
    @param prompt: the prompt to display in the dialog box

    @return: the selected file or 0.
    """
    return idaapi.askfile_c(forsave, mask, prompt)


def AskAddr(defval, prompt):
    """
    Ask the user to enter an address

    @param defval: the default address value. This value
             will appear in the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered address or BADADDR.
    """
    return idaapi.askaddr(defval, prompt)


def AskLong(defval, prompt):
    """
    Ask the user to enter a number

    @param defval: the default value. This value
             will appear in the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered number or -1.
    """
    return idaapi.asklong(defval, prompt)


def AskSeg(defval, prompt):
    """
    Ask the user to enter a segment value

    @param defval: the default value. This value
             will appear in the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered segment selector or BADSEL.
    """
    return idaapi.askseg(defval, prompt)


def AskIdent(defval, prompt):
    """
    Ask the user to enter an identifier

    @param defval: the default identifier. This value will appear in 
             the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered identifier or 0.
    """
    return idaapi.askident(defval, prompt)


def AskYN(defval, prompt):
    """
    Ask the user a question and let him answer Yes/No/Cancel

    @param defval: the default answer. This answer will be selected if the user
            presses Enter. -1:cancel,0-no,1-ok
    @param prompt: the prompt to display in the dialog box

    @return: -1:cancel,0-no,1-ok
    """
    return idaapi.askyn_c(defval, prompt)


def Message(msg):
    """
    Display a message in the message window

    @param msg: message to print (formatting is done in Python)

    This function can be used to debug IDC scripts
    """
    idaapi.msg(msg)


def Warning(msg):
    """
    Display a message in a message box

    @param msg: message to print (formatting is done in Python)

    This function can be used to debug IDC scripts
    The user will be able to hide messages if they appear twice in a row on
    the screen
    """
    idaapi.warning(msg)


def Fatal(format):
    """
    Display a fatal message in a message box and quit IDA
    
    @param format: message to print
    """
    idaapi.error(format)


def SetStatus(status):
    """
    Change IDA indicator.

    @param status: new status

    @return: the previous status.
    """
    return idaapi.setStat(status)


IDA_STATUS_READY    = 0 # READY     IDA is idle
IDA_STATUS_THINKING = 1 # THINKING  Analyzing but the user may press keys
IDA_STATUS_WAITING  = 2 # WAITING   Waiting for the user input
IDA_STATUS_WORK     = 3 # BUSY      IDA is busy

def Refresh():
    """
    Refresh all disassembly views
    """
    idaapi.refresh_idaview_anyway()


def RefreshLists():
    """
    Refresh all list views (names, functions, etc)
    """
    idaapi.refresh_lists()


#----------------------------------------------------------------------------
#                        S E G M E N T A T I O N
#----------------------------------------------------------------------------
def AskSelector(sel):
    """
    Get a selector value

    @param sel: the selector number

    @return:        selector value if found
            otherwise the input value (sel)
    
    @note:           selector values are always in paragraphs
    """
    sel = idaapi.getn_selector(sel)

    if not sel:
        return sel
    else:
        return sel.base


def FindSelector(val):
    """
    Find a selector which has the specifed value

    @param val: value to search for
    
    @return:        the selector number if found,
            otherwise the input value (val & 0xFFFF)

    @note:           selector values are always in paragraphs
    """
    sel = idaapi.find_selector(val)

    if not sel:
        return val & 0xffff
    else:
        return sel.n
    

def SetSelector(sel, value):
    """
    Set a selector value

    @param sel: the selector number
    @param value: value of selector

    @return: None
    
    @note: ida supports up to 4096 selectors.
            if 'sel' == 'val' then the selector is destroyed because
            it has no significance
    """
    return idaapi.set_selector(sel, value)


def DelSelector(sel):
    """
    Delete a selector

    @param sel: the selector number to delete

    @return: None

    @note: if the selector is found, it will be deleted
    """
    return idaapi.del_selector(sel)


def FirstSeg():
    """
    Get first segment

    @return: address of the start of the first segment
        BADADDR - no segments are defined
    """
    segn = idaapi.get_segm_qty()

    if segn == 0:
        return BADADDR
    else:
        seg = idaapi.getnseg(0)

        if not seg:
            return BADADDR
        else:
            return seg.startEA


def NextSeg(ea):
    """
    Get next segment

    @param ea: linear address

    @return: start of the next segment
        BADADDR - no next segment

    TODO: Any better way of doing this?
    """

    for n in range(idaapi.get_segm_qty()):
        currseg = idaapi.getnseg(n)

        if ea >= currseg.startEA and ea < currseg.endEA:
            nextseg = idaapi.getnseg(n+1)

            if not nextseg:
                return BADADDR
            else:
                return nextseg.startEA

    return BADADDR


def SegStart(ea):
    """
    Get start address of a segment

    @param ea: any address in the segment

    @return: start of segment
        BADADDR - the specified address doesn't belong to any segment
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return BADADDR
    else:
        return seg.startEA


def SegEnd(ea):
    """
    Get end address of a segment

    @param ea: any address in the segment

    @return: end of segment (an address past end of the segment)
        BADADDR - the specified address doesn't belong to any segment
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return BADADDR
    else:
        return seg.endEA


def SegName(ea):
    """
    Get name of a segment

    @param ea: any address in the segment

    @return: "" - no segment at the specified address
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return ""
    else:
        name = idaapi.get_true_segm_name(seg)

        if not name:
            return ""
        else:
            return name


def SegCreate(startea, endea, base, use32, align, comb):
    """
    Create a new segment

    @param startea: linear address of the start of the segment
    @param endea: linear address of the end of the segment
               this address will not belong to the segment
               'endea' should be higher than 'startea'
    @param base: base paragraph or selector of the segment.
               a paragraph is 16byte memory chunk.
               If a selector value is specified, the selector should be
               already defined.
    @param use32: 0: 16bit segment, 1: 32bit segment, 2: 64bit segment
    @param align: segment alignment. see below for alignment values
    @param comb: segment combination. see below for combination values.
    
    @return: 0-failed, 1-ok
    """
    success = idaapi.add_segm(base, startea, endea, "Segment", "CODE")

    if success != 1:
        return 0

    seg = idaapi.getseg(startea)

    if not seg:
        return 0

    seg.bitness = use32    
    seg.align = align
    seg.comb = comb

    return 1


def SegDelete(ea, flags):
    """
    Delete a segment

    @param ea: any address in the segment
    @param flags: combination of SEGDEL_* flags

    @return: boolean success
    """
    return idaapi.del_segm(ea, disable)

SEGDEL_PERM   = idaapi.SEGDEL_PERM   # permanently, i.e. disable addresses
SEGDEL_KEEP   = idaapi.SEGDEL_KEEP   # keep information (code & data, etc)
SEGDEL_SILENT = idaapi.SEGDEL_SILENT # be silent

def SegBounds(ea, startea, endea, disable):
    """
    Change segment boundaries

    @param ea: any address in the segment
    @param startea: new start address of the segment
    @param endea: new end address of the segment
    @param disable: discard bytes that go out of the segment

    @return: boolean success
    """
    return idaapi.set_segm_start(ea, startea, disable) & \
           idaapi.set_segm_end(ea, endea, disable)


def SegRename(ea, name):
    """
    Change name of the segment

    @param ea: any address in the segment
    @param name: new name of the segment

    @return: success (boolean)
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return False

    return idaapi.set_segm_name(seg, name)    


def SegClass(ea, segclass):
    """
    Change class of the segment

    @param ea: any address in the segment
    @param segclass: new class of the segment

    @return: success (boolean)
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return False

    return idaapi.set_segm_class(seg, segclass)    


def SegAlign(ea, alignment):
    """
    Change alignment of the segment
    
    @param ea: any address in the segment
    @param alignment: new alignment of the segment (one of the sa... constants)

    @return: success (boolean)
    """
    return SetSegmentAttr(ea, SEGATTR_ALIGN, alignment)


saAbs        = idaapi.saAbs        # Absolute segment.
saRelByte    = idaapi.saRelByte    # Relocatable, byte aligned.
saRelWord    = idaapi.saRelWord    # Relocatable, word (2-byte, 16-bit) aligned.
saRelPara    = idaapi.saRelPara    # Relocatable, paragraph (16-byte) aligned.
saRelPage    = idaapi.saRelPage    # Relocatable, aligned on 256-byte boundary 
                                   # (a "page" in the original Intel specification).
saRelDble    = idaapi.saRelDble    # Relocatable, aligned on a double word 
                                   # (4-byte) boundary. This value is used by 
                                   # the PharLap OMF for the same alignment.
saRel4K      = idaapi.saRel4K      # This value is used by the PharLap OMF for 
                                   # page (4K) alignment. It is not supported 
                                   # by LINK.
saGroup      = idaapi.saGroup      # Segment group
saRel32Bytes = idaapi.saRel32Bytes # 32 bytes
saRel64Bytes = idaapi.saRel64Bytes # 64 bytes
saRelQword   = idaapi.saRelQword   # 8 bytes


def SegComb(segea, comb):
    """
    Change combination of the segment

    @param segea: any address in the segment
    @param comb: new combination of the segment (one of the sc... constants)

    @return: success (boolean)
    """
    return SetSegmentAttr(ea, SEGATTR_COMB, comb)


scPriv   = idaapi.scPriv   # Private. Do not combine with any other program
                           # segment.
scPub    = idaapi.scPub    # Public. Combine by appending at an offset that 
                           # meets the alignment requirement.
scPub2   = idaapi.scPub2   # As defined by Microsoft, same as C=2 (public).
scStack  = idaapi.scStack  # Stack. Combine as for C=2. This combine type 
                           # forces byte alignment.
scCommon = idaapi.scCommon # Common. Combine by overlay using maximum size.
scPub3   = idaapi.scPub3   # As defined by Microsoft, same as C=2 (public).


def SegAddrng(ea, bitness):
    """
    Change segment addressing

    @param ea: any address in the segment
    @param bitness: 0: 16bit, 1: 32bit, 2: 64bit
    
    @return: success (boolean)
    """
    seg = idaapi.getseg(segea)

    if not seg:
        return False

    seg.bitness = use32

    return True


def SegByName(segname):
    """
    Get segment by name

    @param segname: name of segment

    @return: segment selector or BADADDR
    """
    seg = idaapi.get_segm_by_name(segname)

    if not seg:
        return BADADDR

    return seg.startEA


def SegDefReg(ea, reg, value):
    """
    Set default segment register value for a segment

    @param ea: any address in the segment
               if no segment is present at the specified address
               then all segments will be affected
    @param reg: name of segment register
    @param value: default value of the segment register. -1-undefined.
    """
    seg = idaapi.getseg(ea)

    if seg and _REGMAP.has_key(reg):
        return idaapi.SetDefaultRegisterValue(seg, _REGMAP[reg], value)
    else:
        return False


def SetSegmentType(segea, type):
    """
    Set segment type

    @param segea: any address within segment
    @param type: new segment type:

    @return: !=0 - ok
    """
    seg = idaapi.getseg(segea)

    if not seg:
        return False

    seg.type = type
    return seg.update()


SEG_NORM   = idaapi.SEG_NORM        
SEG_XTRN   = idaapi.SEG_XTRN   # * segment with 'extern' definitions
                               #   no instructions are allowed
SEG_CODE   = idaapi.SEG_CODE   # pure code segment
SEG_DATA   = idaapi.SEG_DATA   # pure data segment
SEG_IMP    = idaapi.SEG_IMP    # implementation segment
SEG_GRP    = idaapi.SEG_GRP    # * group of segments
                               #   no instructions are allowed
SEG_NULL   = idaapi.SEG_NULL   # zero-length segment
SEG_UNDF   = idaapi.SEG_UNDF   # undefined segment type
SEG_BSS    = idaapi.SEG_BSS    # uninitialized segment
SEG_ABSSYM = idaapi.SEG_ABSSYM # * segment with definitions of absolute symbols
                               #   no instructions are allowed
SEG_COMM   = idaapi.SEG_COMM   # * segment with communal definitions
                               #   no instructions are allowed
SEG_IMEM   = idaapi.SEG_IMEM   # internal processor memory & sfr (8051)


def GetSegmentAttr(segea, attr):
    """
    Get segment attribute

    @param segea: any address within segment
    @param attr: one of SEGATTR_... constants
    """
    seg = idaapi.getseg(segea)
    assert seg, "could not find segment at 0x%x" % segea
    if attr in [ SEGATTR_ES, SEGATTR_CS, SEGATTR_SS, SEGATTR_DS, SEGATTR_FS, SEGATTR_GS ]:
        return idaapi.get_defsr(seg, _SEGATTRMAP[attr])
    else:
        return _IDC_GetAttr(seg, _SEGATTRMAP, attr)


def SetSegmentAttr(segea, attr, value):
    """
    Set segment attribute
        
    @param segea: any address within segment
    @param attr: one of SEGATTR_... constants

    @note: Please note that not all segment attributes are modifiable.
           Also some of them should be modified using special functions
           like SegAddrng, etc.
    """
    seg = idaapi.getseg(segea)
    assert seg, "could not find segment at 0x%x" % segea
    if attr in [ SEGATTR_ES, SEGATTR_CS, SEGATTR_SS, SEGATTR_DS, SEGATTR_FS, SEGATTR_GS ]:
        idaapi.set_defsr(seg, _SEGATTRMAP[attr], value)
    else:
        _IDC_SetAttr(seg, _SEGATTRMAP, attr, value)
    return seg.update()


SEGATTR_START   =  0      # starting address
SEGATTR_END     =  4      # ending address
SEGATTR_ORGBASE = 16
SEGATTR_ALIGN   = 20      # alignment
SEGATTR_COMB    = 21      # combination
SEGATTR_PERM    = 22      # permissions
SEGATTR_BITNESS = 23      # bitness (0: 16, 1: 32, 2: 64 bit segment)
                          # Note: modifying the attribute directly does
                          #       not lead to the reanalysis of the segment.
                          #       Using SegAddrng() is more correct.
SEGATTR_FLAGS   = 24      # segment flags
SEGATTR_SEL     = 26      # segment selector
SEGATTR_ES      = 30      # default ES value
SEGATTR_CS      = 34      # default CS value
SEGATTR_SS      = 38      # default SS value
SEGATTR_DS      = 42      # default DS value
SEGATTR_FS      = 46      # default FS value
SEGATTR_GS      = 50      # default GS value
SEGATTR_TYPE    = 94      # segment type
SEGATTR_COLOR   = 95      # segment color

_SEGATTRMAP = {
    SEGATTR_START   : 'startEA',
    SEGATTR_END     : 'endEA',
    SEGATTR_ORGBASE : 'orgbase',
    SEGATTR_ALIGN   : 'align',
    SEGATTR_COMB    : 'comb',
    SEGATTR_PERM    : 'perm',
    SEGATTR_BITNESS : 'bitness',
    SEGATTR_FLAGS   : 'flags',
    SEGATTR_SEL     : 'sel',
    SEGATTR_ES      : 0,
    SEGATTR_CS      : 1,
    SEGATTR_SS      : 2,
    SEGATTR_DS      : 3,
    SEGATTR_FS      : 4,
    SEGATTR_GS      : 5,
    SEGATTR_TYPE    : 'type',
    SEGATTR_COLOR   : 'color',
}


#----------------------------------------------------------------------------
#                    C R O S S   R E F E R E N C E S
#----------------------------------------------------------------------------
#      Flow types (combine with XREF_USER!):
fl_CF   = 16              # Call Far
fl_CN   = 17              # Call Near
fl_JF   = 18              # Jump Far
fl_JN   = 19              # Jump Near
fl_F    = 21              # Ordinary flow

XREF_USER = 32            # All user-specified xref types
                          # must be combined with this bit


# Mark exec flow 'from' 'to'
def AddCodeXref(From, To, flowtype):
    """
    """
    return idaapi.add_cref(From, To, flowtype)


def DelCodeXref(From, To, undef):
    """
    Unmark exec flow 'from' 'to'

    @param undef: make 'To' undefined if no more references to it

    @returns: 1 - planned to be made undefined
    """
    return idaapi.del_cref(From, To, undef)


# The following functions include the ordinary flows:
# (the ordinary flow references are returned first)
def Rfirst(From):            
    """
    Get first code xref from 'From'
    """
    return idaapi.get_first_cref_from(From)


def Rnext(From, current):
    """
    Get next code xref from
    """
    return idaapi.get_next_cref_from(From, current)


def RfirstB(To):
    """
    Get first code xref to 'To'
    """
    return idaapi.get_first_cref_to(To)


def RnextB(To, current):
    """
    Get next code xref to 'To'
    """
    return idaapi.get_next_cref_to(To, current)


# The following functions don't take into account the ordinary flows:
def Rfirst0(From):
    """
    Get first xref from 'From'
    """
    return idaapi.get_first_fcref_from(From)


def Rnext0(From, current):
    """
    Get next xref from
    """
    return idaapi.get_next_fcref_from(From, current)


def RfirstB0(To):
    """
    Get first xref to 'To'
    """
    return idaapi.get_first_fcref_to(To)


def RnextB0(To, current):
    """
    Get next xref to 'To'
    """
    return idaapi.get_next_fcref_to(To, current)


# Data reference types (combine with XREF_USER!):
dr_O    = idaapi.dr_O  # Offset
dr_W    = idaapi.dr_W  # Write
dr_R    = idaapi.dr_R  # Read
dr_T    = idaapi.dr_T  # Text (names in manual operands)
dr_I    = idaapi.dr_I  # Informational


def add_dref(From, To, drefType):
    """
    Create Data Ref
    """
    return idaapi.add_dref(From, To, drefType)


def del_dref(From, To):
    """
    Unmark Data Ref
    """
    return idaapi.del_dref(From, To)


def Dfirst(From):
    """
    Get first data xref from 'From'
    """
    return idaapi.get_first_dref_from(From)


def Dnext(From, current):
    """
    Get next data xref from 'From'
    """
    return idaapi.get_next_dref_from(From, current)


def DfirstB(To):
    """
    Get first data xref to 'To'
    """
    return idaapi.get_first_dref_to(To)


def DnextB(To, current):
    """
    Get next data xref to 'To'
    """
    return idaapi.get_next_dref_to(To, current)


def XrefType():
    """
    Return type of the last xref obtained by 
    [RD]first/next[B0] functions. 
    
    @return: constants fl_* or dr_*
    """
    raise DeprecatedIDCError, "use XrefsFrom() XrefsTo() from idautils instead."


#----------------------------------------------------------------------------
#                            F I L E   I / O
#----------------------------------------------------------------------------
def fopen(file, mode):
    raise DeprecatedIDCError, "fopen() deprecated. Use Python file objects instead."

def fclose(handle):
    raise DeprecatedIDCError, "fclose() deprecated. Use Python file objects instead."

def filelength(handle):
    raise DeprecatedIDCError, "filelength() deprecated. Use Python file objects instead."

def fseek(handle, offset, origin):
    raise DeprecatedIDCError, "fseek() deprecated. Use Python file objects instead."

def ftell(handle):
    raise DeprecatedIDCError, "ftell() deprecated. Use Python file objects instead."


def LoadFile(filepath, pos, ea, size):
    """
    Load file into IDA database

    @param filepath: path to input file
    @param pos: position in the file
    @param ea: linear address to load
    @param size: number of bytes to load

    @return: 0 - error, 1 - ok
    """
    li = idaapi.open_linput(filepath, False)

    if li:
        retval = idaapi.file2base(li, pos, ea, ea+size, False)
        idaapi.close_linput(li)
        return retval
    else:
        return 0

def loadfile(filepath, pos, ea, size): LoadFile(filepath, pos, ea, size)


def SaveFile(filepath, pos, ea, size):
    """
    Save from IDA database to file

    @param filepath: path to output file
    @param pos: position in the file
    @param ea: linear address to save from
    @param size: number of bytes to save

    @return: 0 - error, 1 - ok
    """
    of = idaapi.fopenWB(filepath)

    if of:
        retval = idaapi.base2file(of, pos, ea, ea+size)
        idaapi.eclose(of)
        return retval
    else:
        return 0

def savefile(filepath, pos, ea, size): SaveFile(filepath, pos, ea, size)


def fgetc(handle):
    raise DeprecatedIDCError, "fgetc() deprecated. Use Python file objects instead."

def fputc(byte, handle):
    raise DeprecatedIDCError, "fputc() deprecated. Use Python file objects instead."

def fprintf(handle, format, *args):
    raise DeprecatedIDCError, "fprintf() deprecated. Use Python file objects instead."

def readshort(handle, mostfirst):
    raise DeprecatedIDCError, "readshort() deprecated. Use Python file objects instead."

def readlong(handle, mostfirst):
    raise DeprecatedIDCError, "readlong() deprecated. Use Python file objects instead."

def writeshort(handle, word, mostfirst):
    raise DeprecatedIDCError, "writeshort() deprecated. Use Python file objects instead."

def writelong(handle, dword, mostfirst):
    raise DeprecatedIDCError, "writelong() deprecated. Use Python file objects instead."

def readstr(handle):
    raise DeprecatedIDCError, "readstr() deprecated. Use Python file objects instead."

def writestr(handle, str):
    raise DeprecatedIDCError, "writestr() deprecated. Use Python file objects instead."

# ----------------------------------------------------------------------------
#                           F U N C T I O N S
# ----------------------------------------------------------------------------

def MakeFunction(start, end):
    """
    Create a function
    
    @param start: function bounds
    @param end: function bounds

    If the function end address is BADADDR, then
    IDA will try to determine the function bounds
    automatically. IDA will define all necessary
    instructions to determine the function bounds.

    @return: !=0 - ok

    @note: an instruction should be present at the start address
    """
    return idaapi.add_func(start, end)


def DelFunction(ea):
    """
    Delete a function

    @param ea: any address belonging to the function
    
    @return: !=0 - ok
    """
    return idaapi.del_func(ea)


def SetFunctionEnd(ea, end):
    """
    Change function end address
    
    @param ea: any address belonging to the function
    @param end: new function end address

    @return: !=0 - ok
    """
    return idaapi.func_setend(ea, end)


def NextFunction(ea):
    """
    Find next function
    
    @param ea: any address belonging to the function

    @return:        -1 - no more functions
            otherwise returns the next function start address
    """
    func = idaapi.get_next_func(ea)

    if not func:
        return BADADDR
    else:
        return func.startEA


def PrevFunction(ea):
    """
    Find previous function
    
    @param ea: any address belonging to the function

    @return: -1 - no more functions
            otherwise returns the previous function start address
    """
    func = idaapi.get_prev_func(ea)

    if not func:
        return BADADDR
    else:
        return func.startEA


def GetFunctionAttr(ea, attr):
    """
    Get a function attribute

    @param ea: any address belonging to the function
    @param attr: one of FUNCATTR_... constants

    @return: -1 - error otherwise returns the attribute value
    """
    func = idaapi.get_func(ea)

    if func:
        return _IDC_GetAttr(func, _FUNCATTRMAP, attr)


def SetFunctionAttr(ea, attr, value):
    """
    Set a function attribute

    @param ea: any address belonging to the function
    @param attr: one of FUNCATTR_... constants
    @param value: new value of the attribute

    @return: 1-ok, 0-failed
    """
    func = idaapi.get_func(ea)

    if func:
        _IDC_SetAttr(func, _FUNCATTRMAP, attr, value)
        return idaapi.update_func(func)


FUNCATTR_START   =  0     # function start address
FUNCATTR_END     =  4     # function end address
FUNCATTR_FLAGS   =  8     # function flags
FUNCATTR_FRAME   = 10     # function frame id
FUNCATTR_FRSIZE  = 14     # size of local variables
FUNCATTR_FRREGS  = 18     # size of saved registers area
FUNCATTR_ARGSIZE = 20     # number of bytes purged from the stack
FUNCATTR_FPD     = 24     # frame pointer delta
FUNCATTR_COLOR   = 28     # function color code

_FUNCATTRMAP = {
    FUNCATTR_START   : 'startEA',
    FUNCATTR_END     : 'endEA',
    FUNCATTR_FLAGS   : 'flags',
    FUNCATTR_FRAME   : 'frame',
    FUNCATTR_FRSIZE  : 'frsize',
    FUNCATTR_FRREGS  : 'frregs',
    FUNCATTR_ARGSIZE : 'argsize',
    FUNCATTR_FPD     : 'fpd',
    FUNCATTR_COLOR   : 'color'
}


def GetFunctionFlags(ea):
    """
    Retrieve function flags

    @param ea: any address belonging to the function

    @return: -1 - function doesn't exist otherwise returns the flags
    """
    func = idaapi.get_func(ea)

    if not func:
        return -1
    else:
        return func.flags


FUNC_NORET    = idaapi.FUNC_NORET    # function doesn't return
FUNC_FAR      = idaapi.FUNC_FAR      # far function
FUNC_LIB      = idaapi.FUNC_LIB      # library function
FUNC_STATIC   = idaapi.FUNC_STATIC   # static function
FUNC_FRAME    = idaapi.FUNC_FRAME    # function uses frame pointer (BP)
FUNC_USERFAR  = idaapi.FUNC_USERFAR  # user has specified far-ness
                                     # of the function
FUNC_HIDDEN   = idaapi.FUNC_HIDDEN   # a hidden function
FUNC_THUNK    = idaapi.FUNC_THUNK    # thunk (jump) function
FUNC_BOTTOMBP = idaapi.FUNC_BOTTOMBP # BP points to the bottom of the stack frame


def SetFunctionFlags(ea, flags):
    """
    Change function flags

    @param ea: any address belonging to the function
    @param flags: see GetFunctionFlags() for explanations

    @return: !=0 - ok
    """
    func = idaapi.get_func(ea)

    if not func:
        return 0
    else:
        func.flags = flags
        idaapi.update_func(func)
        return 1


def GetFunctionName(ea):
    """
    Retrieve function name

    @param ea: any address belonging to the function

    @return: null string - function doesn't exist
            otherwise returns function name
    """
    name = idaapi.get_func_name(ea)

    if not name:
        return ""
    else:
        return name


def GetFunctionCmt(ea, repeatable):
    """
    Retrieve function comment

    @param ea: any address belonging to the function
    @param repeatable: 1: get repeatable comment
            0: get regular comment
    
    @return: function comment string
    """
    func = idaapi.get_func(ea)

    if not func:
        return ""
    else:
        comment = idaapi.get_func_cmt(func, repeatable)

        if not comment:
            return ""
        else:
            return comment


def SetFunctionCmt(ea, cmt, repeatable):
    """
    Set function comment

    @param ea: any address belonging to the function
    @param cmt: a function comment line
    @param repeatable: 1: get repeatable comment
            0: get regular comment
    """
    func = idaapi.get_func(ea)

    if not func:
        return None
    else:
        return idaapi.set_func_cmt(func, cmt, repeatable)


def ChooseFunction(title):
    """
    Ask the user to select a function

    Arguments:

    @param title: title of the dialog box
    
    @return: -1 - user refused to select a function
             otherwise returns the selected function start address
    """
    return idaapi.choose_func(title)


def GetFuncOffset(ea):
    """
    Convert address to 'funcname+offset' string

    @param ea - address to convert

    @return: if the address belongs to a function then return a string
             formed as 'name+offset' where 'name' is a function name
             'offset' is offset within the function else return null string
    """
    return idaapi.a2funcoff(ea)


def FindFuncEnd(ea):
    """
    Determine a new function boundaries

    @param ea: starting address of a new function

    @return: if a function already exists, then return its end address.
            If a function end cannot be determined, the return BADADDR
            otherwise return the end address of the new function
    """
    func = idaapi.func_t()

    res = idaapi.find_func_bounds(ea, func, idaapi.FIND_FUNC_DEFINE) 

    if res == idaapi.FIND_FUNC_UNDEF:
        return BADADDR
    else:
        return func.endEA


def GetFrame(ea):
    """
    Get ID of function frame structure

    @param ea: any address belonging to the function

    @return: ID of function frame or None In order to access stack variables 
             you need to use structure member manipulaion functions with the
             obtained ID.
    """
    frame = idaapi.get_frame(ea)

    if frame:
        return frame.id
    else:
        return None


def GetFrameLvarSize(ea):
    """
    Get size of local variables in function frame

    @param ea: any address belonging to the function

    @return: Size of local variables in bytes.
             If the function doesn't have a frame, return 0
             If the function does't exist, return None
    """
    return GetFunctionAttr(ea, FUNCATTR_FRSIZE)


def GetFrameRegsSize(ea):
    """
    Get size of saved registers in function frame

    @param ea: any address belonging to the function

    @return: Size of saved registers in bytes.
             If the function doesn't have a frame, return 0
             This value is used as offset for BP (if FUNC_FRAME is set)
             If the function does't exist, return None
    """
    return GetFunctionAttr(ea, FUNCATTR_FRREGS)


def GetFrameArgsSize(ea):
    """
    Get size of arguments in function frame which are purged upon return

    @param ea: any address belonging to the function

    @return: Size of function arguments in bytes.
             If the function doesn't have a frame, return 0
             If the function does't exist, return -1
    """
    return GetFunctionAttr(ea, FUNCATTR_ARGSIZE)


def GetFrameSize(ea):
    """
    Get full size of function frame

    @param ea: any address belonging to the function
    @returns: Size of function frame in bytes.
                This function takes into account size of local
                variables + size of saved registers + size of
                return address + size of function arguments
                If the function doesn't have a frame, return size of
                function return address in the stack.
                If the function does't exist, return 0
    """
    func = idaapi.get_func(ea)

    if not func:
        return 0
    else:
        return idaapi.get_frame_size(func)


def MakeFrame(ea, lvsize, frregs, argsize):
    """
    Make function frame

    @param ea: any address belonging to the function
    @param lvsize: size of function local variables
    @param frregs: size of saved registers
    @param argsize: size of function arguments

    @return: ID of function frame or -1
             If the function did not have a frame, the frame
             will be created. Otherwise the frame will be modified
    """
    func = idaapi.get_func(ea)

    if not func:
        return -1

    id = idaapi.add_frame(func, lvsize, frregs, argsize)

    if not id:
        if not idaapi.set_frame_size(func, lvsize, frregs, argsize):
            return -1

    return func.frame


def GetSpd(ea):
    """
    Get current delta for the stack pointer

    @param ea: end address of the instruction
               i.e.the last address of the instruction+1

    @return: The difference between the original SP upon
             entering the function and SP for the specified address
    """
    func = idaapi.get_func(ea)

    if not func:
        return None

    return idaapi.get_spd(func, ea)


def GetSpDiff(ea):
    """
    Get modification of SP made by the instruction
    
    @param ea: end address of the instruction 
               i.e.the last address of the instruction+1

    @return: Get modification of SP made at the specified location
             If the specified location doesn't contain a SP change point, return 0
             Otherwise return delta of SP modification
    """
    func = idaapi.get_func(ea)

    if not func:
        return None

    return idaapi.get_sp_delta(func, ea)


def SetSpDiff(ea, delta):
    """
    Setup modification of SP made by the instruction

    @param ea: end address of the instruction
               i.e.the last address of the instruction+1
    @param delta: the difference made by the current instruction.

    @return: 1-ok, 0-failed
    """
    return idaapi.add_user_stkpnt(ea, delta)


# ----------------------------------------------------------------------------
#                        E N T R Y   P O I N T S
# ----------------------------------------------------------------------------

def GetEntryPointQty():
    """
    Retrieve number of entry points

    @returns: number of entry points
    """
    return idaapi.get_entry_qty()


def AddEntryPoint(ordinal, ea, name, makecode):
    """
    Add entry point

    @param ordinal: entry point number
            if entry point doesn't have an ordinal
            number, 'ordinal' should be equal to 'ea'
    @param ea: address of the entry point
    @param name: name of the entry point. If null string,
            the entry point won't be renamed.
    @param makecode: if 1 then this entry point is a start
            of a function. Otherwise it denotes data bytes.

    @return: 0 - entry point with the specifed ordinal already exists
            1 - ok
    """
    return idaapi.add_entry(ordinal, ea, name, makecode)


def GetEntryOrdinal(index):
    """
    Retrieve entry point ordinal number

    @param index: 0..GetEntryPointQty()-1

    @return: 0 if entry point doesn't exist
            otherwise entry point ordinal
    """
    return idaapi.get_entry_ordinal(index)


def GetEntryPoint(ordinal):
    """
    Retrieve entry point address

    @param ordinal: entry point number
        it is returned by GetEntryPointOrdinal()

    @return: -1 if entry point doesn't exist
            otherwise entry point address.
            If entry point address is equal to its ordinal
            number, then the entry point has no ordinal.
    """
    return idaapi.get_entry(ordinal)


def RenameEntryPoint(ordinal, name):
    """
    Rename entry point

    @param ordinal: entry point number
    @param name: new name
    
    @return: !=0 - ok
    """
    return idaapi.rename_entry(ordinal, name)


# ----------------------------------------------------------------------------
#                              F I X U P S
# ----------------------------------------------------------------------------
def GetNextFixupEA(ea):
    """
    Find next address with fixup information

    @param ea: current address

    @return: -1 - no more fixups otherwise returns the next 
                address with fixup information
    """
    return idaapi.get_next_fixup_ea(ea)


def GetPrevFixupEA(ea):
    """
    Find previous address with fixup information

    @param ea: current address

    @return: -1 - no more fixups otherwise returns the 
                previous address with fixup information
    """
    return idaapi.get_prev_fixup_ea(ea)


def GetFixupTgtType(ea):
    """
    Get fixup target type

    @param ea: address to get information about

    @return: -1 - no fixup at the specified address
                otherwise returns fixup target type:
    """
    fd = idaapi.get_fixup(ea)

    if not fd:
        return -1

    return fd.type


FIXUP_MASK      = 0xF
FIXUP_OFF8      = 0       # 8-bit offset.
FIXUP_BYTE      = FIXUP_OFF8 # 8-bit offset.
FIXUP_OFF16     = 1       # 16-bit offset.
FIXUP_SEG16     = 2       # 16-bit base--logical segment base (selector).
FIXUP_PTR32     = 3       # 32-bit long pointer (16-bit base:16-bit
                          # offset).
FIXUP_OFF32     = 4       # 32-bit offset.
FIXUP_PTR48     = 5       # 48-bit pointer (16-bit base:32-bit offset).
FIXUP_HI8       = 6       # high  8 bits of 16bit offset
FIXUP_HI16      = 7       # high 16 bits of 32bit offset
FIXUP_LOW8      = 8       # low   8 bits of 16bit offset
FIXUP_LOW16     = 9       # low  16 bits of 32bit offset
FIXUP_REL       = 0x10    # fixup is relative to the linear address
                          # specified in the 3d parameter to set_fixup()
FIXUP_SELFREL   = 0x0     # self-relative?
                          #   - disallows the kernel to convert operands
                          #      in the first pass
                          #   - this fixup is used during output
                          # This type of fixups is not used anymore.
                          # Anyway you can use it for commenting purposes
                          # in the loader modules
FIXUP_EXTDEF    = 0x20    # target is a location (otherwise - segment)
FIXUP_UNUSED    = 0x40    # fixup is ignored by IDA
                          #   - disallows the kernel to convert operands
                          #   - this fixup is not used during output
FIXUP_CREATED   = 0x80    # fixup was not present in the input file


def GetFixupTgtSel(ea):
    """
    Get fixup target selector

    @param ea: address to get information about

    @return: -1 - no fixup at the specified address
                    otherwise returns fixup target selector
    """
    fd = idaapi.get_fixup(ea)

    if not fd:
        return -1

    return fd.sel


def GetFixupTgtOff(ea):
    """
    Get fixup target offset

    @param ea: address to get information about

    @return: -1 - no fixup at the specified address
                otherwise returns fixup target offset
    """
    fd = idaapi.get_fixup(ea)

    if not fd:
        return -1

    return fd.off


def GetFixupTgtDispl(ea):
    """
    Get fixup target displacement

    @param ea: address to get information about

    @return: -1 - no fixup at the specified address
                otherwise returns fixup target displacement
    """
    fd = idaapi.get_fixup(ea)

    if not fd:
        return -1

    return fd.displacement


def SetFixup(ea, type, targetsel, targetoff, displ):
    """
    Set fixup information

    @param ea: address to set fixup information about
    @param type: fixup type. see GetFixupTgtType()
                for possible fixup types.
    @param targetsel: target selector
    @param targetoff: target offset
    @param displ: displacement

    @return:        none
    """
    fd = idaapi.fixup_data_t()
    fd.type = type
    fd.sel  = targetsel
    fd.off  = targetoff
    fd.displacement = displ

    idaapi.set_fixup(ea, fd) 


def DelFixup(ea):
    """
    Delete fixup information

    @param ea: address to delete fixup information about
    
    @return: None
    """
    idaapi.del_fixup(ea)


#----------------------------------------------------------------------------
#                   M A R K E D   P O S I T I O N S
#----------------------------------------------------------------------------

def MarkPosition(ea, lnnum, x, y, slot, comment):
    """
    Mark position

    @param ea: address to mark
    @param lnnum: number of generated line for the 'ea'
    @param x: x coordinate of cursor
    @param y: y coordinate of cursor
    @param slot: slot number: 1..1024
                 if the specifed value is not within the
                 range, IDA will ask the user to select slot.
    @param comment: description of the mark. Should be not empty.

    @return: None
    """
    curloc = idaapi.curloc()
    curloc.ea = ea
    curloc.lnnum = lnnum
    curloc.x = x
    curloc.y = y
    curloc.mark(slot, comment, comment)


def GetMarkedPos(slot):
    """
    Get marked position

    @param slot: slot number: 1..1024 if the specifed value is <= 0
                 range, IDA will ask the user to select slot.

    @return: BADADDR - the slot doesn't contain a marked address
             otherwise returns the marked address
    """
    curloc = idaapi.curloc()
    intp = idaapi.int_pointer()
    intp.assign(slot)
    return curloc.markedpos(intp)


def GetMarkComment(slot):
    """
    Get marked position comment

    @param slot: slot number: 1..1024

    @return: None if the slot doesn't contain a marked address
             otherwise returns the marked address comment
    """
    curloc = idaapi.curloc()
    return curloc.markdesc(slot)


# ----------------------------------------------------------------------------
#                          S T R U C T U R E S
# ----------------------------------------------------------------------------

def GetStrucQty():
    """
    Get number of defined structure types

    @return: number of structure types
    """
    return idaapi.get_struc_qty()


def GetFirstStrucIdx():
    """
    Get index of first structure type

    @return:      -1 if no structure type is defined
                    index of first structure type.
                    Each structure type has an index and ID.
                    INDEX determines position of structure definition
                    in the list of structure definitions. Index 1
                    is listed first, after index 2 and so on.
                    The index of a structure type can be changed any
                    time, leading to movement of the structure definition
                    in the list of structure definitions.
                    ID uniquely denotes a structure type. A structure
                    gets a unique ID at the creation time and this ID
                    can't be changed. Even when the structure type gets
                    deleted, its ID won't be resued in the future.
    """
    return idaapi.get_first_struc_idx()


def GetLastStrucIdx():
    """
    Get index of last structure type

    @return:        -1 if no structure type is defined
                    index of last structure type.
                    See GetFirstStrucIdx() for the explanation of
                    structure indices and IDs.
    """
    return idaapi.get_last_struc_idx()


def GetNextStrucIdx(index):
    """
    Get index of next structure type

    @param index: current structure index

    @return:    -1 if no (more) structure type is defined
                index of the next structure type.
                See GetFirstStrucIdx() for the explanation of
                structure indices and IDs.
    """
    return idaapi.get_next_struc_idx(index)


def GetPrevStrucIdx(index):
    """
    Get index of previous structure type

    @param index: current structure index

    @return:    -1 if no (more) structure type is defined
                index of the presiouvs structure type.
                See GetFirstStrucIdx() for the explanation of
                structure indices and IDs.
    """
    return idaapi.get_prev_struc_idx(index)


def GetStrucIdx(id):
    """
    Get structure index by structure ID

    @param id: structure ID

    @return:    -1 if bad structure ID is passed
                otherwise returns structure index.
                See GetFirstStrucIdx() for the explanation of
                structure indices and IDs.
    """
    return idaapi.get_struc_idx(id)


def GetStrucId(index):
    """
    Get structure ID by structure index

    @param index: structure index

    @return: -1 if bad structure index is passed otherwise returns structure ID.

    @note: See GetFirstStrucIdx() for the explanation of structure indices and IDs.
    """
    return idaapi.get_struc_by_idx(index)


def GetStrucIdByName(name):
    """
    Get structure ID by structure name

    @param name: structure type name

    @return:    -1 if bad structure type name is passed
                otherwise returns structure ID.
    """
    return idaapi.get_struc_id(name)


def GetStrucName(id):
    """
    Get structure type name

    @param id: structure type ID

    @return:    -1 if bad structure type ID is passed
                otherwise returns structure type name.
    """
    return idaapi.get_struc_name(id)


def GetStrucComment(id, repeatable):
    """
    Get structure type comment

    @param id: structure type ID
    @param repeatable: 1: get repeatable comment
                0: get regular comment

    @return: None if bad structure type ID is passed
                otherwise returns comment.
    """
    return idaapi.get_struc_cmt(id, repeatable)


def GetStrucSize(id):
    """
    Get size of a structure

    @param id: structure type ID

    @return:    -1 if bad structure type ID is passed
                otherwise returns size of structure in bytes.
    """
    return idaapi.get_struc_size(id)


def GetMemberQty(id):
    """
    Get number of members of a structure

    @param id: structure type ID

    @return: -1 if bad structure type ID is passed otherwise 
             returns number of members.
    """
    s = idaapi.get_struc(id)
    if not s:
        return -1

    return s.memqty


def GetStrucPrevOff(id, offset):
    """
    Get previous offset in a structure

    @param id: structure type ID
    @param offset: current offset

    @return: -1 if bad structure type ID is passed
             or no (more) offsets in the structure
             otherwise returns previous offset in a structure.
    
    @note: IDA allows 'holes' between members of a
           structure. It treats these 'holes'
           as unnamed arrays of bytes.
           This function returns a member offset or a hole offset.
           It will return size of the structure if input
           'offset' is bigger than the structure size.
    """
    s = idaapi.get_struc(id)
    if not s:
        return -1

    return idaapi.get_struc_prev_offset(s, offset)


def GetStrucNextOff(id, offset):
    """
    Get next offset in a structure

    @param id:     structure type ID
    @param offset: current offset

    @return: -1 if bad structure type ID is passed
             or no (more) offsets in the structure
             otherwise returns next offset in a structure.

    @note: IDA allows 'holes' between members of a
           structure. It treats these 'holes'
           as unnamed arrays of bytes.
           This function returns a member offset or a hole offset.
           It will return size of the structure if input
           'offset' belongs to the last member of the structure.
    """
    s = idaapi.get_struc(id)
    if not s:
        return -1

    return idaapi.get_struc_next_offset(s, offset)


def GetFirstMember(id):
    """
    Get offset of the first member of a structure

    @param id: structure type ID

    @return: -1 if bad structure type ID is passed
             or structure has no members
             otherwise returns offset of the first member.

    @note: IDA allows 'holes' between members of a
          structure. It treats these 'holes'
          as unnamed arrays of bytes.
    """
    s = idaapi.get_struc(id)
    if not s:
        return -1

    return idaapi.get_struc_first_offset(s)


def GetLastMember(id):
    """
    Get offset of the last member of a structure

    @param id: structure type ID

    @return: -1 if bad structure type ID is passed
             or structure has no members
             otherwise returns offset of the last member.

    @note: IDA allows 'holes' between members of a
          structure. It treats these 'holes'
          as unnamed arrays of bytes.
    """
    s = idaapi.get_struc(id)
    if not s:
        return -1

    return idaapi.get_struc_last_offset(s)


def GetMemberOffset(id, member_name):
    """
    Get offset of a member of a structure by the member name

    @param id: structure type ID
    @param member_name: name of structure member

    @return: -1 if bad structure type ID is passed
             or no such member in the structure
             otherwise returns offset of the specified member.
    """
    s = idaapi.get_struc(id)
    if not s:
        return -1

    m = idaapi.get_member_by_name(s, member_name)
    if not m:
        return -1

    return m.get_soff()


def GetMemberName(id, member_offset):
    """
    Get name of a member of a structure

    @param id: structure type ID
    @param member_offset: member offset. The offset can be
                          any offset in the member. For example,
                          is a member is 4 bytes long and starts
                          at offset 2, then 2,3,4,5 denote
                          the same structure member.

    @return: None if bad structure type ID is passed
             or no such member in the structure
             otherwise returns name of the specified member.
    """
    s = idaapi.get_struc(id)
    if not s:
        return None

    m = idaapi.get_member(s, member_offset)
    if not m:
        return None

    return idaapi.get_member_name(m.id)


def GetMemberComment(id, member_offset, repeatable):
    """
    Get comment of a member

    @param id: structure type ID
    @param member_offset: member offset. The offset can be
                          any offset in the member. For example,
                          is a member is 4 bytes long and starts
                          at offset 2, then 2,3,4,5 denote
                          the same structure member.
    @param repeatable: 1: get repeatable comment
                       0: get regular comment

    @return: None if bad structure type ID is passed
             or no such member in the structure
             otherwise returns comment of the specified member.
    """
    s = idaapi.get_struc(id)
    if not s:
        return None

    m = idaapi.get_member(s, member_offset)
    if not m:
        return None

    return idaapi.get_member_cmt(m.id, repeatable)


def GetMemberSize(id, member_offset):
    """
    Get size of a member

    @param id: structure type ID
    @param member_offset: member offset. The offset can be
                          any offset in the member. For example,
                          is a member is 4 bytes long and starts
                          at offset 2, then 2,3,4,5 denote
                          the same structure member.

    @return: -1 if bad structure type ID is passed
             or no such member in the structure
             otherwise returns size of the specified
             member in bytes.
    """
    s = idaapi.get_struc(id)
    if not s:
        return None

    m = idaapi.get_member(s, member_offset)
    if not m:
        return None

    return idaapi.get_member_size(m)


def GetMemberFlag(id, member_offset):
    """
    Get type of a member

    @param id: structure type ID
    @param member_offset: member offset. The offset can be
                          any offset in the member. For example,
                          is a member is 4 bytes long and starts
                          at offset 2, then 2,3,4,5 denote
                          the same structure member.

    @return: -1 if bad structure type ID is passed
             or no such member in the structure
             otherwise returns type of the member, see bit
             definitions above. If the member type is a structure
             then function GetMemberStrid() should be used to
             get the structure type id.
    """
    s = idaapi.get_struc(id)
    if not s:
        return -1

    m = idaapi.get_member(s, member_offset)
    if not m:
        return -1

    return m.flag


def GetMemberStrId(id, member_offset):
    """
    Get structure id of a member

    @param id: structure type ID
    @param member_offset: member offset. The offset can be
                          any offset in the member. For example,
                          is a member is 4 bytes long and starts
                          at offset 2, then 2,3,4,5 denote
                          the same structure member.
    @return: -1 if bad structure type ID is passed
             or no such member in the structure
             otherwise returns structure id of the member.
             If the current member is not a structure, returns -1.
    """
    s = idaapi.get_struc(id)
    if not s:
        return -1

    m = idaapi.get_member(s, member_offset)
    if not m:
        return -1

    cs = idaapi.get_member_struc(m)
    if cs:
        return cs.id
    else:
        return -1


def IsUnion(id):
    """
    Is a structure a union?

    @param id: structure type ID

    @return: 1: yes, this is a union id
             0: no

    @note: Unions are a special kind of structures
    """
    s = idaapi.get_struc(id)
    if not s:
        return 0

    return s.is_union()


def AddStrucEx(index, name, is_union):
    """
    Define a new structure type

    @param index: index of new structure type
                  If another structure has the specified index,
                  then index of that structure and all other
                  structures will be incremented, freeing the specifed
                  index. If index is == -1, then the biggest index
                  number will be used.
                  See GetFirstStrucIdx() for the explanation of
                  structure indices and IDs.
    @param name: name of the new structure type.
    @param is_union: 0: structure
                     1: union

    @return: -1 if can't define structure type because of
             bad structure name: the name is ill-formed or is
             already used in the program.
             otherwise returns ID of the new structure type
    """
    if index == -1:
        index = BADADDR

    return idaapi.add_struc(index, name, is_union)


def DelStruc(id):
    """
    Delete a structure type

    @param id: structure type ID

    @return: 0 if bad structure type ID is passed
             1 otherwise the structure type is deleted. All data
               and other structure types referencing to the
               deleted structure type will be displayed as array
               of bytes.
    """
    s = idaapi.get_struc(id)
    if not s:
        return 0

    return idaapi.del_struc(s)


def SetStrucIdx(id, index):
    """
    Change structure index

    @param id: structure type ID
    @param index: new index of the structure

    @return: != 0 - ok

    @note: See GetFirstStrucIdx() for the explanation of
           structure indices and IDs.
    """
    s = idaapi.get_struc(id)
    if not s:
        return 0

    return idaapi.set_struc_idx(s, index)


def SetStrucName(id, name):
    """
    Change structure name

    @param id: structure type ID
    @param name: new name of the structure
    
    @return: != 0 - ok
    """
    return idaapi.set_struc_name(id, name)


def SetStrucComment(id, comment, repeatable):
    """
    Change structure comment

    @param id: structure type ID
    @param comment: new comment of the structure
    @param repeatable: 1: change repeatable comment
                       0: change regular comment
    @return: != 0 - ok
    """
    return idaapi.set_struc_cmt(id, comment, repeatable)


def _IDC_PrepareStrucMemberTypeinfo(flag, typeid):
    """ Internal function to prepare typeinfo_t for adding/setting structure members """

    simple_types = [ FF_BYTE, FF_WORD, FF_DWRD, FF_QWRD, FF_OWRD, FF_TBYT, FF_FLOAT, FF_DOUBLE, FF_PACKREAL ]
    
    if idaapi.isASCII(flag):
        ti = idaapi.typeinfo_t()
        ti.strtype = typeid
    elif idaapi.isStruct(flag):
        ti = idaapi.typeinfo_t()
        ti.tid = typeid
    elif idaapi.isOff0(flag):
        ti = idaapi.typeinfo_t()
        ri = idaapi.refinfo_t()
        ri.target = BADADDR
        ri.base = typeid
        ri.tdelta = 0
        if (flag & FF_WORD):
            ri.flags = REF_OFF16
        else:
            ri.flags = REF_OFF32
        ti.ri = ri
    elif idaapi.isEnum0(flag):
        ti = idaapi.typeinfo_t()
        ec = idaapi.enum_const_t()
        ec.tid = typeid
        ti.ec = ec
    elif idaapi.isStroff0(flag):
        ti = idaapi.typeinfo_t()
        ti.path.len = 2
        target_struct = idaapi.get_struc(typeid)
        assert target_struct, "Target structure is invalid"
        target_member = idaapi.get_member(target_struct, 0)
        assert target_member, "Target member is not found"
        ti.path.ids = [ typeid, target_member.id ]
    elif ((flag & 0xFFFFFF) & idaapi.DT_TYPE) in simple_types:
        ti = None
    else:
        assert False, "Unknown type flag 0x%08x" % flag
    return ti


def AddStrucMember(id, name, offset, flag, typeid, nbytes):
    """
    Add structure member

    @param id: structure type ID
    @param name: name of the new member
    @param offset: offset of the new member
                   -1 means to add at the end of the structure
    @param flag: type of the new member. Should be one of 
                 FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA
    @param typeid: structure id if 'flag' == FF_STRU
                   Denotes type of the member if the member itself is a structure.
                   if isOff0(flag) then typeid specifies the offset base.
                   if isASCII(flag) then typeid specifies the string type (ASCSTR_...).
                   if isStroff(flag) then typeid specifies the structure id
                   Otherwise should be -1.
    @param nbytes: number of bytes in the new member

    @return: 0 - ok, otherwise error code (one of STRUC_ERROR_*)
    """
    struc = idaapi.get_struc(id)
    assert struct, "get_struc() failed"
    ti = _IDC_PrepareStrucMemberTypeinfo(flag, typeid)
    return idaapi.add_struc_member(struc, name, offset, flag, ti, nbytes)


STRUC_ERROR_MEMBER_NAME    = -1 # already has member with this name (bad name)
STRUC_ERROR_MEMBER_OFFSET  = -2 # already has member at this offset
STRUC_ERROR_MEMBER_SIZE    = -3 # bad number of bytes or bad sizeof(type)
STRUC_ERROR_MEMBER_TINFO   = -4 # bad typeid parameter
STRUC_ERROR_MEMBER_STRUCT  = -5 # bad struct id (the 1st argument)
STRUC_ERROR_MEMBER_UNIVAR  = -6 # unions can't have variable sized members
STRUC_ERROR_MEMBER_VARLAST = -7 # variable sized member should be the last member in the structure


def DelStrucMember(id, member_offset):
    """
    Delete structure member

    @param id: structure type ID
    @param member_offset: offset of the member

    @return: != 0 - ok.

    @note: IDA allows 'holes' between members of a
           structure. It treats these 'holes'
           as unnamed arrays of bytes.
    """
    s = idaapi.get_struc(id)
    if not s:
        return 0

    return idaapi.del_struc_member(s, member_offset)


def SetMemberName(id, member_offset, name):
    """
    Change structure member name

    @param id: structure type ID
    @param member_offset: offset of the member
    @param name: new name of the member

    @return: != 0 - ok.
    """
    s = idaapi.get_struc(id)
    if not s:
        return 0

    return idaapi.set_member_name(s, member_offset, name)


def SetMemberType(id, member_offset, flag, typeid, nitems):
    """
    Change structure member type

    @param id: structure type ID
    @param member_offset: offset of the member
    @param flag: new type of the member. Should be one of
                 FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA
    @param typeid: structure id if 'flag' == FF_STRU
                   Denotes type of the member is the member
                   itself is a structure. Otherwise should be -1.
                   if isOff0(flag) then typeid specifies the offset base.
                   if isASCII(flag) then typeid specifies the string type
                   (ASCSTR_...).
    @param nitems: number of items in the member

    @return: !=0 - ok.
    """
    struc = idaapi.get_struc(id)
    assert struct, "get_struc() failed"
    ti = _IDC_PrepareStrucMemberTypeinfo(flag, typeid)
    return idaapi.set_member_type(struc, member_offset, flag, ti, nitems)


def SetMemberComment(id, member_offset, comment, repeatable):
    """
    Change structure member comment

    @param id: structure type ID
    @param member_offset: offset of the member
    @param comment: new comment of the structure member
    @param repeatable: 1: change repeatable comment
                       0: change regular comment
    
    @return: != 0 - ok
    """
    s = idaapi.get_struc(id)
    if not s:
        return 0

    m = idaapi.get_member(s, member_offset)
    if not m:
        return 0

    return idaapi.set_member_cmt(m, comment, repeatable)


def GetFchunkAttr(ea, attr):
    """
    Get a function chunk attribute

    @param ea: any address in the chunk
                         @param attr: one of: FUNCATTR_START, FUNCATTR_END, FUNCATTR_COLOR

    @return: desired attribute or -1
    """
    if attr in [ FUNCATTR_START, FUNCATTR_END, FUNCATTR_COLOR ]:
        return GetFunctionAttr(ea, attr)
    else:
        return -1


def SetFchunkAttr(ea, attr, value):
    """
    Set a function chunk attribute

    @param ea: any address in the chunk
    @param attr: only FUNCATTR_COLOR
    @param value: desired bg color (RGB)

    @return: 0 if failed, 1 if success
    """
    if attr in [ FUNCATTR_COLOR ]:
        return SetFunctionAttr(ea, attr, value)
    else:
        return 0


def NextFchunk(ea):
    """
    Get next function chunk

    @param ea: any address

    @return:  the starting address of the next function chunk or BADADDR

    @note: This function enumerates all chunks of all functions in the database
    """
    func = idaapi.get_next_fchunk(ea)

    if func:
        return func.startEA
    else:
        return BADADDR


def PrevFchunk(ea):
    """
    Get previous function chunk

    @param ea: any address

    @return: the starting address of the function chunk or BADADDR

    @note: This function enumerates all chunks of all functions in the database
    """
    func = idaapi.get_prev_fchunk(ea)

    if func:
        return func.startEA
    else:
        return BADADDR


def AppendFchunk(funcea, ea1, ea2):
    """
    Append a function chunk to the function

    @param funcea: any address in the function
    @param ea1: start of function tail
    @param ea2: end of function tail
    @return: 0 if failed, 1 if success

    @note: If a chunk exists at the specified addresses, it must have exactly
           the specified boundaries
    """
    func = idaapi.get_func(funcea)

    if not func:
        return 0
    else:
        return idaapi.append_func_tail(func, ea1, ea2)


def RemoveFchunk(funcea, tailea):
    """
    Remove a function chunk from the function

    @param funcea: any address in the function
    @param ea1: any address in the function chunk to remove
    
    @return: 0 if failed, 1 if success
    """
    func = idaapi.get_func(funcea)

    if not func:
        return 0
    else:
        return idaapi.remove_func_tail(func, tailea)
    

def SetFchunkOwner(tailea, funcea):
    """
    Change the function chunk owner

    @param tailea: any address in the function chunk
    @param funcea: the starting address of the new owner
    
    @return: 0 if failed, 1 if success

    @note: The new owner must already have the chunk appended before the call
    """
    tail = idaapi.get_func(tailea)

    if not tail:
        return 0
    else:
        return idaapi.set_tail_owner(tail, funcea)


def FirstFuncFchunk(funcea):
    """
    Get the first function chunk of the specified function

    @param funcea: any address in the function

    @return: the function entry point or BADADDR

    @note: This function returns the first (main) chunk of the specified function
    """
    func = idaapi.get_func(funcea)
    fci = idaapi.func_tail_iterator_t(func, funcea)
    if fci.main():
        return fci.chunk().startEA
    else:
        return BADADDR


def NextFuncFchunk(funcea, tailea):
    """
    Get the next function chunk of the specified function

    @param funcea: any address in the function
    @param tailea: any address in the current chunk

    @return: the starting address of the next function chunk or BADADDR

    @note: This function returns the next chunk of the specified function
    """
    func = idaapi.get_func(funcea)
    fci = idaapi.func_tail_iterator_t(func, funcea)
    if not fci.main():
        return BADADDR

    # Iterate and try to find the current chunk
    found = False
    while True:
        if fci.chunk().startEA <= tailea and \
           fci.chunk().endEA > tailea:
            found = True
            break
        if not fci.next():
            break

    # Return the next chunk, if there is one
    if found and fci.next():
        return fci.chunk().startEA
    else:
        return BADADDR


# ----------------------------------------------------------------------------
#                          E N U M S
# ----------------------------------------------------------------------------
def GetEnumQty():
    """
    Get number of enum types

    @return: number of enumerations
    """
    return idaapi.get_enum_qty()


def GetnEnum(idx):
    """
    Get ID of the specified enum by its serial number

    @param idx: number of enum (0..GetEnumQty()-1)
    
    @return: ID of enum or -1 if error
    """
    return idaapi.getn_enum(idx)


def GetEnumIdx(enum_id):
    """
    Get serial number of enum by its ID

    @param enum_id: ID of enum
    
    @return: (0..GetEnumQty()-1) or -1 if error
    """
    return idaapi.get_enum_idx(enum_id)


def GetEnum(name):
    """
    Get enum ID by the name of enum

    Arguments:
    name - name of enum
    
    returns:        ID of enum or -1 if no such enum exists
    """
    return idaapi.get_enum(name)


def GetEnumName(enum_id):
    """
    Get name of enum

    @param enum_id: ID of enum

    @return: name of enum or empty string
    """
    return idaapi.get_enum_name(enum_id)


def GetEnumCmt(enum_id, repeatable):
    """
    Get comment of enum

    @param enum_id: ID of enum
    @param repeatable: 0:get regular comment
                 1:get repeatable comment

    @return: comment of enum
    """
    return idaapi.get_enum_cmt(enum_id, repeatable)


def GetEnumSize(enum_id):
    """
    Get size of enum

    @param enum_id: ID of enum

    @return:  number of constants in the enum
              Returns 0 if enum_id is bad.
    """
    return idaapi.get_enum_size(enum_id)


def GetEnumFlag(enum_id):
    """
    Get flag of enum

    @param enum_id: ID of enum

    @return: flags of enum. These flags determine representation
        of numeric constants (binary,octal,decimal,hex)
        in the enum definition. See start of this file for
        more information about flags.
        Returns 0 if enum_id is bad.
    """
    return idaapi.get_enum_flag(enum_id)


def GetConstByName(name):
    """
    Get member of enum - a symbolic constant ID

    @param name: name of symbolic constant

    @return: ID of constant or -1
    """
    return idaapi.get_const_by_name(name)


def GetConstValue(const_id):
    """
    Get value of symbolic constant

    @param const_id: id of symbolic constant

    @return: value of constant or 0
    """
    return idaapi.get_const_value(const_id)


def GetConstBmask(const_id):
    """
    Get bit mask of symbolic constant

    @param const_id: id of symbolic constant

    @return: bitmask of constant or 0
             ordinary enums have bitmask = -1
    """
    return idaapi.get_const_bitmask(const_id)


def GetConstEnum(const_id):
    """
    Get id of enum by id of constant

    @param const_id: id of symbolic constant

    @return: id of enum the constant belongs to.
             -1 if const_id is bad.
    """
    return idaapi.get_const_enum(const_id)


def GetConstEx(enum_id, value, serial, bmask):
    """
    Get id of constant

    @param enum_id: id of enum
    @param value: value of constant
    @param serial: serial number of the constant in the
              enumeration. See OpEnumEx() for details.
    @param bmask: bitmask of the constant
              ordinary enums accept only -1 as a bitmask
    
    @return: id of constant or -1 if error
    """
    return idaapi.get_const(enum_id, value, serial, bmask)


def GetFirstBmask(enum_id):
    """
    Get first bitmask in the enum (bitfield)

    @param enum_id: id of enum (bitfield)

    @return: the smallest bitmask of constant or -1
             no bitmasks are defined yet
             All bitmasks are sorted by their values
             as unsigned longs.
    """
    return idaapi.get_first_bmask(enum_id)


def GetLastBmask(enum_id):
    """
    Get last bitmask in the enum (bitfield)

    @param enum_id: id of enum

    @return: the biggest bitmask or -1 no bitmasks are defined yet
             All bitmasks are sorted by their values as unsigned longs.
    """
    return idaapi.get_last_bmask(enum_id)


def GetNextBmask(enum_id, value):
    """
    Get next bitmask in the enum (bitfield)

    @param enum_id: id of enum
    @param value: value of the current bitmask

    @return:  value of a bitmask with value higher than the specified
              value. -1 if no such bitmasks exist.
              All bitmasks are sorted by their values
              as unsigned longs.
    """
    return idaapi.get_next_bmask(enum_id, value)


def GetPrevBmask(enum_id, value):
    """
    Get prev bitmask in the enum (bitfield)

    @param enum_id: id of enum
    @param value: value of the current bitmask

    @return: value of a bitmask with value lower than the specified
             value. -1 no such bitmasks exist.
             All bitmasks are sorted by their values as unsigned longs.
    """
    return idaapi.get_prev_bmask(enum_id, value)


def GetBmaskName(enum_id, bmask):
    """
    Get bitmask name (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant

    @return: name of bitmask or None
    """
    return idaapi.get_bmask_name(enum_id, bmask)
    

def GetBmaskCmt(enum_id, bmask, repeatable):
    """
    Get bitmask comment (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant
    @param repeatable: type of comment, 0-regular, 1-repeatable

    @return: comment attached to bitmask or None
    """
    return idaapi.get_bmask_cmt(enum_id, bmask, repeatable)


def SetBmaskName(enum_id, bmask, name):
    """
    Set bitmask name (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant
    @param name: name of bitmask

    @return: 1-ok, 0-failed
    """
    return idaapi.set_bmask_name(enum_id, bmask, name)


def SetBmaskCmt(enum_id, bmask, cmt, repeatable):
    """
    Set bitmask comment (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant
    @param cmt: comment
    repeatable - type of comment, 0-regular, 1-repeatable

    @return: 1-ok, 0-failed
    """
    return idaapi.set_bmask_cmt(enum_id, bmask, cmt, repeatable)


def GetFirstConst(enum_id, bmask):
    """
    Get first constant in the enum

    @param enum_id: id of enum
    @param bmask: bitmask of the constant (ordinary enums accept only -1 as a bitmask)

    @return: value of constant or -1 no constants are defined
             All constants are sorted by their values as unsigned longs.
    """
    return idaapi.get_first_const(enum_id, bmask)


def GetLastConst(enum_id, bmask):
    """
    Get last constant in the enum
    
    @param enum_id: id of enum
    @param bmask: bitmask of the constant (ordinary enums accept only -1 as a bitmask)

    @return: value of constant or -1 no constants are defined
             All constants are sorted by their values
             as unsigned longs.
    """
    return idaapi.get_last_const(enum_id, bmask)


def GetNextConst(enum_id, value, bmask):
    """
    Get next constant in the enum

    @param enum_id: id of enum
    @param bmask: bitmask of the constant ordinary enums accept only -1 as a bitmask
    @param value: value of the current constant

    @return: value of a constant with value higher than the specified
             value. -1 no such constants exist.
             All constants are sorted by their values as unsigned longs.
    """
    return idaapi.get_next_const(enum_id, value, bmask)


def GetPrevConst(enum_id, value, bmask):
    """
    Get prev constant in the enum

    @param enum_id: id of enum
    @param bmask  : bitmask of the constant
              ordinary enums accept only -1 as a bitmask
    @param value: value of the current constant
    
    @return: value of a constant with value lower than the specified
        value. -1 no such constants exist.
        All constants are sorted by their values as unsigned longs.
    """
    return idaapi.get_prev_const(enum_id, value, bmask)


def GetConstName(const_id):
    """
    Get name of a constant

    @param const_id: id of const

    Returns: name of constant
    """
    name = idaapi.get_const_name(const_id)

    if not name:
        return ""
    else:
        return name


def GetConstCmt(const_id, repeatable):
    """
    Get comment of a constant

    @param const_id: id of const
    @param repeatable: 0:get regular comment, 1:get repeatable comment

    @return: comment string
    """
    cmt = idaapi.get_const_cmt(const_id, repeatable)

    if not cmt:
        return ""
    else:
        return cmt


def AddEnum(idx, name, flag):
    """
    Add a new enum type

    @param idx: serial number of the new enum.
            If another enum with the same serial number
            exists, then all enums with serial
            numbers >= the specified idx get their
            serial numbers incremented (in other words,
            the new enum is put in the middle of the list of enums).

            If idx >= GetEnumQty() or idx == -1
            then the new enum is created at the end of
            the list of enums.
    @param name: name of the enum.
    @param flag: flags for representation of numeric constants
            in the definition of enum.

    @return: id of new enum or -1.
    """
    return idaapi.add_enum(idx, name, flag)


def DelEnum(enum_id):
    """
    Delete enum type

    @param enum_id: id of enum

    @return: None
    """
    idaapi.del_enum(enum_id)


def SetEnumIdx(enum_id, idx):
    """
    Give another serial number to a enum

    @param enum_id: id of enum
    @param idx: new serial number.
        If another enum with the same serial number
        exists, then all enums with serial
        numbers >= the specified idx get their
        serial numbers incremented (in other words,
        the new enum is put in the middle of the list of enums).

        If idx >= GetEnumQty() then the enum is
        moved to the end of the list of enums.

    @return: comment string
    """
    return idaapi.set_enum_idx(enum_id, idx)
    

def SetEnumName(enum_id, name):
    """
    Rename enum

    @param enum_id: id of enum
    @param name: new name of enum

    @return: 1-ok,0-failed
    """
    return idaapi.set_enum_name(enum_id, name)


def SetEnumCmt(enum_id, cmt, repeatable):
    """
    Set comment of enum

    @param enum_id: id of enum
    @param cmt: new comment for the enum
    @param repeatable: is the comment repeatable?
        - 0:set regular comment
        - 1:set repeatable comment

    @return: 1-ok,0-failed
    """
    return idaapi.set_enum_cmt(enum_id, cmt, repeatable)


def SetEnumFlag(enum_id, flag):
    """
    Set flag of enum

    @param enum_id: id of enum
    @param flag: flags for representation of numeric constants
        in the definition of enum.

    @return: 1-ok,0-failed
    """
    return idaapi.set_enum_flag(enum_id, flag)


def SetEnumBf(enum_id, flag):
    """
    Set bitfield property of enum

    @param enum_id: id of enum
    @param flag: flags
        - 1: convert to bitfield
        - 0: convert to ordinary enum

    @return: 1-ok,0-failed
    """
    return idaapi.set_enum_bf(enum_id, flag)


def IsBitfield(enum_id):
    """
    Is enum a bitfield?

    @param enum_id: id of enum

    @return: 1-yes, 0-no, ordinary enum
    """
    return idaapi.is_bf(enum_id)


def AddConstEx(enum_id, name, value, bmask):
    """
    Add a member of enum - a symbolic constant

    @param enum_id: id of enum
    @param name: name of symbolic constant. Must be unique in the program.
    @param value: value of symbolic constant.
    @param bmask: bitmask of the constant
        ordinary enums accept only -1 as a bitmask
        all bits set in value should be set in bmask too

    @return: 0-ok, otherwise error code (one of CONST_ERROR_*)
    """
    return idaapi.add_const(enum_id, name, value, bmask)


CONST_ERROR_NAME  = idaapi.CONST_ERROR_NAME  # already have member with this name (bad name)
CONST_ERROR_VALUE = idaapi.CONST_ERROR_VALUE # already have member with this value
CONST_ERROR_ENUM  = idaapi.CONST_ERROR_ENUM  # bad enum id
CONST_ERROR_MASK  = idaapi.CONST_ERROR_MASK  # bad bmask
CONST_ERROR_ILLV  = idaapi.CONST_ERROR_ILLV  # bad bmask and value combination (~bmask & value != 0)


def DelConstEx(enum_id, value, serial, bmask):
    """
    Delete a member of enum - a symbolic constant

    @param enum_id: id of enum
    @param value: value of symbolic constant.
    @param serial: serial number of the constant in the
        enumeration. See OpEnumEx() for for details.
    @param bmask: bitmask of the constant ordinary enums accept 
        only -1 as a bitmask

    @return: 1-ok, 0-failed
    """
    return idaapi.del_const(enum_id, value, serial, bmask)


def SetConstName(const_id, name):
    """
    Rename a member of enum - a symbolic constant

    @param const_id: id of const
    @param name: new name of constant

    @return: 1-ok, 0-failed
    """
    return idaapi.set_const_name(const_id, name)


def SetConstCmt(const_id, cmt, repeatable):
    """
    Set a comment of a symbolic constant

    @param const_id: id of const
    @param cmt: new comment for the constant
    @param repeatable: is the comment repeatable? 
        0: set regular comment
        1: set repeatable comment

    @return: 1-ok, 0-failed
    """
    return idaapi.set_const_cmt(const_id, cmt, repeatable)

#----------------------------------------------------------------------------
#                         A R R A Y S  I N  I D C
#----------------------------------------------------------------------------

def CreateArray(name):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetArrayId(name):
    raise DeprecatedIDCError, "Use python pickles instead."

def RenameArray(id, newname):
    raise DeprecatedIDCError, "Use python pickles instead."

def DeleteArray(id):
    raise DeprecatedIDCError, "Use python pickles instead."

def SetArrayLong(id, idx, value):
    raise DeprecatedIDCError, "Use python pickles instead."

def SetArrayString(id, idx, str):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetArrayElement(tag, id, idx):
    raise DeprecatedIDCError, "Use python pickles instead."

def DelArrayElement(tag, id, idx):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetFirstIndex(tag, id):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetLastIndex(tag, id):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetNextIndex(tag, id, idx):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetPrevIndex(tag, id, idx):
    raise DeprecatedIDCError, "Use python pickles instead."

def SetHashLong(id, idx, value):
    raise DeprecatedIDCError, "Use python pickles instead."

def SetHashString(id, idx, value):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetHashLong(id, idx):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetHashString(id, idx):
    raise DeprecatedIDCError, "Use python pickles instead."

def DelHashElement(id, idx):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetFirstHashKey(id):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetNextHashKey(id, idx):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetLastHashKey(id):
    raise DeprecatedIDCError, "Use python pickles instead."

def GetPrevHashKey(id, idx):
    raise DeprecatedIDCError, "Use python pickles instead."


#----------------------------------------------------------------------------
#                 S O U R C E   F I L E / L I N E   N U M B E R S
#----------------------------------------------------------------------------
def AddSourceFile(ea1, ea2, filename):
    """
    Mark a range of address as belonging to a source file
    An address range may belong only to one source file.
    A source file may be represented by several address ranges.

    @param ea1: linear address of start of the address range
    @param ea2: linear address of end of the address range
    @param filename: name of source file.

    @return: 1-ok, 0-failed.

    @note: IDA can keep information about source files used to create the program.
           Each source file is represented by a range of addresses.
           A source file may contains several address ranges.
    """
    return idaapi.add_sourcefile(ea1, ea2, filename)


def GetSourceFile(ea):
    """
    Get name of source file occupying the given address

    @param ea: linear address

    @return: NULL - source file information is not found
             otherwise returns pointer to file name
    """
    return idaapi.get_sourcefile(ea)


def DelSourceFile(ea):
    """
    Delete information about the source file

    @param ea: linear address belonging to the source file

    @return: NULL - source file information is not found
             otherwise returns pointer to file name
    """
    return idaapi.del_sourcefile(ea)


def SetLineNumber(ea, lnnum):
    """
    Set source line number

    @param ea: linear address
    @param lnnum: number of line in the source file

    @return: None
    """
    idaapi.set_source_linnum(ea, lnnum)
    

def GetLineNumber(ea):
    """
    Get source line number

    @param ea: linear address

    @return: number of line in the source file or -1
    """
    return idaapi.get_source_linnum(ea)
    

def DelLineNumber(ea):
    """
    Delete information about source line number

    @param ea: linear address

    @return: None
    """
    idaapi.del_source_linnum(ea)
    

#----------------------------------------------------------------------------
#                T Y P E  L I B R A R I E S
#----------------------------------------------------------------------------

def LoadTil(name, tildir=None):
    """
    Load a type library

    @param name: name of type library.
    @param tildir: drectory to load the TIL from (defaults to "til/pc")
    
    @return: 1-ok, 0-failed.
    """
    if not tildir:
        tildir = "til" + os.sep + "pc"
    
    til = idaapi.load_til(tildir, name)
    
    if til:
        return 1
    else:
        return 0


def Til2Idb(idx, type_name):
    """
    Copy information from type library to database
    Copy structure, union, or enum definition from the type library
    to the IDA database.

    @param idx: the position of the new type in the list of
                types (structures or enums) -1 means at the end of the list
    @param type_name: name of type to copy

    @return: BADNODE-failed, otherwise the type id (structure id or enum id)
    """
    return idaapi.til2idb(idx, type_name)
    

def GetType(ea):
    """
    Get type of function/variable

    @param ea: the address of the object

    @return: type string or None if failed
    """
    return idaapi.idc_get_type(ea)


def GuessType(ea):
    """
    Guess type of function/variable

    @param ea: the address of the object, can be the structure member id too

    @return: type string or None if failed
    """
    return idaapi.idc_guess_type(ea)


def SetType(ea, type):
    """
    Set type of function/variable

    @param ea: the address of the object
    @param type: the type string in C declaration form. 
                 Must contain the closing ';'
                if specified as an empty string, then the
                assciated with 'ea' will be deleted

    @return: 1-ok, 0-failed.
    """
    return idaapi.apply_cdecl(ea, type)


def ParseTypes(input, flags):
    """
    Parse type declarations
    
    @param input: file name or C declarations (depending on the flags)
    @param flags: combination of PT_... constants or 0

    @return: number of errors
    """
    return idaapi.idc_parse_types(input, flags)


PT_FILE =   0x0001  # input if a file name (otherwise contains type declarations)
PT_SILENT = 0x0002  # silent mode
PT_PAKDEF = 0x0000  # default pack value
PT_PAK1 =   0x0010  # #pragma pack(1)
PT_PAK2 =   0x0020  # #pragma pack(2)
PT_PAK4 =   0x0030  # #pragma pack(4)
PT_PAK8 =   0x0040  # #pragma pack(8)
PT_PAK16 =  0x0050  # #pragma pack(16)

# ----------------------------------------------------------------------------
#                           H I D D E N  A R E A S
# ----------------------------------------------------------------------------
def HideArea(start, end, description, header, footer, color):
    """
    Hide an area

    Hidden areas - address ranges which can be replaced by their descriptions

    @param start:       area start
    @param end:         area end
    @param description: description to display if the area is collapsed
    @param header:      header lines to display if the area is expanded
    @param footer:      footer lines to display if the area is expanded
    @param color:       RGB color code (-1 means default color)

    @returns:    !=0 - ok
    """
    return idaapi.add_hidden_area(start, end, description, header, footer, color)


def SetHiddenArea(ea, visible):
    """
    Set hidden area state

    @param ea:      any address belonging to the hidden area
    @param visible: new state of the area

    @return: != 0 - ok
    """
    ha = idaapi.get_hidden_area(ea)

    if not ha:
        return 0
    else:
        ha.visible = visible
        return idaapi.update_hidden_area(ha)


def DelHiddenArea(ea):
    """
    Delete a hidden area

    @param ea: any address belonging to the hidden area
    @returns:  != 0 - ok
    """
    return idaapi.del_hidden_area(ea)


#--------------------------------------------------------------------------
#                   D E B U G G E R  I N T E R F A C E
#--------------------------------------------------------------------------

def GetRegValue(name):
    """
    Get register value

    @param name: the register name

    @note: The debugger should be running. otherwise the function fails
           the register name should be valid.
           It is not necessary to use this function to get register values
           because a register name in the script will do too.

    @return: register value (integer or floating point)
    """
    rv = idaapi.regval_t()
    res = idaapi.get_reg_val(name, rv)
    assert res, "get_reg_val() failed, bogus name perhaps?"
    return rv.ival


def SetRegValue(value, name):
    """
    Set register value

    @param name: the register name
    @param value: new register value

    @note: The debugger should be running
           It is not necessary to use this function to set register values.
           A register name in the left side of an assignment will do too.
    """
    rv = idaapi.regval_t()
    rv.ival = value
    return idaapi.set_reg_val(name, value)


def GetBptQty():
    """
    Get number of breakpoints.

    @return: number of breakpoints
    """
    return idaapi.get_bpt_qty()


def GetBptEA(n):
    """
    Get breakpoint address

    @param n: number of breakpoint, is in range 0..GetBptQty()-1

    @return: addresss of the breakpoint or BADADDR
    """
    bpt = idaapi.bpt_t()

    if idaapi.getn_bpt(n, bpt):
        return bpt.ea
    else:
        return BADADDR


def GetBptAttr(ea, bptattr):
    """
    Get the characteristics of a breakpoint

    @param address: any address in the breakpoint range
    @param bptattr: the desired attribute code, one of BPTATTR_... constants

    @return: the desired attribute value or -1
    """
    bpt = idaapi.bpt_t()

    if not idaapi.get_bpt(ea, bpt):
        return -1
    else:
        if bptattr == BPTATTR_EA:
            return bpt.ea
        if bptattr == BPTATTR_SIZE:
            return bpt.size
        if bptattr == BPTATTR_TYPE:
            return bpt.type
        if bptattr == BPTATTR_COUNT:
            return bpt.pass_count
        if bptattr == BPTATTR_FLAGS:
            return bpt.flags
        if bptattr == BPTATTR_COND:
            return bpt.condition
        return -1
    

BPTATTR_EA    =  0   # starting address of the breakpoint
BPTATTR_SIZE  =  4   # size of the breakpoint (undefined if software breakpoint)
BPTATTR_TYPE  =  8   # type of the breakpoint
BPTATTR_COUNT = 12   # how many times does the execution reach this breakpoint ?
BPTATTR_FLAGS = 16   # Breakpoint attributes:
BPTATTR_COND  = 20   # Breakpoint condition NOTE: the return value is a string in this case

# Breakpoint types:
BPT_EXEC    = 0    # Hardware: Execute instruction
BPT_WRITE   = 1    # Hardware: Write access
BPT_RDWR    = 3    # Hardware: Read/write access
BPT_SOFT    = 4    # Software breakpoint

BPT_BRK        = 0x01  # does the debugger stop on this breakpoint?
BPT_TRACE      = 0x02  # does the debugger add trace information when this breakpoint is reached?


def SetBptAttr(address, bptattr, value):
    """
        modifiable characteristics of a breakpoint

    @param address: any address in the breakpoint range
    @param bptattr: the attribute code, one of BPTATTR_* constants
                    BPTATTR_CND is not allowed, see SetBptCnd()
    @param value: the attibute value

    @return: success
    """
    bpt = idaapi.bpt_t()

    if not idaapi.get_bpt(address, bpt):
        return False
    else:
        if bptattr not in [ BPTATTR_SIZE, BPTATTR_TYPE, BPTATTR_FLAGS, BPTATTR_COUNT ]:
            return False
        if bptattr == BPTATTR_SIZE:
            bpt.size = value
        if bptattr == BPTATTR_TYPE:
            bpt.type = value
        if bptattr == BPTATTR_COUNT:
            bpt.pass_count = value
        if bptattr == BPTATTR_FLAGS:
            bpt.flags = value

        idaapi.update_bpt(bpt)
        return True


def SetBptCnd(ea, cnd):
    """
    Set breakpoint condition
    
    @param address: any address in the breakpoint range
    @param cnd: breakpoint condition
    
    @return: success
    """
    bpt = idaapi.bpt_t()
    
    if not idaapi.get_bpt(ea, bpt):
        return False

    bpt.condition = cnd

    return idaapi.update_bpt(bpt)


def AddBptEx(ea, size, bpttype):
    """
    Add a new breakpoint
    
    @param ea: any address in the process memory space:
    @param size: size of the breakpoint (irrelevant for software breakpoints):
    @param type: type of the breakpoint (one of BPT_... constants)

    @return: success

    @note: Only one breakpoint can exist at a given address.
    """
    return idaapi.add_bpt(ea, size, bpttype)


def AddBpt(ea): return AddBptEx(ea, 0, BPT_SOFT)


def DelBpt(ea):
    """
    Delete breakpoint
    
    @param ea: any address in the process memory space:

    @return: success
    """
    return idaapi.del_bpt(ea)


def EnableBpt(ea, enable):
    """
    Enable/disable breakpoint

    @param ea: any address in the process memory space:

    @return: success

    @note: Disabled breakpoints are not written to the process memory
    """
    return idaapi.enable_bpt(ea, enable)


#--------------------------------------------------------------------------
#                             C O L O R S
#--------------------------------------------------------------------------

def GetColor(ea, what):
    """
    Get item color

    @param ea: address of the item
    @param what: type of the item (one of  CIC_* constants)

    @return: color code in RGB (hex 0xBBGGRR)
    """
    if what not in [ CIC_ITEM, CIC_FUNC, CIC_SEGM ]:
        raise ValueError, "'what' must be one of CIC_ITEM, CIC_FUNC and CIC_SEGM"
    
    if what == CIC_ITEM:
        return idaapi.get_item_color(ea)
        
    if what == CIC_FUNC:
        func = idaapi.get_func(ea)
        if func:
            return func.color
        else:
            return DEFCOLOR

    if what == CIC_SEGM:
        seg = idaapi.getseg(ea)
        if seg:
            return seg.color
        else:
            return DEFCOLOR

# color item codes:
CIC_ITEM = 1         # one instruction or data
CIC_FUNC = 2         # function
CIC_SEGM = 3         # segment

DEFCOLOR = 0xFFFFFFFF  # Default color


def SetColor(ea, what, color):
    """
    Set item color

    @param ea: address of the item
    @param what: type of the item (one of CIC_* constants)
    @param color: new color code in RGB (hex 0xBBGGRR)

    @return: success (True or False)
    """
    if what not in [ CIC_ITEM, CIC_FUNC, CIC_SEGM ]:
        raise ValueError, "'what' must be one of CIC_ITEM, CIC_FUNC and CIC_SEGM"
    
    if what == CIC_ITEM:
        return idaapi.set_item_color(ea, color)
        
    if what == CIC_FUNC:
        func = idaapi.get_func(ea)
        if func:
            func.color = color
            return True
        else:
            return False

    if what == CIC_SEGM:
        seg = idaapi.getseg(ea)
        if seg:
            seg.color = color
            return True
        else:
            return False



#--------------------------------------------------------------------------
#                               X M L
#--------------------------------------------------------------------------

def SetXML(path, name, value):
    """
    Set or update one or more XML values.

    @param path: XPath expression of elements where to create value(s)
    @param name: name of the element/attribute
                 (use @XXX for an attribute) to create.
                 If 'name' is empty, the elements or
                 attributes returned by XPath are directly
                 updated to contain the new 'value'.
    @param value: value of the element/attribute

    @return: success (True or False)
    """
    return idaapi.set_xml(path, name, value)


def GetXML(path):
    """
    Get one XML value.

    @param path: XPath expression to an element
                 or attribute whose value is requested

    @return: the value, None if failed
    """
    v = idaapi.value_t()
    if idaapi.get_xml(path):
        return v.str
    else:
        return None
    

#--------------------------------------------------------------------------
# Compatibility macros:
def OpOffset(ea,base):       return OpOff(ea,-1,base)
def OpNum(ea):               return OpNumber(ea,-1)
def OpChar(ea):              return OpChr(ea,-1)
def OpSegment(ea):           return OpSeg(ea,-1)
def OpDec(ea):               return OpDecimal(ea,-1)
def OpAlt1(ea,str):          return OpAlt(ea,0,str)
def OpAlt2(ea,str):          return OpAlt(ea,1,str)
def StringStp(x):            return SetCharPrm(INF_ASCII_BREAK,x)
def LowVoids(x):             return SetLongPrm(INF_LOW_OFF,x)
def HighVoids(x):            return SetLongPrm(INF_HIGH_OFF,x)
def TailDepth(x):            return SetLongPrm(INF_MAXREF,x)
def Analysis(x):             return SetCharPrm(INF_AUTO,x)
def Tabs(x):                 return SetCharPrm(INF_ENTAB,x)
#def Comments(x):             SetCharPrm(INF_CMTFLAG,((x) ? (SW_ALLCMT|GetCharPrm(INF_CMTFLAG)) : (~SW_ALLCMT&GetCharPrm(INF_CMTFLAG))))
def Voids(x):                return SetCharPrm(INF_VOIDS,x)
def XrefShow(x):             return SetCharPrm(INF_XREFNUM,x)
def Indent(x):               return SetCharPrm(INF_INDENT,x)
def CmtIndent(x):            return SetCharPrm(INF_COMMENT,x)
def AutoShow(x):             return SetCharPrm(INF_SHOWAUTO,x)
def MinEA():                 return GetLongPrm(INF_MIN_EA)
def MaxEA():                 return GetLongPrm(INF_MAX_EA)
def BeginEA():               return GetLongPrm(INF_BEGIN_EA)
def set_start_cs(x):         return SetLongPrm(INF_START_CS,x)
def set_start_ip(x):         return SetLongPrm(INF_START_IP,x)

def WriteMap(filepath):
    return GenerateFile(OFILE_MAP, filepath, 0, BADADDR, GENFLG_MAPSEGS|GENFLG_MAPNAME)

def WriteTxt(filepath, ea1, ea2):
    return GenerateFile(OFILE_ASM, filepath, ea1, ea2, 0)

def WriteExe(filepath):
    return GenerateFile(OFILE_EXE, filepath, 0, BADADDR, 0)

def AddConst(enum_id,name,value): return AddConstEx(enum_id,name,value,-1)
def AddStruc(index,name):   return AddStrucEx(index,name,0)
def AddUnion(index,name):   return AddStrucEx(index,name,1)
def OpStroff(ea,n,strid):   return OpStroffEx(ea,n,strid,0)
def OpEnum(ea,n,enumid):    return OpEnumEx(ea,n,enumid,0)
def DelConst(id,v,mask):    return DelConstEx(id,v,0,mask)
def GetConst(id,v,mask):    return GetConstEx(id,v,0,mask)
def AnalyseArea(sEA, eEA):       AnalyzeArea(sEA,eEA)

def MakeStruct(ea,name):         return MakeStructEx(ea, -1, name)
def Name(ea):               return NameEx(BADADDR, ea)
def GetTrueName(ea):        return GetTrueNameEx(BADADDR, ea)
def MakeName(ea, name):           MakeNameEx(ea,name,SN_CHECK)

def GetFrame(ea):                return GetFunctionAttr(ea, FUNCATTR_FRAME)
def GetFrameLvarSize(ea):        return GetFunctionAttr(ea, FUNCATTR_FRSIZE)
def GetFrameRegsSize(ea):        return GetFunctionAttr(ea, FUNCATTR_FRREGS)
def GetFrameArgsSize(ea):        return GetFunctionAttr(ea, FUNCATTR_ARGSIZE)
def GetFunctionFlags(ea):        return GetFunctionAttr(ea, FUNCATTR_FLAGS)
def SetFunctionFlags(ea, flags): return SetFunctionAttr(ea, FUNCATTR_FLAGS, flags)

def SegStart(ea):                return GetSegmentAttr(ea, SEGATTR_START)
def SegEnd(ea):                  return GetSegmentAttr(ea, SEGATTR_END)
def SetSegmentType(ea, type):    return SetSegmentAttr(ea, SEGATTR_TYPE, type)

def Comment(ea):                return GetCommentEx(ea, 0)
def RptCmt(ea):                 return GetCommentEx(ea, 1)

def loadfile(filepath, pos, ea, size): return LoadFile(filepath, pos, ea, size)
def savefile(filepath, pos, ea, size): return SaveFile(filepath, pos, ea, size)

# A convenice macro:
def here(): return ScreenEA()

# END OF IDC COMPATIBILY CODE
