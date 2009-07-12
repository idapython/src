#------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler Pro
#
# Copyright (c) 2004-2009 Gergely Erdelyi <dyce@d-dome.net> 
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#------------------------------------------------------------
"""
idautils.py - High level utility functions for IDA
"""
import idaapi
import idc

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
    
        for ref in DataRefsTo(ScreenEA(), 1):
            print ref
    """
    return refs(ea, idaapi.get_first_dref_to, idaapi.get_next_dref_to)    


def DataRefsFrom(ea):
    """
    Get a list of data references from 'ea'

    @param ea:   Target address

    @return: list of references (may be empty list)

    Example::
    
        for ref in DataRefsFrom(ScreenEA(), 1):
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
    class _xref:
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

    Example:
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

    Example:
           for xref in XrefsTo(here(), 0):
               print xref.type, XrefTypeName(xref.type), \
                         'from', hex(xref.frm), 'to', hex(xref.to)
    """
    xref = idaapi.xrefblk_t()
    if xref.first_to(ea, flags):
        yield _copy_xref(xref)
        while xref.next_to():
            yield _copy_xref(xref)


def Heads(start=idaapi.cvar.inf.minEA, end=idaapi.cvar.inf.maxEA):
    """
    Get a list of heads (instructions or data)

    @param start: start address (default: inf.minEA)
    @param end:   end address (default: inf.maxEA)

    @return: list of heads between start and end
    """
    ea = start
    if not idc.isHead(idc.GetFlags(ea)):
        ea = idaapi.next_head(ea, end)
    while ea != idaapi.BADADDR:
        yield ea
        ea = idaapi.next_head(ea, end)


def Functions(start=idaapi.cvar.inf.minEA, end=idaapi.cvar.inf.maxEA):
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
    func = idaapi.get_func(start)
    if not func:
        func = idaapi.get_next_func(start)
    while func and func.startEA < end:
        yield func.startEA
        func = idaapi.get_next_func(func.startEA)


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


def Segments():
    """
    Get list of segments (sections) in the binary image

    @return: List of segment start addresses.
    """
    for n in range(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(n)
        if seg:
            yield seg.startEA


def GetDataList(ea, count, itemsize=1):
    """
    Get data list - INTERNAL USE ONLY
    """
    getdata = None

    if itemsize == 1:
        getdata = idaapi.get_byte
    if itemsize == 2:
        getdata = idaapi.get_word
    if itemsize == 4:
        getdata = idaapi.get_long

    assert getdata, "Invalid data size! Must be 1, 2 or 4"

    for curea in xrange(ea, ea+itemsize*count, itemsize):
        yield getdata(curea)


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


class _cpu:
    "Simple wrapper around GetRegValue/SetRegValue"
    def __getattr__(self, name):
        #print "cpu.get(%s)"%name
        return idc.GetRegValue(name)

    def __setattr__(self, name, value):
        #print "cpu.set(%s)"%name
        return idc.SetRegValue(value, name)

cpu = _cpu()
