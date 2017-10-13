#---------------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler
#
# (c) The IDAPython Team <idapython@googlegroups.com>
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#---------------------------------------------------------------------
#
# dex.py - module to access DEX-file related information
#
#---------------------------------------------------------------------
# pylint: disable=C0103, C0111, C0301, C0326, W0511, R0903
import ctypes
import idaapi
import ida_idaapi
import ida_bytes

uint8  = ctypes.c_ubyte
char   = ctypes.c_char
uint32 = ctypes.c_uint
uint64 = ctypes.c_uint64
uint16 = ctypes.c_ushort
ushort = uint16
# __EA64__ is set if IDA is running in 64-bit mode
__EA64__ = ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL
ea_t = uint64 if __EA64__ else uint32

# parse a ctypes struct from byte data in str_ at 'off'
def get_struct(str_, off, struct):
    s = struct()
    slen = ctypes.sizeof(s)
    bytebuf = str_[off:off+slen]
    fit = min(len(bytebuf), slen)
    if fit < slen:
        raise Exception("can't read struct: %d bytes available but %d required" % (fit, slen))
    ctypes.memmove(ctypes.addressof(s), bytebuf, fit)
    return s

#---------------------------------------------------------------------------
# This structure is used both for imported methods and locally defined ones
#
class dex_method(ctypes.LittleEndianStructure):
    # flags
    IS_LOCAL = 1
    HAS_CODE = 2
    _fields_ = [
        ("flags",          uint32), # Class type where this method is defined
        ("defaddr",          ea_t), # Address in file where the "definiton" (DexMethodId) is stored
        ("cname",          uint32), # Class type where this method is defined
        ("id",             uint32), # Id of method; key to look up name
        ("proto_ret",      uint32), # Name of return type
        ("proto_shorty",   uint32), # 'shorty' parameter descirptor name
        ("nparams",        ushort), # No of parameters to method. May be >32
        ("proto_params",uint32*32), # Name of types for the first 32 parameters
        ("access_flags",   uint32), # Access flags
        ("startAddr",       ea_t),  # Function start and end address
        ("endAddr",         ea_t),  #
        ("reg_total",      ushort), # Registers total, parameters and out
        ("reg_params",     ushort), #
        ("reg_out",        ushort), #
        ("catchHData",       ea_t), # offset to methods catch handler data
    ]
    def is_local(self):
        return (self.flags & dex_method.IS_LOCAL) != 0


"""
struct dex_field
{
  uint32 ctype, name, type;
  ea_t maddr;   // Address used for xrefs.
};

"""
class dex_field(ctypes.LittleEndianStructure):
    # flags
    _fields_ = [
        ("ctype",   uint32), #
        ("name",   uint32), #
        ("type",   uint32), #
        ("maddr",   ea_t), # Address used for xrefs.
    ]

"""
struct longname_director_t
{
  char zero;
  netnode node;
};
"""
class longname_director_t(ctypes.LittleEndianStructure):
    # flags
    _pack_ = 1
    _fields_ = [
        ("zero",   uint8), #
        ("node",   ea_t), # netnode index with the actual string blob
    ]


class Dex(object):

    # meta-data
    HASHVAL_MAGIC = "version"           # Interface version
    HASHVAL_OPTIMIZED = "optimized"     # 1 for optimized dex files, 0 - for others
    HASHVAL_DEXVERSION = "dex_version"  # DEX File version

    # The dex string table; lookup from string id# to values
    STRTAB_TAB  = 1     # Lookup string id => address
    STRTAB_RTAB = 2     # Lookup address => id

    # fields
    FIELDTAB_DESCR    = 1       # Field id => struct dex_field
    FIELDTAB_NAMEDATA = 2       # Field id => char data, field name

    # The dex method table; lookup method meta-data based on index
    METHTAB_BEGIN       = 1     # Method id => start address
    METHTAB_RBEGIN      = 2     # Start address => method id
    METHTAB_DESCR       = 3     # Method id => struct dex_method
    METHTAB_NAMEDATA    = 4     # Method id => char data, method name
    METHTAB_NAMEORGDATA = 5     # Method id => char data, method name from dex file
    METHTAB_NTAB        = 6     # Method id => String id of method name

    # debug info representation
    DEBINFO_LINEINFO = 1        # Line start EA => dex_lineinfo_t

    # Try/Catches
    TRYTAB_TRYLIST        = 3   # key=methodIdx, value= tryItem data
    TRYTAB_HANDLERLIST    = 4   # key=ea (handler start), value=list of typeIdx, handled types
    TRYTAB_HANDLERTRYLIST = 5   # key=ea (handler start), value=list of tryItemIdx

    # Types
    TYPETAB_TAB        = 1      # Type ID => String ID
    TYPETAB_STRDATA    = 2      # Type ID => String data (possible user redefined)
    TYPETAB_STRORGDATA = 3      # Type ID => Original String data
    TYPETAB_EA         = 4      # Type ID => ea

    #---------------------------------------------------------------------------
    def __init__(self):
        self.nn_meta = idaapi.netnode("$ dex_meta")
        self.nn_strtab = idaapi.netnode("$ dex_strtab")
        self.nn_fieldtab = idaapi.netnode("$ dex_fields")
        self.nn_methtab = idaapi.netnode("$ dex_methtab")
        self.nn_debinfo = idaapi.netnode("$ dex_debinfo")
        self.nn_trytab = idaapi.netnode("$ dex_tries")
        self.nn_typetab = idaapi.netnode("$ dex_types")

    #---------------------------------------------------------------------------
    ACCESS_FLAGS = {
        "public"        : 0x00000001,
        "private"       : 0x00000002,
        "protected"     : 0x00000004,
        "static"        : 0x00000008,
        "final"         : 0x00000010,
        "synchronized"  : 0x00000020,
        "volatile"      : 0x00000040,
        "bridge"        : 0x00000040,
        "transient"     : 0x00000080,
        "varargs"       : 0x00000080,
        "native"        : 0x00000100,
        "interface"     : 0x00000200,
        "abstract"      : 0x00000400,
        "strictfp"      : 0x00000800,
        "synthetic"     : 0x00001000,
        "annotation"    : 0x00002000,
        "enum"          : 0x00004000,
        "constructor"   : 0x00010000,
        "dsynchronized" : 0x00020000, }

    #---------------------------------------------------------------------------
    @staticmethod
    def access_string(flags):
        res = ""
        for access_bit in ("synchronized", "synthetic", "public",
                           "private", "protected", "interface",
                           "abstract", "strictfp", "final",
                           "native", "static"):
            if flags & Dex.ACCESS_FLAGS[access_bit] != 0:
                res += " " + access_bit
        return res[1:] if res else ""

    #---------------------------------------------------------------------------
    def get_string(self, string_idx):
        addr = self.nn_strtab.altval(string_idx, Dex.STRTAB_TAB)
        if addr is 0:
            return None
        length = ida_bytes.get_max_strlit_length(addr, STRTYPE_C, ida_bytes.ALOPT_IGNHEADS|ida_bytes.ALOPT_IGNPRINT)
        return ida_bytes.get_strlit_contents(addr, length, STRTYPE_C)

    def get_method_idx(self, ea):
        return self.nn_methtab.altval(ea, Dex.METHTAB_RBEGIN)

    def get_method(self, method_idx):
        val = self.nn_methtab.supval(method_idx, Dex.METHTAB_DESCR)
        if len(val) != ctypes.sizeof(dex_method):
            print "bad data in METHTAB_DESCR for index 0x%X" % method_idx
            return None
        method = get_struct(val,0, dex_method)
        return method

    #---------------------------------------------------------------------------
    @staticmethod
    def get_string_by_index(node, idx, tag):
        if idx is None:
            return None
        val = node.supval(idx, tag)
        # check for long line
        if len(val) == ctypes.sizeof(longname_director_t):
            longname_director = get_struct(val, 0, longname_director_t)
            if longname_director.zero == 0:
                nn = idaapi.netnode(longname_director.node)
                return nn.getblob(0, tag)[:-1]
        if len(val) > 0:
            return val[:-1]
        return ""

    #---------------------------------------------------------------------------
    # Converts a single-char primitive type into its human-readable equivalent
    PRIMITVE_TYPES = {
        'B': "byte",
        'C': "char",
        'D': "double",
        'F': "float",
        'I': "int",
        'J': "long",
        'S': "short",
        'V': "void",
        'Z': "boolean",
        'L': "ref" }
    @staticmethod
    def _primitive_type_label(typechar):
        if typechar in Dex.PRIMITVE_TYPES:
            return Dex.PRIMITVE_TYPES[typechar]
        return "UNKNOWN"

    @staticmethod
    def is_wide_type(typechar):
        return typechar[0] == 'J' or typechar[0] == 'D'

    #---------------------------------------------------------------------------
    # Converts a type descriptor to human-readable "dotted" form.  For
    # example, "Ljava/lang/String;" becomes "java.lang.String", and
    # "[I" becomes "int[]".  Also converts '$' to '.', which means this
    # form can't be converted back to a descriptor.
    @staticmethod
    def decorate_java_typename(desc):
        target_len = len(desc)
        offset = 0
        # strip leading [s; will be added to end
        while target_len > 1 and desc[offset] == '[':
            offset += 1
            target_len -= 1
        array_depth = offset
        if target_len == 1:
            # primitive type
            desc = Dex._primitive_type_label(desc[offset])
            offset = 0
            target_len = len(desc)
        else:
            # account for leading 'L' and trailing ';'
            if target_len >= 2 and desc[offset] == 'L' and desc[offset + target_len - 1] == ';':
                target_len -= 2
                offset += 1
        # copy class name over
        res = ""
        for _i in range(0, target_len):
            ch = desc[offset + _i]
            res += '.' if ch == '/' else ch
        # add the appropriate number of brackets for arrays
        res += "[]"*array_depth
        return res

    #---------------------------------------------------------------------------
    def get_type_string(self, type_idx):
        return Dex.get_string_by_index(self.nn_typetab, type_idx, Dex.TYPETAB_STRDATA)

    def get_method_name(self, method_idx):
        return Dex.get_string_by_index(self.nn_methtab, method_idx, Dex.METHTAB_NAMEDATA)

    def get_field_name(self, field_idx):
        return Dex.get_string_by_index(self.nn_fieldtab, field_idx, Dex.FIELDTAB_NAMEDATA)

    def get_parameter_name(self, idx):
        return self.get_string(idx)

    #---------------------------------------------------------------------------
    @staticmethod
    def get_short_type_name(longname):
        if not longname:
            return "unknown"
        deco = Dex.decorate_java_typename(longname)
        if not deco:
            return "unknown"
        start = deco.rfind('.')
        if start == -1:
            start = 0
        else:
            start += 1
        return deco[start:].replace('<', '_').replace('>', '_')

    @staticmethod
    def get_full_type_name(longname):
        if not longname:
            return "unknown"
        return Dex.decorate_java_typename(longname)

    #---------------------------------------------------------------------------
    def get_short_method_name(self, method):
        res = Dex.get_short_type_name(self.get_type_string(method.cname))
        res += '.'
        res += self.get_method_name(method.id)
        res += '@'
        res += self.get_string(method.proto_shorty)
        return res

    def get_full_method_name(self, method):
        res = Dex.get_full_type_name(self.get_type_string(method.proto_ret))
        res += ' '
        res += self.get_full_type_name(self.get_type_string(method.cname))
        res += '.'
        res += self.get_method_name(method.id)

    def get_call_method_name(self, method):
        shorty = self.get_string(method.proto_shorty)
        res = Dex._primitive_type_label(shorty[0])
        res += ' '
        res += Dex.get_short_type_name(self.get_type_string(method.cname))
        res += '.'
        res += self.get_method_name(method.id)
        res += '('
        last_idx = len(shorty) - 1
        for s in range(1, last_idx + 1):
            res += Dex._primitive_type_label(shorty[s])
            if s != last_idx:
                res += ", "
        res += ')'
        return res

    def get_field(self, method_idx):
        val = self.nn_fieldtab.supval(method_idx, Dex.FIELDTAB_DESCR)
        if len(val) != ctypes.sizeof(dex_field):
            print "bad data in FIELDTAB_DESCR for index 0x%X" % method_idx
            return None
        field = get_struct(val,0, dex_field)
        return field

    #---------------------------------------------------------------------------
    def get_full_field_name(self, field_idx, field, field_name):
        res = Dex.get_full_type_name(self.get_type_string(field.type))
        res += ' '
        res += Dex.get_full_type_name(self.get_type_string(field_idx))
        res += '.'
        res += field_name if field_name else self.get_field_name(field_idx)
        return res

    #---------------------------------------------------------------------------
    def get_short_field_name(self, field_idx, field, field_name):
        res = Dex.get_short_type_name(self.get_type_string(field.ctype))
        res += '_'
        res += field_name if field_name else self.get_field_name(field_idx)


#---------------------------------------------------------------------------
if __name__ == '__main__':
    dex = Dex()
    # reproduce IDA function header
    f = idaapi.get_func(here())
    if not f:
        print "ERROR: must be in a function!"
        exit(1)

    func_start_ea = f.start_ea
    methno = dex.get_method_idx(func_start_ea)
    func_method = dex.get_method(methno)
    if func_method is None:
        print "ERROR: Missing method info"
        exit(1)
    out = ""
    # Return type
    out += Dex.access_string(func_method.access_flags) + " "
    method_proto = dex.get_type_string(func_method.proto_ret)
    if method_proto:
        out += Dex.get_full_type_name(method_proto)
    else:
        out += "%x" % func_method.proto_ret
    out += ' '
    # Class name
    method_classnm = dex.get_type_string(func_method.cname)
    if method_classnm:
        out += Dex.get_full_type_name(method_classnm)
    else:
        out += "%x" % func_method.cname
    out += '.'
    # Method name
    method_name = dex.get_method_name(methno)
    if method_name:
        out += method_name
    else:
        out += "%x" % methno
    # Method parameters
    if func_method.nparams == 0:
        print out + "()"
    else:
        print out + "("
        out = ""
        maxp = min(func_method.nparams, 32)
        start_reg = func_method.reg_total - func_method.reg_params
        if func_method.access_flags & Dex.ACCESS_FLAGS["static"] == 0:
            start_reg += 1
        for i in range(0, maxp):
            ptype = dex.get_type_string(func_method.proto_params[i])

            out = "  %s " % dex.get_full_type_name(ptype)
            regbuf = "v%u" % start_reg
            start_reg += 1
            r = idaapi.find_regvar(f, f.start_ea, regbuf)
            if r is None:
                out += regbuf
                if Dex.is_wide_type(ptype):
                    out += ':'
                    regbuf = "v%u" % start_reg
                    start_reg += 1
            else:
                out += r.user
            out += ')' if i + 1 == maxp else ','
            print out
