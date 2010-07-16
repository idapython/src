# -----------------------------------------------------------------------
# This is an example illustrating how to use custom data types in Python
# (c) Hex-Rays
#
from idaapi import data_type_t, data_format_t, NW_OPENIDB, NW_CLOSEIDB, NW_TERMIDA, NW_REMOVE, COLSTR
import struct
import ctypes
import platform

#<pycode(ex_custdata)>

# -----------------------------------------------------------------------
class pascal_data_type(data_type_t):
    def __init__(self):
        data_type_t.__init__(self, name="py_pascal_string",
                             value_size = 2, menu_name = "Pascal string",
                             asm_keyword = "pstr")

    def calc_item_size(self, ea, maxsize):
        # Custom data types may be used in structure definitions. If this case
        # ea is a member id. Check for this situation and return 1
        if _idaapi.is_member_id(ea):
            return 1

        # get the length byte
        n = _idaapi.get_byte(ea)

        # string too big?
        if n > maxsize:
            return 0
        # ok, accept the string
        return n + 1

class pascal_data_format(data_format_t):
    FORMAT_NAME = "py_pascal_string_pstr"
    def __init__(self):
        data_format_t.__init__(self, name=pascal_data_format.FORMAT_NAME)

    def printf(self, value, current_ea, operand_num, dtid):
        # Take the length byte
        n = ord(value[0])
        o = ['"']
        for ch in value[1:]:
            b = ord(ch)
            if b < 0x20 or b > 128:
                o.append(r'\x%02x' % ord(ch))
            else:
                o.append(ch)
        o.append('"')
        return "".join(o)

# -----------------------------------------------------------------------
class simplevm_data_type(data_type_t):
    ASM_KEYWORD = "svm_emit"
    def __init__(self):
        data_type_t.__init__(self,
                             name="py_simple_vm",
                             value_size = 1,
                             menu_name = "SimpleVM",
                             asm_keyword = simplevm_data_type.ASM_KEYWORD)

    def calc_item_size(self, ea, maxsize):
        if _idaapi.is_member_id(ea):
            return 1
        # get the opcode and see if it has an imm
        n = 5 if (_idaapi.get_byte(ea) & 3) == 0 else 1
        # string too big?
        if n > maxsize:
            return 0
        # ok, accept
        return n

class simplevm_data_format(data_format_t):
    def __init__(self):
        data_format_t.__init__(self,
                               name="py_simple_vm_format",
                               menu_name = "SimpleVM")

    # Some tables for the disassembler
    INST = {1: 'add', 2: 'mul', 3: 'sub', 4: 'xor', 5: 'mov'}
    REGS = {1: 'r1', 2: 'r2', 3: 'r3'}
    def disasm(self, inst):
        """A simple local disassembler. In reality one can use a full-blown disassembler to render the text"""
        opbyte = ord(inst[0])
        op     = opbyte >> 4
        if not (1<=op<=5):
            return None
        r1     = (opbyte & 0xf) >> 2
        r2     = opbyte & 3
        sz     = 0
        if r2 == 0:
            if len(inst) != 5:
                return None
            imm = struct.unpack_from('L', inst, 1)[0]
            sz  = 5
        else:
            imm = None
            sz  = 1
        text = "%s %s, %s" % (
            COLSTR(simplevm_data_format.INST[op], idaapi.SCOLOR_INSN),
            COLSTR(simplevm_data_format.REGS[r1], idaapi.SCOLOR_REG),
            COLSTR("0x%08X" % imm, idaapi.SCOLOR_NUMBER) if imm is not None else COLSTR(simplevm_data_format.REGS[r2], idaapi.SCOLOR_REG))
        return (sz, text)

    def printf(self, value, current_ea, operand_num, dtid):
        r = self.disasm(value)
        if not r:
            return None
        if dtid == 0:
            return "%s(%s)" % (simplevm_data_type.ASM_KEYWORD, r[1])
        return r[1]

# -----------------------------------------------------------------------
# This format will display DWORD values as MAKE_DWORD(0xHI, 0xLO)
class makedword_data_format(data_format_t):
    def __init__(self):
        data_format_t.__init__(self,
                               name="py_makedword",
                               value_size = 4,
                               menu_name = "Make DWORD")

    def printf(self, value, current_ea, operand_num, dtid):
        if len(value) != 4: return None
        w1 = struct.unpack_from("H", value, 0)[0]
        w2 = struct.unpack_from("H", value, 2)[0]
        return "MAKE_DWORD(0x%04X, 0x%04X)" % (w2, w1)

# -----------------------------------------------------------------------
# This format will try to load a resource string given a number
# So instead of displaying:
#    push 66h
#    call message_box_from_rsrc_string
# It can be rendered as;
#    push RSRC("The message")
#    call message_box_from_rsrc_string
#
# The get_rsrc_string() is not optimal since it loads/unloads the
# DLL each time for a new string. It can be improved in many ways.
class rsrc_string_format(data_format_t):
    def __init__(self):
        data_format_t.__init__(self,
                               name="py_w32rsrcstring",
                               value_size = 1,
                               menu_name = "Resource string")
        self.cache_node = idaapi.netnode("$ py_w32rsrcstring", 0, 1)

    def get_rsrc_string(self, fn, id):
        """
        Simple method that loads the input file as a DLL with LOAD_LIBRARY_AS_DATAFILE flag.
        It then tries to LoadString()
        """
        k32 = ctypes.windll.kernel32
        u32 = ctypes.windll.user32

        hinst = k32.LoadLibraryExA(fn, 0, 0x2)
        if hinst == 0:
            return ""
        buf = ctypes.create_string_buffer(1024)
        r   = u32.LoadStringA(hinst, id, buf, 1024-1)
        k32.FreeLibrary(hinst)
        return buf.value if r else ""

    def printf(self, value, current_ea, operand_num, dtid):
        # Is it already cached?
        val = self.cache_node.supval(current_ea)

        # Not cached?
        if val == None:
            # Retrieve it
            num = idaapi.struct_unpack(value)
            val = self.get_rsrc_string(idaapi.get_input_file_path(), num)
            # Cache it
            self.cache_node.supset(current_ea, val)

        # Failed to retrieve?
        if val == "" or val == "\x00":
            return None
        # Return the format
        return "RSRC_STR(\"%s\")" % COLSTR(val, idaapi.SCOLOR_IMPNAME)

# -----------------------------------------------------------------------
# Table of formats and types to be registered/unregistered
# If a tuple has one element then it is the format to be registered with dtid=0
# If the tuple has more than one element, the tuple[0] is the data type and tuple[1:] are the data formats
new_formats = [
  (pascal_data_type(), pascal_data_format()),
  (simplevm_data_type(), simplevm_data_format()),
  (makedword_data_format(),),
  (simplevm_data_format(),)
]

if platform.system() == 'Windows':
    new_formats.append((rsrc_string_format(),))

#</pycode(ex_custdata)>

# -----------------------------------------------------------------------
def nw_handler(code, old=0):
    # delete notifications
    if code == NW_OPENIDB:
        idaapi.register_data_types_and_formats(new_formats)
    elif code == NW_CLOSEIDB:
        idaapi.unregister_data_types_and_formats(new_formats)
    elif code == NW_TERMIDA:
        idaapi.notify_when(NW_TERMIDA | NW_OPENIDB | NW_CLOSEIDB | NW_REMOVE, nw_handler)

# -----------------------------------------------------------------------
# Check if already installed
if idaapi.find_custom_data_type(pascal_data_format.FORMAT_NAME) == -1:
    if not idaapi.register_data_types_and_formats(new_formats):
        print "Failed to register types!"
    else:
        idaapi.notify_when(NW_TERMIDA | NW_OPENIDB | NW_CLOSEIDB, nw_handler)
        print "Formats installed!"
else:
    print "Formats already installed!"
