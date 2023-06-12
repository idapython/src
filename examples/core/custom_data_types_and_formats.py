"""
summary: using custom data types & printers

description:
  IDA can be extended to support certain data types that it
  does not know about out-of-the-box.

  A 'custom data type' provide information about the type &
  size of a piece of data, while a 'custom data format' is in
  charge of formatting that data (there can be more than
  one format for a specific 'custom data type'.)
"""

import ida_bytes
import ida_idaapi
import ida_lines
import ida_struct
import ida_netnode
import ida_nalt

import sys
import struct
import ctypes
import platform

# -----------------------------------------------------------------------
class pascal_data_type(ida_bytes.data_type_t):
    def __init__(self):
        ida_bytes.data_type_t.__init__(
            self,
            "py_pascal_string",
            2,
            "Pascal string",
            None,
            "pstr")

    def calc_item_size(self, ea, maxsize):
        # Custom data types may be used in structure definitions. If this case
        # ea is a member id. Check for this situation and return 1
        if ida_struct.is_member_id(ea):
            return 1

        # get the length byte
        n = ida_bytes.get_byte(ea)

        # string too big?
        if n > maxsize:
            return 0
        # ok, accept the string
        return n + 1

class pascal_data_format(ida_bytes.data_format_t):
    FORMAT_NAME = "py_pascal_string_pstr"
    def __init__(self):
        ida_bytes.data_format_t.__init__(
            self,
            pascal_data_format.FORMAT_NAME)

    def printf(self, value, current_ea, operand_num, dtid):
        # Take the length byte
        n = ord(value[0]) if sys.version_info.major < 3 else value[0]
        o = ['"']
        for ch in value[1:]:
            b = ord(ch) if sys.version_info.major < 3 else ch
            if b < 0x20 or b > 128:
                o.append(r'\x%02x' % b)
            else:
                o.append(ch)
        o.append('"')
        return "".join(o)

# -----------------------------------------------------------------------
class simplevm_data_type(ida_bytes.data_type_t):
    ASM_KEYWORD = "svm_emit"
    def __init__(
            self,
            name="py_simple_vm",
            value_size=1,
            menu_name="SimpleVM",
            asm_keyword=ASM_KEYWORD):
        ida_bytes.data_type_t.__init__(
            self,
            name,
            value_size,
            menu_name,
            None,
            asm_keyword)

    def calc_item_size(self, ea, maxsize):
        if ida_struct.is_member_id(ea):
            return 1
        # get the opcode and see if it has an imm
        n = 5 if (ida_bytes.get_byte(ea) & 3) == 0 else 1
        # string too big?
        if n > maxsize:
            return 0
        # ok, accept
        return n

class simplevm_data_format(ida_bytes.data_format_t):
    def __init__(
            self,
            name="py_simple_vm_format",
            menu_name="SimpleVM"):
        ida_bytes.data_format_t.__init__(
            self,
            name,
            0,
            menu_name)

    # Some tables for the disassembler
    INST = {1: 'add', 2: 'mul', 3: 'sub', 4: 'xor', 5: 'mov'}
    REGS = {1: 'r1', 2: 'r2', 3: 'r3'}
    def disasm(self, inst):
        """A simple local disassembler. In reality one can use a full-blown disassembler to render the text"""
        opbyte = ord(inst[0]) if sys.version_info.major < 3 else inst[0]
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
            ida_lines.COLSTR(simplevm_data_format.INST[op], ida_lines.SCOLOR_INSN),
            ida_lines.COLSTR(simplevm_data_format.REGS[r1], ida_lines.SCOLOR_REG),
            ida_lines.COLSTR("0x%08X" % imm, ida_lines.SCOLOR_NUMBER) if imm is not None else ida_lines.COLSTR(simplevm_data_format.REGS[r2], ida_lines.SCOLOR_REG))
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
class makedword_data_format(ida_bytes.data_format_t):
    def __init__(self):
        ida_bytes.data_format_t.__init__(
            self,
            "py_makedword",
            4,
            "Make DWORD")

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
class rsrc_string_format(ida_bytes.data_format_t):
    def __init__(self):
        ida_bytes.data_format_t.__init__(
            self,
            "py_w32rsrcstring",
            1,
            "Resource string")
        self.cache_node = ida_netnode.netnode("$ py_w32rsrcstring", 0, 1)

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
            num = ida_idaapi.struct_unpack(value)
            val = self.get_rsrc_string(ida_nalt.get_input_file_path(), num)
            # Cache it
            self.cache_node.supset(current_ea, val)

        # Failed to retrieve?
        if val == "" or val == "\x00":
            return None
        # Return the format
        return "RSRC_STR(\"%s\")" % ida_lines.COLSTR(val, ida_lines.SCOLOR_IMPNAME)

# -----------------------------------------------------------------------
# Table of formats and types to be registered/unregistered
# If a tuple has one element then it is the format to be registered with dtid=0
# If the tuple has more than one element, the tuple[0] is the data type and tuple[1:] are the data formats
new_formats = [
  (pascal_data_type(), pascal_data_format()),
  (simplevm_data_type(), simplevm_data_format()),
  (makedword_data_format(),),
  (simplevm_data_format(),),
]

try:
    if platform.system() == 'Windows':
        new_formats.append((rsrc_string_format(),))
except:
    pass

# -----------------------------------------------------------------------
def nw_handler(code, old=0):
    # delete notifications
    if code == ida_idaapi.NW_OPENIDB:
        if not ida_bytes.register_data_types_and_formats(new_formats):
            print("Failed to register types!")
    elif code == ida_idaapi.NW_CLOSEIDB:
        ida_bytes.unregister_data_types_and_formats(new_formats)
    elif code == ida_idaapi.NW_TERMIDA:
        f = ida_idaapi.NW_TERMIDA | ida_idaapi.NW_OPENIDB | ida_idaapi.NW_CLOSEIDB | ida_idaapi.NW_REMOVE
        ida_idaapi.notify_when(f, nw_handler)

# -----------------------------------------------------------------------
# Check if already installed
if ida_bytes.find_custom_data_type(pascal_data_format.FORMAT_NAME) == -1:
    if not ida_bytes.register_data_types_and_formats(new_formats):
        print("Failed to register types!")
    else:
        f = ida_idaapi.NW_TERMIDA | ida_idaapi.NW_OPENIDB | ida_idaapi.NW_CLOSEIDB
        ida_idaapi.notify_when(f, nw_handler)
        print("Formats installed!")
else:
    print("Formats already installed!")
