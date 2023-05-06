"""
summary: notify the user when an instruction operand changes

description:
  Show notifications whenever the user changes
  an instruction's operand, or a data item.
"""

import binascii

import ida_idp
import ida_bytes
import ida_nalt
import ida_struct
import ida_enum

class operand_changed_t(ida_idp.IDB_Hooks):
    def log(self, msg):
        print(">>> %s" % msg)

    def op_type_changed(self, ea, n):
        flags = ida_bytes.get_flags(ea)
        self.log("op_type_changed(ea=0x%08X, n=%d). Flags now: 0x%08X" % (ea, n, flags))

        buf = ida_nalt.opinfo_t()
        opi = ida_bytes.get_opinfo(buf, ea, n, flags)
        if opi:
            if ida_bytes.is_struct(flags):
                self.log("New struct: 0x%08X (name=%s)" % (
                    opi.tid,
                    ida_struct.get_struc_name(opi.tid)))
            elif ida_bytes.is_strlit(flags):
                encidx = ida_nalt.get_str_encoding_idx(opi.strtype)
                if encidx == ida_nalt.STRENC_DEFAULT:
                    encidx = ida_nalt.get_default_encoding_idx(ida_nalt.get_strtype_bpu(opi.strtype))
                encname = ida_nalt.get_encoding_name(encidx)
                strlen = ida_bytes.get_max_strlit_length(
                    ea,
                    opi.strtype,
                    ida_bytes.ALOPT_IGNHEADS | ida_bytes.ALOPT_IGNCLT)
                raw = ida_bytes.get_strlit_contents(ea, strlen, opi.strtype) or b""
                self.log("New strlit: 0x%08X, raw hex=%s (encoding=%s)" % (
                    opi.strtype,
                    binascii.hexlify(raw),
                    encname))
            elif ida_bytes.is_off(flags, n):
                self.log("New offset: refinfo={target=0x%08X, base=0x%08X, tdelta=0x%08X, flags=0x%X}" % (
                    opi.ri.target,
                    opi.ri.base,
                    opi.ri.tdelta,
                    opi.ri.flags))
            elif ida_bytes.is_enum(flags, n):
                self.log("New enum: 0x%08X (enum=%s), serial=%d" % (
                    opi.ec.tid,
                    ida_enum.get_enum_name(opi.ec.tid),
                    opi.ec.serial))
                pass
            elif ida_bytes.is_stroff(flags, n):
                parts = []
                for i in range(opi.path.len):
                    tid = opi.path.ids[i]
                    parts.append("0x%08X (name=%s)" % (tid, ida_struct.get_struc_name(tid)))
                self.log("New stroff: path=[%s] (len=%d, delta=0x%08X)" % (
                    ", ".join(parts),
                    opi.path.len,
                    opi.path.delta))
            elif ida_bytes.is_custom(flags) or ida_bytes.is_custfmt(flags, n):
                self.log("New custom data type") # unimplemented
        else:
            print("Cannot retrieve opinfo_t")
