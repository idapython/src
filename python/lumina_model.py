
import sys

import ida_pro
import ida_funcs
import ida_lumina
import ida_typeinf
import ida_bytes

import idautils

dquot_escaped_str = ida_pro.str2user

if sys.version_info.major >= 3:
    int_types = [int]
else:
    int_types = [int, long]

def escaped_bytestr(bts):
    return "".join(map(lambda b: "\\x%02X" % ord(b), bts))

class func_md_t:
    def __init__(self, pfn, retrieve=True):
        if type(pfn) in int_types:
            pfn = ida_funcs.get_func(pfn)
        self.pfn_ea = pfn.start_ea
        self.func_info = ida_lumina.func_info_t()
        if retrieve:
            funcsize, self.sig = ida_lumina.calc_func_metadata(self.func_info, pfn)

    def pfn(self):
        return ida_funcs.get_func(self.pfn_ea)


class idb_md_t:
    def __init__(self):
        # take a snapshot right away
        self.functions = []
        for ea in idautils.Functions():
            self.functions.append(func_md_t(ea))


class differ_t:
    def __init__(self, flags=0):
        self.flags = flags
        self.lines = []
        self.pfn_ea = None

    def put(self, line):
        self.lines.append(line)

    def on_function_diff_start(self, pfn_ea):
        pass

    def on_score_changed(self, pfn, was, now):
        pass

    def on_func_name_changed(self, pfn, was, now):
        pass

    def on_func_proto_changed(self, pfn, was, now):
        pass

    def on_func_cmt_changed(self, pfn, was, now, rep):
        pass

    def on_cmt_changed(self, ea, was, now, rep):
        pass

    def on_extra_cmt_changed(self, ea, was, now, is_prev):
        pass

    def on_user_stkpnt_changed(self, ea, was, now):
        pass

    def on_frame_mem_changed(self, offset, was, now):
        pass

    def on_insn_ops_repr_changed(self, ea, was, now):
        pass

    def diff_function(self, left, right):
        assert(left.pfn_ea == right.pfn_ea)

        self.pfn_ea = left.pfn_ea
        self.on_function_diff_start(left.pfn_ea)

        class trampoline_t(ida_lumina.func_md_diff_handler_t):
            def __init__(self, pfn, differ):
                ida_lumina.func_md_diff_handler_t.__init__(self)
                self.pfn = pfn
                self.differ = differ

            def _toea(self, fchunk_nr, fchunk_off):
                site = ida_lumina.insn_site_t()
                site.fchunk_nr = fchunk_nr
                site.fchunk_off = fchunk_off
                return site.toea(self.pfn)

            def on_score_changed(self, l, r):
                self.differ.on_score_changed(self.pfn, l, r)

            def on_name_changed(self, l, r):
                self.differ.on_func_name_changed(self.pfn, l, r)

            def on_proto_changed(self, l, r):
                ltif, rtif = ida_typeinf.tinfo_t(), ida_typeinf.tinfo_t()
                self.differ.on_func_proto_changed(
                    self.pfn,
                    ltif if ltif.deserialize(None, l.type, l.fields) else None,
                    rtif if rtif.deserialize(None, r.type, r.fields) else None)

            def on_function_comment_changed(self, l, r, rep):
                self.differ.on_func_cmt_changed(self.pfn, l, r, rep)

            def on_comment_changed(self, fchunk_nr, fchunk_off, l, r, rep):
                ea = self._toea(fchunk_nr, fchunk_off)
                self.differ.on_cmt_changed(ea, l, r, rep)

            def on_extra_comment_changed(self, fchunk_nr, fchunk_off, l, r, is_prev):
                ea = self._toea(fchunk_nr, fchunk_off)
                self.differ.on_extra_cmt_changed(ea, l, r, is_prev)

            def on_user_stkpnt_changed(self, fchunk_nr, fchunk_off, l, r):
                ea = self._toea(fchunk_nr, fchunk_off)
                self.differ.on_user_stkpnt_changed(ea, l, r)

            def on_frame_member_changed(self, offset, l, r):
                self.differ.on_frame_mem_changed(offset, l, r)

            def on_insn_ops_repr_changed(self, fchunk_nr, fchunk_off, l, r):
                ea = self._toea(fchunk_nr, fchunk_off)
                self.differ.on_insn_ops_repr_changed(ea, l, r)

        trampoline = trampoline_t(left.pfn(), self)
        ida_lumina.diff_metadata(
            trampoline,
            left.func_info,
            right.func_info,
            self.flags)


class diff2script_t(differ_t):
    def on_function_diff_start(self, pfn_ea):
        self.put("pfn = ida_funcs.get_func(0x%x)" % pfn_ea)

    def on_func_name_changed(self, pfn, was, now):
        raise Exception("unimp!")

    def on_func_proto_changed(self, pfn, was, now):
        raise Exception("unimp!")

    def on_func_cmt_changed(self, pfn, was, now, rep):
        self.put("""ida_funcs.set_func_cmt(pfn, "%s", %s)""" % (
            dquot_escaped_str(now or ''),
            rep))

    def on_cmt_changed(self, ea, was, now, rep):
        self.put("""ida_bytes.set_cmt(0x%x, "%s", %s)""" % (
            ea,
            dquot_escaped_str(now or ''),
            rep))

    def on_extra_cmt_changed(self, ea, was, now, is_prev):
        raise Exception("unimp!")

    def on_user_stkpnt_changed(self, ea, was, now):
        if now is not None:
            self.put("""ida_frame.add_user_stkpnt(0x%x, %s)""" % (ea, hex(now)))
        else:
            self.put("""ida_frame.del_stkpnt(pfn, 0x%x)""" % (ea,))

    def on_frame_mem_changed(self, offset, was, now):
        put = self.put
        put("""ida_struct.del_struc_member(frame, 0x%x)""" % offset)
        if now:
            put("""opinfo = None""")
            put("""tif = ida_typeinf.tinfo_t()""")
            if now.type.type:
                put("""if tif.deserialize(None, "%s", "%s"):""" % (
                    escaped_bytestr(now.type.type),
                    escaped_bytestr(now.type.fields)))
                put("""    ok, size, flags, opinfo, alsize = ida_typeinf.get_idainfo_by_type(tif)""")

            elif ida_bytes.is_off0(now.flags):
                put("""opinfo = ida_nalt.opinfo_t()""")
                put("""opinfo.ri.target = 0x%x""" % now.opinfo.ri.target)
                put("""opinfo.ri.base = 0x%x""" % now.opinfo.ri.base)
                put("""opinfo.ri.tdelta = 0x%x""" % now.opinfo.ri.tdelta)
                put("""opinfo.ri.flags = 0x%x""" % now.opinfo.ri.flags)

            put("""ida_struct.add_struc_member(frame, "%s", 0x%x, 0x%x, opinfo, %d)""" % (
                dquot_escaped_str(now.name),
                offset,
                now.info.flags,
                now.nbytes))
            put("""mptr = ida_struct.get_member(frame, 0x%x)""" % offset)
            put("""if not tif.empty():""")
            put("""    ida_struct.set_member_tinfo(frame, mptr, 0, tif, ida_struct.SET_MEMTI_USERTI)""")
            put("""    ida_nalt.set_userti(mptr.id)""")
            if now.cmt:
                put("""ida_struct.set_member_cmt(mptr, "%s", False)""" % dquot_escaped_str(now.cmt))
            if now.rptcmt:
                put("""ida_struct.set_member_cmt(mptr, "%s", True)""" % dquot_escaped_str(now.rptcmt))

    def on_insn_ops_repr_changed(self, ea, was, now):
        raise Exception("Unimp")
