
#<pycode(py_lumina)>
import ida_bytes
import ida_typeinf
import ida_ida
import ida_pro

class simple_idb_diff_handler_t(func_md_diff_handler_t):

    NO_DATA_MARKER = None

    class indenter_t(object):
        def __init__(self, handler):
            self.handler = handler
            self.handler.indent += 1
        def __del__(self):
            self.handler.indent -= 1

    def __init__(self, pfn):
        super(self.__class__, self).__init__()
        self.pfn = pfn
        self.header_generated = False
        self.lines = []
        self.indent = 0

    def on_score_changed(self, l, r):
        self.put2(str(l), str(r), "Score")

    def on_name_changed(self, l, r):
        self.put2(l, r, "Name")

    def on_proto_changed(self, l, r):
        self.put2(self.format_type(l), self.format_type(r), "Prototype")

    def on_function_comment_changed(self, l, r, rep):
        self.put2(l, r, "Function comment (%s)" % ("repeatable" if rep else "regular"))

    def on_comment_changed(self, fchunk_nr, fchunk_off, l, r, rep):
        loc = self.where(fchunk_nr, fchunk_off)
        self.put2(l, r, "%s comment @ %s" % ("repeatable" if rep else "regular", loc))

    def on_extra_comment_changed(self, fchunk_nr, fchunk_off, l, r, is_prev):
        loc = self.where(fchunk_nr, fchunk_off)
        self.put2(self.format_extra_cmt(l),
                  self.format_extra_cmt(r),
                  "%sterior extra comment @ %s" % ("An" if is_prev else "Pos", loc))

    def on_user_stkpnt_changed(self, fchunk_nr, fchunk_off, l, r):
        loc = self.where(fchunk_nr, fchunk_off)
        self.put2(self.format_stkpnt(l),
                  self.format_stkpnt(r),
                  "User stack point @ %s" % loc)

    def on_frame_member_changed(self, offset, l, r):
        self.ensure_header_generated()
        self.put("Member @ 0x%X" % offset)

        indenter = self.indenter_t(self)
        ltype, loprepr, lcmt, lrptcmt = self.format_frame_member(l)
        rtype, roprepr, rcmt, rrptcmt = self.format_frame_member(r)

        cmp_put = lambda l, r, topic: self.put2(l, r, topic) if l != r else None
        cmp_put(ltype, rtype, ".type")
        cmp_put(loprepr, roprepr, ".opinfo")
        cmp_put(lcmt, rcmt, ".cmt")
        cmp_put(lrptcmt, rrptcmt, ".rptcmt")

    def on_insn_ops_repr_changed(self, fchunk_nr, fchunk_off, l, r):
        loc = self.where(fchunk_nr, fchunk_off)
        ls, rs = self.format_insn_ops(l), self.format_insn_ops(r)
        self.put2(ls, rs, "Insn operands @ %s" % loc)

    # --- helpers ---

    def ensure_header_generated(self):
        if not self.header_generated:
            self.lines.append("")
            self.lines.append("Function 0x%X" % self.pfn.start_ea)
            self.header_generated = True

    def where(self, fchunk_nr, fchunk_off):
        site = insn_site_t()
        site.fchunk_nr = fchunk_nr
        site.fchunk_off = fchunk_off
        return "0x%X" % site.toea(self.pfn)

    def format_type(self, type_parts):
        tif = ida_typeinf.tinfo_t()
        if tif.deserialize(None, type_parts.type, type_parts.fields):
            return tif._print()

    def format_extra_cmt(self, cmt):
        if cmt:
            cmt = ida_pro.str2user(cmt)
        return cmt

    def format_stkpnt(self, stkpnt):
        if stkpnt is not None:
            return "%d" % stkpnt

    def format_frame_member(self, m):
        _type = self.NO_DATA_MARKER
        _oprepr = self.NO_DATA_MARKER
        _cmt = self.NO_DATA_MARKER
        _rptcmt = self.NO_DATA_MARKER
        if m:
            if len(m.type.type):
                _type = self.format_type(m.type)
            if ida_bytes.is_off0(m.info.flags):
                _oprepr = '{"target" : 0x%X, "base" : 0x%X, "tdelta" : 0x%X, "flags" : 0x%08x}' % (
                    m.info.opinfo.ri.target,
                    m.info.opinfo.ri.base,
                    m.info.opinfo.ri.tdelta,
                    m.info.opinfo.ri.flags)
            _cmt = m.cmt
            _rptcmt = m.rptcmt
        return (_type, _oprepr, _cmt, _rptcmt)

    def format_insn_ops(self, ro):
        if not ro:
            return "[<no ops repr>]"
        parts = []
        for i in range(ida_ida.UA_MAXOP):
            parts.append("op%d=0x%X" % (i, (ro.flags >> ida_bytes.get_operand_type_shift(i)) & 0xF))
        return "[%s]" % ", ".join(parts)

    def put(self, msg):
        self.lines.append("    " * self.indent + msg)

    def put2(self, l, r, topic):
        self.ensure_header_generated()
        if l is None: l = self.NO_DATA_MARKER
        if r is None: r = self.NO_DATA_MARKER

        self.put(topic)
        indenter = self.indenter_t(self)
        self.put("- %s" % l)
        self.put("+ %s" % r)

#</pycode(py_lumina)>
