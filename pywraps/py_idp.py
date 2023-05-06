#<pycode(py_idp)>

#----------------------------------------------------------------------------
#               P R O C E S S O R  M O D U L E S  C O N S T A N T S
#----------------------------------------------------------------------------

# ----------------------------------------------------------------------
# processor_t related constants

REAL_ERROR_FORMAT   = -1   #  not supported format for current .idp
REAL_ERROR_RANGE    = -2   #  number too big (small) for store (mem NOT modifyed)
REAL_ERROR_BADDATA  = -3   #  illegal real data for load (IEEE data not filled)

#
# Set IDP options constants
#
IDPOPT_STR        =  1    # string constant
IDPOPT_NUM        =  2    # number
IDPOPT_BIT        =  3    # bit, yes/no
IDPOPT_FLT        =  4    # float
IDPOPT_I64        =  5    # 64bit number

IDPOPT_OK         =  0    # ok
IDPOPT_BADKEY     =  1    # illegal keyword
IDPOPT_BADTYPE    =  2    # illegal type of value
IDPOPT_BADVALUE   =  3    # illegal value (bad range, for example)

# ----------------------------------------------------------------------
import ida_pro
import ida_funcs
import ida_segment
import ida_ua
class processor_t(IDP_Hooks):
    __idc_cvt_id__ = ida_idaapi.PY_ICID_OPAQUE

    """
    Base class for all processor module scripts

    A processor_t instance is both an ida_idp.IDP_Hooks, and an
    ida_idp.IDB_Hooks at the same time: any method of those two classes
    can be overridden in your processor_t subclass (with the exception of
    'ida_idp.IDP_Hooks.ev_init' (replaced with processor_t.__init__),
    and 'ida_idp.IDP_Hooks.ev_term' (replaced with processor_t.__del__)).
    """
    def __init__(self):
        IDP_Hooks.__init__(self, ida_idaapi.HBF_CALL_WITH_NEW_EXEC)
        self.idb_hooks = _processor_t_Trampoline_IDB_Hooks(self)

    def get_idpdesc(self):
        """
        This function must be present and should return the list of
        short processor names similar to the one in ph.psnames.
        This method can be overridden to return to the kernel a different IDP description.
        """
        return '\x01'.join(map(lambda t: '\x01'.join(t), zip(self.plnames, self.psnames)))

    def get_uFlag(self):
        """Use this utility function to retrieve the 'uFlag' global variable"""
        return ida_ua.cvar.uFlag

    def get_auxpref(self, insn):
        """This function returns insn.auxpref value"""
        return insn.auxpref

    def _get_idp_notifier_addr(self):
        return _ida_idp.get_idp_notifier_addr(self)

    def _get_idp_notifier_ud_addr(self):
        return _ida_idp.get_idp_notifier_ud_addr(self)

    def _get_idb_notifier_addr(self):
        return _ida_idp.get_idb_notifier_addr(self)

    def _get_idb_notifier_ud_addr(self):
        return _ida_idp.get_idb_notifier_ud_addr(self.idb_hooks)

    def _make_forced_value_wrapper(self, val, meth=None):
        def f(*args):
            if meth:
                meth(*args)
            return val
        return f

    def _make_int_returning_wrapper(self, meth, intval=0):
        def f(*args):
            val = meth(*args)
            if val is None:
                val = intval
            return val
        return f

    def _get_notify(self, what, unimp_val=0, imp_forced_val=None, add_prefix=True, mandatory_impl=None):
        """
        This helper is used to implement backward-compatibility
        of pre IDA 7.3 processor_t interfaces.
        """
        if add_prefix:
            what = "notify_%s" % what
        meth = getattr(self, what, None)
        if meth is None:
            if mandatory_impl:
                raise Exception("processor_t.%s() must be implemented" % mandatory_impl)
            meth = self._make_forced_value_wrapper(unimp_val)
        else:
            if imp_forced_val is not None:
                meth = self._make_forced_value_wrapper(imp_forced_val, meth)
            else:
                meth = self._make_int_returning_wrapper(meth)
        return meth

    # The default implementations below are what guarantees that
    # pre IDA 7.3 processor_t subclasses, will continue working

    def ev_newprc(self, *args):
        return self._get_notify("newprc")(*args)

    def ev_newfile(self, *args):
        return self._get_notify("newfile")(*args)

    def ev_oldfile(self, *args):
        return self._get_notify("oldfile")(*args)

    def ev_newbinary(self, *args):
        return self._get_notify("newbinary")(*args)

    def ev_endbinary(self, *args):
        return self._get_notify("endbinary")(*args)

    def ev_set_idp_options(self, keyword, value_type, value, idb_loaded):
        res = self._get_notify("set_idp_options", unimp_val=None)(keyword, value_type, value)
        if res is None:
            return 0
        return 1 if res == IDPOPT_OK else -1

    def ev_set_proc_options(self, *args):
        return self._get_notify("set_proc_options")(*args)

    def ev_ana_insn(self, *args):
        rc = self._get_notify("ana", mandatory_impl="ev_ana_insn")(*args)
        return rc > 0

    def ev_emu_insn(self, *args):
        rc = self._get_notify("emu", mandatory_impl="ev_emu_insn")(*args)
        return rc > 0

    def ev_out_header(self, *args):
        return self._get_notify("out_header", imp_forced_val=1)(*args)

    def ev_out_footer(self, *args):
        return self._get_notify("out_footer", imp_forced_val=1)(*args)

    def ev_out_segstart(self, ctx, s):
        return self._get_notify("out_segstart", imp_forced_val=1)(ctx, s.start_ea)

    def ev_out_segend(self, ctx, s):
        return self._get_notify("out_segend", imp_forced_val=1)(ctx, s.end_ea)

    def ev_out_assumes(self, *args):
        return self._get_notify("out_assumes", imp_forced_val=1)(*args)

    def ev_out_insn(self, *args):
        return self._get_notify("out_insn", mandatory_impl="ev_out_insn", imp_forced_val=True)(*args)

    def ev_out_mnem(self, *args):
        return self._get_notify("out_mnem", add_prefix=False, imp_forced_val=1)(*args)

    def ev_out_operand(self, *args):
        rc = self._get_notify("out_operand", mandatory_impl="ev_out_operand", imp_forced_val=1)(*args)
        return rc > 0

    def ev_out_data(self, *args):
        return self._get_notify("out_data", imp_forced_val=1)(*args)

    def ev_out_label(self, *args):
        return self._get_notify("out_label")(*args)

    def ev_out_special_item(self, *args):
        return self._get_notify("out_special_item")(*args)

    def ev_gen_regvar_def(self, ctx, v):
        return self._get_notify("gen_regvar_def")(ctx, v.canon, v.user, v.cmt)

    def ev_gen_src_file_lnnum(self, *args):
        return self._get_notify("gen_src_file_lnnum")(*args)

    def ev_creating_segm(self, s):
        sname = ida_segment.get_visible_segm_name(s)
        sclass = ida_segment.get_segm_class(s)
        return self._get_notify("creating_segm")(s.start_ea, sname, sclass)

    def ev_moving_segm(self, s, to_ea, flags):
        sname = ida_segment.get_visible_segm_name(s)
        sclass = ida_segment.get_segm_class(s)
        return self._get_notify("moving_segm")(s.start_ea, sname, sclass, to_ea, flags)

    def ev_coagulate(self, *args):
        return self._get_notify("coagulate")(*args)

    def ev_undefine(self, *args):
        return self._get_notify("undefine")(*args)

    def ev_treat_hindering_item(self, *args):
        return self._get_notify("treat_hindering_item")(*args)

    def ev_rename(self, *args):
        return self._get_notify("rename")(*args)

    def ev_is_far_jump(self, *args):
        rc = self._get_notify("is_far_jump", unimp_val=False)(*args)
        return 1 if rc else -1

    def ev_is_sane_insn(self, *args):
        return self._get_notify("is_sane_insn")(*args)

    def ev_is_call_insn(self, *args):
        return self._get_notify("is_call_insn")(*args)

    def ev_is_ret_insn(self, *args):
        return self._get_notify("is_ret_insn")(*args)

    def ev_may_be_func(self, *args):
        return self._get_notify("may_be_func")(*args)

    def ev_is_basic_block_end(self, *args):
        return self._get_notify("is_basic_block_end")(*args)

    def ev_is_indirect_jump(self, *args):
        return self._get_notify("is_indirect_jump")(*args)

    def ev_is_insn_table_jump(self, *args):
        return self._get_notify("is_insn_table_jump")(*args)

    def ev_is_switch(self, *args):
        rc = self._get_notify("is_switch")(*args)
        return 1 if rc else 0

    def ev_create_switch_xrefs(self, *args):
        return self._get_notify("create_switch_xrefs", imp_forced_val=1)(*args)

    def ev_is_align_insn(self, *args):
        return self._get_notify("is_align_insn")(*args)

    def ev_is_alloca_probe(self, *args):
        return self._get_notify("is_alloca_probe")(*args)

    def ev_is_sp_based(self, mode, insn, op):
        rc = self._get_notify("is_sp_based", unimp_val=None)(insn, op)
        if type(rc) == int:
            ida_pro.int_pointer.frompointer(mode).assign(rc)
            return 1
        return 0

    def ev_can_have_type(self, *args):
        rc = self._get_notify("can_have_type")(*args)
        if rc is True:
            return 1
        elif rc is False:
            return -1
        else:
            return 0

    def ev_cmp_operands(self, *args):
        rc = self._get_notify("cmp_operands")(*args)
        if rc is True:
            return 1
        elif rc is False:
            return -1
        else:
            return 0

    def ev_get_operand_string(self, buf, insn, opnum):
        rc = self._get_notify("get_operand_string")(insn, opnum)
        if rc:
            return 1
        return 0

    def ev_str2reg(self, *args):
        rc = self._get_notify("notify_str2reg", unimp_val=-1)(*args)
        return 0 if rc < 0 else rc + 1

    def ev_get_autocmt(self, *args):
        return self._get_notify("get_autocmt")(*args)

    def ev_func_bounds(self, _possible_return_code, pfn, max_func_end_ea):
        possible_return_code = ida_pro.int_pointer.frompointer(_possible_return_code)
        rc = self._get_notify("func_bounds", unimp_val=None)(
            possible_return_code.value(),
            pfn.start_ea,
            max_func_end_ea)
        if type(rc) == int:
            possible_return_code.assign(rc)
        return 0

    def ev_verify_sp(self, pfn):
        return self._get_notify("verify_sp")(pfn.start_ea)

    def ev_verify_noreturn(self, pfn):
        return self._get_notify("verify_noreturn")(pfn.start_ea)

    def ev_create_func_frame(self, pfn):
        rc = self._get_notify("create_func_frame", imp_forced_val=1)(pfn.start_ea)
        if rc is True:
            return 1
        elif rc is False:
            return -1
        else:
            return rc

    def ev_get_frame_retsize(self, frsize, pfn):
        rc = self._get_notify("get_frame_retsize", unimp_val=None)(pfn.start_ea)
        if type(rc) == int:
            ida_pro.int_pointer.frompointer(frsize).assign(rc)
            return 1
        return 0

    def ev_coagulate_dref(self, from_ea, to_ea, may_define, _code_ea):
        code_ea = ida_pro.ea_pointer.frompointer(_code_ea)
        rc = self._get_notify("coagulate_dref")(from_ea, to_ea, may_define, code_ea.value())
        if rc == -1:
            return -1
        if rc != 0:
            code_ea.assign(rc)
        return 0

    def ev_may_show_sreg(self, *args):
        return self._get_notify("may_show_sreg")(*args)

    def ev_auto_queue_empty(self, *args):
        return self._get_notify("auto_queue_empty")(*args)

    def ev_validate_flirt_func(self, *args):
        return self._get_notify("validate_flirt_func")(*args)

    def ev_assemble(self, *args):
        return self._get_notify("assemble")(*args)

    def ev_gen_map_file(self, nlines, fp):
        import ida_fpro
        qfile = ida_fpro.qfile_t_from_fp(fp)
        rc = self._get_notify("gen_map_file")(qfile)
        if rc > 0:
            ida_pro.int_pointer.frompointer(nlines).assign(rc)
            return 1
        else:
            return 0

    def ev_calc_step_over(self, target, ip):
        rc = self._get_notify("calc_step_over", unimp_val=None)(ip)
        if rc is not None and rc != ida_idaapi.BADADDR:
            ida_pro.ea_pointer.frompointer(target).assign(rc)
            return 1
        return 0

    # IDB hooks handling

    def closebase(self, *args):
        self._get_notify("closebase")(*args)

    def savebase(self, *args):
        self._get_notify("savebase")(*args)

    def auto_empty(self, *args):
        self._get_notify("auto_empty")(*args)

    def auto_empty_finally(self, *args):
        self._get_notify("auto_empty_finally")(*args)

    def determined_main(self, *args):
        self._get_notify("determined_main")(*args)

    def idasgn_loaded(self, *args):
        self._get_notify("load_idasgn")(*args)

    def kernel_config_loaded(self, *args):
        self._get_notify("kernel_config_loaded")(*args)

    def compiler_changed(self, *args):
        self._get_notify("set_compiler")(*args)

    def segm_moved(self, from_ea, to_ea, size, changed_netmap):
        s = ida_segment.getseg(to_ea)
        sname = ida_segment.get_visible_segm_name(s)
        sclass = ida_segment.get_segm_class(s)
        self._get_notify("move_segm")(from_ea, to_ea, sname, sclass, changed_netmap)

    def func_added(self, pfn):
        self._get_notify("add_func")(pfn.start_ea)

    def set_func_start(self, *args):
        self._get_notify("set_func_start")(*args)

    def set_func_end(self, *args):
        self._get_notify("set_func_end")(*args)

    def deleting_func(self, pfn):
        self._get_notify("del_func")(pfn.start_ea)

    def sgr_changed(self, *args):
        self._get_notify("setsgr")(*args)

    def make_code(self, *args):
        self._get_notify("make_code")(*args)

    def make_data(self, *args):
        self._get_notify("make_data")(*args)

    def renamed(self, *args):
        self._get_notify("renamed")(*args)


# ----------------------------------------------------------------------
class __ph(object):
    id = property(lambda self: ph_get_id())
    cnbits = property(lambda self: ph_get_cnbits())
    dnbits = property(lambda self: ph_get_dnbits())
    flag = property(lambda self: ph_get_flag())
    icode_return = property(lambda self: ph_get_icode_return())
    instruc = property(lambda self: ph_get_instruc())
    instruc_end = property(lambda self: ph_get_instruc_end())
    instruc_start = property(lambda self: ph_get_instruc_start())
    reg_code_sreg = property(lambda self: ph_get_reg_code_sreg())
    reg_data_sreg = property(lambda self: ph_get_reg_data_sreg())
    reg_first_sreg = property(lambda self: ph_get_reg_first_sreg())
    reg_last_sreg = property(lambda self: ph_get_reg_last_sreg())
    regnames = property(lambda self: ph_get_regnames())
    segreg_size = property(lambda self: ph_get_segreg_size())
    tbyte_size = property(lambda self: ph_get_tbyte_size())
    version = property(lambda self: ph_get_version())

ph = __ph()

class _idp_cvar_t:
    ash = property(lambda self: get_ash())
cvar = _idp_cvar_t()

#</pycode(py_idp)>
