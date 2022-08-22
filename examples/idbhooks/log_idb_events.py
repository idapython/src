"""
summary: logging IDB events

description:
  these hooks will be notified about IDB events, and
  dump their information to the "Output" window
"""

import inspect

import ida_idp

class idb_logger_hooks_t(ida_idp.IDB_Hooks):

    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        self.inhibit_log = 0;

    def _format_value(self, v):
        return str(v)

    def _log(self, msg=None):
        if self.inhibit_log <= 0:
            if msg:
                print(">>> idb_logger_hooks_t: %s" % msg)
            else:
                stack = inspect.stack()
                frame, _, _, _, _, _ = stack[1]
                args, _, _, values = inspect.getargvalues(frame)
                method_name = inspect.getframeinfo(frame)[2]
                argstrs = []
                for arg in args[1:]:
                    argstrs.append("%s=%s" % (arg, self._format_value(values[arg])))
                print(">>> idb_logger_hooks_t.%s: %s" % (method_name, ", ".join(argstrs)))
        return 0

    def adding_segm(self, segment):
        return self._log()

    def allsegs_moved(self, info):
        return self._log()

    def auto_empty(self):
        return self._log()

    def auto_empty_finally(self):
        return self._log()

    def bookmark_changed(self, index, pos, desc, op):
        return self._log()

    def byte_patched(self, ea, old_value):
        return self._log()

    def callee_addr_changed(self, ea, callee):
        return self._log()

    def changing_cmt(self, ea, is_repeatable, new_comment):
        return self._log()

    def changing_enum_bf(self, tid, new_bf):
        return self._log()

    def changing_enum_cmt(self, tid, is_repeatable, new_comment):
        return self._log()

    def changing_op_ti(self, ea, n, new_type, new_fnames):
        return self._log()

    def changing_op_type(self, ea, n, opinfo):
        return self._log()

    def changing_range_cmt(self, kind, _range, comment, is_repeatable):
        return self._log()

    def changing_segm_class(self, segment):
        return self._log()

    def changing_segm_end(self, segment, new_end, flags):
        return self._log()

    def changing_segm_name(self, segment, old_name):
        return self._log()

    def changing_segm_start(self, segment, new_start, flags):
        return self._log()

    def changing_struc_align(self, sptr):
        return self._log()

    def changing_struc_cmt(self, tid, is_repeatable, comment):
        return self._log()

    def changing_struc_member(self, sptr, mptr, flags, ti, nbytes):
        return self._log()

    def changing_ti(self, ea, new_type, new_fnames):
        return self._log()

    def closebase(self):
        return self._log()

    def cmt_changed(self, ea, is_repeatable):
        return self._log()

    def compiler_changed(self, may_adjust_inf_fields):
        return self._log()

    def deleting_enum(self, tid):
        return self._log()

    def deleting_enum_member(self, tid, cid):
        return self._log()

    def deleting_func(self, pfn):
        return self._log()

    def deleting_func_tail(self, pfn, tail):
        return self._log()

    def deleting_segm(self, start_ea):
        return self._log()

    def deleting_struc(self, sptr):
        return self._log()

    def deleting_struc_member(self, sptr, mptr):
        return self._log()

    def deleting_tryblks(self, _range):
        return self._log()

    def destroyed_items(self, ea1, ea2, will_disable_range):
        return self._log()

    def determined_main(self, main):
        return self._log()

    def dirtree_link(self, dt, path, is_link):
        return self._log()

    def dirtree_mkdir(self, dt, path):
        return self._log()

    def dirtree_move(self, dt, _from, to):
        return self._log()

    def dirtree_rank(self, dt, path, rank):
        return self._log()

    def dirtree_rmdir(self, dt, path):
        return self._log()

    def dirtree_rminode(self, dt, inode):
        return self._log()

    def dirtree_segm_moved(self, dt):
        return self._log()

    def enum_bf_changed(self, tid):
        return self._log()

    def enum_cmt_changed(self, tid, is_repeatable):
        return self._log()

    def enum_created(self, tid):
        return self._log()

    def enum_deleted(self, tid):
        return self._log()

    def enum_member_created(self, tid, cid):
        return self._log()

    def enum_member_deleted(self, tid, cid):
        return self._log()

    def enum_renamed(self, tid):
        return self._log()

    def expanding_struc(self, sptr, offset, delta):
        return self._log()

    def extlang_changed(self, kind, el, idx):
        return self._log()

    def extra_cmt_changed(self, ea, line_idx, comment):
        return self._log()

    def flow_chart_created(self, fc):
        return self._log()

    def frame_deleted(self, pfn):
        return self._log()

    def func_added(self, pfn):
        return self._log()

    def func_deleted(self, func_ea):
        return self._log()

    def func_noret_changed(self, pfn):
        return self._log()

    def func_tail_appended(self, pfn, tail):
        return self._log()

    def func_tail_deleted(self, pfn, tail_ea):
        return self._log()

    def func_updated(self, pfn):
        return self._log()

    def idasgn_loaded(self, sig_name):
        return self._log()

    def item_color_changed(self, ea, color):
        return self._log()

    def kernel_config_loaded(self, pass_number):
        return self._log()

    def loader_finished(self, li, neflags, filetypename):
        return self._log()

    def local_types_changed(self):
        return self._log()

    def make_code(self, insn):
        return self._log()

    def make_data(self, ea, flags, tid, _len):
        return self._log()

    def op_ti_changed(self, ea, n, _type, fnames):
        return self._log()

    def op_type_changed(self, ea, n):
        return self._log()

    def range_cmt_changed(self, kind, _range, comment, is_repeatable):
        return self._log()

    def renamed(self, ea, new_name, is_local_name, old_name):
        return self._log()

    def renaming_enum(self, tid, is_enum, new_name):
        return self._log()

    def renaming_struc(self, tid, old_name, new_name):
        return self._log()

    def renaming_struc_member(self, sptr, mptr, new_name):
        return self._log()

    def savebase(self):
        return self._log()

    def segm_added(self, segment):
        return self._log()

    def segm_attrs_updated(self, segment):
        return self._log()

    def segm_class_changed(self, segment, sclass):
        return self._log()

    def segm_deleted(self, start_ea, end_ea, flags):
        return self._log()

    def segm_end_changed(self, segment, old_end):
        return self._log()

    def segm_moved(self, _from, to, size, changed_netmap):
        return self._log()

    def segm_name_changed(self, segment, name):
        return self._log()

    def segm_start_changed(self, segment, old_start):
        return self._log()

    def set_func_end(self, pfn, new_end):
        return self._log()

    def set_func_start(self, pfn, new_start):
        return self._log()

    def sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag):
        return self._log()

    def sgr_deleted(self, start_ea, end_ea, regnum):
        return self._log()

    def stkpnts_changed(self, pfn):
        return self._log()

    def struc_align_changed(self, sptr):
        return self._log()

    def struc_cmt_changed(self, tid, is_repeatable):
        return self._log()

    def struc_created(self, tid):
        return self._log()

    def struc_deleted(self, tid):
        return self._log()

    def struc_expanded(self, sptr):
        return self._log()

    def struc_member_changed(self, sptr, mptr):
        return self._log()

    def struc_member_created(self, sptr, mptr):
        return self._log()

    def struc_member_deleted(self, sptr, mid, offset):
        return self._log()

    def struc_member_renamed(self, sptr, mptr):
        return self._log()

    def struc_renamed(self, sptr, success):
        return self._log()

    def tail_owner_changed(self, tail, owner_func, old_owner):
        return self._log()

    def thunk_func_created(self, pfn):
        return self._log()

    def ti_changed(self, ea, _type, fnames):
        return self._log()

    def tryblks_updated(self, tbv):
        return self._log()

    def updating_tryblks(self, tbv):
        return self._log()

    def upgraded(self, _from):
        return self._log()

    def enum_width_changed(self, tid, width):
        return self._log()

    def enum_flag_changed(self, tid, flags):
        return self._log()

    def enum_ordinal_changed(self, tid, ordinal):
        return self._log()


idb_hooks = idb_logger_hooks_t()
idb_hooks.hook()
