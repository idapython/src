
//<inline(py_idp_idbhooks)>

//---------------------------------------------------------------------------
// IDB hooks
//---------------------------------------------------------------------------
ssize_t idaapi IDB_Callback(void *ud, int notification_code, va_list va);
class IDB_Hooks
{
public:
  virtual ~IDB_Hooks() { unhook(); }

  bool hook()
  {
    return idapython_hook_to_notification_point(HT_IDB, IDB_Callback, this);
  }
  bool unhook()
  {
    return idapython_unhook_from_notification_point(HT_IDB, IDB_Callback, this);
  }

  // hookgenIDB:methods
virtual int closebase() {return 0;}
virtual int savebase() {return 0;}
virtual int upgraded(int from) {qnotused(from); return 0;}
virtual int auto_empty() {return 0;}
virtual int auto_empty_finally() {return 0;}
virtual int determined_main(ea_t main) {qnotused(main); return 0;}
virtual int local_types_changed() {return 0;}
virtual int extlang_changed(int kind, extlang_t * el, int idx) {qnotused(kind); qnotused(el); qnotused(idx); return 0;}
virtual int idasgn_loaded(const char * short_sig_name) {qnotused(short_sig_name); return 0;}
virtual int kernel_config_loaded() {return 0;}
virtual int loader_finished(linput_t * li, uint16 neflags, const char * filetypename) {qnotused(li); qnotused(neflags); qnotused(filetypename); return 0;}
virtual int flow_chart_created(qflow_chart_t * fc) {qnotused(fc); return 0;}
virtual int compiler_changed() {return 0;}
virtual int changing_ti(ea_t ea, const type_t * new_type, const p_list * new_fnames) {qnotused(ea); qnotused(new_type); qnotused(new_fnames); return 0;}
virtual int ti_changed(ea_t ea, const type_t * type, const p_list * fnames) {qnotused(ea); qnotused(type); qnotused(fnames); return 0;}
virtual int changing_op_ti(ea_t ea, int n, const type_t * new_type, const p_list * new_fnames) {qnotused(ea); qnotused(n); qnotused(new_type); qnotused(new_fnames); return 0;}
virtual int op_ti_changed(ea_t ea, int n, const type_t * type, const p_list * fnames) {qnotused(ea); qnotused(n); qnotused(type); qnotused(fnames); return 0;}
virtual int changing_op_type(ea_t ea, int n, const opinfo_t * opinfo) {qnotused(ea); qnotused(n); qnotused(opinfo); return 0;}
virtual int op_type_changed(ea_t ea, int n) {qnotused(ea); qnotused(n); return 0;}
virtual int enum_created(enum_t id) {qnotused(id); return 0;}
virtual int deleting_enum(enum_t id) {qnotused(id); return 0;}
virtual int enum_deleted(enum_t id) {qnotused(id); return 0;}
virtual int renaming_enum(tid_t id, bool is_enum, const char * newname) {qnotused(id); qnotused(is_enum); qnotused(newname); return 0;}
virtual int enum_renamed(tid_t id) {qnotused(id); return 0;}
virtual int changing_enum_bf(enum_t id, bool new_bf) {qnotused(id); qnotused(new_bf); return 0;}
virtual int enum_bf_changed(enum_t id) {qnotused(id); return 0;}
virtual int changing_enum_cmt(tid_t id, bool repeatable, const char * newcmt) {qnotused(id); qnotused(repeatable); qnotused(newcmt); return 0;}
virtual int enum_cmt_changed(tid_t id, bool repeatable) {qnotused(id); qnotused(repeatable); return 0;}
virtual int enum_member_created(enum_t id, const_t cid) {qnotused(id); qnotused(cid); return 0;}
virtual int deleting_enum_member(enum_t id, const_t cid) {qnotused(id); qnotused(cid); return 0;}
virtual int enum_member_deleted(enum_t id, const_t cid) {qnotused(id); qnotused(cid); return 0;}
virtual int struc_created(tid_t struc_id) {qnotused(struc_id); return 0;}
virtual int deleting_struc(struc_t * sptr) {qnotused(sptr); return 0;}
virtual int struc_deleted(tid_t struc_id) {qnotused(struc_id); return 0;}
virtual int changing_struc_align(struc_t * sptr) {qnotused(sptr); return 0;}
virtual int struc_align_changed(struc_t * sptr) {qnotused(sptr); return 0;}
virtual int renaming_struc(tid_t id, const char * oldname, const char * newname) {qnotused(id); qnotused(oldname); qnotused(newname); return 0;}
virtual int struc_renamed(struc_t * sptr) {qnotused(sptr); return 0;}
virtual int expanding_struc(struc_t * sptr, ea_t offset, adiff_t delta) {qnotused(sptr); qnotused(offset); qnotused(delta); return 0;}
virtual int struc_expanded(struc_t * sptr) {qnotused(sptr); return 0;}
virtual int struc_member_created(struc_t * sptr, member_t * mptr) {qnotused(sptr); qnotused(mptr); return 0;}
virtual int deleting_struc_member(struc_t * sptr, member_t * mptr) {qnotused(sptr); qnotused(mptr); return 0;}
virtual int struc_member_deleted(struc_t * sptr, tid_t member_id, ea_t offset) {qnotused(sptr); qnotused(member_id); qnotused(offset); return 0;}
virtual int renaming_struc_member(struc_t * sptr, member_t * mptr, const char * newname) {qnotused(sptr); qnotused(mptr); qnotused(newname); return 0;}
virtual int struc_member_renamed(struc_t * sptr, member_t * mptr) {qnotused(sptr); qnotused(mptr); return 0;}
virtual int changing_struc_member(struc_t * sptr, member_t * mptr, flags_t flag, const opinfo_t * ti, asize_t nbytes) {qnotused(sptr); qnotused(mptr); qnotused(flag); qnotused(ti); qnotused(nbytes); return 0;}
virtual int struc_member_changed(struc_t * sptr, member_t * mptr) {qnotused(sptr); qnotused(mptr); return 0;}
virtual int changing_struc_cmt(tid_t struc_id, bool repeatable, const char * newcmt) {qnotused(struc_id); qnotused(repeatable); qnotused(newcmt); return 0;}
virtual int struc_cmt_changed(tid_t struc_id, bool repeatable_cmt) {qnotused(struc_id); qnotused(repeatable_cmt); return 0;}
virtual int segm_added(segment_t * s) {qnotused(s); return 0;}
virtual int deleting_segm(ea_t start_ea) {qnotused(start_ea); return 0;}
virtual int segm_deleted(ea_t start_ea, ea_t end_ea) {qnotused(start_ea); qnotused(end_ea); return 0;}
virtual int changing_segm_start(segment_t * s, ea_t new_start, int segmod_flags) {qnotused(s); qnotused(new_start); qnotused(segmod_flags); return 0;}
virtual int segm_start_changed(segment_t * s, ea_t oldstart) {qnotused(s); qnotused(oldstart); return 0;}
virtual int changing_segm_end(segment_t * s, ea_t new_end, int segmod_flags) {qnotused(s); qnotused(new_end); qnotused(segmod_flags); return 0;}
virtual int segm_end_changed(segment_t * s, ea_t oldend) {qnotused(s); qnotused(oldend); return 0;}
virtual int changing_segm_name(segment_t * s, const char * oldname) {qnotused(s); qnotused(oldname); return 0;}
virtual int segm_name_changed(segment_t * s, const char * name) {qnotused(s); qnotused(name); return 0;}
virtual int changing_segm_class(segment_t * s) {qnotused(s); return 0;}
virtual int segm_class_changed(segment_t * s, const char * sclass) {qnotused(s); qnotused(sclass); return 0;}
virtual int segm_attrs_updated(segment_t * s) {qnotused(s); return 0;}
virtual int segm_moved(ea_t from, ea_t to, asize_t size, bool changed_netmap) {qnotused(from); qnotused(to); qnotused(size); qnotused(changed_netmap); return 0;}
virtual int allsegs_moved(segm_move_infos_t * info) {qnotused(info); return 0;}
virtual int func_added(func_t * pfn) {qnotused(pfn); return 0;}
virtual int func_updated(func_t * pfn) {qnotused(pfn); return 0;}
virtual int set_func_start(func_t * pfn, ea_t new_start) {qnotused(pfn); qnotused(new_start); return 0;}
virtual int set_func_end(func_t * pfn, ea_t new_end) {qnotused(pfn); qnotused(new_end); return 0;}
virtual int deleting_func(func_t * pfn) {qnotused(pfn); return 0;}
virtual int frame_deleted(func_t * pfn) {qnotused(pfn); return 0;}
virtual int thunk_func_created(func_t * pfn) {qnotused(pfn); return 0;}
virtual int func_tail_appended(func_t * pfn, func_t * tail) {qnotused(pfn); qnotused(tail); return 0;}
virtual int deleting_func_tail(func_t * pfn, const range_t * tail) {qnotused(pfn); qnotused(tail); return 0;}
virtual int func_tail_deleted(func_t * pfn, ea_t tail_ea) {qnotused(pfn); qnotused(tail_ea); return 0;}
virtual int tail_owner_changed(func_t * tail, ea_t owner_func, ea_t old_owner) {qnotused(tail); qnotused(owner_func); qnotused(old_owner); return 0;}
virtual int func_noret_changed(func_t * pfn) {qnotused(pfn); return 0;}
virtual int stkpnts_changed(func_t * pfn) {qnotused(pfn); return 0;}
virtual int updating_tryblks(const tryblks_t * tbv) {qnotused(tbv); return 0;}
virtual int tryblks_updated(const tryblks_t * tbv) {qnotused(tbv); return 0;}
virtual int deleting_tryblks(const range_t * range) {qnotused(range); return 0;}
virtual int sgr_changed(ea_t start_ea, ea_t end_ea, int regnum, sel_t value, sel_t old_value, uchar tag) {qnotused(start_ea); qnotused(end_ea); qnotused(regnum); qnotused(value); qnotused(old_value); qnotused(tag); return 0;}
virtual int make_code(const insn_t* insn) {qnotused(insn); return 0;}
virtual int make_data(ea_t ea, flags_t flags, tid_t tid, asize_t len) {qnotused(ea); qnotused(flags); qnotused(tid); qnotused(len); return 0;}
virtual int destroyed_items(ea_t ea1, ea_t ea2, bool will_disable_range) {qnotused(ea1); qnotused(ea2); qnotused(will_disable_range); return 0;}
virtual int renamed(ea_t ea, const char * new_name, bool local_name) {qnotused(ea); qnotused(new_name); qnotused(local_name); return 0;}
virtual int byte_patched(ea_t ea, uint32 old_value) {qnotused(ea); qnotused(old_value); return 0;}
virtual int changing_cmt(ea_t ea, bool repeatable_cmt, const char * newcmt) {qnotused(ea); qnotused(repeatable_cmt); qnotused(newcmt); return 0;}
virtual int cmt_changed(ea_t ea, bool repeatable_cmt) {qnotused(ea); qnotused(repeatable_cmt); return 0;}
virtual int changing_range_cmt(range_kind_t kind, const range_t * a, const char * cmt, bool repeatable) {qnotused(kind); qnotused(a); qnotused(cmt); qnotused(repeatable); return 0;}
virtual int range_cmt_changed(range_kind_t kind, const range_t * a, const char * cmt, bool repeatable) {qnotused(kind); qnotused(a); qnotused(cmt); qnotused(repeatable); return 0;}
virtual int extra_cmt_changed(ea_t ea, int line_idx, const char * cmt) {qnotused(ea); qnotused(line_idx); qnotused(cmt); return 0;}
virtual int item_color_changed(ea_t ea, bgcolor_t color) {qnotused(ea); qnotused(color); return 0;}
virtual int callee_addr_changed(ea_t ea, ea_t callee) {qnotused(ea); qnotused(callee); return 0;}
virtual int bookmark_changed(uint32 index, const lochist_entry_t * pos, const char * desc) {qnotused(index); qnotused(pos); qnotused(desc); return 0;}
virtual int sgr_deleted(ea_t start_ea, ea_t end_ea, int regnum) {qnotused(start_ea); qnotused(end_ea); qnotused(regnum); return 0;}
};
//</inline(py_idp_idbhooks)>


//<code(py_idp_idbhooks)>
//---------------------------------------------------------------------------
ssize_t idaapi IDB_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  class IDB_Hooks *proxy = (class IDB_Hooks *)ud;
  ssize_t ret = 0;
  try
  {
    switch ( notification_code )
    {
      // hookgenIDB:notifications
case idb_event::closebase:
{
  ret = proxy->closebase();
}
break;

case idb_event::savebase:
{
  ret = proxy->savebase();
}
break;

case idb_event::upgraded:
{
  int from = va_arg(va, int);
  ret = proxy->upgraded(from);
}
break;

case idb_event::auto_empty:
{
  ret = proxy->auto_empty();
}
break;

case idb_event::auto_empty_finally:
{
  ret = proxy->auto_empty_finally();
}
break;

case idb_event::determined_main:
{
  ea_t main = va_arg(va, ea_t);
  ret = proxy->determined_main(main);
}
break;

case idb_event::local_types_changed:
{
  ret = proxy->local_types_changed();
}
break;

case idb_event::extlang_changed:
{
  int kind = va_arg(va, int);
  extlang_t * el = va_arg(va, extlang_t *);
  int idx = va_arg(va, int);
  ret = proxy->extlang_changed(kind, el, idx);
}
break;

case idb_event::idasgn_loaded:
{
  const char * short_sig_name = va_arg(va, const char *);
  ret = proxy->idasgn_loaded(short_sig_name);
}
break;

case idb_event::kernel_config_loaded:
{
  ret = proxy->kernel_config_loaded();
}
break;

case idb_event::loader_finished:
{
  linput_t * li = va_arg(va, linput_t *);
  uint16 neflags = uint16(va_arg(va, int));
  const char * filetypename = va_arg(va, const char *);
  ret = proxy->loader_finished(li, neflags, filetypename);
}
break;

case idb_event::flow_chart_created:
{
  qflow_chart_t * fc = va_arg(va, qflow_chart_t *);
  ret = proxy->flow_chart_created(fc);
}
break;

case idb_event::compiler_changed:
{
  ret = proxy->compiler_changed();
}
break;

case idb_event::changing_ti:
{
  ea_t ea = va_arg(va, ea_t);
  const type_t * new_type = va_arg(va, const type_t *);
  const p_list * new_fnames = va_arg(va, const p_list *);
  ret = proxy->changing_ti(ea, new_type, new_fnames);
}
break;

case idb_event::ti_changed:
{
  ea_t ea = va_arg(va, ea_t);
  const type_t * type = va_arg(va, const type_t *);
  const p_list * fnames = va_arg(va, const p_list *);
  ret = proxy->ti_changed(ea, type, fnames);
}
break;

case idb_event::changing_op_ti:
{
  ea_t ea = va_arg(va, ea_t);
  int n = va_arg(va, int);
  const type_t * new_type = va_arg(va, const type_t *);
  const p_list * new_fnames = va_arg(va, const p_list *);
  ret = proxy->changing_op_ti(ea, n, new_type, new_fnames);
}
break;

case idb_event::op_ti_changed:
{
  ea_t ea = va_arg(va, ea_t);
  int n = va_arg(va, int);
  const type_t * type = va_arg(va, const type_t *);
  const p_list * fnames = va_arg(va, const p_list *);
  ret = proxy->op_ti_changed(ea, n, type, fnames);
}
break;

case idb_event::changing_op_type:
{
  ea_t ea = va_arg(va, ea_t);
  int n = va_arg(va, int);
  const opinfo_t * opinfo = va_arg(va, const opinfo_t *);
  ret = proxy->changing_op_type(ea, n, opinfo);
}
break;

case idb_event::op_type_changed:
{
  ea_t ea = va_arg(va, ea_t);
  int n = va_arg(va, int);
  ret = proxy->op_type_changed(ea, n);
}
break;

case idb_event::enum_created:
{
  enum_t id = va_arg(va, enum_t);
  ret = proxy->enum_created(id);
}
break;

case idb_event::deleting_enum:
{
  enum_t id = va_arg(va, enum_t);
  ret = proxy->deleting_enum(id);
}
break;

case idb_event::enum_deleted:
{
  enum_t id = va_arg(va, enum_t);
  ret = proxy->enum_deleted(id);
}
break;

case idb_event::renaming_enum:
{
  tid_t id = va_arg(va, tid_t);
  bool is_enum = bool(va_arg(va, int));
  const char * newname = va_arg(va, const char *);
  ret = proxy->renaming_enum(id, is_enum, newname);
}
break;

case idb_event::enum_renamed:
{
  tid_t id = va_arg(va, tid_t);
  ret = proxy->enum_renamed(id);
}
break;

case idb_event::changing_enum_bf:
{
  enum_t id = va_arg(va, enum_t);
  bool new_bf = bool(va_arg(va, int));
  ret = proxy->changing_enum_bf(id, new_bf);
}
break;

case idb_event::enum_bf_changed:
{
  enum_t id = va_arg(va, enum_t);
  ret = proxy->enum_bf_changed(id);
}
break;

case idb_event::changing_enum_cmt:
{
  tid_t id = va_arg(va, tid_t);
  bool repeatable = bool(va_arg(va, int));
  const char * newcmt = va_arg(va, const char *);
  ret = proxy->changing_enum_cmt(id, repeatable, newcmt);
}
break;

case idb_event::enum_cmt_changed:
{
  tid_t id = va_arg(va, tid_t);
  bool repeatable = bool(va_arg(va, int));
  ret = proxy->enum_cmt_changed(id, repeatable);
}
break;

case idb_event::enum_member_created:
{
  enum_t id = va_arg(va, enum_t);
  const_t cid = va_arg(va, const_t);
  ret = proxy->enum_member_created(id, cid);
}
break;

case idb_event::deleting_enum_member:
{
  enum_t id = va_arg(va, enum_t);
  const_t cid = va_arg(va, const_t);
  ret = proxy->deleting_enum_member(id, cid);
}
break;

case idb_event::enum_member_deleted:
{
  enum_t id = va_arg(va, enum_t);
  const_t cid = va_arg(va, const_t);
  ret = proxy->enum_member_deleted(id, cid);
}
break;

case idb_event::struc_created:
{
  tid_t struc_id = va_arg(va, tid_t);
  ret = proxy->struc_created(struc_id);
}
break;

case idb_event::deleting_struc:
{
  struc_t * sptr = va_arg(va, struc_t *);
  ret = proxy->deleting_struc(sptr);
}
break;

case idb_event::struc_deleted:
{
  tid_t struc_id = va_arg(va, tid_t);
  ret = proxy->struc_deleted(struc_id);
}
break;

case idb_event::changing_struc_align:
{
  struc_t * sptr = va_arg(va, struc_t *);
  ret = proxy->changing_struc_align(sptr);
}
break;

case idb_event::struc_align_changed:
{
  struc_t * sptr = va_arg(va, struc_t *);
  ret = proxy->struc_align_changed(sptr);
}
break;

case idb_event::renaming_struc:
{
  tid_t id = va_arg(va, tid_t);
  const char * oldname = va_arg(va, const char *);
  const char * newname = va_arg(va, const char *);
  ret = proxy->renaming_struc(id, oldname, newname);
}
break;

case idb_event::struc_renamed:
{
  struc_t * sptr = va_arg(va, struc_t *);
  ret = proxy->struc_renamed(sptr);
}
break;

case idb_event::expanding_struc:
{
  struc_t * sptr = va_arg(va, struc_t *);
  ea_t offset = va_arg(va, ea_t);
  adiff_t delta = va_arg(va, adiff_t);
  ret = proxy->expanding_struc(sptr, offset, delta);
}
break;

case idb_event::struc_expanded:
{
  struc_t * sptr = va_arg(va, struc_t *);
  ret = proxy->struc_expanded(sptr);
}
break;

case idb_event::struc_member_created:
{
  struc_t * sptr = va_arg(va, struc_t *);
  member_t * mptr = va_arg(va, member_t *);
  ret = proxy->struc_member_created(sptr, mptr);
}
break;

case idb_event::deleting_struc_member:
{
  struc_t * sptr = va_arg(va, struc_t *);
  member_t * mptr = va_arg(va, member_t *);
  ret = proxy->deleting_struc_member(sptr, mptr);
}
break;

case idb_event::struc_member_deleted:
{
  struc_t * sptr = va_arg(va, struc_t *);
  tid_t member_id = va_arg(va, tid_t);
  ea_t offset = va_arg(va, ea_t);
  ret = proxy->struc_member_deleted(sptr, member_id, offset);
}
break;

case idb_event::renaming_struc_member:
{
  struc_t * sptr = va_arg(va, struc_t *);
  member_t * mptr = va_arg(va, member_t *);
  const char * newname = va_arg(va, const char *);
  ret = proxy->renaming_struc_member(sptr, mptr, newname);
}
break;

case idb_event::struc_member_renamed:
{
  struc_t * sptr = va_arg(va, struc_t *);
  member_t * mptr = va_arg(va, member_t *);
  ret = proxy->struc_member_renamed(sptr, mptr);
}
break;

case idb_event::changing_struc_member:
{
  struc_t * sptr = va_arg(va, struc_t *);
  member_t * mptr = va_arg(va, member_t *);
  flags_t flag = va_arg(va, flags_t);
  const opinfo_t * ti = va_arg(va, const opinfo_t *);
  asize_t nbytes = va_arg(va, asize_t);
  ret = proxy->changing_struc_member(sptr, mptr, flag, ti, nbytes);
}
break;

case idb_event::struc_member_changed:
{
  struc_t * sptr = va_arg(va, struc_t *);
  member_t * mptr = va_arg(va, member_t *);
  ret = proxy->struc_member_changed(sptr, mptr);
}
break;

case idb_event::changing_struc_cmt:
{
  tid_t struc_id = va_arg(va, tid_t);
  bool repeatable = bool(va_arg(va, int));
  const char * newcmt = va_arg(va, const char *);
  ret = proxy->changing_struc_cmt(struc_id, repeatable, newcmt);
}
break;

case idb_event::struc_cmt_changed:
{
  tid_t struc_id = va_arg(va, tid_t);
  bool repeatable_cmt = bool(va_arg(va, int));
  ret = proxy->struc_cmt_changed(struc_id, repeatable_cmt);
}
break;

case idb_event::segm_added:
{
  segment_t * s = va_arg(va, segment_t *);
  ret = proxy->segm_added(s);
}
break;

case idb_event::deleting_segm:
{
  ea_t start_ea = va_arg(va, ea_t);
  ret = proxy->deleting_segm(start_ea);
}
break;

case idb_event::segm_deleted:
{
  ea_t start_ea = va_arg(va, ea_t);
  ea_t end_ea = va_arg(va, ea_t);
  ret = proxy->segm_deleted(start_ea, end_ea);
}
break;

case idb_event::changing_segm_start:
{
  segment_t * s = va_arg(va, segment_t *);
  ea_t new_start = va_arg(va, ea_t);
  int segmod_flags = va_arg(va, int);
  ret = proxy->changing_segm_start(s, new_start, segmod_flags);
}
break;

case idb_event::segm_start_changed:
{
  segment_t * s = va_arg(va, segment_t *);
  ea_t oldstart = va_arg(va, ea_t);
  ret = proxy->segm_start_changed(s, oldstart);
}
break;

case idb_event::changing_segm_end:
{
  segment_t * s = va_arg(va, segment_t *);
  ea_t new_end = va_arg(va, ea_t);
  int segmod_flags = va_arg(va, int);
  ret = proxy->changing_segm_end(s, new_end, segmod_flags);
}
break;

case idb_event::segm_end_changed:
{
  segment_t * s = va_arg(va, segment_t *);
  ea_t oldend = va_arg(va, ea_t);
  ret = proxy->segm_end_changed(s, oldend);
}
break;

case idb_event::changing_segm_name:
{
  segment_t * s = va_arg(va, segment_t *);
  const char * oldname = va_arg(va, const char *);
  ret = proxy->changing_segm_name(s, oldname);
}
break;

case idb_event::segm_name_changed:
{
  segment_t * s = va_arg(va, segment_t *);
  const char * name = va_arg(va, const char *);
  ret = proxy->segm_name_changed(s, name);
}
break;

case idb_event::changing_segm_class:
{
  segment_t * s = va_arg(va, segment_t *);
  ret = proxy->changing_segm_class(s);
}
break;

case idb_event::segm_class_changed:
{
  segment_t * s = va_arg(va, segment_t *);
  const char * sclass = va_arg(va, const char *);
  ret = proxy->segm_class_changed(s, sclass);
}
break;

case idb_event::segm_attrs_updated:
{
  segment_t * s = va_arg(va, segment_t *);
  ret = proxy->segm_attrs_updated(s);
}
break;

case idb_event::segm_moved:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  asize_t size = va_arg(va, asize_t);
  bool changed_netmap = bool(va_arg(va, int));
  ret = proxy->segm_moved(from, to, size, changed_netmap);
}
break;

case idb_event::allsegs_moved:
{
  segm_move_infos_t * info = va_arg(va, segm_move_infos_t *);
  ret = proxy->allsegs_moved(info);
}
break;

case idb_event::func_added:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->func_added(pfn);
}
break;

case idb_event::func_updated:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->func_updated(pfn);
}
break;

case idb_event::set_func_start:
{
  func_t * pfn = va_arg(va, func_t *);
  ea_t new_start = va_arg(va, ea_t);
  ret = proxy->set_func_start(pfn, new_start);
}
break;

case idb_event::set_func_end:
{
  func_t * pfn = va_arg(va, func_t *);
  ea_t new_end = va_arg(va, ea_t);
  ret = proxy->set_func_end(pfn, new_end);
}
break;

case idb_event::deleting_func:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->deleting_func(pfn);
}
break;

case idb_event::frame_deleted:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->frame_deleted(pfn);
}
break;

case idb_event::thunk_func_created:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->thunk_func_created(pfn);
}
break;

case idb_event::func_tail_appended:
{
  func_t * pfn = va_arg(va, func_t *);
  func_t * tail = va_arg(va, func_t *);
  ret = proxy->func_tail_appended(pfn, tail);
}
break;

case idb_event::deleting_func_tail:
{
  func_t * pfn = va_arg(va, func_t *);
  const range_t * tail = va_arg(va, const range_t *);
  ret = proxy->deleting_func_tail(pfn, tail);
}
break;

case idb_event::func_tail_deleted:
{
  func_t * pfn = va_arg(va, func_t *);
  ea_t tail_ea = va_arg(va, ea_t);
  ret = proxy->func_tail_deleted(pfn, tail_ea);
}
break;

case idb_event::tail_owner_changed:
{
  func_t * tail = va_arg(va, func_t *);
  ea_t owner_func = va_arg(va, ea_t);
  ea_t old_owner = va_arg(va, ea_t);
  ret = proxy->tail_owner_changed(tail, owner_func, old_owner);
}
break;

case idb_event::func_noret_changed:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->func_noret_changed(pfn);
}
break;

case idb_event::stkpnts_changed:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->stkpnts_changed(pfn);
}
break;

case idb_event::updating_tryblks:
{
  const tryblks_t * tbv = va_arg(va, const tryblks_t *);
  ret = proxy->updating_tryblks(tbv);
}
break;

case idb_event::tryblks_updated:
{
  const tryblks_t * tbv = va_arg(va, const tryblks_t *);
  ret = proxy->tryblks_updated(tbv);
}
break;

case idb_event::deleting_tryblks:
{
  const range_t * range = va_arg(va, const range_t *);
  ret = proxy->deleting_tryblks(range);
}
break;

case idb_event::sgr_changed:
{
  ea_t start_ea = va_arg(va, ea_t);
  ea_t end_ea = va_arg(va, ea_t);
  int regnum = va_arg(va, int);
  sel_t value = va_arg(va, sel_t);
  sel_t old_value = va_arg(va, sel_t);
  uchar tag = uchar(va_arg(va, int));
  ret = proxy->sgr_changed(start_ea, end_ea, regnum, value, old_value, tag);
}
break;

case idb_event::make_code:
{
  const insn_t* insn = va_arg(va, const insn_t*);
  ret = proxy->make_code(insn);
}
break;

case idb_event::make_data:
{
  ea_t ea = va_arg(va, ea_t);
  flags_t flags = va_arg(va, flags_t);
  tid_t tid = va_arg(va, tid_t);
  asize_t len = va_arg(va, asize_t);
  ret = proxy->make_data(ea, flags, tid, len);
}
break;

case idb_event::destroyed_items:
{
  ea_t ea1 = va_arg(va, ea_t);
  ea_t ea2 = va_arg(va, ea_t);
  bool will_disable_range = bool(va_arg(va, int));
  ret = proxy->destroyed_items(ea1, ea2, will_disable_range);
}
break;

case idb_event::renamed:
{
  ea_t ea = va_arg(va, ea_t);
  const char * new_name = va_arg(va, const char *);
  bool local_name = bool(va_arg(va, int));
  ret = proxy->renamed(ea, new_name, local_name);
}
break;

case idb_event::byte_patched:
{
  ea_t ea = va_arg(va, ea_t);
  uint32 old_value = va_arg(va, uint32);
  ret = proxy->byte_patched(ea, old_value);
}
break;

case idb_event::changing_cmt:
{
  ea_t ea = va_arg(va, ea_t);
  bool repeatable_cmt = bool(va_arg(va, int));
  const char * newcmt = va_arg(va, const char *);
  ret = proxy->changing_cmt(ea, repeatable_cmt, newcmt);
}
break;

case idb_event::cmt_changed:
{
  ea_t ea = va_arg(va, ea_t);
  bool repeatable_cmt = bool(va_arg(va, int));
  ret = proxy->cmt_changed(ea, repeatable_cmt);
}
break;

case idb_event::changing_range_cmt:
{
  range_kind_t kind = range_kind_t(va_arg(va, int));
  const range_t * a = va_arg(va, const range_t *);
  const char * cmt = va_arg(va, const char *);
  bool repeatable = bool(va_arg(va, int));
  ret = proxy->changing_range_cmt(kind, a, cmt, repeatable);
}
break;

case idb_event::range_cmt_changed:
{
  range_kind_t kind = range_kind_t(va_arg(va, int));
  const range_t * a = va_arg(va, const range_t *);
  const char * cmt = va_arg(va, const char *);
  bool repeatable = bool(va_arg(va, int));
  ret = proxy->range_cmt_changed(kind, a, cmt, repeatable);
}
break;

case idb_event::extra_cmt_changed:
{
  ea_t ea = va_arg(va, ea_t);
  int line_idx = va_arg(va, int);
  const char * cmt = va_arg(va, const char *);
  ret = proxy->extra_cmt_changed(ea, line_idx, cmt);
}
break;

case idb_event::item_color_changed:
{
  ea_t ea = va_arg(va, ea_t);
  bgcolor_t color = va_arg(va, bgcolor_t);
  ret = proxy->item_color_changed(ea, color);
}
break;

case idb_event::callee_addr_changed:
{
  ea_t ea = va_arg(va, ea_t);
  ea_t callee = va_arg(va, ea_t);
  ret = proxy->callee_addr_changed(ea, callee);
}
break;

case idb_event::bookmark_changed:
{
  uint32 index = va_arg(va, uint32);
  const lochist_entry_t * pos = va_arg(va, const lochist_entry_t *);
  const char * desc = va_arg(va, const char *);
  ret = proxy->bookmark_changed(index, pos, desc);
}
break;

case idb_event::sgr_deleted:
{
  ea_t start_ea = va_arg(va, ea_t);
  ea_t end_ea = va_arg(va, ea_t);
  int regnum = va_arg(va, int);
  ret = proxy->sgr_deleted(start_ea, end_ea, regnum);
}
break;

    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in IDB Hook function: %s\n", e.getMessage());
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return 0;
}
//</code(py_idp_idbhooks)>
