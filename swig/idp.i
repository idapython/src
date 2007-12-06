%ignore gen_idb_event;

// Ignore the function pointers
%ignore asm_t::checkarg_dispatch;
%ignore asm_t::func_header;
%ignore asm_t::func_footer;
%ignore asm_t::get_type_name;
%ignore processor_t::notify;
%ignore processor_t::header;
%ignore processor_t::footer;
%ignore processor_t::segstart;
%ignore processor_t::segend;
%ignore processor_t::assumes;
%ignore processor_t::u_ana;
%ignore processor_t::u_emu;
%ignore processor_t::u_out;
%ignore processor_t::u_outop;
%ignore processor_t::d_out;
%ignore processor_t::cmp_opnd;
%ignore processor_t::can_have_type;
%ignore processor_t::getreg;
%ignore processor_t::is_far_jump;
%ignore processor_t::translate;
%ignore processor_t::realcvt;
%ignore processor_t::is_switch;
%ignore processor_t::gen_map_file;
%ignore processor_t::extract_address;
%ignore processor_t::is_sp_based;
%ignore processor_t::create_func_frame;
%ignore processor_t::get_frame_retsize;
%ignore processor_t::gen_stkvar_def;
%ignore processor_t::u_outspec;
%ignore processor_t::is_align_insn;

%include "idp.hpp"

%feature("director") IDB_Hooks;

%inline %{

int idaapi IDB_Callback(void *ud, int notification_code, va_list va);
class IDB_Hooks 
{
public:
	virtual ~IDB_Hooks() {};

	bool hook() { return hook_to_notification_point(HT_IDB, IDB_Callback, this); }
	bool unhook() { return unhook_from_notification_point(HT_IDB, IDB_Callback, this); }
	/* Hook functions to override in Python */
	virtual int byte_patched(ea_t ea) { return 0; };
	virtual int cmt_changed(ea_t, bool repeatable_cmt) { return 0; };
	virtual int ti_changed(ea_t ea, const type_t *type, const p_list *fnames) { msg("ti_changed hook not supported yet\n"); return 0; };
	virtual int op_ti_changed(ea_t ea, int n, const type_t *type, const p_list *fnames) { msg("op_ti_changed hook not supported yet\n"); return 0; };
	virtual int op_type_changed(ea_t ea, int n) { return 0; };
	virtual int enum_created(enum_t id) { return 0; };
	virtual int enum_deleted(enum_t id) { return 0; };
	virtual int enum_bf_changed(enum_t id) { return 0; };
	virtual int enum_renamed(enum_t id) { return 0; };
	virtual int enum_cmt_changed(enum_t id) { return 0; };
	virtual int enum_const_created(enum_t id, const_t cid) { return 0; };
	virtual int enum_const_deleted(enum_t id, const_t cid) { return 0; };
	virtual int struc_created(tid_t struc_id) { return 0; };
	virtual int struc_deleted(tid_t struc_id) { return 0; };
	virtual int struc_renamed(struc_t *sptr) { return 0; };
	virtual int struc_expanded(struc_t *sptr) { return 0; };
	virtual int struc_cmt_changed(tid_t struc_id) { return 0; };
	virtual int struc_member_created(struc_t *sptr, member_t *mptr) { return 0; };
	virtual int struc_member_deleted(struc_t *sptr, tid_t member_id) { return 0; };
	virtual int struc_member_renamed(struc_t *sptr, member_t *mptr) { return 0; };
	virtual int struc_member_changed(struc_t *sptr, member_t *mptr) { return 0; };
	virtual int thunk_func_created(func_t *pfn) { return 0; };
	virtual int func_tail_appended(func_t *pfn, func_t *tail) { return 0; };
	virtual int func_tail_removed(func_t *pfn, ea_t tail_ea) { return 0; };
	virtual int tail_owner_changed(func_t *tail, ea_t owner_func) { return 0; };
	virtual int func_noret_changed(func_t *pfn) { return 0; };
	virtual int segm_added(segment_t *s) { return 0; };
	virtual int segm_deleted(ea_t startEA) { return 0; };
	virtual int segm_start_changed(segment_t *s) { return 0; };
	virtual int segm_end_changed(segment_t *s) { return 0; };
	virtual int segm_moved(ea_t from, ea_t to, asize_t size) { return 0; };
};

int idaapi IDB_Callback(void *ud, int notification_code, va_list va)
{
  class IDB_Hooks *proxy = (class IDB_Hooks *)ud;
  ea_t ea, ea2;
  bool repeatable_cmt;
  type_t *type;
  /*  p_list *fnames; */
  int n;
  enum_t id;
  const_t cid;
  tid_t struc_id;
  struc_t *sptr;
  member_t *mptr;
  tid_t member_id;
  func_t *pfn;
  func_t *tail;
  segment_t *seg;
  asize_t size;

  try {
    switch (notification_code)
      {
      case idb_event::byte_patched:
	ea = va_arg(va, ea_t);
	return proxy->byte_patched(ea);

      case idb_event::cmt_changed:
	ea = va_arg(va, ea_t);
	repeatable_cmt = va_arg(va, int);
	return proxy->cmt_changed(ea, repeatable_cmt);
#if 0
      case idb_event::ti_changed:
	ea = va_arg(va, ea_t);
	type = va_arg(va, type_t *);
	fnames = va_arg(va, fnames);
	return proxy->ti_changed(ea, type, fnames);

      case idb_event::op_ti_changed:
	ea = va_arg(va, ea_t);
	n = va_arg(va, int);
	type = va_arg(va, type_t *);
	fnames = va_arg(va, fnames);
	return proxy->op_ti_changed(ea, n, type, fnames);
#endif
      case idb_event::op_type_changed:
	ea = va_arg(va, ea_t);
	n = va_arg(va, int);
	return proxy->op_type_changed(ea, n);

      case idb_event::enum_created:
	id = va_arg(va, enum_t);
	return proxy->enum_created(id);

      case idb_event::enum_deleted:
	id = va_arg(va, enum_t);
	return proxy->enum_deleted(id);

      case idb_event::enum_bf_changed:
	id = va_arg(va, enum_t);
	return proxy->enum_bf_changed(id);

      case idb_event::enum_cmt_changed:
	id = va_arg(va, enum_t);
	return proxy->enum_cmt_changed(id);

      case idb_event::enum_const_created:
	id = va_arg(va, enum_t);
	cid = va_arg(va, const_t);
	return proxy->enum_const_created(id, cid);

      case idb_event::enum_const_deleted:
	id = va_arg(va, enum_t);
	cid = va_arg(va, const_t);
	return proxy->enum_const_deleted(id, cid);

      case idb_event::struc_created:
	struc_id = va_arg(va, tid_t);
	return proxy->struc_created(struc_id);

      case idb_event::struc_deleted:
	struc_id = va_arg(va, tid_t);
	return proxy->struc_deleted(struc_id);

      case idb_event::struc_renamed:
	sptr = va_arg(va, struc_t *);
	return proxy->struc_renamed(sptr);

      case idb_event::struc_expanded:
	sptr = va_arg(va, struc_t *);
	return proxy->struc_expanded(sptr);

      case idb_event::struc_cmt_changed:
	struc_id = va_arg(va, tid_t);
	return proxy->struc_cmt_changed(struc_id);

      case idb_event::struc_member_created:
	sptr = va_arg(va, struc_t *);
	mptr = va_arg(va, member_t *);
	return proxy->struc_member_created(sptr, mptr);

      case idb_event::struc_member_deleted:
	sptr = va_arg(va, struc_t *);
	member_id = va_arg(va, tid_t);
	return proxy->struc_member_deleted(sptr, member_id);

      case idb_event::struc_member_renamed:
	sptr = va_arg(va, struc_t *);
	mptr = va_arg(va, member_t *);
	return proxy->struc_member_renamed(sptr, mptr);

      case idb_event::struc_member_changed:
	sptr = va_arg(va, struc_t *);
	mptr = va_arg(va, member_t *);
	return proxy->struc_member_changed(sptr, mptr);

      case idb_event::thunk_func_created:
	pfn = va_arg(va, func_t *);
	return proxy->thunk_func_created(pfn);

      case idb_event::func_tail_appended:
	pfn = va_arg(va, func_t *);
	tail = va_arg(va, func_t *);
	return proxy->func_tail_appended(pfn, tail);

      case idb_event::func_tail_removed:
	pfn = va_arg(va, func_t *);
	ea = va_arg(va, ea_t);
	return proxy->func_tail_removed(pfn, ea);

      case idb_event::tail_owner_changed:
	tail = va_arg(va, func_t *);
	ea = va_arg(va, ea_t);
	return proxy->tail_owner_changed(tail, ea);

      case idb_event::func_noret_changed:
	pfn = va_arg(va, func_t *);
	return proxy->func_noret_changed(pfn);

      case idb_event::segm_added:
	seg = va_arg(va, segment_t *);
	return proxy->segm_added(seg);

      case idb_event::segm_deleted:
	ea = va_arg(va, ea_t);
	return proxy->segm_deleted(ea);

      case idb_event::segm_start_changed:
	seg = va_arg(va, segment_t *);
	return proxy->segm_start_changed(seg);

      case idb_event::segm_end_changed:
	seg = va_arg(va, segment_t *);
	return proxy->segm_end_changed(seg);

      case idb_event::segm_moved:
	ea = va_arg(va, ea_t);
	ea2 = va_arg(va, ea_t);
	size = va_arg(va, asize_t);
	return proxy->segm_moved(ea, ea2, size);
      }
  }
  catch (Swig::DirectorException &e) 
    { 
      msg("Exception in IDP Hook function:\n"); 
      if (PyErr_Occurred())
	{
	  PyErr_Print();
	}
    }
}
%}
