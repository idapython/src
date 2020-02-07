
//<code(py_hexrays_hooks)>
//---------------------------------------------------------------------------
ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t event, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  class Hexrays_Hooks *proxy = (class Hexrays_Hooks *)ud;
  ssize_t ret = 0;
  try
  {
    switch ( event )
    {
      // hookgenHEXRAYS:notifications
case hxe_flowchart:
{
  qflow_chart_t * fc = va_arg(va, qflow_chart_t *);
  ret = proxy->flowchart(fc);
}
break;

case hxe_stkpnts:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  stkpnts_t * stkpnts = va_arg(va, stkpnts_t *);
  ret = proxy->stkpnts(mba, stkpnts);
}
break;

case hxe_prolog:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  qflow_chart_t * fc = va_arg(va, qflow_chart_t *);
  bitset_t * reachable_blocks = va_arg(va, bitset_t *);
  ret = proxy->prolog(mba, fc, reachable_blocks);
}
break;

case hxe_microcode:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->microcode(mba);
}
break;

case hxe_preoptimized:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->preoptimized(mba);
}
break;

case hxe_locopt:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->locopt(mba);
}
break;

case hxe_prealloc:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->prealloc(mba);
}
break;

case hxe_glbopt:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->glbopt(mba);
}
break;

case hxe_structural:
{
  control_graph_t * ct = va_arg(va, control_graph_t *);
  ret = proxy->structural(ct);
}
break;

case hxe_maturity:
{
  cfunc_t * cfunc = va_arg(va, cfunc_t *);
  ctree_maturity_t new_maturity = ctree_maturity_t(va_arg(va, int));
  ret = proxy->maturity(cfunc, new_maturity);
}
break;

case hxe_interr:
{
  int  errcode = va_arg(va, int );
  ret = proxy->interr(errcode);
}
break;

case hxe_combine:
{
  mblock_t * blk = va_arg(va, mblock_t *);
  minsn_t * insn = va_arg(va, minsn_t *);
  ret = proxy->combine(blk, insn);
}
break;

case hxe_print_func:
{
  cfunc_t * cfunc = va_arg(va, cfunc_t *);
  vc_printer_t * vp = va_arg(va, vc_printer_t *);
  ret = proxy->print_func(cfunc, vp);
}
break;

case hxe_func_printed:
{
  cfunc_t * cfunc = va_arg(va, cfunc_t *);
  ret = proxy->func_printed(cfunc);
}
break;

case hxe_resolve_stkaddrs:
{
  mbl_array_t * mba = va_arg(va, mbl_array_t *);
  ret = proxy->resolve_stkaddrs(mba);
}
break;

case hxe_open_pseudocode:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->open_pseudocode(vu);
}
break;

case hxe_switch_pseudocode:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->switch_pseudocode(vu);
}
break;

case hxe_refresh_pseudocode:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->refresh_pseudocode(vu);
}
break;

case hxe_close_pseudocode:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->close_pseudocode(vu);
}
break;

case hxe_keyboard:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  int key_code = va_arg(va, int);
  int shift_state = va_arg(va, int);
  ret = proxy->keyboard(vu, key_code, shift_state);
}
break;

case hxe_right_click:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->right_click(vu);
}
break;

case hxe_double_click:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  int shift_state = va_arg(va, int);
  ret = proxy->double_click(vu, shift_state);
}
break;

case hxe_curpos:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->curpos(vu);
}
break;

case hxe_create_hint:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  qstring * result_hint = va_arg(va, qstring *);
  int * implines = va_arg(va, int *);
  PyObject * _tmp = proxy->create_hint(vu);
  ret = Hexrays_Hooks::handle_create_hint_output(_tmp, vu, result_hint, implines);
}
break;

case hxe_text_ready:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->text_ready(vu);
}
break;

case hxe_populating_popup:
{
  TWidget * widget = va_arg(va, TWidget *);
  TPopupMenu * popup_handle = va_arg(va, TPopupMenu *);
  vdui_t * vu = va_arg(va, vdui_t *);
  ret = proxy->populating_popup(widget, popup_handle, vu);
}
break;

case lxe_lvar_name_changed:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  lvar_t * v = va_arg(va, lvar_t *);
  const char * name = va_arg(va, const char *);
  bool is_user_name = bool(va_arg(va, int));
  ret = proxy->lvar_name_changed(vu, v, name, is_user_name);
}
break;

case lxe_lvar_type_changed:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  lvar_t * v = va_arg(va, lvar_t *);
  const tinfo_t * tinfo = va_arg(va, const tinfo_t *);
  ret = proxy->lvar_type_changed(vu, v, tinfo);
}
break;

case lxe_lvar_cmt_changed:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  lvar_t * v = va_arg(va, lvar_t *);
  const char * cmt = va_arg(va, const char *);
  ret = proxy->lvar_cmt_changed(vu, v, cmt);
}
break;

case lxe_lvar_mapping_changed:
{
  vdui_t * vu = va_arg(va, vdui_t *);
  lvar_t * from = va_arg(va, lvar_t *);
  lvar_t * to = va_arg(va, lvar_t *);
  ret = proxy->lvar_mapping_changed(vu, from, to);
}
break;

case hxe_cmt_changed:
{
  cfunc_t * cfunc = va_arg(va, cfunc_t *);
  const treeloc_t * loc = va_arg(va, const treeloc_t *);
  const char * cmt = va_arg(va, const char *);
  ret = proxy->cmt_changed(cfunc, loc, cmt);
}
break;

    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in Hexrays Hook function: %s\n", e.getMessage());
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return ret;
}

//-------------------------------------------------------------------------
static qvector<Hexrays_Hooks*> hexrays_hooks_instances;

//-------------------------------------------------------------------------
static void hexrays_unloading__unhook_hooks(void)
{
  for ( size_t i = 0, n = hexrays_hooks_instances.size(); i < n; ++i )
    hexrays_hooks_instances[i]->unhook();
}

//-------------------------------------------------------------------------
Hexrays_Hooks::Hexrays_Hooks()
  : hooked(false)
{
  hexrays_hooks_instances.push_back(this);
}

//-------------------------------------------------------------------------
Hexrays_Hooks::~Hexrays_Hooks()
{
  hexrays_hooks_instances.del(this);
  unhook();
}
//</code(py_hexrays_hooks)>

//<inline(py_hexrays_hooks)>
//-------------------------------------------------------------------------
// Hexrays hooks
//---------------------------------------------------------------------------
ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t event, va_list va);
class control_graph_t;

class Hexrays_Hooks
{
  friend ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t event, va_list va);
  static ssize_t handle_create_hint_output(PyObject *o, vdui_t *, qstring *out_hint, int *out_implines)
  {
    ssize_t rc = 0;
    if ( o != NULL && PySequence_Check(o) && PySequence_Size(o) == 3 )
    {
      newref_t py_rc(PySequence_GetItem(o, 0));
      newref_t py_hint(PySequence_GetItem(o, 1));
      newref_t py_implines(PySequence_GetItem(o, 2));
      if ( IDAPyInt_Check(py_rc.o) && IDAPyStr_Check(py_hint.o) && IDAPyInt_Check(py_implines.o) )
      {
        char *buf;
        Py_ssize_t bufsize;
        if ( IDAPyBytes_AsMemAndSize(py_hint.o, &buf, &bufsize) > -1 )
        {
          rc = IDAPyInt_AsLong(py_rc.o);
          qstring tmp(buf, bufsize);
          out_hint->swap(tmp);
          *out_implines = IDAPyInt_AsLong(py_implines.o);
        }
      }
    }
    return rc;
  }

  bool hooked;

public:
  Hexrays_Hooks();
  virtual ~Hexrays_Hooks();

  bool hook()
  {
    if ( !hooked )
      hooked = install_hexrays_callback(Hexrays_Callback, this);
    return hooked;
  }
  bool unhook()
  {
    if ( hooked )
      hooked = !remove_hexrays_callback(Hexrays_Callback, this);
    return !hooked;
  }

  // hookgenHEXRAYS:methods
virtual int flowchart(qflow_chart_t * fc) {qnotused(fc); return 0;}
virtual int stkpnts(mbl_array_t * mba, stkpnts_t * stkpnts) {qnotused(mba); qnotused(stkpnts); return 0;}
virtual int prolog(mbl_array_t * mba, qflow_chart_t * fc, bitset_t * reachable_blocks) {qnotused(mba); qnotused(fc); qnotused(reachable_blocks); return 0;}
virtual int microcode(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int preoptimized(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int locopt(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int prealloc(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int glbopt(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int structural(control_graph_t * ct) {qnotused(ct); return 0;}
virtual int maturity(cfunc_t * cfunc, ctree_maturity_t new_maturity) {qnotused(cfunc); qnotused(new_maturity); return 0;}
virtual int interr(int  errcode) {qnotused(errcode); return 0;}
virtual int combine(mblock_t * blk, minsn_t * insn) {qnotused(blk); qnotused(insn); return 0;}
virtual int print_func(cfunc_t * cfunc, vc_printer_t * vp) {qnotused(cfunc); qnotused(vp); return 0;}
virtual int func_printed(cfunc_t * cfunc) {qnotused(cfunc); return 0;}
virtual int resolve_stkaddrs(mbl_array_t * mba) {qnotused(mba); return 0;}
virtual int open_pseudocode(vdui_t * vu) {qnotused(vu); return 0;}
virtual int switch_pseudocode(vdui_t * vu) {qnotused(vu); return 0;}
virtual int refresh_pseudocode(vdui_t * vu) {qnotused(vu); return 0;}
virtual int close_pseudocode(vdui_t * vu) {qnotused(vu); return 0;}
virtual int keyboard(vdui_t * vu, int key_code, int shift_state) {qnotused(vu); qnotused(key_code); qnotused(shift_state); return 0;}
virtual int right_click(vdui_t * vu) {qnotused(vu); return 0;}
virtual int double_click(vdui_t * vu, int shift_state) {qnotused(vu); qnotused(shift_state); return 0;}
virtual int curpos(vdui_t * vu) {qnotused(vu); return 0;}
virtual PyObject * create_hint(vdui_t * vu) {qnotused(vu); Py_RETURN_NONE;}
virtual int text_ready(vdui_t * vu) {qnotused(vu); return 0;}
virtual int populating_popup(TWidget * widget, TPopupMenu * popup_handle, vdui_t * vu) {qnotused(widget); qnotused(popup_handle); qnotused(vu); return 0;}
virtual int lvar_name_changed(vdui_t * vu, lvar_t * v, const char * name, bool is_user_name) {qnotused(vu); qnotused(v); qnotused(name); qnotused(is_user_name); return 0;}
virtual int lvar_type_changed(vdui_t * vu, lvar_t * v, const tinfo_t * tinfo) {qnotused(vu); qnotused(v); qnotused(tinfo); return 0;}
virtual int lvar_cmt_changed(vdui_t * vu, lvar_t * v, const char * cmt) {qnotused(vu); qnotused(v); qnotused(cmt); return 0;}
virtual int lvar_mapping_changed(vdui_t * vu, lvar_t * from, lvar_t * to) {qnotused(vu); qnotused(from); qnotused(to); return 0;}
virtual int cmt_changed(cfunc_t * cfunc, const treeloc_t * loc, const char * cmt) {qnotused(cfunc); qnotused(loc); qnotused(cmt); return 0;}
};
//</inline(py_hexrays_hooks)>
