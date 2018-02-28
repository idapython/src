%{
#include <kernwin.hpp>
%}

%{
#ifdef __NT__
idaman __declspec(dllimport) plugin_t PLUGIN;
#else
extern plugin_t PLUGIN;
#endif
%}

// Ignore the va_list functions
%ignore vask_form;
%ignore ask_form;
%ignore open_form;
%ignore vopen_form;
%ignore close_form;
%ignore vask_str;
%ignore ask_str;
%ignore ask_ident;
%ignore vask_buttons;
%ignore vask_file;
%ignore vask_yn;
%ignore strvec_t;
%ignore load_custom_icon;
%ignore vask_text;
%ignore ask_text;
%ignore vwarning;

%ignore choose_idasgn;
%rename (choose_idasgn) py_choose_idasgn;

%ignore get_chooser_data;
%rename (get_chooser_data) py_get_chooser_data;

%rename (del_hotkey) py_del_hotkey;
%rename (add_hotkey) py_add_hotkey;

%ignore msg;
%rename (msg) py_msg;

%ignore umsg;
%rename (umsg) py_umsg;

%ignore vinfo;
%ignore UI_Callback;
%ignore vnomem;
%ignore vmsg;
%ignore show_wait_box_v;
%ignore create_custom_viewer;
%ignore take_database_snapshot;
%rename (take_database_snapshot) py_take_database_snapshot;
%ignore restore_database_snapshot;
%rename (restore_database_snapshot) py_restore_database_snapshot;
%ignore destroy_custom_viewer;
%ignore destroy_custom_viewerdestroy_custom_viewer;
%ignore set_custom_viewer_handler;
%ignore set_custom_viewer_range;
%ignore is_idaview;
%ignore refresh_custom_viewer;
%ignore set_custom_viewer_handlers;
%ignore get_viewer_name;
// Ignore these string functions. There are trivial replacements in Python.
%ignore trim;
%ignore skip_spaces;
%ignore stristr;
%ignore set_nav_colorizer;
%rename (set_nav_colorizer) py_set_nav_colorizer;
%rename (call_nav_colorizer) py_call_nav_colorizer;

%ignore get_highlight;
%rename (get_highlight) py_get_highlight;

%ignore action_desc_t::handler;
%ignore action_handler_t;
%ignore register_action;
%rename (register_action) py_register_action;
%ignore attach_dynamic_action_to_popup;
%rename (attach_dynamic_action_to_popup) py_attach_dynamic_action_to_popup;
%ignore get_registered_actions;
%rename (get_registered_actions) py_get_registered_actions;

%include "typemaps.i"

%rename (ask_text) py_ask_text;
%rename (ask_str) py_ask_str;
%rename (str2ea)  py_str2ea;
%ignore process_ui_action;
%rename (process_ui_action) py_process_ui_action;
%ignore execute_sync;
%ignore exec_request_t;
%rename (execute_sync) py_execute_sync;

%ignore ui_request_t;
%ignore execute_ui_requests;
%rename (execute_ui_requests) py_execute_ui_requests;

%ignore timer_t;
%ignore register_timer;
%rename (register_timer) py_register_timer;
%ignore unregister_timer;
%rename (unregister_timer) py_unregister_timer;

%ignore chooser_item_attrs_t::cb;

// Make ask_addr(), ask_seg(), and ask_long() return a
// tuple: (result, value)
%rename (_ask_long) ask_long;
%rename (_ask_addr) ask_addr;
%rename (_ask_seg) ask_seg;

%ignore qvector<disasm_line_t>::operator==;
%ignore qvector<disasm_line_t>::operator!=;
%ignore qvector<disasm_line_t>::find;
%ignore qvector<disasm_line_t>::has;
%ignore qvector<disasm_line_t>::del;
%ignore qvector<disasm_line_t>::add_unique;

%ignore gen_disasm_text;
%rename (gen_disasm_text) py_gen_disasm_text;

%ignore UI_Hooks::handle_hint_output;
%ignore UI_Hooks::handle_get_ea_hint_output;

// We will %ignore those ATM, since they cannot be trivially
// wrapped: bytevec_t is not exposed.
// (besides, serializing/deserializing should probably
// be done by locstack_t instances only.)
%ignore place_t::serialize;
%ignore place_t__serialize;
%ignore place_t::deserialize;
%ignore place_t__deserialize;
%ignore place_t::generate;
%ignore place_t__generate;
%rename (generate) py_generate;

%ignore register_place_class;
%ignore register_loc_converter;
%ignore lookup_loc_converter;

%ignore hexplace_t;
%ignore hexplace_gen_t;

%ignore msg_get_lines;
%rename (msg_get_lines) py_msg_get_lines;

%feature("director") UI_Hooks;

//-------------------------------------------------------------------------
%{
struct py_action_handler_t : public action_handler_t
{
  py_action_handler_t(); // No.
  py_action_handler_t(PyObject *_o)
    : pyah(borref_t(_o)), has_activate(false), has_update(false)
  {
    ref_t act(PyW_TryGetAttrString(pyah.o, "activate"));
    if ( act != NULL && PyCallable_Check(act.o) > 0 )
      has_activate = true;

    ref_t upd(PyW_TryGetAttrString(pyah.o, "update"));
    if ( upd != NULL && PyCallable_Check(upd.o) > 0 )
      has_update = true;
  }
  virtual idaapi ~py_action_handler_t()
  {
    PYW_GIL_GET;
    // NOTE: We need to do the decref _within_ the PYW_GIL_GET scope,
    // and not leave it to the destructor to clean it up, because when
    // ~ref_t() gets called, the GIL will have already been released.
    pyah = ref_t();
  }
  virtual int idaapi activate(action_activation_ctx_t *ctx)
  {
    if ( !has_activate )
      return 0;
    PYW_GIL_GET_AND_REPORT_ERROR;
    newref_t pyctx(SWIG_NewPointerObj(SWIG_as_voidptr(ctx), SWIGTYPE_p_action_activation_ctx_t, 0));
    newref_t pyres(PyObject_CallMethod(pyah.o, (char *)"activate", (char *) "O", pyctx.o));
    return PyErr_Occurred() ? 0 : ((pyres != NULL && PyInt_Check(pyres.o)) ? PyInt_AsLong(pyres.o) : 0);
  }
  virtual action_state_t idaapi update(action_update_ctx_t *ctx)
  {
    if ( !has_update )
      return AST_DISABLE;
    PYW_GIL_GET_AND_REPORT_ERROR;
    newref_t pyctx(SWIG_NewPointerObj(SWIG_as_voidptr(ctx), SWIGTYPE_p_action_update_ctx_t, 0));
    newref_t pyres(PyObject_CallMethod(pyah.o, (char *)"update", (char *) "O", pyctx.o));
    return PyErr_Occurred() ? AST_DISABLE_ALWAYS : ((pyres != NULL && PyInt_Check(pyres.o)) ? action_state_t(PyInt_AsLong(pyres.o)) : AST_DISABLE);
  }

private:
  ref_t pyah;
  bool has_activate;
  bool has_update;
};

%}

%inline %{
void refresh_choosers(void)
{
  Py_BEGIN_ALLOW_THREADS;
  callui(ui_refresh_choosers);
  Py_END_ALLOW_THREADS;
}
%}

# This is for get_cursor()
%apply int *OUTPUT {int *x, int *y};

%ignore textctrl_info_t;
SWIG_DECLARE_PY_CLINKED_OBJECT(textctrl_info_t)

%{
static void _py_unregister_compiled_form(PyObject *py_form, bool shutdown);
%}

%{
//<decls(py_kernwin)>
//</decls(py_kernwin)>
%}

%inline %{
//<inline(py_kernwin)>
//</inline(py_kernwin)>
%}

%{
//<code(py_kernwin)>
//</code(py_kernwin)>
%}

// CLI
%ignore cli_t;
%ignore install_command_interpreter;
%rename (install_command_interpreter) py_install_command_interpreter;
%ignore remove_command_interpreter;
%rename (remove_command_interpreter) py_remove_command_interpreter;

%include "kernwin.hpp"

%template(disasm_text_t) qvector<disasm_line_t>;

%extend action_desc_t {
  action_desc_t(
          const char *name,
          const char *label,
          PyObject *handler,
          const char *shortcut = NULL,
          const char *tooltip = NULL,
          int icon = -1,
          int flags = 0)
  {
    action_desc_t *ad = new action_desc_t();
#define DUPSTR(Prop) ad->Prop = Prop == NULL ? NULL : qstrdup(Prop)
    DUPSTR(name);
    DUPSTR(label);
    DUPSTR(shortcut);
    DUPSTR(tooltip);
#undef DUPSTR
    ad->icon = icon;
    ad->handler = new py_action_handler_t(handler);
    ad->flags = flags | ADF_OWN_HANDLER;
    ad->owner = &PLUGIN;
    return ad;
  }

  ~action_desc_t()
  {
    if ( $self->handler != NULL ) // Ownership not taken?
      delete $self->handler;
#define FREESTR(Prop) qfree((char *) $self->Prop)
    FREESTR(name);
    FREESTR(label);
    FREESTR(shortcut);
    FREESTR(tooltip);
#undef FREESTR
    delete $self;
  }
}

%extend action_ctx_base_t {

  int _get_reg() const { return $self->reg; }

#ifdef BC695
  TWidget *_get_form() const { return $self->widget; }
  twidget_type_t _get_form_type() const { return $self->widget_type; }
  qstring _get_form_title() const { return $self->widget_title; }
#endif

  %pythoncode {
    reg = property(_get_reg)
#ifdef BC695
    form = property(_get_form)
    form_type = property(_get_form_type)
    form_title = property(_get_form_title)
#endif
  }
}

//-------------------------------------------------------------------------
%extend place_t {
  static idaplace_t *as_idaplace_t(place_t *p) { return (idaplace_t *) p; }
  static enumplace_t *as_enumplace_t(place_t *p) { return (enumplace_t *) p; }
  static structplace_t *as_structplace_t(place_t *p) { return (structplace_t *) p; }
  static simpleline_place_t *as_simpleline_place_t(place_t *p) { return (simpleline_place_t *) p; }

  PyObject *py_generate(void *ud, int maxsize)
  {
    qstrvec_t lines;
    int deflnnum = 0;
    color_t pfx_color = 0;
    bgcolor_t bgcolor = DEFCOLOR;
    int generated = $self->generate(&lines, &deflnnum, &pfx_color, &bgcolor, ud, maxsize);
    PyObject *tuple = PyTuple_New(4);
    PyTuple_SetItem(tuple, 0, qstrvec2pylist(lines));
    PyTuple_SetItem(tuple, 1, PyLong_FromLong(deflnnum));
    PyTuple_SetItem(tuple, 2, PyLong_FromLong(uchar(pfx_color)));
    PyTuple_SetItem(tuple, 3, PyLong_FromLong(bgcolor));
    return tuple;
  }
}

%extend twinpos_t {

  %pythoncode {
    def place_as_idaplace_t(self):
        return place_t.as_idaplace_t(self.at)
    def place_as_enumplace_t(self):
        return place_t.as_enumplace_t(self.at)
    def place_as_structplace_t(self):
        return place_t.as_structplace_t(self.at)
    def place_as_simpleline_place_t(self):
        return place_t.as_simpleline_place_t(self.at)

    def place(self, view):
        ptype = get_viewer_place_type(view)
        if ptype == TCCPT_IDAPLACE:
            return self.place_as_idaplace_t()
        elif ptype == TCCPT_ENUMPLACE:
            return self.place_as_enumplace_t()
        elif ptype == TCCPT_STRUCTPLACE:
            return self.place_as_structplace_t()
        elif ptype == TCCPT_SIMPLELINE_PLACE:
            return self.place_as_simpleline_place_t()
        else:
            return self.at
  }
}

%pythoncode %{
#<pycode(py_kernwin)>
#</pycode(py_kernwin)>
%}

//-------------------------------------------------------------------------
//                                Choose
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_choose)>
//</code(py_kernwin_choose)>
%}

%inline %{
//<inline(py_kernwin_choose)>
//</inline(py_kernwin_choose)>
%}

%pythoncode %{
#<pycode(py_kernwin_choose)>
#</pycode(py_kernwin_choose)>
%}

//-------------------------------------------------------------------------
//                               ask_form
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_askform)>
//</code(py_kernwin_askform)>
%}

%inline %{
//<inline(py_kernwin_askform)>
//</inline(py_kernwin_askform)>
%}

%pythoncode %{
#<pycode(py_kernwin_askform)>
#</pycode(py_kernwin_askform)>
%}


//-------------------------------------------------------------------------
//                                    cli_t
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_cli)>
//</code(py_kernwin_cli)>
%}

%inline %{
//<inline(py_kernwin_cli)>
//</inline(py_kernwin_cli)>
%}

%pythoncode %{
#<pycode(py_kernwin_cli)>
#</pycode(py_kernwin_cli)>
%}

//-------------------------------------------------------------------------
%init %{
//<init(py_kernwin_askform)>
//</init(py_kernwin_askform)>
%}

//-------------------------------------------------------------------------
//                              CustomIDAMemo
//-------------------------------------------------------------------------
%ignore View_Callback;

%inline %{
//<inline(py_kernwin_viewhooks)>
//</inline(py_kernwin_viewhooks)>
%}

%{
//<code(py_kernwin_viewhooks)>
//</code(py_kernwin_viewhooks)>
%}

%pythoncode %{
#<pycode(py_kernwin_viewhooks)>
#</pycode(py_kernwin_viewhooks)>
%}


//-------------------------------------------------------------------------
//                               IDAView
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_idaview)>
//</code(py_kernwin_idaview)>

%}

%inline %{
//<inline(py_kernwin_idaview)>
//</inline(py_kernwin_idaview)>
%}

%pythoncode %{
#<pycode(py_kernwin_idaview)>
#</pycode(py_kernwin_idaview)>
%}

//-------------------------------------------------------------------------
//                          simplecustviewer_t
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_custview)>
//</code(py_kernwin_custview)>
%}

%inline %{
//<inline(py_kernwin_custview)>
//</inline(py_kernwin_custview)>
%}

%pythoncode %{
#<pycode(py_kernwin_custview)>
#</pycode(py_kernwin_custview)>
%}

//-------------------------------------------------------------------------
//                              PluginForm
//-------------------------------------------------------------------------
%{
//<code(py_kernwin_plgform)>
//</code(py_kernwin_plgform)>
%}

%inline %{
//<inline(py_kernwin_plgform)>
//</inline(py_kernwin_plgform)>
%}

%pythoncode %{
#<pycode(py_kernwin_plgform)>
#</pycode(py_kernwin_plgform)>
%}
