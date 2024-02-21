
%{
#include <kernwin.hpp>
#include <parsejson.hpp>
%}

%{
struct dirspec_t;
%}

%force_declare_SWiG_type(dirspec_t);
%force_declare_SWiG_type(dirtree_t);

%apply qstring *result { qstring *label };
%apply qstring *result { qstring *shortcut };
%apply qstring *result { qstring *tooltip };

%typemap(out) void *get_window_id
{
  // %typemap(out) void *get_window_id
  $result = PyLong_FromUnsignedLongLong((unsigned long long) $1);
}

%ignore callui_t;
%ignore sync_source_t::sync_source_t();
%ignore l_compare;

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
// Note: don't do that for ask_form(), since that calls back into Python.
%modal_dialog_triggering_function(ask_addr);
%modal_dialog_triggering_function(ask_seg);
%modal_dialog_triggering_function(ask_long);
%modal_dialog_triggering_function(ask_yn);
%modal_dialog_triggering_function(ask_buttons);
%modal_dialog_triggering_function(ask_file);

%ignore simpleline_t::simpleline_t(const qstring &);

%calls_execute_sync(clr_cancelled);
%calls_execute_sync(set_cancelled);
%calls_execute_sync(user_cancelled);
%calls_execute_sync(py_hide_wait_box);

%ignore show_wait_box;
%rename (show_wait_box) py_show_wait_box;
%ignore hide_wait_box;
%rename (hide_wait_box) py_hide_wait_box;

%ignore choose_idasgn;
%rename (choose_idasgn) py_choose_idasgn;

%ignore get_chooser_data;
%rename (get_chooser_data) py_get_chooser_data;

%template(chooser_row_info_vec_t) qvector<chooser_row_info_t>;
%typemap(out) qstrvec_t *
{
  Py_XDECREF($result);
  $result = qstrvec2pylist(*$1);
}

%rename (del_hotkey) py_del_hotkey;
%rename (add_hotkey) py_add_hotkey;

%ignore msg;
%rename (msg) py_msg;

%ignore vinfo;

%define_Hooks_class(UI);

%ignore ida_checkmem;
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

%ignore add_spaces;
%rename (add_spaces) py_add_spaces;

%include "typemaps.i"

%rename (ask_text) py_ask_text;
%rename (ask_str) py_ask_str;
%ignore process_ui_action;
%rename (process_ui_action) py_process_ui_action;
%ignore execute_sync;
%ignore exec_request_t;
%rename (execute_sync) py_execute_sync;

%ignore ea2str(char *, size_t, ea_t);

%ignore ui_request_t;
%ignore execute_ui_requests;
%rename (execute_ui_requests) py_execute_ui_requests;

%ignore timer_t;
%ignore register_timer;
%rename (register_timer) py_register_timer;
%ignore unregister_timer;
%rename (unregister_timer) py_unregister_timer;

%ignore chooser_item_attrs_t::cb;

// chooser_base_t should be read-only
%ignore chooser_base_t::chooser_base_t;
%ignore chooser_base_t::~chooser_base_t;
%ignore chooser_base_t::call_destructor;
%ignore chooser_base_t::check_version;
%ignore chooser_base_t::closed;
%ignore chooser_base_t::get_chooser_obj;
%ignore chooser_base_t::get_obj_id;
%ignore chooser_base_t::init;
%ignore chooser_base_t::set_ask_item_attrs;
%ignore chooser_base_t::ALL_CHANGED;
%ignore chooser_base_t::NOTHING_CHANGED;
%ignore chooser_base_t::SELECTION_CHANGED;
%ignore chooser_base_t::ALREADY_EXISTS;
%ignore chooser_base_t::EMPTY_CHOOSER;
%ignore chooser_base_t::NO_ATTR;
%ignore chooser_base_t::NO_SELECTION;

%feature("nodirector") chooser_base_t;
%ignore chooser_base_t::get_row(qstrvec_t *, int *, chooser_item_attrs_t *, size_t) const;
%extend chooser_base_t {
  PyObject *get_row(size_t n) const
  {
    return py_chooser_base_t_get_row($self, n);
  }
}

// Make ask_addr(), ask_seg(), and ask_long() return a
// tuple: (result, value)
%rename (_ask_long) ask_long;
%rename (_ask_addr) ask_addr;
%rename (_ask_seg) ask_seg;

%ignore gen_disasm_text;
%rename (gen_disasm_text) py_gen_disasm_text;

%ignore jobj_wrapper_t::jobj_wrapper_t;
%ignore jobj_wrapper_t::~jobj_wrapper_t;
%ignore jobj_wrapper_t::fill_jobj_from_dict;

%ignore place_t__serialize;
%ignore place_t::deserialize(const uchar **pptr, const uchar *end);
%ignore place_t__deserialize;
%ignore place_t::generate;
%ignore place_t__generate;
%rename (generate) py_generate;
%newobject place_t::clone;

// For place_t::serialize()
%apply bytevec_t *vout { bytevec_t *out };

%ignore register_place_class;
%ignore register_loc_converter2;
%ignore lookup_loc_converter2;

%ignore hexplace_t;
%ignore hexplace_gen_t;

%ignore msg_get_lines;
%rename (msg_get_lines) py_msg_get_lines;

%extend input_event_t {

  size_t _source_as_size() const { return size_t($self->source); }
  size_t _target_as_size() const { return size_t($self->target); }

  %pythoncode {
     def get_source_QEvent(self):
         ptr = self._source_as_size();
         if ptr:
             from PyQt5 import sip
             if self.kind in [iek_key_press, iek_key_release]:
                 from PyQt5.QtGui import QInputEvent
                 return sip.wrapinstance(ptr, QInputEvent)
             elif self.kind in [
                     iek_mouse_button_press,
                     iek_mouse_button_release]:
                 from PyQt5.QtGui import QMouseEvent
                 return sip.wrapinstance(ptr, QMouseEvent)
             elif self.kind == iek_mouse_wheel:
                 from PyQt5.QtGui import QWheelEvent
                 return sip.wrapinstance(ptr, QWheelEvent)
             else:
                 from PyQt5.QtCore import QEvent
                 return sip.wrapinstance(ptr, QEvent)

     def get_target_QWidget(self):
         ptr = self._target_as_size()
         if ptr:
              from PyQt5 import sip
              from PyQt5.QtWidgets import QWidget, QAbstractScrollArea
              return sip.wrapinstance(ptr, QWidget)
  }
}

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
    if ( act && PyCallable_Check(act.o) > 0 )
      has_activate = true;

    ref_t upd(PyW_TryGetAttrString(pyah.o, "update"));
    if ( upd && PyCallable_Check(upd.o) > 0 )
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
    newref_t pyctx(SWIG_InternalNewPointerObj(SWIG_as_voidptr(ctx), SWIGTYPE_p_action_ctx_base_t, 0));
    newref_t pyres(PyObject_CallMethod(pyah.o, (char *)"activate", (char *) "O", pyctx.o));
    return PyErr_Occurred() != nullptr ? 0 : ((pyres && PyLong_Check(pyres.o)) ? PyLong_AsLong(pyres.o) : 0);
  }
  virtual action_state_t idaapi update(action_update_ctx_t *ctx)
  {
    if ( !has_update )
      return AST_DISABLE;
    PYW_GIL_GET_AND_REPORT_ERROR;
    newref_t pyctx(SWIG_InternalNewPointerObj(SWIG_as_voidptr(ctx), SWIGTYPE_p_action_ctx_base_t, 0));
    newref_t pyres(PyObject_CallMethod(pyah.o, (char *)"update", (char *) "O", pyctx.o));
    return PyErr_Occurred() != nullptr ? AST_DISABLE_ALWAYS : ((pyres && PyLong_Check(pyres.o)) ? action_state_t(PyLong_AsLong(pyres.o)) : AST_DISABLE);
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
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  callui(ui_refresh_choosers);
  SWIG_PYTHON_THREAD_END_ALLOW;
}
%}

// get_cursor()
%apply int *OUTPUT {int *x, int *y};

// get_navband_pixel()
%apply bool *OUTPUT {bool *out_is_vertical};


%ignore textctrl_info_t;
SWIG_DECLARE_PY_CLINKED_OBJECT(textctrl_info_t)

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

%ignore qvector<line_rendering_output_entry_t*>::grow;
%template(line_rendering_output_entries_refs_t) qvector<line_rendering_output_entry_t*>;
%ignore line_rendering_output_entries_refs_t::push_back;

%ignore qvector<const twinline_t*>::grow;
%template(section_lines_refs_t) qvector<const twinline_t*>;
%template(sections_lines_refs_t) qvector<section_lines_refs_t>;

%uncomparable_elements_qvector(twinline_t, text_t);

%ignore qvector<sync_source_t>::grow;
%ignore qvector<sync_source_t>::resize;
%ignore qvector<sync_source_t>::push_back();
%template(sync_source_vec_t) qvector<sync_source_t>;

//<typemaps(kernwin)>
//</typemaps(kernwin)>

%include "kernwin.hpp"

%uncomparable_elements_qvector(disasm_line_t, disasm_text_t);

%extend qvector<line_rendering_output_entry_t*> {
  void _internal_push_back(line_rendering_output_entry_t *e)
  {
    $self->push_back(e);
  }
  %pythoncode {
      def push_back(self, e):
          if e and e.thisown:
              self._internal_push_back(e)
              e.thisown = False
  }
}

%extend place_t {
  virtual bool idaapi deserialize(const bytevec_t &in)
  {
    const uchar *ptr = in.begin();
    return $self->deserialize(&ptr, ptr + in.size());
  }
}

%extend action_desc_t {
  action_desc_t(
          const char *name,
          const char *label,
          PyObject *handler,
          const char *shortcut = nullptr,
          const char *tooltip = nullptr,
          int icon = -1,
          int flags = 0)
  {
    action_desc_t *ad = new action_desc_t();
#define DUPSTR(Prop) ad->Prop = Prop == nullptr ? nullptr : qstrdup(Prop)
    DUPSTR(name);
    DUPSTR(label);
    DUPSTR(shortcut);
    DUPSTR(tooltip);
#undef DUPSTR
    ad->icon = icon;
    ad->handler = new py_action_handler_t(handler);
    ad->flags = flags | ADF_OWN_HANDLER | ADF_GLOBAL | ADF_OT_PLUGIN;
    ad->owner = &PLUGIN;
    return ad;
  }

  ~action_desc_t()
  {
    if ( $self->handler != nullptr ) // Ownership not taken?
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

  %pythoncode {
    cur_extracted_ea = cur_value
#ifdef MISSED_BC695
    form = ida_idaapi._make_missed_695bwcompat_property("form", "widget", has_setter=False)
    form_type = ida_idaapi._make_missed_695bwcompat_property("form_type", "widget_type", has_setter=False)
    form_title = ida_idaapi._make_missed_695bwcompat_property("form_title", "widget_title", has_setter=False)
#endif
  }
}

//-------------------------------------------------------------------------
%newobject place_t::as_idaplace_t;
%newobject place_t::as_enumplace_t;
%newobject place_t::as_structplace_t;
%newobject place_t::as_simpleline_place_t;
%newobject place_t::as_tiplace_t;
%extend place_t {
  static idaplace_t *as_idaplace_t(place_t *p) { return p != nullptr ? (idaplace_t *) p->clone() : nullptr; }
  static enumplace_t *as_enumplace_t(place_t *p) { return p != nullptr ? (enumplace_t *) p->clone() : nullptr; }
  static structplace_t *as_structplace_t(place_t *p) { return p != nullptr ? (structplace_t *) p->clone() : nullptr; }
  static simpleline_place_t *as_simpleline_place_t(place_t *p) { return p != nullptr ? (simpleline_place_t *) p->clone() : nullptr; }
  static tiplace_t *as_tiplace_t(place_t *p) { return p != nullptr ? (tiplace_t *) p->clone() : nullptr; }

  PyObject *py_generate(void *ud, int maxsize)
  {
    qstrvec_t lines;
    int deflnnum = 0;
    color_t pfx_color = 0;
    bgcolor_t bgcolor = DEFCOLOR;
    /*int generated = */ $self->generate(&lines, &deflnnum, &pfx_color, &bgcolor, ud, maxsize);
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
    def place_as_tiplace_t(self):
        return place_t.as_tiplace_t(self.at)

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
        elif ptype == TCCPT_TIPLACE:
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
%define_Hooks_class(View);

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
