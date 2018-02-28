//-------------------------------------------------------------------------
//<code(py_hexrays)>
#ifdef WITH_HEXRAYS
static int _debug_hexrays_ctree = -1;
static bool is_debug_hexrays_ctree()
{
  if ( _debug_hexrays_ctree < 0 )
    _debug_hexrays_ctree = qgetenv("IDAPYTHON_DEBUG_HEXRAYS_CTREEE");
  return bool(_debug_hexrays_ctree);
}

//-------------------------------------------------------------------------
static void debug_hexrays_ctree(const char *format, ...)
{
  if ( is_debug_hexrays_ctree() )
  {
    va_list va;
    va_start(va, format);
    msg("HEXRAYS CTREE: ");
    vmsg(format, va);
    va_end(va);
  }
}

//-------------------------------------------------------------------------
// The hexrays+IDAPython term sequence goes as follows:
//   - hexrays is unloaded before IDAPython
//   - we receive the notification about hexrays going away and:
//        + call hexrays_clear_python_clearable_references();
//        + set 'hexdsp = exit_time_dummy_hexdsp' (an NOP hexdsp)
//   - we receive 'ui_term', and
//        + set 'hexdsp = init_time_dummy_hexdsp'
//   - IDAPython is unloaded, and during cleanup of the runtime data,
//     reachable citem_t's will get destroyed.
// => this means we vill receive 'hx_c*t_cleanup' and 'hx_remitem'
//    notifications most likely in the init_time_dummy_hexdsp(),
//    rather than in exit_time_dummy_hexdsp() -- which is more than
//    just a little counter-intuitive.
static void *idaapi init_time_dummy_hexdsp(int code, ...)
{
  switch ( code )
  {
    case hx_remitem:
    case hx_cexpr_t_cleanup:
    case hx_cinsn_t_cleanup:
      {
#ifdef _DEBUG
        va_list va;
        va_start(va, code);
        citem_t *item = va_arg(va, citem_t *);
        // catch leaks
        if ( code == hx_cexpr_t_cleanup )
          QASSERT(30497, ((cexpr_t *)item)->op == cot_empty && ((cexpr_t *)item)->n == NULL);
        else if ( code == hx_cinsn_t_cleanup )
          QASSERT(30498, ((cinsn_t *)item)->op == cit_empty && ((cinsn_t *)item)->cblock == NULL);
        else // code == hx_remitem
          QASSERT(30529, item->op == cot_empty || item->op == cit_empty);
        va_end(va);
#endif
      }
      break;
    default:
      warning("Hex-Rays Decompiler got called from Python without being loaded");
      break;
  }
  return NULL;
}

hexdsp_t *hexdsp = init_time_dummy_hexdsp;
#endif // WITH_HEXRAYS

#define MODULE_NAME   "Hex-Rays Decompiler" // Copied from vd/hexrays.cpp

//-------------------------------------------------------------------------
qstring_printer_t *new_qstring_printer_t(const cfunc_t *f, bool tags)
{
  return new qstring_printer_t(f, * (new qstring()), tags);
}

//-------------------------------------------------------------------------
void delete_qstring_printer_t(qstring_printer_t *qs)
{
  delete &(qs->s);
  delete qs;
}

//---------------------------------------------------------------------
static ref_t hexrays_python_call(ref_t fct, ref_t args)
{
  PYW_GIL_GET;

  newref_t resultobj(PyEval_CallObject(fct.o, args.o));
  if ( PyErr_Occurred() )
  {
    PyErr_Print();
    return borref_t(Py_None);
  }
  return resultobj;
}

//---------------------------------------------------------------------
static int hexrays_python_intcall(ref_t fct, ref_t args)
{
  PYW_GIL_GET;

  ref_t resultobj = hexrays_python_call(fct, args);
  int result;
  if ( SWIG_IsOK(SWIG_AsVal_int(resultobj.o, &result)) )
    return result;
  msg("IDAPython: Hex-rays python callback returned non-integer; value ignored.\n");
  return 0;
}

//---------------------------------------------------------------------
static bool idaapi __python_custom_viewer_popup_item_callback(void *ud)
{
    PYW_GIL_GET;

    int ret;
    borref_t fct((PyObject *)ud);
    newref_t nil(NULL);
    ret = hexrays_python_intcall(fct, nil);
    return ret ? true : false;
}

//---------------------------------------------------------------------
static ssize_t idaapi __hexrays_python_callback(void *ud, hexrays_event_t event, va_list va)
{
  PYW_GIL_GET;

  ssize_t ret;
  borref_t fct((PyObject *)ud);
  switch ( event )
  {
    case hxe_maturity:
      ///< Ctree maturity level is being changed.
      ///< cfunc_t *cfunc
      ///< ctree_maturity_t new_maturity
      {
        cfunc_t *arg0 = va_arg(va, cfunc_t *);
        ctree_maturity_t arg1 = va_argi(va, ctree_maturity_t);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_cfunc_t, 0 ));
        newref_t args(Py_BuildValue("(iOi)", event, arg0obj.o, arg1));
        ret = hexrays_python_intcall(fct, args);
      }
      break;
    case hxe_interr:
      ///< Internal error has occurred.
      ///< int errcode
      {
        int arg0 = va_argi(va, int);
        newref_t args(Py_BuildValue("(ii)", event, arg0));
        ret = hexrays_python_intcall(fct, args);
      }
      break;

    case hxe_print_func:
      ///< Printing ctree and generating text.
      ///< cfunc_t *cfunc
      ///< vc_printer_t *vp
      ///< Returns: 1 if text has been generated by the plugin
      {
        cfunc_t *arg0 = va_arg(va, cfunc_t *);
        vc_printer_t *arg1 = va_arg(va, vc_printer_t *);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_cfunc_t, 0 ));
        newref_t arg1obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg1), SWIGTYPE_p_vc_printer_t, 0 ));
        newref_t args(Py_BuildValue("(iOO)", event, arg0obj.o, arg1obj.o));
        ret = hexrays_python_intcall(fct, args);
      }
      break;

    case hxe_func_printed:
      ///< Function text has been generated. Plugins may
      ///< modify the text in \ref sv.
      ///< cfunc_t *cfunc
      {
        cfunc_t *arg0 = va_arg(va, cfunc_t *);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_cfunc_t, 0 ));
        newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
        ret = hexrays_python_intcall(fct, args);
      }
      break;

      // User interface related events:
    case hxe_open_pseudocode:
      ///< New pseudocode view has been opened.
      ///< vdui_t *vu
      {
        vdui_t *arg0 = va_arg(va, vdui_t *);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
        newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
        ret = hexrays_python_intcall(fct, args);
      }
      break;
    case hxe_switch_pseudocode:
      ///< Existing pseudocode view has been reloaded
      ///< with a new function. Its text has not been
      ///< refreshed yet, only cfunc and mba pointers are ready.
      ///< vdui_t *vu
      {
        vdui_t *arg0 = va_arg(va, vdui_t *);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
        newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
        ret = hexrays_python_intcall(fct, args);
      }
      break;
    case hxe_refresh_pseudocode:
      ///< Existing pseudocode text has been refreshed.
      ///< vdui_t *vu
      ///< See also hxe_text_ready, which happens earlier
      {
        vdui_t *arg0 = va_arg(va, vdui_t *);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
        newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
        ret = hexrays_python_intcall(fct, args);
      }
      break;
    case hxe_close_pseudocode:
      ///< Pseudocode view is being closed.
      ///< vdui_t *vu
      {
        vdui_t *arg0 = va_arg(va, vdui_t *);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
        newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
        ret = hexrays_python_intcall(fct, args);
      }
      break;
    case hxe_keyboard:
      ///< Keyboard has been hit.
      ///< vdui_t *vu
      ///< int key_code (VK_...)
      ///< int shift_state
      ///< Should return: 1 if the event has been handled
      {
        vdui_t *arg0 = va_arg(va, vdui_t *);
        int arg1 = va_argi(va, int);
        int arg2 = va_argi(va, int);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
        newref_t args(Py_BuildValue("(iOii)", event, arg0obj.o, arg1, arg2));
        ret = hexrays_python_intcall(fct, args);
      }
      break;
    case hxe_right_click:
      ///< Mouse right click. We can add menu items now.
      ///< vdui_t *vu
      {
        vdui_t *arg0 = va_arg(va, vdui_t *);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
        newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
        ret = hexrays_python_intcall(fct, args);
      }
      break;
    case hxe_double_click:
      ///< Mouse double click.
      ///< vdui_t *vu
      ///< int shift_state
      ///< Should return: 1 if the event has been handled
      {
        vdui_t *arg0 = va_arg(va, vdui_t *);
        int arg1 = va_argi(va, int);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
        newref_t args(Py_BuildValue("(iOi)", event, arg0obj.o, arg1));
        ret = hexrays_python_intcall(fct, args);
      }
      break;
    case hxe_curpos:
      ///< Current cursor position has been changed.
      ///< (for example, by left-clicking or using keyboard)
      ///< vdui_t *vu
      {
        vdui_t *arg0 = va_arg(va, vdui_t *);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
        newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
        ret = hexrays_python_intcall(fct, args);
      }
      break;
    case hxe_create_hint:
      ///< Create a hint for the current item.
      ///< vdui_t *vu
      ///< qstring *result_hint
      ///< int *implines
      ///< Possible return values:
      ///<  0: the event has not been handled
      ///<  1: hint has been created (should set *implines to nonzero as well)
      ///<  2: hint has been created but the standard hints must be
      ///<     appended by the decompiler
      {
        vdui_t *arg0 = va_arg(va, vdui_t *);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
        newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
        ret = 0;
        ref_t resultobj = hexrays_python_call(fct, args);
        if ( PyTuple_Check(resultobj.o) && PyTuple_Size(resultobj.o) == 3 )
        {
          borref_t i0 = PyTuple_GetItem(resultobj.o, 0);
          borref_t i1 = PyTuple_GetItem(resultobj.o, 1);
          borref_t i2 = PyTuple_GetItem(resultobj.o, 2);
          if ( PyInt_Check(i0.o) && PyString_Check(i1.o) && PyInt_Check(i2.o) )
          {
            qstring *result_hint = va_arg(va, qstring *);
            char *buf;
            Py_ssize_t bufsize;
            if ( PyString_AsStringAndSize(i1.o, &buf, &bufsize) > -1 )
            {
              ret = PyInt_AsLong(i0.o);
              qstring tmp(buf, bufsize);
              result_hint->swap(tmp);
              int *implines = va_arg(va, int *);
              *implines = PyInt_AsLong(i2.o);
            }
          }
       }
      }
      break;
    case hxe_text_ready:
      ///< Decompiled text is ready.
      ///< vdui_t *vu
      ///< This event can be used to modify the output text (sv).
      ///< The text uses regular color codes (see lines.hpp)
      ///< COLOR_ADDR is used to store pointers to ctree elements
      {
        vdui_t *arg0 = va_arg(va, vdui_t *);
        newref_t arg0obj(SWIG_NewPointerObj(SWIG_as_voidptr(arg0), SWIGTYPE_p_vdui_t, 0 ));
        newref_t args(Py_BuildValue("(iO)", event, arg0obj.o));
        ret = hexrays_python_intcall(fct, args);
      }
      break;
    case hxe_populating_popup:
      ///< Populating popup menu. We can add menu items now.
      ///< TWidget *widget
      ///< TPopupMenu *popup_handle
      ///< vdui_t *vu
      {
        TWidget *widget = va_arg(va, TWidget *);
        TPopupMenu *pp = va_arg(va, TPopupMenu*);
        vdui_t *vdui = va_arg(va, vdui_t *);
        newref_t py_widget(SWIG_NewPointerObj(SWIG_as_voidptr(widget), SWIGTYPE_p_TWidget, 0));
        newref_t py_popup(SWIG_NewPointerObj(SWIG_as_voidptr(pp), SWIGTYPE_p_TPopupMenu, 0));
        newref_t py_vdui(SWIG_NewPointerObj(SWIG_as_voidptr(vdui), SWIGTYPE_p_vdui_t, 0 ));
        newref_t py_args(Py_BuildValue("(iOOO)", event, py_widget.o, py_popup.o, py_vdui.o));
        ret = hexrays_python_intcall(fct, py_args);
      }
      break;
    default:
      //~ msg("IDAPython: Unknown event `%u' occurred\n", event);
      ret = 0;
      break;
  }

  return ret;
}

//-------------------------------------------------------------------------
//                        Clearable objects
//-------------------------------------------------------------------------
// A set of objects that were created from IDAPython. This is necessary in
// order to delete those objects before the hexrays plugin is unloaded.
// Otherwise, IDAPython will still delete them, but the plugin's 'hexdsp'
// dispatcher function will point to dlclose()'d code.
enum hx_clearable_type_t
{
  hxclr_unknown = 0,
  hxclr_cfuncptr,
  hxclr_cinsn,
  hxclr_cexpr,
  hxclr_cblock,
};
struct hx_clearable_t
{
  void *ptr;
  hx_clearable_type_t type;
};
DECLARE_TYPE_AS_MOVABLE(hx_clearable_t);

typedef qvector<hx_clearable_t> hx_clearables_t;
static hx_clearables_t python_clearables;
void hexrays_clear_python_clearable_references(void)
{
  debug_hexrays_ctree("hexrays_clear_python_clearable_references()\n");
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
  {
    const hx_clearable_t &hxc = python_clearables[i];
    debug_hexrays_ctree("cleaning up %p (%d)\n", hxc.ptr, int(hxc.type));
    switch ( hxc.type )
    {
      case hxclr_cfuncptr:
        ((cfuncptr_t*) hxc.ptr)->reset();
        break;
      case hxclr_cinsn:
        ((cinsn_t *) hxc.ptr)->cleanup();
        break;
      case hxclr_cexpr:
        ((cexpr_t *) hxc.ptr)->cleanup();
        break;
      case hxclr_cblock:
        ((cblock_t *) hxc.ptr)->clear();
        break;
      default: INTERR(30499);
    }
  }
}

//-------------------------------------------------------------------------
void hexrays_register_python_clearable_instance(
        void *ptr,
        hx_clearable_type_t type)
{
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
    if ( python_clearables[i].ptr == ptr )
      return;
  hx_clearable_t &hxc = python_clearables.push_back();
  hxc.ptr = ptr;
  hxc.type = type;
  debug_hexrays_ctree("registered %p\n", hxc.ptr);
}

//-------------------------------------------------------------------------
// Note: drop ownership, but don't cleanup! The cleanup will be done by
// the SWiG destructor wrapper if this object's still owned by the Python
// runtime, or it will be done by the C tree itself later.
void hexrays_deregister_python_clearable_instance(void *ptr)
{
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
  {
    const hx_clearable_t &hxc = python_clearables[i];
    if ( hxc.ptr == ptr )
    {
      python_clearables.erase(python_clearables.begin() + i);
      debug_hexrays_ctree("de-registered %p\n", hxc.ptr);
      break;
    }
  }
}

//-------------------------------------------------------------------------
#ifdef TESTABLE_BUILD
hx_clearable_type_t hexrays_is_registered_python_clearable_instance(
        const void *ptr)
{
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
    if ( python_clearables[i].ptr == ptr )
      return python_clearables[i].type;
  return hxclr_unknown;
}
#endif

//-------------------------------------------------------------------------
//
//-------------------------------------------------------------------------
cfuncptr_t _decompile(func_t *pfn, hexrays_failure_t *hf)
{
    try
    {
        cfuncptr_t cfunc = decompile(pfn, hf);
        return cfunc;
    }
    catch(...)
    {
        error("Hex-Rays Python: decompiler threw an exception.\n");
    }
    return cfuncptr_t(0);
}

//-------------------------------------------------------------------------
static bool is_hexrays_plugin(const plugin_info_t *pinfo)
{
  bool is_hx = false;
  if ( pinfo != NULL && pinfo->entry != NULL )
  {
    const plugin_t *p = pinfo->entry;
    if ( streq(p->wanted_name, MODULE_NAME) )
      is_hx = true;
  }
  return is_hx;
}

//-------------------------------------------------------------------------
static void try_init()
{
  init_hexrays_plugin(0);
  if ( hexdsp != NULL )
    msg("IDAPython Hex-Rays bindings initialized.\n");
}

//-------------------------------------------------------------------------
static void *idaapi exit_time_dummy_hexdsp(int code, ...)
{
/* This callback exists to avoid crashes if the user calls any hexrays functions
   after unloading the decompiler.
  switch ( code )
  {
    case hx_cexpr_t_cleanup: break;
    case hx_cinsn_t_cleanup: break;
    default: break;
  }*/
  return NULL;
}

//-------------------------------------------------------------------------
inline bool hexdsp_inited()
{
  return hexdsp != NULL
      && hexdsp != init_time_dummy_hexdsp
      && hexdsp != exit_time_dummy_hexdsp;
}

//-------------------------------------------------------------------------
static ssize_t idaapi ida_hexrays_ui_notification(void *, int code, va_list va)
{
  switch ( code )
  {
    case ui_plugin_loaded:
      if ( !hexdsp_inited() )
      {
        const plugin_info_t *pi = va_arg(va, plugin_info_t *);
        if ( is_hexrays_plugin(pi) )
          try_init();
      }
      break;

    case ui_plugin_unloading:
      if ( hexdsp != NULL && hexdsp != init_time_dummy_hexdsp )
      {
        // Make sure all the refcounted objects are cleared right away.
        const plugin_info_t *pi = va_arg(va, plugin_info_t *);
        if ( is_hexrays_plugin(pi) )
        {
          QASSERT(30500, hexdsp != exit_time_dummy_hexdsp);
          hexrays_clear_python_clearable_references();
          hexdsp = exit_time_dummy_hexdsp;
        }
      }
      break;
    case ui_term:
      hexdsp = init_time_dummy_hexdsp;
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
static void ida_hexrays_term(void)
{
  idapython_unhook_from_notification_point(
          HT_UI, ida_hexrays_ui_notification, NULL);
}

//-------------------------------------------------------------------------
static void ida_hexrays_closebase(void) {}
//</code(py_hexrays)>


//<inline(py_hexrays)>
//-------------------------------------------------------------------------
void py_debug_hexrays_ctree(const char *msg)
{
  debug_hexrays_ctree(msg);
}

//---------------------------------------------------------------------
bool py_init_hexrays_plugin(int flags=0)
{
  // Only initialize one time
  return hexdsp_inited() || init_hexrays_plugin(flags);
}

//---------------------------------------------------------------------
bool py_install_hexrays_callback(PyObject *hx_cblist_callback)
{
  PYW_GIL_GET;
  if ( install_hexrays_callback(__hexrays_python_callback, hx_cblist_callback) )
  {
    Py_INCREF(hx_cblist_callback);
    return true;
  }
  return false;
}

//---------------------------------------------------------------------
int py_remove_hexrays_callback(PyObject *hx_cblist_callback)
{
  PYW_GIL_GET;
  int result, i;
  result = remove_hexrays_callback(__hexrays_python_callback, hx_cblist_callback);
  for ( i = 0; i < result; i++ )
    Py_DECREF(hx_cblist_callback);

  return result;
}

cfuncptr_t _decompile(func_t *pfn, hexrays_failure_t *hf);

//-------------------------------------------------------------------------
bool py_decompile_many(const char *outfile, PyObject *funcaddrs, int flags)
{
  eavec_t leas, *eas = NULL;
  if ( funcaddrs != Py_None )
  {
    if ( !PySequence_Check(funcaddrs)
      || PyW_PyListToEaVec(&leas, funcaddrs) < 0 )
    {
      return false;
    }
    eas = &leas;
  }
  return decompile_many(outfile, eas, flags);
}

//-------------------------------------------------------------------------
// Some examples will want to use action_handler_t's whose update() method
// calls get_widget_vdui() to figure out whether the action should be enabled
// for the current widget. Unfortunately, if hexrays is first unloaded before
// the widget cleanup is performed (e.g., while loading another IDB),
// the action would crash. Ideally we should wrap all toplevel calls
// with such wrappers, but it doesn't seem to be really necessary at the
// moment: only corner-cases will reveal this issue (reported by
// the idapython_hr-decompile test.)
vdui_t *py_get_widget_vdui(TWidget *f)
{
  return hexdsp_inited() ? get_widget_vdui(f) : NULL;
}

inline boundaries_iterator_t py_boundaries_find(const boundaries_t *map, const cinsn_t *key)
{
  return boundaries_find(map, key);
}

inline boundaries_iterator_t py_boundaries_insert(boundaries_t *map, const cinsn_t *key, const rangeset_t &val)
{
  return boundaries_insert(map, key, val);
}

//-------------------------------------------------------------------------
void py_term_hexrays_plugin(void) {}
//</inline(py_hexrays)>

//<init(py_hexrays)>
idapython_hook_to_notification_point(HT_UI, ida_hexrays_ui_notification, NULL);
//</init(py_hexrays)>
