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
//        + call hexrays_unloading__clear_python_clearable_references();
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
    case hx_mop_t_erase:
    case hx_mbl_array_t_term:
    case hx_valrng_t_clear:
      {
#ifdef _DEBUG
        va_list va;
        va_start(va, code);
        void *item = va_arg(va, void *);
        // catch leaks
        if ( code == hx_remitem )
          QASSERT(30529, ((cinsn_t *)item)->op == cot_empty || ((cinsn_t *)item)->op == cit_empty);
        else if ( code == hx_cexpr_t_cleanup )
          QASSERT(30497, ((cexpr_t *)item)->op == cot_empty && ((cexpr_t *)item)->n == NULL);
        else if ( code == hx_cinsn_t_cleanup )
          QASSERT(30498, ((cinsn_t *)item)->op == cit_empty && ((cinsn_t *)item)->cblock == NULL);
        else if ( code == hx_mop_t_erase )
          QASSERT(30595, ((mop_t *)item)->t == mop_z && ((mop_t *)item)->nnn == NULL);
        else if ( code == hx_mbl_array_t_term )
          QASSERT(30596, ((mbl_array_t *)item)->blocks == NULL);
        else if ( code == hx_valrng_t_clear )
          QASSERT(30601, ((valrng_t *)item)->empty());
        else
          INTERR(30597);
        va_end(va);
#endif
      }
      break;
    case hx_remove_optinsn_handler:
      {
#ifdef _DEBUG
        static bool in_removal = false;
        if ( !in_removal )
        {
          in_removal = true;
          va_list va;
          va_start(va, code);
          optinsn_t *oi = va_arg(va, optinsn_t *);
          QASSERT(30598, remove_optinsn_handler(oi) == false); // must have been removed already
          in_removal = false;
        }
#endif
      }
      break;
    case hx_remove_optblock_handler:
      {
#ifdef _DEBUG
        static bool in_removal = false;
        if ( !in_removal )
        {
          in_removal = true;
          va_list va;
          va_start(va, code);
          optblock_t *ob = va_arg(va, optblock_t *);
          QASSERT(30599, remove_optblock_handler(ob) == false); // must have been removed already
          in_removal = false;
        }
#endif
      }
      break;
    default:
#ifdef _DEBUG
      if ( under_debugger )
        BPT;
#endif
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
  hxclr_cinsn_t,
  hxclr_cexpr_t,
  hxclr_cblock_t,
  hxclr_mbl_array_t,
  hxclr_mop_t,
  hxclr_minsn_t,
  hxclr_optinsn_t,
  hxclr_optblock_t,
  hxclr_valrng_t,
};
struct hx_clearable_t
{
  void *ptr;
  hx_clearable_type_t type;
};
DECLARE_TYPE_AS_MOVABLE(hx_clearable_t);

typedef qvector<hx_clearable_t> hx_clearables_t;
static hx_clearables_t python_clearables;
void hexrays_unloading__clear_python_clearable_references(void)
{
  debug_hexrays_ctree("hexrays_unloading__clear_python_clearable_references()\n");
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
  {
    const hx_clearable_t &hxc = python_clearables[i];
    debug_hexrays_ctree("cleaning up %p (%d)\n", hxc.ptr, int(hxc.type));
    switch ( hxc.type )
    {
      case hxclr_cfuncptr:
        ((cfuncptr_t*) hxc.ptr)->reset();
        break;
      case hxclr_cinsn_t:
        ((cinsn_t *) hxc.ptr)->cleanup();
        break;
      case hxclr_cexpr_t:
        ((cexpr_t *) hxc.ptr)->cleanup();
        break;
      case hxclr_cblock_t:
        ((cblock_t *) hxc.ptr)->clear();
        break;
      case hxclr_mbl_array_t:
        ((mbl_array_t *) hxc.ptr)->term();
        break;
      case hxclr_mop_t:
        ((mop_t *) hxc.ptr)->erase();
        break;
      case hxclr_minsn_t:
        ((minsn_t *) hxc.ptr)->_make_nop();
        break;
      case hxclr_optinsn_t:
        remove_optinsn_handler((optinsn_t *) hxc.ptr);
        break;
      case hxclr_optblock_t:
        remove_optblock_handler((optblock_t *) hxc.ptr);
        break;
      case hxclr_valrng_t:
        ((valrng_t *) hxc.ptr)->set_none();
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
  if ( ptr == NULL )
    return;
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
hx_clearable_type_t hexrays_is_registered_python_clearable_instance(
        const void *ptr)
{
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
    if ( python_clearables[i].ptr == ptr )
      return python_clearables[i].type;
  return hxclr_unknown;
}

//-------------------------------------------------------------------------
//
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
static void *idaapi exit_time_dummy_hexdsp(int /*code*/, ...)
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
static void hexrays_unloading__unhook_hooks(void);
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
        const plugin_info_t *pi = va_arg(va, plugin_info_t *);
        if ( is_hexrays_plugin(pi) )
        {
          QASSERT(30500, hexdsp != exit_time_dummy_hexdsp);

          // Make sure all the refcounted objects are cleared right away.
          hexrays_unloading__clear_python_clearable_references();

          // Make sure all hooks are unhooked
          hexrays_unloading__unhook_hooks();

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
static void ida_hexrays_init(void) {}

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

//-------------------------------------------------------------------------
inline boundaries_iterator_t py_boundaries_find(
        const boundaries_t *map,
        const cinsn_t *key)
{
  return boundaries_find(map, key);
}

//-------------------------------------------------------------------------
inline boundaries_iterator_t py_boundaries_insert(
        boundaries_t *map,
        const cinsn_t *key,
        const rangeset_t &val)
{
  return boundaries_insert(map, key, val);
}

//-------------------------------------------------------------------------
void py_term_hexrays_plugin(void) {}
//</inline(py_hexrays)>

//<init(py_hexrays)>
idapython_hook_to_notification_point(HT_UI, ida_hexrays_ui_notification, NULL, /*is_hooks_base=*/ false);
//</init(py_hexrays)>
