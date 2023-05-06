//-------------------------------------------------------------------------
//<code(py_hexrays)>
static bool do_not_check_ctree = false;
static bool idapython_exiting = false;
#ifdef WITH_HEXRAYS
#define DCLVL_SIMPLE 1
#define DCLVL_FULL 2
static int _debug_hexrays_ctree = -1;
static int is_debug_hexrays_ctree(int level)
{
  if ( _debug_hexrays_ctree < 0 )
  {
    qstring tmp;
    if ( qgetenv("IDAPYTHON_DEBUG_HEXRAYS_CTREE", &tmp) )
      _debug_hexrays_ctree = atol(tmp.c_str());
  }
  return _debug_hexrays_ctree >= level;
}

//-------------------------------------------------------------------------
static void debug_hexrays_ctree(int level, const char *format, ...)
{
  if ( is_debug_hexrays_ctree(level) && format != nullptr )
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
//        + set 'do_not_check_ctree = true'
//   - we receive 'ui_database_closed', and
//        + use 'idapython_dummy_hexdsp'
//        + set 'do_not_check_ctree = false'
//   - IDAPython is unloaded, and during cleanup of the runtime data,
//     reachable citem_t's will get destroyed.
// => this means we vill receive 'hx_c*t_cleanup' and 'hx_remitem'
//    notifications most likely in the idapython_dummy_hexdsp()
static void *idaapi idapython_dummy_hexdsp(int code, ...)
{
  if ( do_not_check_ctree )
    return nullptr;
  switch ( code )
  {
    case hx_remitem:
    case hx_cexpr_t_cleanup:
    case hx_cinsn_t_cleanup:
    case hx_mop_t_erase:
    case hx_mba_t_term:
    case hx_valrng_t_clear:
    case hx_udc_filter_t_cleanup:
      {
#ifdef TESTABLE_BUILD
        va_list va;
        va_start(va, code);
        void *item = va_arg(va, void *);
        // catch leaks
        if ( code == hx_remitem )
          QASSERT(30529, ((cinsn_t *)item)->op == cot_empty || ((cinsn_t *)item)->op == cit_empty);
        else if ( code == hx_cexpr_t_cleanup )
          QASSERT(30497, ((cexpr_t *)item)->op == cot_empty && ((cexpr_t *)item)->n == nullptr);
        else if ( code == hx_cinsn_t_cleanup )
          QASSERT(30498, ((cinsn_t *)item)->op == cit_empty && ((cinsn_t *)item)->cblock == nullptr);
        else if ( code == hx_mop_t_erase )
          QASSERT(30595, ((mop_t *)item)->t == mop_z && ((mop_t *)item)->nnn == nullptr);
        else if ( code == hx_mba_t_term )
          QASSERT(30596, ((mba_t *)item)->blocks == nullptr);
        else if ( code == hx_valrng_t_clear )
          QASSERT(30601, ((valrng_t *)item)->empty());
        else if ( code == hx_udc_filter_t_cleanup )
          QASSERT(30633, ((udc_filter_t *)item)->empty()
                  && !install_microcode_filter((udc_filter_t *)item, false));
        else
          INTERR(30597);
        va_end(va);
#endif
      }
      break;
    case hx_remove_optinsn_handler:
      {
#ifdef TESTABLE_BUILD
        static bool in_removal = false;
        if ( !in_removal )
        {
          in_removal = true;
          va_list va;
          va_start(va, code);
          optinsn_t *oi = va_arg(va, optinsn_t *);
          QASSERT(30598, !remove_optinsn_handler(oi)); // must have been removed already
          in_removal = false;
        }
#endif
      }
      break;
    case hx_remove_optblock_handler:
      {
#ifdef TESTABLE_BUILD
        static bool in_removal = false;
        if ( !in_removal )
        {
          in_removal = true;
          va_list va;
          va_start(va, code);
          optblock_t *ob = va_arg(va, optblock_t *);
          QASSERT(30599, !remove_optblock_handler(ob)); // must have been removed already
          in_removal = false;
        }
#endif
      }
      break;
    case hx_install_microcode_filter:
      {
        va_list va;
        va_start(va, code);
        microcode_filter_t *mf = va_arg(va, microcode_filter_t *);
        bool install = va_argi(va, bool);
        if ( install )
          goto BAD_CODE;
#ifdef TESTABLE_BUILD
        static bool in_removal = false;
        if ( !in_removal )
        {
          in_removal = true;
          QASSERT(30620, !install_microcode_filter(mf, false)); // must have been removed already
          in_removal = false;
        }
#else
        qnotused(mf);
#endif
      }
      break;
    case hx_hexrays_free:
#ifdef TESTABLE_BUILD
      if ( !idapython_exiting )
        goto BAD_CODE;
#endif
      break;
    default:
BAD_CODE:
#ifdef _DEBUG
      if ( under_debugger )
        BPT;
#endif
      warning("Hex-Rays Decompiler got called from Python without being loaded");
      break;
  }
  return nullptr;
}

hexdsp_t *get_idapython_hexdsp()
{
  auto hrdsp = get_hexdsp();
  return hrdsp == nullptr ? idapython_dummy_hexdsp : hrdsp;
}
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
// Otherwise, IDAPython will still delete them, but the plugin's
// dispatcher function will point to idapython_dummy_hexdsp
enum hx_clearable_type_t
{
  hxclr_unknown = 0,
  hxclr_cfuncptr,
  hxclr_cinsn_t,
  hxclr_cexpr_t,
  hxclr_cblock_t,
  hxclr_mba_t,
  hxclr_mop_t,
  hxclr_minsn_t,
  hxclr_optinsn_t,
  hxclr_optblock_t,
  hxclr_valrng_t,
  hxclr_udc_filter_t,
};
struct hx_clearable_t
{
  void *ptr;
  hx_clearable_type_t type;
};
DECLARE_TYPE_AS_MOVABLE(hx_clearable_t);

typedef qvector<hx_clearable_t> hx_clearables_t;
static hx_clearables_t python_clearables;

//-------------------------------------------------------------------------
static void debug_hexrays_dump_clearable_instances(int level=DCLVL_FULL)
{
  if ( is_debug_hexrays_ctree(level) )
  {
    for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
    {
      const hx_clearable_t &hxc = python_clearables[i];
      debug_hexrays_ctree(level, "\t#%3d: %p (%d)\n", int(i), hxc.ptr, int(hxc.type));
    }
  }
}

//-------------------------------------------------------------------------
void hexrays_unloading__clear_python_clearable_references(void)
{
  debug_hexrays_ctree(DCLVL_SIMPLE, "hexrays_unloading__clear_python_clearable_references()\n");
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
  {
    const hx_clearable_t &hxc = python_clearables[i];
    debug_hexrays_ctree(DCLVL_SIMPLE, "cleaning up %p (%d)\n", hxc.ptr, int(hxc.type));
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
      case hxclr_mba_t:
        ((mba_t *) hxc.ptr)->term();
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
      case hxclr_udc_filter_t:
        {
          udc_filter_t *uf = (udc_filter_t *) hxc.ptr;
          install_microcode_filter(uf, false);
          uf->cleanup();
        }
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
  if ( ptr == nullptr )
    return;
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
    if ( python_clearables[i].ptr == ptr )
      return;
  hx_clearable_t &hxc = python_clearables.push_back();
  hxc.ptr = ptr;
  hxc.type = type;
  debug_hexrays_ctree(DCLVL_SIMPLE, "registered %p\n", hxc.ptr);
  debug_hexrays_dump_clearable_instances(DCLVL_FULL);
}

//-------------------------------------------------------------------------
// Note: drop ownership, but don't cleanup! The cleanup will be done by
// the SWiG destructor wrapper if this object's still owned by the Python
// runtime, or it will be done by the C tree itself later.
void hexrays_deregister_python_clearable_instance(void *ptr)
{
  debug_hexrays_ctree(DCLVL_SIMPLE, "maybe de-registering %p\n", ptr);
  for ( size_t i = 0, n = python_clearables.size(); i < n; ++i )
  {
    const hx_clearable_t &hxc = python_clearables[i];
    if ( hxc.ptr == ptr )
    {
      debug_hexrays_ctree(DCLVL_SIMPLE, "de-registered %p\n", hxc.ptr);
      python_clearables.erase(python_clearables.begin() + i);
      break;
    }
  }
  debug_hexrays_dump_clearable_instances(DCLVL_FULL);
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
static bool is_hexrays_plugin(const plugin_t *entry)
{
  return entry != nullptr && streq(entry->wanted_name, MODULE_NAME);
}

//-------------------------------------------------------------------------
static void try_init()
{
  init_hexrays_plugin(0);
  if ( get_hexdsp() != nullptr )
    msg("IDAPython Hex-Rays bindings initialized.\n");
}

//-------------------------------------------------------------------------
inline bool hexdsp_inited()
{
  return get_hexdsp() != nullptr;
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
        if ( pi != nullptr && is_hexrays_plugin(pi->entry) )
          try_init();
      }
      break;

    case ui_destroying_plugmod:
      if ( get_hexdsp() != nullptr )
      {
        /*const plugmod_t *plugmod =*/ va_arg(va, plugmod_t *);
        const plugin_t *entry = va_arg(va, plugin_t *);
        if ( is_hexrays_plugin(entry) )
        {
          QASSERT(30500, !do_not_check_ctree);

          // Make sure all the refcounted objects are cleared right away.
          hexrays_unloading__clear_python_clearable_references();

          // Make sure all hooks are unhooked
          hexrays_unloading__unhook_hooks();

          do_not_check_ctree = true;
        }
      }
      break;
    case ui_database_closed:
      do_not_check_ctree = false;
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
static void ida_hexrays_init(void) {}

//-------------------------------------------------------------------------
static void ida_hexrays_term(void)
{
  idapython_exiting = true;
  idapython_unhook_from_notification_point(
          HT_UI, ida_hexrays_ui_notification, nullptr);
}

//-------------------------------------------------------------------------
static void ida_hexrays_closebase(void) {}

//-------------------------------------------------------------------------
static void install_udc_filter(udc_filter_t *instance)
{
  install_microcode_filter(instance, true);
}

//-------------------------------------------------------------------------
static bool remove_udc_filter(udc_filter_t *instance)
{
  return install_microcode_filter(instance, false);
}
//</code(py_hexrays)>


//<inline(py_hexrays)>
//-------------------------------------------------------------------------
void py_debug_hexrays_ctree(int level, const char *msg)
{
  debug_hexrays_ctree(level, msg);
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
  return hexdsp_inited() ? get_widget_vdui(f) : nullptr;
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
idapython_hook_to_notification_point(HT_UI, ida_hexrays_ui_notification, nullptr, /*is_hooks_base=*/ false);
//</init(py_hexrays)>
