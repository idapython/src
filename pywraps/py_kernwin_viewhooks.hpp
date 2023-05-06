
//<inline(py_kernwin_viewhooks)>

//---------------------------------------------------------------------------
// View hooks
//---------------------------------------------------------------------------
ssize_t idaapi View_Callback(void *ud, int notification_code, va_list va);
struct View_Hooks : public hooks_base_t
{
  // hookgenVIEW:methodsinfo_decl

  View_Hooks(uint32 _flags=0, uint32 _hkcb_flags=HKCB_GLOBAL)
    : hooks_base_t("ida_kernwin.View_Hooks", View_Callback, HT_VIEW, _flags, _hkcb_flags) {}

  bool hook() { return hooks_base_t::hook(); }
  bool unhook() { return hooks_base_t::unhook(); }
#ifdef TESTABLE_BUILD
  PyObject *dump_state(bool assert_all_reimplemented=false) { return hooks_base_t::dump_state(mappings, mappings_size, assert_all_reimplemented); }
#endif

  // hookgenVIEW:methods

  ssize_t dispatch(int code, va_list va)
  {
    switch ( code )
    {
      // hookgenVIEW:notifications
    }
    return 0;
  }
};

//</inline(py_kernwin_viewhooks)>


//<code(py_kernwin_viewhooks)>

// hookgenVIEW:methodsinfo_def

//---------------------------------------------------------------------------
ssize_t idaapi View_Callback(void *ud, int code, va_list va)
{
  // hookgenVIEW:safecall=View_Hooks
}
//</code(py_kernwin_viewhooks)>
