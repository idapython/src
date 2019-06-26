
//<inline(py_idp_idbhooks)>

//---------------------------------------------------------------------------
// IDB hooks
//---------------------------------------------------------------------------
ssize_t idaapi IDB_Callback(void *ud, int notification_code, va_list va);
struct IDB_Hooks : public hooks_base_t
{
  // hookgenIDB:methodsinfo_decl

  IDB_Hooks(uint32 _flags=0)
    : hooks_base_t("ida_idp.IDB_Hooks", IDB_Callback, HT_IDB, _flags) {}

  bool hook() { return hooks_base_t::hook(); }
  bool unhook() { return hooks_base_t::unhook(); }
#ifdef TESTABLE_BUILD
  qstring dump_state() { return hooks_base_t::dump_state(mappings, mappings_size); }
#endif

  // hookgenIDB:methods

  ssize_t dispatch(int code, va_list va)
  {
    switch ( code )
    {
      // hookgenIDB:notifications
    }
    return 0;
  }
};

//-------------------------------------------------------------------------
PyObject *get_idb_notifier_addr(PyObject *)
{
  return _wrap_addr_in_pycobject((void *) IDB_Callback);
}

//-------------------------------------------------------------------------
PyObject *get_idb_notifier_ud_addr(IDB_Hooks *hooks)
{
  return _wrap_addr_in_pycobject(hooks);
}
//</inline(py_idp_idbhooks)>


//<code(py_idp_idbhooks)>

// hookgenIDB:methodsinfo_def

//---------------------------------------------------------------------------
ssize_t idaapi IDB_Callback(void *ud, int code, va_list va)
{
  // hookgenIDB:safecall=IDB_Hooks
}

//</code(py_idp_idbhooks)>
