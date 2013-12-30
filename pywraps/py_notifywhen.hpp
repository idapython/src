#ifndef __PYWRAPS_NOTIFY_WHEN__
#define __PYWRAPS_NOTIFY_WHEN__

//------------------------------------------------------------------------
//<code(py_idaapi)>
//------------------------------------------------------------------------

//------------------------------------------------------------------------
class pywraps_notify_when_t
{
  ref_vec_t table[NW_EVENTSCNT];
  qstring err;
  bool in_notify;
  struct notify_when_args_t
  {
    int when;
    PyObject *py_callable;
  };
  typedef qvector<notify_when_args_t> notify_when_args_vec_t;
  notify_when_args_vec_t delayed_notify_when_list;

  //------------------------------------------------------------------------
  static int idaapi idp_callback(void *ud, int event_id, va_list va)
  {
    // This hook gets called from the kernel. Ensure we hold the GIL.
    PYW_GIL_GET;
    pywraps_notify_when_t *_this = (pywraps_notify_when_t *)ud;
    switch ( event_id )
    {
    case processor_t::newfile:
    case processor_t::oldfile:
      {
        int old = event_id == processor_t::oldfile ? 1 : 0;
        char *dbname = va_arg(va, char *);
        _this->notify(NW_OPENIDB_SLOT, old);
      }
      break;
    case processor_t::closebase:
      _this->notify(NW_CLOSEIDB_SLOT);
      break;
    }
    // event not processed, let other plugins or the processor module handle it
    return 0;
  }

  //------------------------------------------------------------------------
  bool unnotify_when(int when, PyObject *py_callable)
  {
    int cnt = 0;
    for ( int slot=0; slot<NW_EVENTSCNT; slot++ )
    {
      // convert index to flag and see
      if ( ((1 << slot) & when) != 0 )
      {
        unregister_callback(slot, py_callable);
        ++cnt;
      }
    }
    return cnt > 0;
  }

  //------------------------------------------------------------------------
  void register_callback(int slot, PyObject *py_callable)
  {
    borref_t callable_ref(py_callable);
    ref_vec_t &tbl = table[slot];
    ref_vec_t::iterator it_end = tbl.end(), it = std::find(tbl.begin(), it_end, callable_ref);

    // Already added
    if ( it != it_end )
      return;

    // Insert the element
    tbl.push_back(callable_ref);
  }

  //------------------------------------------------------------------------
  void unregister_callback(int slot, PyObject *py_callable)
  {
    borref_t callable_ref(py_callable);
    ref_vec_t &tbl = table[slot];
    ref_vec_t::iterator it_end = tbl.end(), it = std::find(tbl.begin(), it_end, callable_ref);

    // Not found?
    if ( it == it_end )
      return;

    // Delete the element
    tbl.erase(it);
  }

public:
  //------------------------------------------------------------------------
  bool init()
  {
    return hook_to_notification_point(HT_IDP, idp_callback, this);
  }

  //------------------------------------------------------------------------
  bool deinit()
  {
    // Uninstall all objects
    ref_vec_t::iterator it, it_end;
    for ( int slot=0; slot<NW_EVENTSCNT; slot++ )
    {
      for ( it = table[slot].begin(), it_end = table[slot].end(); it!=it_end; ++it )
        unregister_callback(slot, it->o);
    }
    // ...and remove the notification
    return unhook_from_notification_point(HT_IDP, idp_callback, this);
  }

  //------------------------------------------------------------------------
  bool notify_when(int when, PyObject *py_callable)
  {
    // While in notify() do not allow insertion or deletion to happen on the spot
    // Instead we will queue them so that notify() will carry the action when it finishes
    // dispatching the notification handlers
    if ( in_notify )
    {
      notify_when_args_t &args = delayed_notify_when_list.push_back();
      args.when = when;
      args.py_callable = py_callable;
      return true;
    }
    // Uninstalling the notification?
    if ( (when & NW_REMOVE) != 0 )
      return unnotify_when(when & ~NW_REMOVE, py_callable);

    int cnt = 0;
    for ( int slot=0; slot<NW_EVENTSCNT; slot++ )
    {
      // is this flag set?
      if ( ((1 << slot) & when) != 0 )
      {
        register_callback(slot, py_callable);
        ++cnt;
      }
    }
    return cnt > 0;
  }

  //------------------------------------------------------------------------
  bool notify(int slot, ...)
  {
    va_list va;
    va_start(va, slot);
    bool ok = notify_va(slot, va);
    va_end(va);
    return ok;
  }

  //------------------------------------------------------------------------
  bool notify_va(int slot, va_list va)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    // Sanity bounds check!
    if ( slot < 0 || slot >= NW_EVENTSCNT )
      return false;

    bool ok = true;
    in_notify = true;
    int old = slot == NW_OPENIDB_SLOT ? va_arg(va, int) : 0;

    {
      for (ref_vec_t::iterator it = table[slot].begin(), it_end = table[slot].end();
           it != it_end;
           ++it)
      {
        // Form the notification code
        newref_t py_code(PyInt_FromLong(1 << slot));
        ref_t py_result;
        switch ( slot )
        {
          case NW_CLOSEIDB_SLOT:
          case NW_INITIDA_SLOT:
          case NW_TERMIDA_SLOT:
            {
              py_result = newref_t(PyObject_CallFunctionObjArgs(it->o, py_code.o, NULL));
              break;
            }
          case NW_OPENIDB_SLOT:
            {
              newref_t py_old(PyInt_FromLong(old));
              py_result = newref_t(PyObject_CallFunctionObjArgs(it->o, py_code.o, py_old.o, NULL));
            }
            break;
        }
        if ( PyW_GetError(&err) || py_result == NULL )
        {
          PyErr_Clear();
          warning("notify_when(): Error occured while notifying object.\n%s", err.c_str());
          ok = false;
        }
      }
    }
    in_notify = false;

    // Process any delayed notify_when() calls that
    if ( !delayed_notify_when_list.empty() )
    {
      for (notify_when_args_vec_t::iterator it = delayed_notify_when_list.begin(), it_end=delayed_notify_when_list.end();
           it != it_end;
           ++it)
      {
        notify_when(it->when, it->py_callable);
      }
      delayed_notify_when_list.qclear();
    }

    return ok;
  }

  //------------------------------------------------------------------------
  pywraps_notify_when_t()
  {
    in_notify = false;
  }
};

static pywraps_notify_when_t *g_nw = NULL;

//------------------------------------------------------------------------
// Initializes the notify_when mechanism
// (Normally called by IDAPython plugin.init())
bool pywraps_nw_init()
{
  if ( g_nw != NULL )
    return true;

  g_nw = new pywraps_notify_when_t();
  if ( g_nw->init() )
    return true;

  // Things went bad, undo!
  delete g_nw;
  g_nw = NULL;
  return false;
}

//------------------------------------------------------------------------
bool pywraps_nw_notify(int slot, ...)
{
  if ( g_nw == NULL )
    return false;

  // Appears to be called from 'driver_notifywhen.cpp', which
  // itself is called from possibly non-python code.
  // I.e., we must acquire the GIL.
  PYW_GIL_GET;
  va_list va;
  va_start(va, slot);
  bool ok = g_nw->notify_va(slot, va);
  va_end(va);

  return ok;
}

//------------------------------------------------------------------------
// Deinitializes the notify_when mechanism
bool pywraps_nw_term()
{
  if ( g_nw == NULL )
    return true;

  // If could not deinitialize then return w/o stopping nw
  if ( !g_nw->deinit() )
    return false;

  // Cleanup
  delete g_nw;
  g_nw = NULL;
  return true;
}

//</code(py_idaapi)>
//------------------------------------------------------------------------

//<inline(py_idaapi)>

//------------------------------------------------------------------------
/*
#<pydoc>
def notify_when(when, callback):
    """
    Register a callback that will be called when an event happens.
    @param when: one of NW_XXXX constants
    @param callback: This callback prototype varies depending on the 'when' parameter:
                     The general callback format:
                         def notify_when_callback(nw_code)
                     In the case of NW_OPENIDB:
                         def notify_when_callback(nw_code, is_old_database)
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool notify_when(int when, PyObject *py_callable)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( g_nw == NULL || !PyCallable_Check(py_callable) )
    return false;
  return g_nw->notify_when(when, py_callable);
}

//</inline(py_idaapi)>
//------------------------------------------------------------------------

#endif
