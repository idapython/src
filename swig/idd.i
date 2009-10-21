%ignore debugger_t;
%ignore memory_info_t;
%ignore register_info_t;

%apply unsigned char { char dtyp };

%include "idd.hpp"

%clear(char dtyp);

%{
//<code(py_idd)>

#ifndef PYUL_DEFINED
#define PYUL_DEFINED
  typedef unsigned PY_LONG_LONG pyul_t;
#endif

bool dbg_can_query()
{
  // Reject the request only if no debugger is set
  // or the debugger cannot be queried while not in suspended state
  return !(dbg == NULL || (!dbg->may_disturb() && get_process_state() != DSTATE_SUSP));
}

PyObject *meminfo_vec_t_to_py(meminfo_vec_t &areas)
{
  PyObject *py_list = PyList_New(areas.size());
  meminfo_vec_t::const_iterator it, it_end(areas.end());
  Py_ssize_t i = 0;
  for (it=areas.begin();it!=it_end;++it, ++i)
  {
    const memory_info_t &mi = *it;
    // startEA endEA name sclass sbase bitness perm
    PyList_SetItem(py_list, i, 
      Py_BuildValue("(KKssKii)", 
        pyul_t(mi.startEA),
        pyul_t(mi.endEA),
        mi.name.c_str(),
        mi.sclass.c_str(),
        pyul_t(mi.sbase),
        (unsigned int)(mi.bitness), 
        (unsigned int)mi.perm));
  }
  return py_list;
}

PyObject *dbg_get_memory_info()
{
  if (!dbg_can_query())
    Py_RETURN_NONE;

  // Invalidate memory
  invalidate_dbgmem_config();
  invalidate_dbgmem_contents(BADADDR, BADADDR);

  meminfo_vec_t areas;
  dbg->get_memory_info(areas);
  return meminfo_vec_t_to_py(areas);
}

PyObject *dbg_get_registers()
{
  if (dbg == NULL)
    Py_RETURN_NONE;
  
  PyObject *py_list = PyList_New(dbg->registers_size);

  for (int i=0;i<dbg->registers_size;i++)
  {
    register_info_t &ri = dbg->registers[i];
    PyObject *py_bits;

    // Does this register have bit strings?
    if (ri.bit_strings != NULL)
    {
      int nbits = (int)b2a_width((int)get_dtyp_size(ri.dtyp), 0) * 4;
      py_bits = PyList_New(nbits);
      for (int i=0;i<nbits;i++)
      {
        const char *s = ri.bit_strings[i];
        PyList_SetItem(py_bits, i, PyString_FromString(s == NULL ? "" : s));
      }
    }
    else
    {
      Py_INCREF(Py_None);
      py_bits = Py_None;
    }

    // name flags class dtyp bit_strings bit_strings_default_mask
    PyList_SetItem(py_list, i, 
      Py_BuildValue("(sIIINI)", 
        ri.name, 
        ri.flags, 
        (unsigned int)ri.register_class, 
        (unsigned int)ri.dtyp,
        py_bits,
        (unsigned int)ri.bit_strings_default));
  }
  return py_list;
}

PyObject *dbg_get_thread_sreg_base(PyObject *py_tid, PyObject *py_sreg_value)
{
  if (!dbg_can_query() || !PyInt_Check(py_tid) || !PyInt_Check(py_sreg_value))
    Py_RETURN_NONE;
  ea_t answer;
  thid_t tid = PyInt_AsLong(py_tid);
  int sreg_value = PyInt_AsLong(py_sreg_value);
  if (dbg->thread_get_sreg_base(tid, sreg_value, &answer) != 1)
    Py_RETURN_NONE;
  return Py_BuildValue("K", pyul_t(answer));
}

PyObject *dbg_read_memory(PyObject *py_ea, PyObject *py_sz)
{
  if (!dbg_can_query() || !PyNumber_Check(py_ea) || !PyNumber_Check(py_sz))
    Py_RETURN_NONE;

  ea_t ea = ea_t(PyInt_AsSsize_t(py_ea));
  size_t sz = ea_t(PyInt_AsSsize_t(py_sz));

  char *buf = new char[sz];
  if (buf == NULL)
    Py_RETURN_NONE;

  PyObject *ret;
  if (dbg->read_memory(ea_t(ea), buf, sz) == sz)
  {
    ret = PyString_FromStringAndSize(buf, sz);
  }
  else
  {
    Py_INCREF(Py_None);
    ret = Py_None;
  }
  delete [] buf;
  return ret;
}

PyObject *dbg_write_memory(PyObject *py_ea, PyObject *py_buf)
{
  if (!dbg_can_query() || !PyString_Check(py_buf) || !PyNumber_Check(py_ea))
    Py_RETURN_NONE;

  ea_t ea = ea_t(PyInt_AsSsize_t(py_ea));
  size_t sz = PyString_GET_SIZE(py_buf);
  void *buf = (void *)PyString_AS_STRING(py_buf);
  if (dbg->write_memory(ea, buf, sz) != sz)
    Py_RETURN_FALSE;
  Py_RETURN_TRUE;
}
//</code(py_idd)>
%}

%inline %{

//<inline(py_idd)>
PyObject *dbg_write_memory(PyObject *py_ea, PyObject *py_buf);
PyObject *dbg_read_memory(PyObject *py_ea, PyObject *py_sz);
PyObject *dbg_get_thread_sreg_base(PyObject *py_tid, PyObject *py_sreg_value);
PyObject *dbg_get_registers();
PyObject *dbg_get_memory_info();
bool dbg_can_query();
//</inline(py_idd)>

char get_event_module_name(const debug_event_t* ev, char *buf, size_t bufsize)
{
    qstrncpy(buf, ev->modinfo.name, bufsize);
    return true;
}

ea_t get_event_module_base(const debug_event_t* ev)
{
    return ev->modinfo.base;
}

asize_t get_event_module_size(const debug_event_t* ev)
{
    return ev->modinfo.size;
}

char get_event_exc_info(const debug_event_t* ev, char *buf, size_t bufsize)
{
    qstrncpy(buf, ev->exc.info, bufsize);
    return true;
}

char get_event_info(const debug_event_t* ev, char *buf, size_t bufsize)
{
    qstrncpy(buf, ev->info, bufsize);
    return true;
}

ea_t get_event_bpt_hea(const debug_event_t* ev)
{
    return ev->bpt.hea;
}

uint get_event_exc_code(const debug_event_t* ev)
{
    return ev->exc.code;
}

ea_t get_event_exc_ea(const debug_event_t* ev)
{
    return ev->exc.ea;
}

bool can_exc_continue(const debug_event_t* ev)
{
    return ev->exc.can_cont;
}
%}
