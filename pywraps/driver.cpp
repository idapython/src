//--------------------------------------------------------------------------
// IDA includes
#include <windows.h>
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <enum.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <bytes.hpp>
#include <graph.hpp>
#include <map>
#include <idd.hpp>
#include <dbg.hpp>
#include <ieee.h>
#include <err.h>
#include <expr.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <nalt.hpp>
#include <frame.hpp>

//--------------------------------------------------------------------------
// PyWraps
#include <Python.h>
#include "pywraps.hpp"
#include "swig_stub.h"
#include "py_cvt.hpp"
#include "py_idaapi.hpp"
#include "py_graph.hpp"
#include "py_typeinf.hpp"
#include "py_bytes.hpp"
#include "py_linput.hpp"
#include "py_qfile.hpp"
#include "py_ua.hpp"
#include "py_custdata.hpp"
#include "py_notifywhen.hpp"
#include "py_dbg.hpp"
#include "py_choose2.hpp"
#include "py_plgform.hpp"
#include "py_cli.hpp"
#include "py_custview.hpp"
#include "py_lines.hpp"
#include "py_nalt.hpp"
#include "py_loader.hpp"
#include "py_idp.hpp"
#include "py_kernwin.hpp"
#include "py_askusingform.hpp"
#include "py_expr.hpp"

//--------------------------------------------------------------------------
qvector<PyMethodDef> all_methods;
void driver_add_methods(PyMethodDef *methods)
{
  for ( ; methods->ml_name != NULL ; ++methods )
    all_methods.push_back(*methods);
}

//--------------------------------------------------------------------------
// Define a class and declare an instance so it gets executed on startup
// It will add the desired methods to the all_methods global variable
#define DRIVER_INIT_METHODS(name) \
  class init_##name##_driver_t \
  { \
  public: \
    init_##name##_driver_t() \
    { \
      driver_add_methods(py_methods_##name##); \
    } \
  } init_##name##_driver;

//--------------------------------------------------------------------------
// PyWraps test drivers
//#include "driver_kernwin.cpp"
//#include "driver_chooser.cpp"
#include "driver_expr.cpp"
//#include "driver_custview.cpp"
//#include "driver_notifywhen.cpp"
//#include "driver_custdata.cpp"
//#include "driver_graph.cpp"
//#include "driver_diskio.cpp"
//#include "driver_bytes.cpp"
//#include "driver_dbg.cpp"
//#include "driver_nalt.cpp"
//#include "driver_cli.cpp"

//--------------------------------------------------------------------------
//#define DRIVER_FIX

#ifdef DRIVER_FIX
  #define PLUGIN_FLAGS PLUGIN_FIX
#else
  #define PLUGIN_FLAGS 0
#endif

//--------------------------------------------------------------------------
void setup_pywraps()
{
  static bool installed = false;
  if ( installed )
  {
    msg("pywraps already installed\n");
    return;
  }
  static const PyMethodDef null_method = {0};
  all_methods.push_back(null_method);
  Py_InitModule("pywraps", all_methods.begin());
  init_pywraps();
  msg("pywraps installed!\n");
  installed = true;
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
  setup_pywraps();
#ifdef DRIVER_RUN
  driver_run(0);
#endif
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
int idaapi init(void)
{
#ifndef DRIVER_FIX
  setup_pywraps();
#endif
#ifdef DRIVER_INIT
  return driver_init();
#else
  return PLUGIN_KEEP;
#endif
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
#ifdef DRIVER_TERM
  driver_term();
#endif
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_FLAGS,         // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  // long comment about the plugin
  "PyWraps plugin",

  // it could appear in the status line
  // or as a hint
  "",                   // multiline help about the plugin

  "pywraps",            // the preferred short name of the plugin
  "Alt-0"               // the preferred hotkey to run the plugin
};
