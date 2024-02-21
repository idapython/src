
#include <pro.h>
#include <expr.hpp>

#include "extapi.hpp"
#include "extapi.cpp"
#include "pywraps.hpp"
#include "pywraps.cpp"

//-------------------------------------------------------------------------
idapython_plugin_t *ida_export get_plugin_instance() { return nullptr; }
void ida_export set_interruptible_state(bool) {}
ssize_t ida_export invoke_callbacks(hook_type_t, int, va_list) { return 0; }
bool ida_export hook_to_notification_point(hook_type_t, hook_cb_t *, void *) { return false; }
int ida_export unhook_from_notification_point(hook_type_t, hook_cb_t *, void *) { return false; }
void ida_export cleanup_argloc(argloc_t *) { INTERR(30755); }
void ida_export clear_tinfo_t(tinfo_t *) { INTERR(30756); }
fpvalue_error_t ida_export ieee_realcvt(void *, fpvalue_t *, uint16) { return REAL_ERROR_FORMAT; }

//-------------------------------------------------------------------------
static qvector<void*> prevent_warnings()
{
  qvector<void *> buf;
  buf.push_back((void *) &clear_python_timer_instances);
  buf.push_back((void *) &til_clear_python_tinfo_t_instances);
  buf.push_back((void *) &deinit_pywraps);
  buf.push_back((void *) &init_pywraps);
  buf.push_back((void *) &pywraps_check_autoscripts);
  buf.push_back((void *) &free_compiled_form_instances);
  return buf;
}

//-------------------------------------------------------------------------
idcfuncs_t idc_func_table = { 0 };

//-------------------------------------------------------------------------
static const char *inifile = "test_pywraps.ini";
static size_t lnnum = 0;

//------------------------------------------------------------------------
AS_PRINTF(1, 2) NORETURN static void fatal(const char *format, ...)
{
  if ( lnnum != 0 )
    qeprintf("%s:%" FMT_Z ": ", inifile, lnnum);

  va_list va;
  va_start(va, format);
  qstring buf;
  buf.vsprnt(format, va);
  qeprintf("%s\n", buf.c_str());
  va_end(va);
  qexit(EXIT_FAILURE);
}

//-------------------------------------------------------------------------
static bool read_test_case(qstring *out, FILE *fp)
{
  out->qclear();
  char buf[MAXSTR];
  bool printed_header = false;
  while ( qfgets(buf, sizeof(buf), fp) )
  {
    ++lnnum;
//    msg("%s", buf);
    if ( buf[0] == '\0' )
      continue;
    buf[strlen(buf)-1] = '\0';
    char *ptr = skip_spaces(buf);
    if ( *ptr == '\0' || *ptr == ';' )
      continue;
    if ( !printed_header )
    {
      msg("--- TEST: %s\n", buf);
      printed_header = true;
    }
    *out = buf;
    return true;
  }
  return false;
}

//-------------------------------------------------------------------------
static void run_test_case(
        qstrvec_t *out,
        const qstring &expr,
        PyObject *globals)
{
  qstrvec_t argv;
  expr.split(&argv, " ");

  QASSERT(30757, argv.size() == 2);
  newref_t py_arg1(extapi.PyRun_StringFlags_ptr(
                           argv[1].c_str(),
                           Py_eval_input,
                           globals,
                           globals,
                           nullptr));
  QASSERT(30758, py_arg1 != nullptr);
  if ( argv[0] == "READ_NUM" )
  {
    {
      qstring &buf = out->push_back();
      buf = "PyW_GetNumber     : ";
      uint64 num = 0;
      bool is_64 = false;
      if ( PyW_GetNumber(py_arg1.o, &num, &is_64) )
      {
        buf.cat_sprnt("is_64: %s, unsigned: %llu; signed: %lld; hex: 0x%llx",
                      is_64 ? "true" : "false", uint64(num), int64(num), uint64(num));
      }
      else
      {
        buf.append("Could not convert to a number");
      }
    }

    {
      qstring &buf = out->push_back();
      buf = "PyW_GetNumberAsIDC: ";
      idc_value_t idcv;
      if ( PyW_GetNumberAsIDC(py_arg1.o, &idcv) )
      {
        switch ( idcv.vtype )
        {
          case VT_LONG:
#ifdef __EA64__
            buf.cat_sprnt("(64-bit sval_t) unsigned: %llu; signed: %lld; hex: 0x%llx",
                          uval_t(idcv.num), idcv.num, uval_t(idcv.num));
#else
            buf.cat_sprnt("(32-bit sval_t) unsigned: %u; signed: %d; hex: 0x%x",
                          uval_t(idcv.num), idcv.num, idcv.num);
#endif
            break;
          case VT_INT64:
            buf.cat_sprnt("(int64) unsigned: %llu; signed: %lld; hex: 0x%llx",
                          uint64(idcv.i64), idcv.i64, uint64(idcv.i64));
            break;
          default:
            INTERR(30759);
        }
      }
      else
      {
        buf.append("Could not convert to an IDC value");
      }
    }
  }
  else
  {
    INTERR(30760);
  }
}

//-------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  if ( argc > 1 )
    inifile = argv[1];

  prevent_warnings();

  FILE *fp = qfopen(inifile, "rt");
  if ( fp == nullptr )
    fatal("%s: %s", inifile, qerrstr(-1));

  Py_InitializeEx(0 /* Don't catch SIGPIPE, SIGXFZ, SIGXFSZ & SIGINT signals */);
  qstring errbuf;
  QASSERT(30761, extapi.load(&errbuf));

  PyObject *module = PyImport_AddModule("__main__");
  PyObject *globals = PyModule_GetDict(module);

  qstring req;
  while ( read_test_case(&req, fp) )
  {
    qstrvec_t resp;
    run_test_case(&resp, req, globals);
    for ( const auto &r : resp )
      msg(" => %s\n", r.c_str());
  }

  Py_Finalize();

  qfclose(fp);

  return EXIT_SUCCESS;
}

