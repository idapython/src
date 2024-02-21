//---------------------------------------------------------------------
// IDAPython - Python plugin for Interactive Disassembler
//
// Copyright (c) The IDAPython Team <idapython@googlegroups.com>
//
// All rights reserved.
//
// For detailed copyright information see the file COPYING in
// the root of the distribution archive.
//---------------------------------------------------------------------
// python.cpp - Main plugin code
//---------------------------------------------------------------------
#include <Python.h>

//-------------------------------------------------------------------------
// This define fixes the redefinition of ssize_t
#ifdef HAVE_SSIZE_T
#define _SSIZE_T_DEFINED 1
#endif

// Python defines snprintf macro so we need to allow it
#define USE_DANGEROUS_FUNCTIONS
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <ida_highlighter.hpp>
#include <signal.h>

#include "pywraps.hpp"

#include "extapi.hpp"
#include "extapi.cpp"

//-------------------------------------------------------------------------
idapython_plugin_t *idapython_plugin_t::instance = nullptr;

#include "pywraps.cpp"

//-------------------------------------------------------------------------
// Defines and constants

// Python-style version tuple comes from the makefile
// Only the serial and status is set here
#define VER_SERIAL 0
#define VER_STATUS "final"
#define IDAPYTHON_RUNSTATEMENT                   0
#define IDAPYTHON_ENABLE_EXTLANG                 3
#define IDAPYTHON_DISABLE_EXTLANG                4
#define PYTHON_DIR_NAME                          "python"
#define S_IDAPYTHON                              "IDAPython"
#define S_INIT_PY                                "init.py"
static const char S_IDC_ARGS_VARNAME[] =         "ARGV";
static const char S_IDC_EXEC_PYTHON[] =          "exec_python";
static const char S_IDC_EVAL_PYTHON[] =          "eval_python";
static const char S_IDAPYTHON_DATA_NODE[] =      "IDAPython_Data";

//lint -e818 could be pointer to const
//lint -e1762 member function '' could be made const

//-------------------------------------------------------------------------
idapython_plugin_t *ida_export get_plugin_instance()
{
  return idapython_plugin_t::get_instance();
}

//-------------------------------------------------------------------------
// Allowing the user to interrupt a script is not entirely trivial.
// Imagine the following script, that is run in an IDB that uses
// an IDAPython processor module (important!) :
// ---
// while True:
//     gen_disasm_text(dtext, ea, ea + 4, False)
// ---
// This script will call the processor module's out/outop functions in
// order to generate the text. If the processor module behaves
// correctly (i.e., doesn't take forever to generate said text), if the
// user presses 'Cancel' once the wait dialog box shows, what we want
// to cancel is _this_ script above: we don't want to interrupt the
// processor module while it's doing its thing!
// In order to do that, we will have to remember the time-of-entry of
// various entry points:
//  - idapython_plugin_t::extlang_compile_file
//  - IDAPython_RunStatement
//  - ... and more importantly in this case:
//  - idapython_plugin_t::extlang_call_method (called by the IDA kernel to generate text)
//
// Of course, in case the processor module's out/outop misbehaves, we still
// want the ability to cancel that operation. The following code allows for
// that, too.

//-------------------------------------------------------------------------
struct exec_entry_t
{
  time_t etime;
  exec_entry_t() { reset_start_time(); }
  void reset_start_time() { etime = time(nullptr); }
};
DECLARE_TYPE_AS_MOVABLE(exec_entry_t);
typedef qvector<exec_entry_t> exec_entries_t;

//-------------------------------------------------------------------------
struct execution_t
{
  exec_entries_t entries;
  int timeout;
  uint32 steps_before_action;
  bool wait_box_shown;
  bool interruptible_state;

  execution_t()
    : timeout(2),
      steps_before_action(0),
      wait_box_shown(false),
      interruptible_state(true)
  {
    reset_steps();
  }
  void reset_steps();
  void push();
  void pop();
  bool can_interrupt_current(time_t now) const;
  void reset_current_start_time();
  void stop_tracking();
  void sync_to_present_time();
  void maybe_hide_wait_box();
  void set_interruptible(bool intr) { interruptible_state = intr; }
  bool is_our_wait_box_in_charge() const;
  static int on_trace(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg);
};
static execution_t execution;

//-------------------------------------------------------------------------
typedef qvector<bool> idapython_wait_box_requests_t;
static idapython_wait_box_requests_t idapython_wait_box_requests;
static inline bool idapython_is_user_waitbox_shown()
{
  return idapython_wait_box_requests.has(false);
}

//-------------------------------------------------------------------------
//lint -esym(683,show_wait_box) function 'show_wait_box' #define'd, semantics may be lost
//lint -esym(750,show_wait_box) local macro '' not referenced
//lint -esym(750,hide_wait_box) local macro '' not referenced
void ida_export idapython_show_wait_box(
        bool internal,
        const char *message)
{
  idapython_wait_box_requests.push_back(internal);
#undef show_wait_box
  show_wait_box("%s", message);
#define show_wait_box USE_IDAPYTHON_SHOW_WAIT_BOX
}

//-------------------------------------------------------------------------
void ida_export idapython_hide_wait_box()
{
  if ( !idapython_wait_box_requests.empty() )
  {
    idapython_wait_box_requests.pop_back();
    execution.reset_current_start_time();
  }
#undef hide_wait_box
  hide_wait_box();
#define hide_wait_box USE_IDAPYTHON_HIDE_WAIT_BOX
}


// #define LOG_EXEC 1
#ifdef LOG_EXEC
#define LEXEC(...) msg("IDAPython exec: " __VA_ARGS__)
#else
#define LEXEC(...)
#endif

#define AVERAGE_STEPS_COUNT 10
#define MAX_STEPS_COUNT ((AVERAGE_STEPS_COUNT * 2) + 1)

//-------------------------------------------------------------------------
void execution_t::reset_steps()
{
  // we want to trace/check the time about every 10 steps. But we don't
  // want it to be exactly 10 steps, or we might never make important
  // checks because the tracing happens always at the wrong point.
  // E.g., imagine the following loop:
  // ---
  // while True:
  //     gen_disasm_text(dtext, ea, ea + 4, False)
  // ---
  // If we never hit the 'trace' callback while in the 'while True' loop
  // but always when performing the call to the processor module's 'out/outop'
  // then the loop will never stop. That was happening on windows (optimized.)
  steps_before_action = 1 + rand() % (AVERAGE_STEPS_COUNT*2);
}

//-------------------------------------------------------------------------
void execution_t::push()
{
  if ( entries.empty() )
    extapi.PyEval_SetTrace_ptr((Py_tracefunc) execution_t::on_trace, nullptr); //lint !e611 cast between pointer to function type '' and pointer to object type 'void *'
  entries.push_back();
  LEXEC("push() (now: %d entries)\n", int(entries.size()));
}

//-------------------------------------------------------------------------
void execution_t::pop()
{
  entries.pop_back();
  if ( entries.empty() )
    stop_tracking();
  LEXEC("pop() (now: %d entries)\n", int(entries.size()));
}

//-------------------------------------------------------------------------
void execution_t::stop_tracking()
{
  extapi.PyEval_SetTrace_ptr(nullptr, nullptr);
  maybe_hide_wait_box();
}

//-------------------------------------------------------------------------
void execution_t::sync_to_present_time()
{
  time_t now = time(nullptr);
  LEXEC("execution_t (%p)::sync_to_present_time() now=%d\n", this, int(now));
  for ( size_t i = 0, n = entries.size(); i < n; ++i )
    entries[i].etime = now;
  maybe_hide_wait_box();
}

//-------------------------------------------------------------------------
void execution_t::maybe_hide_wait_box()
{
  if ( wait_box_shown )
  {
    LEXEC("execution_t (%p)::maybe_hide_wait_box() hiding dialog\n", this);
    idapython_hide_wait_box();
    wait_box_shown = false;
  }
}

//-------------------------------------------------------------------------
bool execution_t::can_interrupt_current(time_t now) const
{
  LEXEC("can_interrupt_current(): nentries: %d\n", int(entries.size()));
  if ( entries.empty() || timeout <= 0 || !interruptible_state )
    return false;
  const exec_entry_t &last = entries.back();
  bool can = (now - last.etime) > timeout;
  LEXEC("can_interrupt_current(): last: %d, now: %d (-> %d)\n",
        int(last.etime), int(now), can);
  return can;
}

//-------------------------------------------------------------------------
void execution_t::reset_current_start_time()
{
  if ( !entries.empty() )
  {
    LEXEC("reset_current_start_time()\n");
    entries.back().reset_start_time();
  }
}

//------------------------------------------------------------------------
int execution_t::on_trace(PyObject *, PyFrameObject *, int, PyObject *)
{
#ifdef TESTABLE_BUILD
  // ensure there was no decrement overflow
  QASSERT(30609, execution.steps_before_action <= MAX_STEPS_COUNT);
#endif
  LEXEC("on_trace() (steps_before_action=%u, entries.size()=%d, timeout=%d)\n",
        int(execution.steps_before_action),
        int(execution.entries.size()),
        execution.timeout);
  if ( execution.timeout < 0 )
  {
    LEXEC("on_trace()::no timeout currently set (%d).\n", execution.timeout);
    return 0;
  }

  // we don't want to query for time at every trace event
  if ( execution.steps_before_action > 0 )
  {
    --execution.steps_before_action;
    return 0;
  }

  if ( get_active_modal_widget() != nullptr )
  {
    LEXEC("on_trace()::a modal widget is active. Not showing our 'interrupt dialog'.\n");

    // in addition, we want to sync the "start time" to now, so that
    // the timeout will be relative to that (otherwise, calling
    // ask_file() might end up showing the waitdialog for a fraction
    // of a second after `_ida_kernwin.ask_file()` returns, but before
    // the `ida_kernwin.ask_file()` one does.)
    execution.sync_to_present_time();

    return 0;
  }

  execution.reset_steps();

  if ( idapython_is_user_waitbox_shown() )
  {
    LEXEC("on_trace()::a user wait dialog is currently shown. Not showing our 'interrupt dialog'.\n");
    return 0;
  }

  time_t now = time(nullptr);
  LEXEC("on_trace()::now: %d\n", int(now));
  if ( execution.can_interrupt_current(now) )
  {
    const bool user_clicked_cancel = user_cancelled();
    LEXEC("on_trace()::can_interrupt. 'Interrupt dialog' shown=%d, user cancelled=%d\n",
          int(execution.wait_box_shown),
          int(user_clicked_cancel));
    if ( execution.wait_box_shown )
    {
      if ( user_clicked_cancel )
      {
        if ( PyErr_Occurred() == nullptr )
        {
          LEXEC("on_trace()::INTERRUPTING (setting 'User interrupted' exception)\n");
          PyErr_SetString(PyExc_KeyboardInterrupt, "User interrupted");
        }
        return -1;
      }
    }
    else
    {
      if ( !user_clicked_cancel )
      {
        LEXEC("on_trace()::showing wait dialog\n");
        idapython_show_wait_box(/*internal=*/ true, "Running Python script");
        execution.wait_box_shown = true;
      }
      else
      {
        LEXEC("on_trace()::not showing wait dialog; user_cancelled()\n");
      }
    }
  }
  return 0;
}

//-------------------------------------------------------------------------
//lint -esym(1788, new_execution_t) is referenced only by its constructor or destructor
void ida_export setup_new_execution(
        new_execution_t *instance,
        bool setup)
{
  if ( setup )
  {
    instance->created = idapython_plugin_t::get_instance()->ui_ready
                     && execution.timeout > 0;
    if ( instance->created )
    {
      PYW_GIL_CHECK_LOCKED_SCOPE();
      execution.push();
    }
  }
  else
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    execution.pop();
  }
}

//-------------------------------------------------------------------------
void ida_export set_interruptible_state(bool interruptible)
{
  execution.set_interruptible(interruptible);
}

//-------------------------------------------------------------------------
void ida_export prepare_programmatic_plugin_load(const char *path)
{
  idapython_plugin_t::get_instance()->requested_plugin_path = path;
}

//-------------------------------------------------------------------------
//lint -esym(714,disable_script_timeout) Symbol not referenced
idaman void ida_export disable_script_timeout()
{
  // Clear timeout
  execution.timeout = 0;

  // Uninstall the trace function and hide the waitbox (if it was shown)
  execution.stop_tracking();
}

//-------------------------------------------------------------------------
//lint -esym(714,set_script_timeout) Symbol not referenced
idaman int ida_export set_script_timeout(int timeout)
{
  // Update the timeout
  qswap(timeout, execution.timeout);

  // Reset the execution time and hide the waitbox (so it is shown again after timeout elapses)
  execution.sync_to_present_time();

  return timeout;
}

//------------------------------------------------------------------------
// Return a formatted error or just print it to the console
static void handle_python_error(
        qstring *errbuf,
        bool clear_error = true)
{
  if ( errbuf != nullptr )
    errbuf->clear();

  // No exception?
  if ( !PyErr_Occurred() )
    return;

  PyW_GetError(errbuf, clear_error);
}

//-------------------------------------------------------------------------
#define ENCODING_COOKIE "# -*- coding: UTF-8 -*-\n"
#define ENCODING_COOKIE_LEN 24
static const char *insert_encoding_cookie(qstring *out)
{
  // This is necessary for pre-3.9 parsers, to parse the
  // input text as proper UTF-8. Python 3.9 switches to the PEG
  // parser that, by default (and in particular since we don't
  // pass PyCompilerFlags), will always assume UTF-8.
  out->insert(0, ENCODING_COOKIE, ENCODING_COOKIE_LEN);
  return out->c_str();
}

//------------------------------------------------------------------------
// Simple Python statement runner function for IDC
static error_t idaapi idc_runpythonstatement(
        idc_value_t *argv,
        idc_value_t *res)
{
  qstring errbuf;
  bool ok = idapython_plugin_t::extlang_eval_snippet(argv[0].c_str(), &errbuf);

  if ( ok )
    res->set_long(0);
  else
    res->set_string(errbuf);

  return eOk;
}
static const char idc_runpythonstatement_args[] = { VT_STR, 0 };
static const ext_idcfunc_t idc_runpythonstatement_desc =
{
  S_IDC_EXEC_PYTHON,
  idc_runpythonstatement,
  idc_runpythonstatement_args,
  nullptr,
  0,
  0
};

//------------------------------------------------------------------------
// Simple Python expression evaluator for IDC
static error_t idaapi idc_eval_python(
        idc_value_t *argv,
        idc_value_t *res)
{
  qstring errbuf;
  const char *snippet = argv[0].c_str();
  bool ok = idapython_plugin_t::extlang_eval_expr(res, BADADDR, snippet, &errbuf);
  if ( !ok )
    return throw_idc_exception(res, errbuf.c_str());
  return eOk;
}

static const char idc_eval_python_args[] = { VT_STR, 0 };
static const ext_idcfunc_t idc_eval_python_desc =
{
  S_IDC_EVAL_PYTHON,
  idc_eval_python,
  idc_eval_python_args,
  nullptr,
  0,
  0
};

//--------------------------------------------------------------------------
static const cfgopt_t opts[] =
{
  CFGOPT_R("SCRIPT_TIMEOUT", idapython_plugin_config_t, execution_timeout, 0, INT_MAX),
  CFGOPT_B("ALERT_AUTO_SCRIPTS", idapython_plugin_config_t, alert_auto_scripts, true),
  CFGOPT_B("REMOVE_CWD_SYS_PATH", idapython_plugin_config_t, remove_cwd_sys_path, true),
  CFGOPT_B("AUTOIMPORT_COMPAT_IDAAPI", idapython_plugin_config_t, autoimport_compat_idaapi, true),
  CFGOPT_B("IDAPYTHON_IDAUSR_SYSPATH", idapython_plugin_config_t, idausr_syspath, true),
  CFGOPT_B("NAMESPACE_AWARE", idapython_plugin_config_t, namespace_aware, true),
  CFGOPT_B("REPL_USE_SYS_DISPLAYHOOK", idapython_plugin_config_t, repl_use_sys_displayhook, true),
};

//-------------------------------------------------------------------------
// Convert return value from Python to IDC or report about an error.
// This function also decrements the reference "result" (python variable)
static bool return_python_result(
        idc_value_t *idc_result,
        const ref_t &py_result,
        qstring *errbuf)
{
  if ( errbuf != nullptr )
    errbuf->clear();

  if ( py_result == nullptr )
  {
    handle_python_error(errbuf);
    return false;
  }

  int cvt = CIP_OK;
  if ( idc_result != nullptr )
  {
    idc_result->clear();
    cvt = pyvar_to_idcvar(py_result, idc_result);
    if ( cvt < CIP_OK && errbuf != nullptr )
      *errbuf = "ERROR: bad return value";
  }

  return cvt >= CIP_OK;
}

//-------------------------------------------------------------------------
// This function parses a name into two different components (if it applies).
// Example:
// parse_py_modname("modname.attrname", mod_buf, attr_buf)
// It splits the full name into two parts.
static bool parse_py_modname(
        const char *full_name,
        char *modname,
        char *attrname,
        size_t sz,
        const char *defmod = S_IDA_IDAAPI_MODNAME)
{
  const char *p = strrchr(full_name, '.');
  if ( p == nullptr )
  {
    qstrncpy(modname, defmod, sz);
    qstrncpy(attrname, full_name, sz);
  }
  else
  {
    qstrncpy(modname, full_name, p - full_name + 1);
    qstrncpy(attrname, p + 1, sz);
  }
  return p != nullptr;
}

//-------------------------------------------------------------------------
static void wrap_in_function(qstring *out, const qstring &body, const char *name)
{
  qstrvec_t lines;
  lines.push_back().sprnt("def %s():\n", name);

  qstring buf(body);
  while ( !buf.empty() && qisspace(buf.last()) ) // dont copy trailing whitespace(s)
    buf.remove_last();

  char *ctx;
  for ( char *p = qstrtok(buf.begin(), "\n", &ctx);
        p != nullptr;
        p = qstrtok(nullptr, "\n", &ctx) )
  {
    static const char FROM_FUTURE_IMPORT_STMT[] = "from __future__ import";
    if ( strneq(p, FROM_FUTURE_IMPORT_STMT, sizeof(FROM_FUTURE_IMPORT_STMT)-1) )
    {
      lines.insert(lines.begin(), p);
    }
    else
    {
      qstring &s = lines.push_back();
      s.append("    ", 4);
      s.append(p);
    }
  }
  out->qclear();
  for ( size_t i = 0; i < lines.size(); ++i )
  {
    if ( i > 0 )
      out->append('\n');
    out->append(lines[i]);
  }
}

//-------------------------------------------------------------------------
struct python_highlighter_t : public ida_syntax_highlighter_t
{
  python_highlighter_t() : ida_syntax_highlighter_t()
  {
    open_strconst = '"';
    close_strconst = '"';
    open_chrconst = '\'';
    close_chrconst = '\'';
    escape_char = '\\';
    preprocessor_char = char(1);
    literal_closer = '\0';
    text_color = HF_DEFAULT;
    comment_color = HF_COMMENT;
    string_color = HF_STRING;
    preprocessor_color = HF_KEYWORD1;
    style = HF_DEFAULT;
    set_open_cmt("#");
    add_multi_line_comment("\"\"\"", "\"\"\"");
    add_multi_line_comment("'''", "'''");
    add_keywords(
      "and|as|assert|break|class|continue|def|"
      "del|elif|else|except|exec|finally|"
      "for|from|global|nonlocal|if|import|in|"
      "is|lambda|not|or|pass|print|"
      "raise|return|try|while|with|yield|"
      "None|True|False",HF_KEYWORD1);
    add_keywords("self", HF_KEYWORD2);
  }

  void add_new_keywords()
  {
    // Add new keywords (3.10+):
    int py_major = 0, py_minor= 0;
    qsscanf(Py_GetVersion(), "%d.%d", &py_major, &py_minor);
    if ( py_major >= 3 && py_minor >= 5 )
      add_keywords("async|await", HF_KEYWORD1);
    if ( py_major >= 3 && py_minor >= 10 )
      add_keywords("match|case", HF_KEYWORD1);
  }
};
static python_highlighter_t python_highlighter;

extlang_t extlang_python =
{
  sizeof(extlang_t),
  0,                  // flags
  0,                  // refcnt
  "Python",           // name
  "py",               // filext
  &python_highlighter,
  idapython_plugin_t::extlang_compile_expr,
  idapython_plugin_t::extlang_compile_file,
  idapython_plugin_t::extlang_call_func,
  idapython_plugin_t::extlang_eval_expr,
  idapython_plugin_t::extlang_eval_snippet,
  idapython_plugin_t::extlang_create_object,
  idapython_plugin_t::extlang_get_attr,
  idapython_plugin_t::extlang_set_attr,
  idapython_plugin_t::extlang_call_method,
  idapython_plugin_t::extlang_load_procmod,
  idapython_plugin_t::extlang_unload_procmod,
};

//-------------------------------------------------------------------------
idaman void ida_export enable_extlang_python(bool enable)
{
  if ( enable )
    select_extlang(&extlang_python);
  else
    select_extlang(nullptr);
}

//-------------------------------------------------------------------------
static const cli_t cli_python =
{
  sizeof(cli_t),
  0,
  "Python",
  "Python - IDAPython plugin",
  "Enter any Python expression",
  idapython_plugin_t::cli_execute_line,
  nullptr,
  nullptr,
  idapython_plugin_t::cli_find_completions,
};

//-------------------------------------------------------------------------
// Control the Python CLI status
idaman void ida_export enable_python_cli(bool enable)
{
  if ( enable )
    install_command_interpreter(&cli_python);
  else
    remove_command_interpreter(&cli_python);
}

//------------------------------------------------------------------------
// Converts the global IDC variable "ARGV" into a Python variable.
// The arguments will then be accessible via 'idc' module / 'ARGV' variable.
void convert_idc_args()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_args(PyList_New(0));

  idc_value_t *idc_args = find_idc_gvar(S_IDC_ARGS_VARNAME);
  if ( idc_args != nullptr )
  {
    idc_value_t attr;
    char attr_name[20] = { "0" };
    for ( int i=1; get_idcv_attr(&attr, idc_args, attr_name) == eOk; i++ )
    {
      PyList_Insert(py_args.o, i, PyUnicode_FromString(attr.c_str()));
      qsnprintf(attr_name, sizeof(attr_name), "%d", i);
    }
  }

  // Get reference to the IDC module (it is imported by init.py)
  ref_t py_mod(PyW_TryImportModule(S_IDC_MODNAME));
  if ( py_mod )
    PyObject_SetAttrString(py_mod.o, S_IDC_ARGS_VARNAME, py_args.o);
}

//-------------------------------------------------------------------------
enum module_lifecycle_notification_t
{
  mln_init = 0,
  mln_term,
  mln_closebase
};
static void send_modules_lifecycle_notification(module_lifecycle_notification_t what)
{
  PYW_GIL_GET;
  for ( size_t i = modules_callbacks.size(); i > 0; --i )
  {
    const module_callbacks_t &m = modules_callbacks[i-1];
    switch ( what )
    {
      case mln_init: m.init(); break;
      case mln_term: m.term(); break;
      case mln_closebase: m.closebase(); break;
    }
    if ( PyErr_Occurred() )
    {
      msg("Error during module lifecycle notification:\n");
      PyErr_Print();
    }
  }
}

//-------------------------------------------------------------------------
static wchar_t *utf8_wchar_t(qvector<wchar_t> *out, const char *in)
{
#ifdef __NT__
  qwstring tmp;
  utf8_utf16(&tmp, in);
  out->qclear();
  out->insert(out->begin(), tmp.begin(), tmp.end());
#else
  const char *p = in;
  while ( *p != '\0' )
  {
    wchar32_t cp = get_utf8_char(&p);
    if ( cp == 0 || cp == BADCP )
      break;
    out->push_back(cp);
  }
  out->push_back(0); // we're not dealing with a qstring; have to do it ourselves
#endif
  return out->begin();
}

//-------------------------------------------------------------------------
idapython_plugin_t::idapython_plugin_t()
  : initialized(false),
    ui_ready(false)
#ifdef TESTABLE_BUILD
    , user_code_lenient(-1)
#endif
{
  QASSERT(30615, instance == nullptr);
  instance = this;
}

//-------------------------------------------------------------------------
// Cleaning up Python
idapython_plugin_t::~idapython_plugin_t()
{
  QASSERT(30616, instance == this);

  if ( !initialized || Py_IsInitialized() == 0 )
    goto SKIP_CLEANUP;

  if ( PyGILState_GetThisThreadState() )
  {
    // Note: No 'PYW_GIL_GET' here, as it would try to release
    // the state after 'Py_Finalize()' has been called.
    // ...nor is it a good idea to try to put it in its own scope,
    // as it will PyGILState_Release() the current thread & GIL, and
    // Py_Finalize() itself wouldn't be happy then.
    PyGILState_Ensure();
  }

  // Let all modules perform possible de-initialization
  send_modules_lifecycle_notification(mln_term);

  unhook_from_notification_point(HT_IDB, on_idb_notification, this);

  // Remove the CLI
  enable_python_cli(false);

  // Remove the extlang
  remove_extlang(&extlang_python);

  // De-init pywraps
  deinit_pywraps();

  // Uninstall IDC function
  del_idc_func(idc_eval_python_desc.name);
  del_idc_func(idc_runpythonstatement_desc.name);

  // Shut the interpreter down
  Py_Finalize();
  initialized = false;

#ifdef TESTABLE_BUILD
  if ( !is_user_code_lenient() ) // Check that all hooks were unhooked
    QASSERT(30509, hook_data_vec.empty());
#endif
  for ( size_t i = hook_data_vec.size(); i > 0; --i )
  {
    const hook_data_t &hd = hook_data_vec[i-1];
    idapython_unhook_from_notification_point(hd.type, hd.cb, hd.ud);
  }
SKIP_CLEANUP:
  instance = nullptr;
}

#ifdef __NT__
// for MessageBox()
#pragma comment(lib, "user32")
#endif
//--------------------------------------------------------------------------
// show an error message, possibly during teardown of the process
AS_PRINTF(1, 2) static void lerror(const char *format, ...)
{
  va_list va;
  va_start(va, format);
#ifdef __NT__
  char buf[MAXSTR];
  qvsnprintf(buf, sizeof(buf), format, va);
  // use MB_SERVICE_NOTIFICATION to prevent UI message loop from running since ida.exe is mostly shut down at this point
  // and can crash if messages get processed
  MessageBox(nullptr, buf, "IDA", MB_ICONERROR|MB_SERVICE_NOTIFICATION);
#else
  qveprintf(format, va);
  //qgetchar();
#endif
}

#define ERRMSG "Unexpected fatal error while initializing Python runtime. Please run idapyswitch to confirm or change the used Python runtime"

volatile sig_atomic_t initdone = 0;
//-------------------------------------------------------------------------
// some Python runtimes may call abort() or exit() if they don't like something
// catch this to avoid silent IDA exit
static void exithandler(void)
{
  if ( !initdone )
  {
    initdone = 1;
    lerror(ERRMSG);
    // return to caller to continue exiting normally
  }
}

//lint -e2761 call to non-async-signal-safe function '' within signal handler ''
//lint -e2762 call to signal registration function 'signal' within signal handler 'aborthandler'
//-------------------------------------------------------------------------
// catch unexpected abort() call
static void aborthandler(int sig)
{
  lerror(ERRMSG);
  initdone = 1; // avoid duplicate message on exit
  // from https://www.gnu.org/software/libc/manual/html_node/Termination-in-Handler.html
  /* Now reraise the signal.  We reactivate the signal's
     default handling, which is to terminate the process.
     We could just call exit or abort,
     but reraising the signal sets the return status
     from the process correctly. */
  signal(sig, SIG_DFL);
  raise(sig);
}

//-------------------------------------------------------------------------
// Initialize the Python environment
bool idapython_plugin_t::init()
{
  if ( Py_IsInitialized() != 0 )
    return true;

  // Read configuration
  read_config_file2("idapython.cfg", opts, qnumber(opts),
                    /*defhdlr=*/ nullptr,
                    /*defines=*/ nullptr,
                    /*ndefines=*/ 0,
                    /*obj=*/ &this->config);
  parse_plugin_options();

  // Form the absolute path to IDA\python folder
  {
    char buf[QMAXPATH];
    qmakepath(buf, sizeof(buf), idadir(PYTHON_DIR_NAME), QSTRINGIZE(PY_MAJOR_VERSION), nullptr);
    idapython_dir = buf;
  }

  execution.timeout = config.execution_timeout;

  // Check for the presence of essential files
  if ( !_check_python_dir() )
    return false;

  char path[QMAXPATH];
  qstring errbuf;
  if ( !extapi.load(&errbuf) )
  {
    warning("Couldn't initialize IDAPython: %s", errbuf.c_str());
    return false;
  }

#ifdef __MAC__
  if ( !extapi.lib_path.empty() )
  {
    // On OSX we should explicitly call Py_SetPythonHome().
    // When using the system Python installation, sys.path will contain paths to other
    // Python installations if they appear in $PATH. This can cause fatal errors during
    // the system python's initialization.
    //
    // Note: The path will be something like:
    // /System/Library/Frameworks/Python.framework/Versions/2.5/Python
    // We need to strip the last part.
    //
    // Also, use a permanent buffer because Py_SetPythonHome() just stores a pointer
    char utf8_pyhomepath[MAXSTR];
    qstrncpy(utf8_pyhomepath, extapi.lib_path.c_str(), sizeof(utf8_pyhomepath));
    char *lastslash = strrchr(utf8_pyhomepath, '/');
    if ( lastslash != nullptr )
    {
      *lastslash = 0;
      utf8_wchar_t(&pyhomepath, utf8_pyhomepath);
      Py_SetPythonHome(pyhomepath.begin());
    }
  }
#endif

  if ( config.alert_auto_scripts )
  {
    if ( pywraps_check_autoscripts(path, sizeof(path))
      && ask_yn(ASKBTN_NO,
                "HIDECANCEL\n"
                "TITLE IDAPython\n"
                "The script '%s' was found in the current directory\n"
                "and will be automatically executed by Python.\n"
                "\n"
                "Do you want to continue loading IDAPython?", path) <= 0 )
    {
      return false;
    }
  }


  typedef void(*SignalHandlerPointer)(int);
  // catch unexpected abort()
  SignalHandlerPointer previousHandler = signal(SIGABRT, aborthandler);
  // ... and exit()
  atexit(exithandler);

  // Start the interpreter
  Py_InitializeEx(0 /* Don't catch SIGPIPE, SIGXFZ, SIGXFSZ & SIGINT signals */);
  // disable handlers
  initdone = 1;
  signal(SIGABRT, previousHandler);

  if ( !Py_IsInitialized() )
  {
    warning("IDAPython: Py_InitializeEx() failed");
    return false;
  }

  // add new Python keywords as needed
  python_highlighter.add_new_keywords();

  // remove current directory
  _prepare_sys_path();

  if ( extapi.PyEval_ThreadsInitialized_ptr != nullptr
    && extapi.PyEval_InitThreads_ptr != nullptr )
  {
    // Enable multi-threading support (before 3.9
    if ( !extapi.PyEval_ThreadsInitialized_ptr() )
      extapi.PyEval_InitThreads_ptr();
  }

#ifdef Py_DEBUG
  msg("HexraysPython: Python compiled with DEBUG enabled.\n");
#endif

  qstring dynload_base;
  if ( !qgetenv("IDAPYTHON_DYNLOAD_BASE", &dynload_base) )
    dynload_base = idadir(nullptr);

  // Set IDAPYTHON_VERSION in Python
  qstring init_code;
  init_code.sprnt(
          "IDAPYTHON_VERSION=(%d, %d, %d, '%s', %d)\n"
          "IDAPYTHON_REMOVE_CWD_SYS_PATH = %s\n"
          "IDAPYTHON_DYNLOAD_BASE = r\"%s\"\n"
          "IDAPYTHON_DYNLOAD_RELPATH = \"ida_%" FMT_Z "\"\n"
          "IDAPYTHON_COMPAT_AUTOIMPORT_MODULES = %s\n"
          "IDAPYTHON_IDAUSR_SYSPATH = %s\n",
          VER_MAJOR, VER_MINOR, VER_PATCH, VER_STATUS, VER_SERIAL,
          config.remove_cwd_sys_path ? "True" : "False",
          dynload_base.c_str(),
          sizeof(ea_t)*8,
          config.autoimport_compat_idaapi ? "True" : "False",
          config.idausr_syspath ? "True" : "False"
                  );

  if ( extapi.PyRun_SimpleStringFlags_ptr(init_code.c_str(), nullptr) != 0 )
  {
    warning("IDAPython: error executing bootstrap code");
    return false;
  }

  // Install extlang. Needs to be done before running init.py
  // in case it's calling idaapi.enable_extlang_python(1)
  if ( config.namespace_aware )
    extlang_python.flags |= EXTLANG_NS_AWARE;
  install_extlang(&extlang_python);

  // Execute init.py (for Python side initialization)
  if ( !_run_init_py() )
  {
    // Try to fetch a one line error string. We must do it before printing
    // the traceback information. Make sure that the exception is not cleared
    handle_python_error(&errbuf, false);

    // Print the exception traceback
    extapi.PyRun_SimpleStringFlags_ptr("import traceback;traceback.print_exc();", nullptr);

    warning("IDAPython: error executing " S_INIT_PY ":\n"
            "%s\n"
            "\n"
            "Refer to the message window to see the full error log.", errbuf.c_str());
    remove_extlang(&extlang_python);
    return false;
  }

  // Init pywraps and notify_when
  if ( !init_pywraps() )
  {
    warning("IDAPython: init_pywraps() failed!");
    remove_extlang(&extlang_python);
    return false;
  }

  // Register a exec_python() function for IDC
  add_idc_func(idc_runpythonstatement_desc);
  add_idc_func(idc_eval_python_desc);

  // A script specified on the command line is run
  if ( config.run_script.when == RSW_on_init )
    _run_user_script();

  hook_event_listener(HT_UI, this);
  hook_to_notification_point(HT_IDB, on_idb_notification, this);

  // Enable the CLI by default
  enable_python_cli(true);

  // Let all modules perform possible initialization
  send_modules_lifecycle_notification(mln_init);

  PyEval_ReleaseThread(PyThreadState_Get());

  initialized = true;
  return true;
}

//------------------------------------------------------------------------
// Parse plugin options
void idapython_plugin_t::parse_plugin_options()
{
  // Get options from IDA
  const char *options = get_plugin_options(S_IDAPYTHON);
  if ( options == nullptr || options[0] == '\0' )
    return;
  qstring obuf(options);
  char *ctx;
  for ( char *p = qstrtok(obuf.begin(), ";", &ctx);
        p != nullptr;
        p = qstrtok(nullptr, ";", &ctx) )
  {
    qstring opt(p);
    char *sep = qstrchr(opt.begin(), '=');
    bool ok = sep != nullptr;
    if ( ok )
    {
      *sep++ = '\0';
      if ( opt == "run_script" )
      {
        config.run_script.path = sep;
        if ( config.run_script.when == RSW_UNKNOWN )
          config.run_script.when = RSW_ui_database_inited;
      }
      else if ( opt == "run_script_when" )
      {
        qstring when(sep);
        if ( when == "db_open" )
          config.run_script.when = RSW_ui_database_inited;
        else if ( when == "ui_ready" )
          config.run_script.when = RSW_ui_ready_to_run;
        else if ( when == "init" )
          config.run_script.when = RSW_on_init;
        else
          warning("Unknown 'run_script_when' directive: '%s'. "
                  "Valid values are: 'db_open', 'ui_ready' and 'init'",
                  when.c_str());
      }
      else if ( opt == "IDAPYTHON_IDAUSR_SYSPATH" )
      {
        qstring imp(sep);
        if ( imp == "YES" )
          config.idausr_syspath = true;
        else if ( imp == "NO" )
          config.idausr_syspath = false;
        else
          warning("Unknown 'IDAPYTHON_IDAUSR_SYSPATH' directive: '%s'. "
                  " Expected 'YES' or 'NO'", imp.c_str());
      }
      else
      {
        warning("Unknown config directive: \"%s\"", opt.c_str());
      }
    }
  }
}

//-------------------------------------------------------------------------
ref_t idapython_plugin_t::get_sys_displayhook()
{
  ref_t h;
  if ( config.repl_use_sys_displayhook )
  {
    if ( ref_t py_sys = ref_t(PyW_TryImportModule("sys")) )
      h = PyW_TryGetAttrString(py_sys.o, "displayhook");
  }
  return h;
}

//-------------------------------------------------------------------------
#ifdef TESTABLE_BUILD
// "user-code-leniency" means that, even in TESTABLE_BUILD builds,
// IDAPython will accept that some things are left in an undesirable,
// but recuperable state (e.g., remaining hooks.)
// This should *ONLY* be used for tests that rely on user code that
// is in such a shape that it would require significant changes to
// have it perform proper cleanup, which means that it would have to
// diverge from the original user's code, which means that we
// would have to maintain our own branch of it, which is not
// the best idea of the world, overhead-wise.
bool idapython_plugin_t::is_user_code_lenient()
{
  if ( user_code_lenient < 0 )
    user_code_lenient = qgetenv("IDAPYTHON_USER_CODE_LENIENT");
  return user_code_lenient > 0;
}
#endif

//-------------------------------------------------------------------------
bool idaapi idapython_plugin_t::run(size_t arg)
{
  try
  {
    switch ( arg )
    {
      case IDAPYTHON_RUNSTATEMENT:
        {
          // Execute Python statement(s) from an editor window
          qstring qbuf;
          netnode history;

          // Get the existing or create a new netnode in the database
          history.create(S_IDAPYTHON_DATA_NODE);
          history.getblob(&qbuf, 0, 'A');

          if ( ask_text(&qbuf, 0, qbuf.c_str(), "ACCEPT TABS\nEnter Python expressions") )
          {
            {
              PYW_GIL_GET;
              new_execution_t exec;
              extapi.PyRun_SimpleStringFlags_ptr(qbuf.c_str(), nullptr);
            }

            // Store the statement to the database
            history.setblob(qbuf.c_str(), qbuf.size(), 0, 'A');
          }
        }
        break;
      case IDAPYTHON_ENABLE_EXTLANG:
        enable_extlang_python(true);
        break;
      case IDAPYTHON_DISABLE_EXTLANG:
        enable_extlang_python(false);
        break;
      default:
        warning("IDAPython: unknown plugin argument %d", int(arg));
        break;
    }
  }
  catch(...)    //lint !e1766 without preceding catch clause
  {
    ask_for_feedback("Exception in Python interpreter.");
  }
  return true;
}

//------------------------------------------------------------------------
//lint -esym(715,va) Symbol not referenced
ssize_t idaapi idapython_plugin_t::on_event(ssize_t code, va_list)
{
  switch ( code )
  {
    case ui_database_closed:
      {
        PYW_GIL_GET; // This hook gets called from the kernel. Ensure we hold the GIL.
        // Let's make sure there are no non-Free()d forms.
        free_compiled_form_instances();
        // and no live python timers
        // Note: It's ok to put this here, because 'ui_datanase_closed' is guaranteed
        // to be sent before the PLUGIN_FIX plugins are terminated.
        clear_python_timer_instances();
      }
      break;

    case ui_ready_to_run:
      {
        PYW_GIL_GET; // See above
        ui_ready = true;
        extapi.PyRun_SimpleStringFlags_ptr("print_banner()", nullptr);
        if ( config.run_script.when == RSW_ui_ready_to_run )
          _run_user_script();
      }
      break;

    case ui_database_inited:
      {
        PYW_GIL_GET; // See above
        convert_idc_args();
        if ( config.run_script.when == RSW_ui_database_inited )
          _run_user_script();
      }
      break;

    default:
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
//lint -esym(526,til_clear_python_tinfo_t_instances) not defined
ssize_t idaapi idapython_plugin_t::on_idb_notification(void *, int code, va_list)
{
  switch ( code )
  {
    case idb_event::closebase:
      // The til machinery is about to garbage-collect: We must go
      // through all the tinfo_t objects that are embedded in SWIG wrappers,
      // (i.e., that were created from Python) and clear those.
      til_clear_python_tinfo_t_instances();
      send_modules_lifecycle_notification(mln_closebase);
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
// Compile callback for Python external language evaluator
bool idapython_plugin_t::_extlang_compile_file(
        const char *path,
        qstring *errbuf)
{
  PYW_GIL_GET;
  new_execution_t exec;
  PyObject *globals = _get_module_globals_from_path(path);
  return _handle_file(path, globals, errbuf);
}

//-------------------------------------------------------------------------
static PyObject *my_CompileString(
        const char *str,
        const char *file,
        int start)
{
#if PY_MAJOR_VERSION < 3
  return extapi.Py_CompileString_ptr(str, file, start);
#else
  return extapi.Py_CompileStringExFlags_ptr(str, file, start, nullptr, -1);
#endif
}

//-------------------------------------------------------------------------
// Compile callback for Python external language evaluator
bool idapython_plugin_t::_extlang_compile_expr(
        const char *name,
        ea_t /*current_ea*/,
        const char *expr,
        qstring *errbuf)
{
  PYW_GIL_GET;
  PyObject *globals = _get_module_globals();
  bool isfunc = false;

  qstring qstr(expr);
  PyObject *code = my_CompileString(insert_encoding_cookie(&qstr), "<string>", Py_eval_input);
  if ( code == nullptr )
  {
    // try compiling as a list of statements
    // wrap them into a function
    handle_python_error(errbuf);
    qstring func;
    wrap_in_function(&func, expr, name);
    insert_encoding_cookie(&func);
    code = my_CompileString(func.c_str(), "<string>", Py_file_input);
    if ( code == nullptr )
    {
      handle_python_error(errbuf);
      return false;
    }
    isfunc = true;
  }

  // Create a function out of code
  PyObject *func = extapi.PyFunction_New_ptr(code, globals);

  if ( func == nullptr )
  {
ERR:
    handle_python_error(errbuf);
    Py_XDECREF(code);
    return false;
  }

  int err = PyDict_SetItemString(globals, name, func);
  Py_XDECREF(func);

  if ( err )
    goto ERR;

  if ( isfunc )
  {
    idc_value_t result;
    return _extlang_call_func(&result, name, nullptr, 0, errbuf);
  }

  return true;
}

//-------------------------------------------------------------------------
// Calculator callback for Python external language evaluator
//lint -e{818}
bool idapython_plugin_t::_extlang_eval_expr(
        idc_value_t *rv,
        ea_t /*current_ea*/,
        const char *expr,
        qstring *errbuf)
{
  PYW_GIL_GET;
  PyObject *globals = _get_module_globals();
  bool ok = globals != nullptr;
  ref_t result;
  if ( ok )
  {
    {
      new_execution_t exec;
      result = newref_t(extapi.PyRun_StringFlags_ptr(expr, Py_eval_input, globals, globals, nullptr));
    }
    ok = return_python_result(rv, result, errbuf);
  }
  return ok;
}

//-------------------------------------------------------------------------
// Load processor module callback for Python external language evaluator
bool idapython_plugin_t::_extlang_load_procmod(
        idc_value_t *procobj,
        const char *path,
        qstring *errbuf)
{
  PYW_GIL_GET;
  bool ok;
  {
    new_execution_t exec;
    PyObject *globals = _get_module_globals_from_path(path);
    ok = _handle_file(path, globals, errbuf, S_IDAAPI_LOADPROCMOD, procobj, /*want_tuple=*/ true);
  }
  if ( ok && procobj->is_zero() )
  {
    errbuf->clear();
    ok = false;
  }
  return ok;
}

//-------------------------------------------------------------------------
// Unload processor module callback for Python external language evaluator
bool idapython_plugin_t::_extlang_unload_procmod(
        const char *path,
        qstring *errbuf)
{
  PYW_GIL_GET;
  new_execution_t exec;
  PyObject *globals = _get_module_globals_from_path(path);
  return _handle_file(path, globals, errbuf, S_IDAAPI_UNLOADPROCMOD);
}

//-------------------------------------------------------------------------
// Create an object instance
//lint -e605 Increase in pointer capability
bool idapython_plugin_t::_extlang_create_object(
        idc_value_t *result,      // out: created object or exception
        const char *name,         // in: object class name
        const idc_value_t args[], // in: input arguments
        size_t nargs,             // in: number of input arguments
        qstring *errbuf)          // out: error message if evaluation fails
{
  PYW_GIL_GET;
  bool ok = false;
  ref_vec_t pargs;
  do
  {
    // Parse the object name (to get the module and class name)
    char modname[MAXSTR];
    char clsname[MAXSTR];
    parse_py_modname(name, modname, clsname, MAXSTR);

    // Get a reference to the module
    ref_t py_mod(PyW_TryImportModule(modname));
    if ( !py_mod )
    {
      errbuf->sprnt("Could not import module '%s'!", modname);
      break;
    }

    // If the class provides an wraper instantiator, use that
    ref_t py_res;
    if ( nargs == 1 && args[0].vtype == VT_PVOID )
      py_res = try_create_swig_wrapper(py_mod, clsname, args[0].pvoid);
    if ( py_res )
    {
      PyObject_SetAttrString(py_res.o, S_PY_IDCCVT_ID_ATTR, PyLong_FromLong(PY_ICID_OPAQUE));
    }
    else
    {
      // Get the class reference
      ref_t py_cls(PyW_TryGetAttrString(py_mod.o, clsname));
      if ( !py_cls )
      {
        errbuf->sprnt("Could not find class type '%s'!", clsname);
        break;
      }

      // Error during conversion?
      ok = pyw_convert_idc_args(args, nargs, pargs, PYWCVTF_AS_TUPLE, errbuf);
      if ( !ok )
        break;

      // Call the constructor
      py_res = newref_t(PyObject_CallObject(py_cls.o, pargs.empty() ? nullptr : pargs[0].o));
    }
    ok = return_python_result(result, py_res, errbuf);
  } while ( false );

  return ok;
}

//------------------------------------------------------------------------
// Executes a simple string
bool idapython_plugin_t::_extlang_eval_snippet(
        const char *str,
        qstring *errbuf)
{
  PYW_GIL_GET;
#ifdef TESTABLE_BUILD
  QASSERT(30639, PyErr_Occurred() == nullptr);
#endif
  PyObject *globals = _get_module_globals();
  bool ok;
  if ( globals == nullptr )
  {
    ok = false;
  }
  else
  {
    errbuf->clear();
    PyErr_Clear();
    {
      new_execution_t exec;
      newref_t result(extapi.PyRun_StringFlags_ptr(
                              str,
                              Py_file_input,
                              globals,
                              globals,
                              nullptr));
      ok = result && !PyErr_Occurred(); //-V560 is always true: !PyErr_Occurred()
      if ( !ok )
        handle_python_error(errbuf);
    }
  }
  if ( !ok && errbuf->empty() )
    *errbuf = "internal error";
  return ok;
}

//-------------------------------------------------------------------------
// Run callback for Python external language evaluator
bool idapython_plugin_t::_extlang_call_func(
        idc_value_t *result,
        const char *name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf)
{
  PYW_GIL_GET;
  // Try to extract module name (if any) from the funcname
  char modname[MAXSTR];
  char funcname[MAXSTR];
  bool imported_module = parse_py_modname(name, modname, funcname, MAXSTR);

  bool ok = true;
  PyObject *module = nullptr;
  ref_vec_t pargs;
  do
  {
    // Convert arguments to python
    ok = pyw_convert_idc_args(args, nargs, pargs, 0, errbuf);
    if ( !ok )
      break;

    const char *final_modname = imported_module ? modname : S_MAIN;
    module = PyImport_ImportModule(final_modname);
    if ( module == nullptr )
    {
      if ( errbuf != nullptr )
        errbuf->sprnt("couldn't import module %s", final_modname);
      ok = false;
      break;
    }

    PyObject *globals = PyModule_GetDict(module);
    QASSERT(30157, globals != nullptr);

    PyObject *func = PyDict_GetItemString(globals, funcname);
    if ( func == nullptr )
    {
      if ( errbuf != nullptr )
        errbuf->sprnt("undefined function %s", name);
      ok = false;
      break;
    }

    borref_t code(extapi.PyFunction_GetCode_ptr(func));
    qvector<PyObject*> pargs_ptrs;
    pargs.to_pyobject_pointers(&pargs_ptrs);
    newref_t py_res(PyEval_EvalCodeEx(
                            code.o,
                            globals, nullptr,
                            pargs_ptrs.begin(),
                            nargs,
                            nullptr, 0, nullptr, 0, nullptr, nullptr));
    ok = return_python_result(result, py_res, errbuf);
  } while ( false );

  if ( imported_module )
    Py_XDECREF(module);
  return ok;
}

//-------------------------------------------------------------------------
static bool is_instance_of(PyObject *obj, PyObject *mod, const char *cls_name)
{
  ref_t py_plugin_t_cls(PyW_TryGetAttrString(mod, cls_name));
  return py_plugin_t_cls != nullptr && PyObject_IsInstance(obj, py_plugin_t_cls.o);
}

//-------------------------------------------------------------------------
bool idapython_plugin_t::_extlang_call_method(
        idc_value_t *result,
        const idc_value_t *idc_obj,
        const char *method_name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf)
{
  PYW_GIL_GET;
  // Check for unsupported usage of call_method.
  // Mainly a method call requires an object and a method.
  if ( method_name == nullptr )
  {
    *errbuf = "call_method does not support this operation";
    return false;
  }
  // Behave like run()
  else if ( idc_obj == nullptr )
  {
    new_execution_t exec;
    return _extlang_call_func(result, method_name, args, nargs, errbuf);
  }

  // Holds conversion status of input object
  int obj_cvt;
  bool ok = false;
  ref_vec_t pargs;
  do
  {
    // Convert input object
    ref_t py_obj;
    obj_cvt = idcvar_to_pyvar(*idc_obj, &py_obj);
    if ( obj_cvt < CIP_OK )
    {
      *errbuf = "Failed to convert input object to Python value";
      break;
    }

    ref_t py_method(PyW_TryGetAttrString(py_obj.o, method_name));
    if ( !py_method || !PyCallable_Check(py_method.o) )
    {
      errbuf->sprnt("The input object does not have a callable method called '%s'", method_name);
      break;
    }

    // Convert arguments to python objects
    uint32 cvtflags = PYWCVTF_AS_TUPLE;
    // if we are running a ida_idaapi.plugin_t.run, we want the 'int64'
    // to be converted to an unsigned python long
    if ( streq(method_name, "run") )
    {
      if ( ref_t py_ida_idaapi_mod = ref_t(PyW_TryImportModule(S_IDA_IDAAPI_MODNAME)) )
      {
        if ( is_instance_of(py_obj.o, py_ida_idaapi_mod.o, "plugin_t")
          || is_instance_of(py_obj.o, py_ida_idaapi_mod.o, "plugmod_t") )
        {
          cvtflags |= PYWCVTF_INT64_AS_UNSIGNED_PYLONG;
        }
      }
    }
    ok = pyw_convert_idc_args(args, nargs, pargs, cvtflags, errbuf);
    if ( !ok )
      break;

    {
      new_execution_t exec;
      newref_t py_res(PyObject_CallObject(py_method.o, pargs.empty() ? nullptr : pargs[0].o));
      ok = return_python_result(result, py_res, errbuf);
    }
  } while ( false );

  return ok;
}

//-------------------------------------------------------------------------
// Returns the attribute value of a given object from the global scope
bool idapython_plugin_t::_extlang_get_attr(
        idc_value_t *result,    // out: result
        const idc_value_t *obj, // in: object (may be nullptr)
        const char *attr)       // in: attribute name
{
  PYW_GIL_GET;
  int cvt = CIP_FAILED;
  do
  {
    // Get a reference to the module
    ref_t py_mod(PyW_TryImportModule(S_MAIN));
    if ( !py_mod )
      break;

    // Object specified:
    // - (1) string contain attribute name in the main module
    // - (2) opaque object (we use it as is)
    ref_t py_obj;
    if ( obj )
    {
      // (1) Get attribute from main module
      if ( obj->vtype == VT_STR )
      {
        py_obj = PyW_TryGetAttrString(py_mod.o, obj->c_str());
      }
      // (2) see if opaque object
      else
      {
        // Convert object (expecting opaque object)
        cvt = idcvar_to_pyvar(*obj, &py_obj);
        if ( cvt != CIP_OK_OPAQUE ) // Only opaque objects are accepted
        {
          py_obj = ref_t();
          cvt = CIP_FAILED;
          break;
        }
      }
      // Get the attribute reference
      if ( !py_obj )
        break;
    }
    // No object specified:
    else
    {
      // ...then work with main module
      py_obj = py_mod;
    }
    // Special case: if attribute not passed then retrieve the class
    // name associated associated with the passed object
    if ( attr == nullptr || attr[0] == '\0' )
    {
      cvt = CIP_FAILED;
      // Get the class
      newref_t cls(PyObject_GetAttrString(py_obj.o, "__class__"));
      if ( !cls )
        break;

      // Get its name
      newref_t name(PyObject_GetAttrString(cls.o, "__name__"));
      if ( !name )
        break;

      // Convert name object to string object
      newref_t string(PyObject_Str(name.o));
      if ( !string )
        break;

      // Convert name python string to a C string
      qstring clsname;
      if ( !PyUnicode_as_qstring(&clsname, string.o) )
        break;

      result->set_string(clsname);  //-V595 'result' was utilized before it was verified against nullptr
      cvt = CIP_OK; //lint !e838
      break;
    }

    ref_t py_attr(PyW_TryGetAttrString(py_obj.o, attr));
    // No attribute?
    if ( !py_attr )
    {
      cvt = CIP_FAILED;
      break;
    }
    // Don't store result
    if ( result == nullptr )
    {
      cvt = CIP_OK;
      // Decrement attribute (because of GetAttrString)
    }
    else
    {
      cvt = pyvar_to_idcvar(py_attr, result);
      // // Conversion succeeded and opaque object was passed:
      // // Since the object will be passed to IDC, it is likely that IDC value will be
      // // destroyed and also destroying the opaque object with it. That is an undesired effect.
      // // We increment the reference of the object so that even if the IDC value dies
      // // the opaque object remains. So by not decrement reference after GetAttrString() call
      // // we are indirectly increasing the reference. If it was not opaque then we decrement the reference.
      // if ( cvt >= CIP_OK && cvt != CIP_OK_NODECREF )
      // {
      //   // Decrement the reference (that was incremented by GetAttrString())
      //   py_attr.decref();
      // }
    }
  } while ( false );
  return cvt >= CIP_OK;
}

//-------------------------------------------------------------------------
// Returns the attribute value of a given object from the global scope
//lint -e{818}
bool idapython_plugin_t::_extlang_set_attr(
        idc_value_t *obj,       // in: object name (may be nullptr)
        const char *attr,       // in: attribute name
        const idc_value_t &value)
{
  PYW_GIL_GET;
  bool ok = false;
  do
  {
    // Get a reference to the module
    ref_t py_mod(PyW_TryImportModule(S_MAIN));
    if ( !py_mod )
      break;
    ref_t py_obj;
    if ( obj != nullptr )
    {
      // Get the attribute reference (from just a name)
      if ( obj->vtype == VT_STR )
      {
        py_obj = PyW_TryGetAttrString(py_mod.o, obj->c_str());
      }
      else
      {
        int cvt = idcvar_to_pyvar(*obj, &py_obj);
        if ( cvt != CIP_OK_OPAQUE )  // Only opaque objects are accepted
          py_obj = ref_t();
      }
      // No object to set_attr on?
      if ( !py_obj )
        break;
    }
    else
    {
      // set_attr on the main module
      py_obj = py_mod;
    }
    // Convert the value
    ref_t py_var;
    int cvt = idcvar_to_pyvar(value, &py_var);
    if ( cvt >= CIP_OK )
    {
      ok = PyObject_SetAttrString(py_obj.o, attr, py_var.o) != -1;
      // if ( cvt != CIP_OK_NODECREF )
      //   Py_XDECREF(py_var);
    }
  } while ( false );
  return ok;
}

//-------------------------------------------------------------------------
// Execute a line in the Python CLI
bool idapython_plugin_t::_cli_execute_line(const char *line)
{
  PYW_GIL_GET;

  // Do not process empty lines
  if ( line[0] == '\0' )
    return true;

  const char *last_line = strrchr(line, '\n');
  if ( last_line == nullptr )
    last_line = line;
  else
    last_line += 1;

  // Skip empty lines
  if ( last_line[0] != '\0' )
  {
    // Line ends with ":" or begins with a space character?
    bool more = last_line[qstrlen(last_line)-1] == ':' || qisspace(last_line[0]);
    if ( more )
      return false;
  }

  //
  // Pseudo commands
  //
  qstring s;
  do
  {
    // Help command?
    if ( line[0] == '?' )
      s.sprnt("help(%s)", line+1);
    // Shell command?
    else if ( line[0] == '!' )
      s.sprnt("idaapi.IDAPython_ExecSystem(r'%s')", line+1);
    else
      break;
    // Patch the command line pointer
    line = s.c_str();
  } while (false);

  {
    new_execution_t exec;

    // Compile as an expression
    qstring qstr(line);
    newref_t py_code(my_CompileString(insert_encoding_cookie(&qstr), "<string>", Py_eval_input));
    if ( !py_code || PyErr_Occurred() )
    {
      // Not an expression?
      PyErr_Clear();

      // Run as a string
      extapi.PyRun_SimpleStringFlags_ptr(line, nullptr);
    }
    else
    {
      PyObject *py_globals = _get_module_globals();
      newref_t py_result(PyEval_EvalCode(py_code.o, py_globals, py_globals));

      if ( !py_result || PyErr_Occurred() )    //-V560 is always false: PyErr_Occurred()
      {
        PyErr_Print();
      }
      else
      {
        ref_t sys_displayhook(idapython_plugin_t::get_instance()->get_sys_displayhook());
        if ( sys_displayhook != nullptr )
        {
          //lint -esym(1788, res) is referenced only by its constructor or destructor
          newref_t res(PyObject_CallFunctionObjArgs(sys_displayhook.o, py_result.o, nullptr));
        }
        else if ( py_result.o != Py_None )
        {
          bool ok = false;
          if ( PyUnicode_Check(py_result.o) )
          {
            qstring utf8;
            PyUnicode_as_qstring(&utf8, py_result.o);
            msg("%s\n", utf8.c_str());
          }
          else
          {
            qstring result_str;
            ok = PyW_ObjectToString(py_result.o, &result_str);
            if ( ok )
              msg("%s\n", result_str.c_str());
          }

          if ( !ok )
            msg("*** IDAPython: Couldn't convert evaluation result\n");
        }
      }
    }
  }

  return true;
}

//-------------------------------------------------------------------------
bool idapython_plugin_t::_cli_find_completions(
        qstrvec_t *out_completions,
        int *out_match_start,
        int *out_match_end,
        const char *line,
        int x)
{
  PYW_GIL_GET;

  ref_t py_fc(get_idaapi_attr(S_IDAAPI_FINDCOMPLETIONS));
  if ( !py_fc )
    return false;

  newref_t py_res(PyObject_CallFunction(py_fc.o, "si", line, x)); //lint !e605 !e1776
  if ( PyErr_Occurred() != nullptr )
    return false;
  return idapython_convert_cli_completions(
          out_completions,
          out_match_start,
          out_match_end,
          py_res);
}

//-------------------------------------------------------------------------
// This function will call the Python function 'idaapi.IDAPython_ExecFile'
// It does not use 'import', thus the executed script will not yield a new module name
// It returns the exception and traceback information.
// We use the Python function to execute the script because it knows how to deal with
// module reloading.
bool idapython_plugin_t::_handle_file(
        const char *path,
        PyObject *globals,
        qstring *errbuf,
        const char *idaapi_executor_func_name,
        idc_value_t *second_res,
        bool want_tuple)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_executor_func(get_idaapi_attr(idaapi_executor_func_name));
  if ( !py_executor_func )
  {
    errbuf->sprnt("Could not find %s.%s ?!", S_IDA_IDAAPI_MODNAME, idaapi_executor_func_name);
    return false;
  }

  char script[MAXSTR];
  qstrncpy(script, path, sizeof(script));
  strrpl(script, '\\', '/');
  newref_t py_script(PyUnicode_FromString(script));

  if ( globals == nullptr )
    globals = _get_module_globals();
  if ( globals != _get_module_globals() )
  {
    // Executions that take place in the scope of their own module,
    // should have the '__file__' attribute properly set (so that
    // it doesn't just get temporarily set and then removed by
    // `ida_idaapi.IDAPython_ExecScript`.
    newref_t py_file_key(PyUnicode_FromString(S_FILE));
    if ( !PyDict_Contains(globals, py_file_key.o) )
      PyDict_SetItem(globals, py_file_key.o, py_script.o);
  }
  borref_t py_false(Py_False);
  newref_t py_ret(PyObject_CallFunctionObjArgs(
                          py_executor_func.o,
                          py_script.o,
                          globals,
                          py_false.o,
                          nullptr));

  // Failure at this point means the script was interrupted
  bool interrupted = false;
  if ( PyW_GetError(errbuf) || !py_ret )
  {
    PyErr_Clear();
    if ( errbuf->empty() )
      *errbuf = "Script interrupted";
    interrupted = true;
  }

  bool ok = false;
  if ( !interrupted )
  {
    PyObject *ret_o;
    if ( want_tuple )
    {
      if ( second_res != nullptr
        && PyTuple_Check(py_ret.o)
        && PyTuple_Size(py_ret.o) == 2 )
      {
        ret_o = PyTuple_GetItem(py_ret.o, 0);   // Borrowed reference
      }
      else
      {
        INTERR(30444);
      }
    }
    else
    {
      ret_o = py_ret.o;
    }

    if ( ret_o == Py_None )   //-V614 uninitialized 'ret_o'
    {
      if ( want_tuple )
      {
        borref_t ret2_o(PyTuple_GetItem(py_ret.o, 1));
        ok = return_python_result(second_res, ret2_o, errbuf);
      }
      else
      {
        ok = true;
      }
    }
    else if ( PyUnicode_Check(ret_o) )
    {
      PyUnicode_as_qstring(errbuf, ret_o);
    }
    else
    {
      INTERR(30154);
    }
  }
  return ok;
}

//-------------------------------------------------------------------------
// Execute the Python script from the plugin
bool idapython_plugin_t::_run_user_script()
{
  qstring errbuf;
  const char *path = config.run_script.path.c_str();
  bool ok;
  {
    new_execution_t exec;
    ok = _handle_file(path, /*globals*/ nullptr, &errbuf);
  }
  if ( !ok )
    warning("IDAPython: error executing '%s':\n%s", path, errbuf.c_str());

  return ok;
}

//-------------------------------------------------------------------------
// Check for the presence of a file in IDADIR/python and complain on error
bool idapython_plugin_t::_check_python_dir()
{
  static const char *const script_files[] =
  {
    S_IDC_MODNAME ".py",
    S_INIT_PY,
    "ida_idaapi.py",
    "idautils.py"
  };
  char filepath[QMAXPATH];
  for ( size_t i=0; i < qnumber(script_files); i++ )
  {
    qmakepath(filepath, sizeof(filepath), idapython_dir.c_str(), script_files[i], nullptr);
    if ( !qfileexist(filepath) )
    {
      warning("IDAPython: Missing required file: '%s'", script_files[i]);
      return false;
    }
  }

  return true;
}

//-------------------------------------------------------------------------
// - remove current directory (empty entry) from the sys.path
// - add idadir("python")
void idapython_plugin_t::_prepare_sys_path()
{
  borref_t path(PySys_GetObject((char *) "path"));
  if ( !path || !PySequence_Check(path.o) )
    return;

  qstring new_path;
  Py_ssize_t path_len = PySequence_Size(path.o);
  if ( path_len > 0 )
  {
    for ( Py_ssize_t i = 0; i < path_len; ++i )
    {
      qstring path_el_utf8;
      newref_t path_el(PySequence_GetItem(path.o, i));
      if ( path_el
        && PyUnicode_Check(path_el.o)
        && PyUnicode_as_qstring(&path_el_utf8, path_el.o) )
      {
        if ( path_el_utf8.empty() )
          continue; // skip empty entry
        if ( !new_path.empty() )
          new_path.append(DELIMITER);
        new_path.append(path_el_utf8);
      }
    }
  }
  if ( !new_path.empty() )
    new_path.append(DELIMITER);
  new_path.append(idadir("python"));
  qvector<wchar_t> wpath;
  PySys_SetPath(utf8_wchar_t(&wpath, new_path.c_str()));
}

//-------------------------------------------------------------------------
// This function will execute a script in the main module context
// It does not use 'import', thus the executed script will not yield a new module name
// Caller of this function should call handle_python_error() to clear the exception and print the error
bool idapython_plugin_t::_run_init_py()
{
  char path[QMAXPATH];
  qmakepath(path, sizeof(path), idapython_dir.c_str(), S_INIT_PY, nullptr);

#ifdef __NT__
  // if the current disk has no space (sic, the current directory, not the one
  // with the input file), PyRun_File() will die with a cryptic message that
  // C runtime library could not be loaded. So we check the disk space before
  // calling it.
  char curdir[QMAXPATH];
  // check if the current directory is accessible. if not, qgetcwd won't return
  qgetcwd(curdir, sizeof(curdir));
  if ( get_free_disk_space(curdir) == 0 )
  {
    warning("No free disk space on %s, python will not be available", curdir);
    return false;
  }
#endif

  PYW_GIL_CHECK_LOCKED_SCOPE();

  PyObject *__main__globals = _get_module_globals();

  //lint -esym(429, fp) custodial pointer not freed or returned
  FILE *fp = qfopen(path, "rt");
  if ( fp == nullptr )
    return false;
  file_janitor_t fpj(fp);
  qstring contents;
  const uint64 fpsz = qfsize(fp);
  if ( fpsz == 0 )
    return false;
  contents.resize(fpsz);
  ssize_t effsz = qfread(fp, contents.begin(), fpsz);
  if ( effsz <= 0 )
    return false;
  contents.resize(effsz);

  newref_t code(my_CompileString(contents.c_str(), path, Py_file_input));
  if ( !code )
    return false;

  newref_t result(PyEval_EvalCode(code.o, __main__globals, __main__globals));
  return result && !PyErr_Occurred();
}

//------------------------------------------------------------------------
// Note: The references are borrowed. No need to free them.
PyObject *idapython_plugin_t::_get_module_globals(const char *modname)
{
  if ( modname == nullptr || modname[0] == '\0' )
    modname = S_MAIN;
  PyObject *module = PyImport_AddModule(modname);
  return module == nullptr ? nullptr : PyModule_GetDict(module);
}

//-------------------------------------------------------------------------
PyObject *idapython_plugin_t::_get_module_globals_from_path_with_kind(
        const char *path,
        const char *kind)
{
  const char *fname = qbasename(path);
  if ( fname != nullptr )
  {
    const char *ext = get_file_ext(fname);
    if ( ext == nullptr )
      ext = tail(fname);
    else
      --ext;
    if ( ext > fname )
    {
      int len = ext - fname;
      qstring modname;
      modname.sprnt("__%s__%*.*s", kind, len, len, fname);
      return _get_module_globals(modname.begin());
    }
  }
  return nullptr;
}

//-------------------------------------------------------------------------
PyObject *idapython_plugin_t::_get_module_globals_from_path(
        const char *path)
{
  if ( (extlang_python.flags & EXTLANG_NS_AWARE) != 0 )
  {
    if ( requested_plugin_path == path )
      return _get_module_globals_from_path_with_kind(path, PLG_SUBDIR);

    char dirpath[QMAXPATH];
    if ( qdirname(dirpath, sizeof(dirpath), path) )
    {
      const char *dirname = qbasename(dirpath);
      if ( streq(dirname, PLG_SUBDIR)
        || streq(dirname, IDP_SUBDIR)
        || streq(dirname, LDR_SUBDIR) )
      {
        return _get_module_globals_from_path_with_kind(path, dirname);
      }
    }
  }
  return nullptr;
}

//-------------------------------------------------------------------------
// Plugin init routine
static plugmod_t *idaapi init()
{
  idapython_plugin_t *p = new idapython_plugin_t;
  if ( p->init() )
    return p;
  delete p;
  return nullptr;
}

//-------------------------------------------------------------------------
// PLUGIN DESCRIPTION BLOCK
//-------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_FIX | PLUGIN_HIDE | PLUGIN_MULTI, // plugin flags
  init,          // initialize
  nullptr,       // terminate. this pointer may be nullptr.
  nullptr,       // invoke plugin
  S_IDAPYTHON,   // long comment about the plugin
                 // it could appear in the status line
                 // or as a hint
  // multiline help about the plugin
  "IDA Python Plugin\n",
  // the preferred short name of the plugin
  S_IDAPYTHON,
  // the preferred hotkey to run the plugin
  nullptr
};
