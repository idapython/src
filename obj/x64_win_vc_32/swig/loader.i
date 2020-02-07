%module(docstring="IDA Plugin SDK API wrapper: loader",directors="1",threads="1") ida_loader
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_LOADER
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_LOADER
  #define HAS_DEP_ON_INTERFACE_LOADER
#endif
%include "header.i"
// Ignore callback members
%ignore loader_t::accept_file;
%ignore loader_t::load_file;
%ignore loader_t::save_file;
%ignore loader_t::move_segm;
%ignore loader_t::process_archive;
%ignore plugin_t;

%ignore vloader_failure;
%ignore loader_failure;

// TODO: These could be wrapped if needed
%ignore load_info_t;
%ignore get_plugins_paths;
%ignore build_loaders_list;
%ignore free_loaders_list;
%ignore get_loader_name_from_dll;
%ignore get_loader_name;
%ignore load_nonbinary_file;
%ignore impinfo_t;
%ignore import_module;
%ignore get_plugins;
%ignore invoke_plugin;
%ignore dbg_info_t;
%ignore get_debugger_plugins;
%ignore init_plugins;
%ignore term_plugins;

// Callback and loader-only symbols are ignored (for now)
%ignore html_header_cb_t;
%ignore html_footer_cb_t;
%ignore html_line_cb_t;
%ignore gen_outline_t;
%ignore create_filename_cmt;

// Ignore kernel-only & unexported symbols
%ignore LDSC;
%ignore PLUGIN;
%ignore LNE_MAXSEG;
%ignore dlldata;
%ignore DLLDATASTART;
%ignore ldrdata;
%ignore LDRDATASTART;
%ignore idadll_t;
%ignore load_dll;
%ignore RE_NOFILE;
%ignore RE_NOTIDP;
%ignore RE_NOPAGE;
%ignore RE_NOLINK;
%ignore RE_BADRTP;
%ignore RE_BADORD;
%ignore RE_BADATP;
%ignore RE_BADMAP;
%ignore load_dll_or_die;
%ignore load_core_module;
%ignore load_core_module_or_die;
%ignore _load_core_module;
%ignore free_dll;
%ignore IDP_DESC_START;
%ignore IDP_DESC_END;
%ignore get_idp_descs;
%ignore init_fileregions;
%ignore term_fileregions;
%ignore save_fileregions;
%ignore add_fileregion;
%ignore move_fileregions;
%ignore del_fileregions;
%ignore enum_plugins;
%ignore is_database_ext;
%ignore is_temp_database;

%ignore mem2base;
%rename (mem2base) py_mem2base;
%ignore update_snapshot_attributes;
%ignore visit_snapshot_tree;
%ignore load_plugin;
%rename (load_plugin) py_load_plugin;
%ignore run_plugin;
%rename (run_plugin) py_run_plugin;
%ignore load_and_run_plugin;
%rename (load_and_run_plugin) py_load_and_run_plugin;

%extend qvector< snapshot_t *> {
    snapshot_t *at(size_t n) { return self->at(n); }
};
%ignore qvector< snapshot_t *>::at(size_t) const;
%ignore qvector< snapshot_t *>::at(size_t);
%ignore qvector< snapshot_t *>::grow;
%template(qvector_snapshotvec_t) qvector<snapshot_t *>;

%include "loader.hpp"

%inline %{
//<inline(py_loader)>

//------------------------------------------------------------------------
/*
#<pydoc>
def mem2base(mem, ea, fpos):
    """
    Load database from the memory.
    @param mem: the buffer
    @param ea: start linear addresses
    @param fpos: position in the input file the data is taken from.
                 if == -1, then no file position correspond to the data.
    @return:
        - Returns zero if the passed buffer was not a string
        - Otherwise 1 is returned
    """
    pass
#</pydoc>
*/
static int py_mem2base(PyObject *py_mem, ea_t ea, qoff64_t fpos = -1)
{
  Py_ssize_t len;
  char *buf;
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( IDAPyBytes_AsMemAndSize(py_mem, &buf, &len) == -1 )
      return 0;
  }

  return mem2base((void *)buf, ea, ea+len, fpos);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def load_plugin(name):
    """
    Loads a plugin
    @return:
        - None if plugin could not be loaded
        - An opaque object representing the loaded plugin
    """
    pass
#</pydoc>
*/
static PyObject *py_load_plugin(const char *name)
{
  if ( qfileexist(name) )
    prepare_programmatic_plugin_load(name);
  plugin_t *r = load_plugin(name);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  prepare_programmatic_plugin_load(NULL);
  if ( r == NULL )
    Py_RETURN_NONE;
  else
    return PyCapsule_New(r, VALID_CAPSULE_NAME, NULL);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def run_plugin(plg):
    """
    Runs a plugin
    @param plg: A plugin object (returned by load_plugin())
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool py_run_plugin(PyObject *plg, int arg)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCapsule_IsValid(plg, VALID_CAPSULE_NAME) )
  {
    return false;
  }
  else
  {
    plugin_t *p = (plugin_t *)PyCapsule_GetPointer(plg, VALID_CAPSULE_NAME);
    bool rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = run_plugin(p, arg);
    Py_END_ALLOW_THREADS;
    return rc;
  }
}

//------------------------------------------------------------------------
static bool py_load_and_run_plugin(const char *name, size_t arg)
{
  if ( qfileexist(name) )
    prepare_programmatic_plugin_load(name);
  bool rc = load_and_run_plugin(name, arg);
  prepare_programmatic_plugin_load(NULL);
  return rc;
}

//</inline(py_loader)>
%}
%pythoncode %{
if _BC695:
    NEF_TIGHT=0
    @bc695redef
    def save_database(outfile, flags=0):
        if isinstance(flags, bool):
            flags = DBFL_KILL if flags else 0
        return _ida_loader.save_database(outfile, flags)
    save_database_ex=save_database
    MAX_FILE_FORMAT_NAME=64

%}