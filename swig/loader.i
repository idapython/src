// Ignore callback members
%ignore loader_t::accept_file;
%ignore loader_t::load_file;
%ignore loader_t::save_file;
%ignore loader_t::move_segm;
%ignore loader_t::init_loader_options;
%ignore plugin_t;

%ignore vloader_failure;
%ignore loader_failure;

// TODO: These could be wrapped if needed
%ignore load_info_t;
%ignore add_plugin_option;
%ignore build_loaders_list;
%ignore free_loaders_list;
%ignore get_loader_name_from_dll;
%ignore get_loader_name;
%ignore init_loader_options;
%ignore load_nonbinary_file;
%ignore impinfo_t;
%ignore import_module;
%ignore plugin_info_t;
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
%ignore hook_cb_t;
%ignore hook_type_t;
%ignore hook_to_notification_point;
%ignore unhook_from_notification_point;
%ignore invoke_callbacks;

// Ignore this experimental function
%ignore gen_dev_event;

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
%ignore load_dll_or_say;
%ignore free_dll;
%ignore IDP_DESC_START;
%ignore IDP_DESC_END;
%ignore get_idp_desc;
%ignore init_fileregions;
%ignore term_fileregions;
%ignore save_fileregions;
%ignore add_fileregion;
%ignore move_fileregions;
%ignore del_fileregions;
%ignore local_gen_idc_file;
%ignore print_all_places;
%ignore save_text_line;
%ignore print_all_structs;
%ignore print_all_enums;
%ignore enum_processor_modules;
%ignore enum_plugins;
%ignore database_id0;
%ignore is_database_ext;
%ignore ida_database_memory;
%ignore ida_workdir;
%ignore DBFL_KILL;
%ignore DBFL_COMP;
%ignore DBFL_BAK;
%ignore DBFL_TEMP;
%ignore is_temp_database;
%ignore pe_create_idata;
%ignore pe_load_resources;
%ignore pe_create_flat_group;
%ignore initializing;
%ignore highest_processor_level;
%ignore dbcheck_t;
%ignore DBCHK_NONE;
%ignore DBCHK_OK;
%ignore DBCHK_BAD;
%ignore DBCHK_NEW;
%ignore check_database;
%ignore open_database;
%ignore get_workbase_fname;
%ignore close_database;
%ignore compress_btree;
%ignore get_input_file_from_archive;
%ignore loader_move_segm;
%ignore generate_ida_copyright;
%ignore clear_plugin_options;
%ignore is_in_loader;
%ignore get_ids_filename;
%ignore is_embedded_dbfile_ext;

%ignore mem2base;
%rename (mem2base) py_mem2base;
%ignore load_plugin;
%rename (load_plugin) py_load_plugin;
%ignore run_plugin;
%rename (run_plugin) py_run_plugin;

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
static int py_mem2base(PyObject *py_mem, ea_t ea, long fpos = -1)
{
  Py_ssize_t len;
  char *buf;
  if ( PyString_AsStringAndSize(py_mem, &buf, &len) == -1 )
    return 0;
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
  plugin_t *r = load_plugin(name);
  if ( r == NULL )
    Py_RETURN_NONE;
  return PyCObject_FromVoidPtr(r, NULL);
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
  if ( !PyCObject_Check(plg) )
    return false;
  return run_plugin((plugin_t *)PyCObject_AsVoidPtr(plg), arg);
}

//</inline(py_loader)>

%}



