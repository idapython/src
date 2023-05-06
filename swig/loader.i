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

%ignore extract_module_from_archive;
%rename (extract_module_from_archive) py_extract_module_from_archive;

/* %extend qvector< snapshot_t *> { */
/*     snapshot_t *at(size_t n) { return self->at(n); } */
/* }; */
/* %ignore qvector< snapshot_t *>::at(size_t) const; */
/* %ignore qvector< snapshot_t *>::at(size_t); */
%ignore qvector< snapshot_t *>::grow;
%template(qvector_snapshotvec_t) qvector<snapshot_t *>;

%include "loader.hpp"

%inline %{
//<inline(py_loader)>
//</inline(py_loader)>
%}
