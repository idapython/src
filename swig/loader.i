// Ignore callback members
%ignore loader_t::accept_file;
%ignore loader_t::load_file;
%ignore loader_t::save_file;
%ignore loader_t::move_segm;
%ignore loader_t::init_loader_options;
%ignore plugin_t::init;
%ignore plugin_t::term;
%ignore plugin_t::run;

%ignore vloader_failure;
%ignore loader_failure;

// TODO: These could be wrapped if needed
%ignore load_info_t;
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
%ignore local_gen_idc_file;
%ignore print_all_places;
%ignore save_text_line;
%ignore print_all_structs;
%ignore print_all_enums;
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

// mem2base() has a custom wrapper
%ignore mem2base;

%include "loader.hpp"

// Custom wrapper for mem2base()
%rename (mem2base) mem2base_wrap;
%apply (char *STRING, int LENGTH) { (char *buf, int len) };
%inline %{
int mem2base_wrap(char *buf, int len, ea_t ea, long fpos)
{
	return mem2base((void *)buf, ea, ea+len, fpos);
}
%}



