[Switch to HTML](http://htmlpreview.github.io/?https://github.com/idapython/src/blob/master/examples/index.html)

# IDAPython examples

## Category: analysis

#### dump_func_info
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/analysis/dump_func_info.py">analysis/dump_func_info.py</a>

#### Category
analysis

#### Description


#### Keywords

#### Uses
* ida_funcs.FUNC_FRAME
* ida_funcs.FUNC_LUMINA
* ida_funcs.FUNC_THUNK
* ida_funcs.get_fchunk
* ida_funcs.is_func_entry
* ida_funcs.is_func_tail
* ida_kernwin.get_screen_ea

#### See also

</blockquote>

  </details>

## Category: core

#### actions
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/actions.py">core/actions.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_DISASM
* ida_kernwin.SETMENU_APP
* ida_kernwin.UI_Hooks
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_menu
* ida_kernwin.attach_action_to_popup
* ida_kernwin.attach_action_to_toolbar
* ida_kernwin.get_widget_type
* ida_kernwin.load_custom_icon
* ida_kernwin.register_action
* ida_kernwin.unregister_action

#### See also

</blockquote>

  </details>

#### add_hotkey
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/add_hotkey.py">core/add_hotkey.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_kernwin.add_hotkey
* ida_kernwin.del_hotkey

#### See also

</blockquote>

  </details>

#### add_idc_hotkey
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/add_idc_hotkey.py">core/add_idc_hotkey.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_expr.compile_idc_text
* ida_kernwin.add_idc_hotkey

#### See also

</blockquote>

  </details>

#### auto_instantiate_widget_plugin
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/auto_instantiate_widget_plugin.py">core/auto_instantiate_widget_plugin.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_idaapi.plugin_t
* ida_kernwin.AST_ENABLE_ALWAYS
* ida_kernwin.SETMENU_APP
* ida_kernwin.UI_Hooks
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_menu
* ida_kernwin.find_widget
* ida_kernwin.register_action
* ida_kernwin.simplecustviewer_t
* ida_kernwin.simplecustviewer_t.Create

#### See also

</blockquote>

  </details>

#### bin_search
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/bin_search.py">core/bin_search.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_bytes.BIN_SEARCH_FORWARD
* ida_bytes.BIN_SEARCH_NOBREAK
* ida_bytes.BIN_SEARCH_NOSHOW
* ida_bytes.bin_search
* ida_bytes.compiled_binpat_vec_t
* ida_bytes.parse_binpat_str
* ida_ida.inf_get_max_ea
* ida_idaapi.BADADDR
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_DISASM
* ida_kernwin.Form
* ida_kernwin.Form.ChkGroupControl
* ida_kernwin.Form.StringInput
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.get_screen_ea
* ida_kernwin.jumpto
* ida_kernwin.register_action
* ida_nalt.BPU_1B
* ida_nalt.BPU_2B
* ida_nalt.get_default_encoding_idx

#### See also

</blockquote>

  </details>

#### create_structure_programmatically
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/create_structure_programmatically.py">core/create_structure_programmatically.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_bytes.FF_BYTE
* ida_bytes.FF_DATA
* ida_bytes.FF_DOUBLE
* ida_bytes.FF_DWORD
* ida_bytes.FF_FLOAT
* ida_bytes.FF_OWORD
* ida_bytes.FF_PACKREAL
* ida_bytes.FF_QWORD
* ida_bytes.FF_STRLIT
* ida_bytes.FF_STRUCT
* ida_bytes.FF_TBYTE
* ida_bytes.FF_WORD
* ida_bytes.off_flag
* ida_bytes.stroff_flag
* ida_idaapi.BADADDR
* ida_nalt.STRTYPE_C
* ida_struct.add_struc
* ida_struct.get_struc_id
* ida_struct.get_struc_size
* idc.add_struc
* idc.add_struc_member
* idc.del_struc
* idc.set_member_type

#### See also

</blockquote>

  </details>

#### custom_cli
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/custom_cli.py">core/custom_cli.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_idaapi.NW_CLOSEIDB
* ida_idaapi.NW_OPENIDB
* ida_idaapi.NW_REMOVE
* ida_idaapi.NW_TERMIDA
* ida_idaapi.notify_when
* ida_kernwin.cli_t

#### See also

</blockquote>

  </details>

#### custom_data_types_and_formats
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/custom_data_types_and_formats.py">core/custom_data_types_and_formats.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_bytes.data_format_t
* ida_bytes.data_type_t
* ida_bytes.find_custom_data_type
* ida_bytes.get_byte
* ida_bytes.register_data_types_and_formats
* ida_bytes.unregister_data_types_and_formats
* ida_idaapi.NW_CLOSEIDB
* ida_idaapi.NW_OPENIDB
* ida_idaapi.NW_REMOVE
* ida_idaapi.NW_TERMIDA
* ida_idaapi.notify_when
* ida_idaapi.struct_unpack
* ida_lines.COLSTR
* ida_lines.SCOLOR_IMPNAME
* ida_lines.SCOLOR_INSN
* ida_lines.SCOLOR_NUMBER
* ida_lines.SCOLOR_REG
* ida_nalt.get_input_file_path
* ida_netnode.netnode
* ida_struct.is_member_id

#### See also

</blockquote>

  </details>

#### dump_extra_comments
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/dump_extra_comments.py">core/dump_extra_comments.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_DISASM
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_popup
* ida_kernwin.find_widget
* ida_kernwin.get_screen_ea
* ida_kernwin.register_action
* ida_kernwin.unregister_action
* ida_lines.E_NEXT
* ida_lines.E_PREV
* ida_lines.get_extra_cmt
* ida_view

#### See also

</blockquote>

  </details>

#### dump_flowchart
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/dump_flowchart.py">core/dump_flowchart.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_funcs.get_func
* ida_gdl.FlowChart
* ida_gdl.qflow_chart_t
* ida_kernwin.get_screen_ea

#### See also

</blockquote>

  </details>

#### dump_selection
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/dump_selection.py">core/dump_selection.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_kernwin.ACF_HAS_SELECTION
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_DISASM
* ida_kernwin.BWN_ENUMS
* ida_kernwin.BWN_PSEUDOCODE
* ida_kernwin.BWN_STRUCTS
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.get_viewer_user_data
* ida_kernwin.l_compare2
* ida_kernwin.linearray_t
* ida_kernwin.register_action
* ida_kernwin.unregister_action
* ida_lines.tag_remove

#### See also

</blockquote>

  </details>

#### extend_idc
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/extend_idc.py">core/extend_idc.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_expr.VT_LONG
* ida_expr.add_idc_func

#### See also

</blockquote>

  </details>

#### idapythonrc
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/idapythonrc.py">core/idapythonrc.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses

#### See also

</blockquote>

  </details>

#### install_user_defined_prefix
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/install_user_defined_prefix.py">core/install_user_defined_prefix.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_idaapi.PLUGIN_KEEP
* ida_idaapi.plugin_t
* ida_lines.SCOLOR_INV
* ida_lines.user_defined_prefix_t

#### See also

</blockquote>

  </details>

#### list_imports
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/list_imports.py">core/list_imports.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_nalt.enum_import_names
* ida_nalt.get_import_module_name
* ida_nalt.get_import_module_qty

#### See also

</blockquote>

  </details>

#### list_patched_bytes
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/list_patched_bytes.py">core/list_patched_bytes.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_bytes.visit_patched_bytes
* ida_idaapi.BADADDR

#### See also

</blockquote>

  </details>

#### list_problems
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/list_problems.py">core/list_problems.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_ida.inf_get_min_ea
* ida_idaapi.BADADDR
* ida_problems.PR_ATTN
* ida_problems.PR_BADSTACK
* ida_problems.PR_COLLISION
* ida_problems.PR_DECIMP
* ida_problems.PR_DISASM
* ida_problems.PR_FINAL
* ida_problems.PR_HEAD
* ida_problems.PR_ILLADDR
* ida_problems.PR_JUMP
* ida_problems.PR_MANYLINES
* ida_problems.PR_NOBASE
* ida_problems.PR_NOCMT
* ida_problems.PR_NOFOP
* ida_problems.PR_NONAME
* ida_problems.PR_NOXREFS
* ida_problems.PR_ROLLED
* ida_problems.get_problem
* ida_problems.get_problem_name

#### See also

</blockquote>

  </details>

#### list_segment_functions
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/list_segment_functions.py">core/list_segment_functions.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_funcs.get_func
* ida_funcs.get_func_name
* ida_funcs.get_next_func
* ida_idaapi.BADADDR
* ida_kernwin.get_screen_ea
* ida_segment.getseg
* ida_xref.get_first_cref_to
* ida_xref.get_next_cref_to

#### See also

</blockquote>

  </details>

#### list_segment_functions_using_idautils
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/list_segment_functions_using_idautils.py">core/list_segment_functions_using_idautils.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_funcs.get_func_name
* ida_idaapi.BADADDR
* ida_kernwin.get_screen_ea
* ida_segment.getseg
* idautils.CodeRefsTo
* idautils.Functions

#### See also

</blockquote>

  </details>

#### list_stkvar_xrefs
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/list_stkvar_xrefs.py">core/list_stkvar_xrefs.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_bytes.get_flags
* ida_bytes.is_stkvar
* ida_frame.calc_stkvar_struc_offset
* ida_frame.get_frame
* ida_funcs.func_item_iterator_t
* ida_funcs.get_func
* ida_ida.UA_MAXOP
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_DISASM
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.get_current_viewer
* ida_kernwin.get_highlight
* ida_kernwin.get_screen_ea
* ida_kernwin.register_action
* ida_struct.get_member_by_name
* ida_struct.get_struc
* ida_ua.decode_insn
* ida_ua.insn_t

#### See also

</blockquote>

  </details>

#### list_strings
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/list_strings.py">core/list_strings.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* idautils.Strings

#### See also

</blockquote>

  </details>

#### produce_c_file
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/produce_c_file.py">core/produce_c_file.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_auto.auto_wait
* ida_hexrays.VDRUN_MAYSTOP
* ida_hexrays.VDRUN_NEWFILE
* ida_hexrays.VDRUN_SILENT
* ida_hexrays.decompile_many
* ida_loader.PATH_TYPE_IDB
* ida_loader.get_path
* ida_pro.qexit

#### See also

</blockquote>

  </details>

#### produce_lst_file
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/produce_lst_file.py">core/produce_lst_file.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_auto.auto_wait
* ida_fpro.qfile_t
* ida_ida.inf_get_max_ea
* ida_ida.inf_get_min_ea
* ida_loader.OFILE_LST
* ida_loader.PATH_TYPE_IDB
* ida_loader.gen_file
* ida_loader.get_path
* ida_pro.qexit

#### See also

</blockquote>

  </details>

#### register_timer
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/register_timer.py">core/register_timer.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_kernwin.register_timer

#### See also

</blockquote>

  </details>

#### trigger_actions_programmatically
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/trigger_actions_programmatically.py">core/trigger_actions_programmatically.py</a>

#### Category
core

#### Description


#### Keywords

#### Uses
* ida_kernwin.ask_yn
* ida_kernwin.execute_ui_requests
* ida_kernwin.msg
* ida_kernwin.process_ui_action

#### See also

</blockquote>

  </details>

## Category: debugging

#### automatic_steps
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/debugging/dbghooks/automatic_steps.py">debugging/dbghooks/automatic_steps.py</a>

#### Category
debugging

#### Description


#### Keywords

#### Uses
* ida_dbg.DBG_Hooks
* ida_dbg.get_reg_val
* ida_dbg.request_exit_process
* ida_dbg.request_run_to
* ida_dbg.request_step_over
* ida_dbg.run_requests
* ida_ida.inf_get_start_ip
* ida_idaapi.BADADDR
* ida_lines.generate_disasm_line
* ida_lines.tag_remove

#### See also

</blockquote>

  </details>

#### dbg_trace
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/debugging/dbghooks/dbg_trace.py">debugging/dbghooks/dbg_trace.py</a>

#### Category
debugging

#### Description


#### Keywords

#### Uses
* GENDSM_FORCE_CODE
* GENDSM_REMOVE_TAGS
* NN_call
* NN_callfi
* NN_callni
* generate_disasm_line
* ida_dbg.DBG_Hooks
* ida_dbg.ST_OVER_DEBUG_SEG
* ida_dbg.ST_OVER_LIB_FUNC
* ida_dbg.enable_step_trace
* ida_dbg.get_process_state
* ida_dbg.get_reg_val
* ida_dbg.get_step_trace_options
* ida_dbg.load_debugger
* ida_dbg.refresh_debugger_memory
* ida_dbg.request_continue_process
* ida_dbg.request_enable_step_trace
* ida_dbg.request_set_step_trace_options
* ida_dbg.run_requests
* ida_dbg.run_to
* ida_dbg.set_step_trace_options
* ida_dbg.wait_for_next_event
* ida_ida.f_ELF
* ida_ida.f_MACHO
* ida_ida.f_PE
* ida_ida.inf_get_filetype
* ida_ida.inf_get_max_ea
* ida_ida.inf_get_min_ea
* ida_ida.inf_get_start_ip
* ida_pro.qexit
* ida_ua.decode_insn
* ida_ua.insn_t
* idc.ARGV

#### See also

</blockquote>

  </details>

#### registers_context_menu
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/debugging/misc/registers_context_menu.py">debugging/misc/registers_context_menu.py</a>

#### Category
debugging

#### Description


#### Keywords

#### Uses
* ida_dbg.get_dbg_reg_info
* ida_dbg.get_reg_val
* ida_idd.register_info_t
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_CPUREGS
* ida_kernwin.UI_Hooks
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_popup
* ida_kernwin.get_widget_type
* ida_kernwin.register_action
* ida_ua.dt_byte
* ida_ua.dt_dword
* ida_ua.dt_qword
* ida_ua.dt_word

#### See also

</blockquote>

  </details>

#### show_debug_names
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/debugging/show_debug_names.py">debugging/show_debug_names.py</a>

#### Category
debugging

#### Description


#### Keywords

#### Uses
* ida_dbg.get_process_state
* ida_dbg.is_debugger_on
* ida_ida.inf_get_max_ea
* ida_ida.inf_get_min_ea
* ida_name.get_debug_names

#### See also

</blockquote>

  </details>

#### simple_appcall_common
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/debugging/appcall/simple_appcall_common.py">debugging/appcall/simple_appcall_common.py</a>

#### Category
debugging

#### Description


#### Keywords

#### Uses
* ida_dbg.DBG_Hooks
* ida_dbg.run_to
* ida_idaapi.BADADDR
* ida_idd.Appcall
* ida_idd.Appcall.byref
* ida_idd.Appcall.int64
* ida_kernwin.get_screen_ea
* ida_name.get_name_ea
* ida_name.set_name
* ida_typeinf.apply_cdecl

#### See also

</blockquote>

  </details>

#### simple_appcall_linux
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/debugging/appcall/simple_appcall_linux.py">debugging/appcall/simple_appcall_linux.py</a>

#### Category
debugging

#### Description


#### Keywords

#### Uses

#### See also

</blockquote>

  </details>

#### simple_appcall_win
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/debugging/appcall/simple_appcall_win.py">debugging/appcall/simple_appcall_win.py</a>

#### Category
debugging

#### Description


#### Keywords

#### Uses
* ida_ida.inf_is_64bit

#### See also

</blockquote>

  </details>

## Category: disassembly

#### colorize_disassembly
<details>
  <summary>change background colours</summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/core/colorize_disassembly.py">core/colorize_disassembly.py</a>

#### Category
disassembly

#### Description
This illustrates the setting/retrieval of background colours
using the IDC wrappers

#### Keywords
coloring
idc

#### Uses
* idc.CIC_FUNC
* idc.CIC_ITEM
* idc.CIC_SEGM
* idc.get_color
* idc.here
* idc.set_color

#### See also

</blockquote>

  </details>

## Category: hexrays

#### colorize_pseudocode_lines
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/colorize_pseudocode_lines.py">hexrays/colorize_pseudocode_lines.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.get_widget_vdui
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_PSEUDOCODE
* ida_kernwin.CK_EXTRA11
* ida_kernwin.UI_Hooks
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.get_custom_viewer_location
* ida_kernwin.line_rendering_output_entry_t
* ida_kernwin.refresh_custom_viewer
* ida_kernwin.register_action
* ida_moves.lochist_entry_t

#### See also

</blockquote>

  </details>

#### decompile_entry_points
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/decompile_entry_points.py">hexrays/decompile_entry_points.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_auto.auto_wait
* ida_entry.get_entry
* ida_entry.get_entry_ordinal
* ida_entry.get_entry_qty
* ida_hexrays.decompile
* ida_hexrays.init_hexrays_plugin
* ida_ida.inf_is_64bit
* ida_idp.PLFM_386
* ida_idp.PLFM_ARM
* ida_idp.PLFM_MIPS
* ida_idp.PLFM_PPC
* ida_idp.ph.id
* ida_kernwin.cvar.batch
* ida_kernwin.msg
* ida_loader.load_plugin
* ida_pro.qexit
* idc.get_idb_path

#### See also

</blockquote>

  </details>

#### vds1
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds1.py">hexrays/vds1.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_funcs.get_func
* ida_hexrays.decompile
* ida_hexrays.get_hexrays_version
* ida_hexrays.init_hexrays_plugin
* ida_kernwin.get_screen_ea
* ida_lines.tag_remove

#### See also

</blockquote>

  </details>

#### vds10
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds10.py">hexrays/vds10.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_bytes.get_cmt
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.mop_str
* ida_hexrays.optinsn_t
* ida_idaapi.PLUGIN_HIDE
* ida_idaapi.PLUGIN_KEEP
* ida_idaapi.plugin_t
* ida_typeinf.STI_PCCHAR
* ida_typeinf.tinfo_t.get_stock

#### See also

</blockquote>

  </details>

#### vds11
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds11.py">hexrays/vds11.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.getf_reginsn
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.m_goto
* ida_hexrays.optblock_t
* ida_idaapi.PLUGIN_HIDE
* ida_idaapi.PLUGIN_KEEP
* ida_idaapi.plugin_t

#### See also

</blockquote>

  </details>

#### vds12
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds12.py">hexrays/vds12.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_bytes.get_flags
* ida_bytes.is_code
* ida_funcs.get_func
* ida_hexrays.ACFL_GUESS
* ida_hexrays.DECOMP_NO_CACHE
* ida_hexrays.DECOMP_WARNINGS
* ida_hexrays.GCO_DEF
* ida_hexrays.GCO_USE
* ida_hexrays.GC_REGS_AND_STKVARS
* ida_hexrays.MERR_OK
* ida_hexrays.MMAT_PREOPTIMIZED
* ida_hexrays.MUST_ACCESS
* ida_hexrays.gco_info_t
* ida_hexrays.gen_microcode
* ida_hexrays.get_current_operand
* ida_hexrays.get_merror_desc
* ida_hexrays.hexrays_failure_t
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.mba_ranges_t
* ida_hexrays.mlist_t
* ida_hexrays.op_parent_info_t
* ida_hexrays.voff_t
* ida_kernwin.Choose
* ida_kernwin.get_screen_ea
* ida_kernwin.jumpto
* ida_kernwin.warning
* ida_lines.GENDSM_REMOVE_TAGS
* ida_lines.generate_disasm_line
* ida_pro.eavec_t

#### See also

</blockquote>

  </details>

#### vds13
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds13.py">hexrays/vds13.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_bytes.get_flags
* ida_bytes.is_code
* ida_hexrays.DECOMP_WARNINGS
* ida_hexrays.gen_microcode
* ida_hexrays.hexrays_failure_t
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.mba_ranges_t
* ida_hexrays.vd_printer_t
* ida_kernwin.read_range_selection
* ida_kernwin.warning
* ida_range.range_t

#### See also

</blockquote>

  </details>

#### vds17
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds17.py">hexrays/vds17.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.USE_KEYBOARD
* ida_hexrays.cot_add
* ida_hexrays.cot_cast
* ida_hexrays.cot_memptr
* ida_hexrays.cot_memref
* ida_hexrays.cot_num
* ida_hexrays.cot_ref
* ida_hexrays.get_hexrays_version
* ida_hexrays.get_widget_vdui
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.select_udt_by_offset
* ida_hexrays.ui_stroff_applicator_t
* ida_hexrays.ui_stroff_ops_t
* ida_idaapi.BADADDR
* ida_idaapi.PLUGIN_HIDE
* ida_idaapi.PLUGIN_KEEP
* ida_idaapi.plugin_t
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_PSEUDOCODE
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.get_custom_viewer_curline
* ida_kernwin.msg
* ida_kernwin.register_action
* ida_kernwin.warning
* ida_lines.tag_remove
* ida_typeinf.PRTYPE_1LINE
* ida_typeinf.print_tinfo
* ida_typeinf.remove_pointer

#### See also

</blockquote>

  </details>

#### vds19
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds19.py">hexrays/vds19.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.m_bnot
* ida_hexrays.m_mov
* ida_hexrays.m_or
* ida_hexrays.minsn_visitor_t
* ida_hexrays.mop_t
* ida_hexrays.optinsn_t
* ida_idaapi.PLUGIN_HIDE
* ida_idaapi.PLUGIN_KEEP
* ida_idaapi.plugin_t

#### See also

</blockquote>

  </details>

#### vds21
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds21.py">hexrays/vds21.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.Hexrays_Hooks
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.m_call
* ida_idaapi.PLUGIN_HIDE
* ida_idaapi.PLUGIN_KEEP
* ida_idaapi.plugin_t
* ida_kernwin.msg
* ida_kernwin.warning
* ida_nalt.get_op_tinfo
* ida_typeinf.parse_decl
* ida_typeinf.tinfo_t

#### See also

</blockquote>

  </details>

#### vds3
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds3.py">hexrays/vds3.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.CMAT_FINAL
* ida_hexrays.CV_FAST
* ida_hexrays.CV_INSNS
* ida_hexrays.Hexrays_Hooks
* ida_hexrays.ITP_ELSE
* ida_hexrays.USE_KEYBOARD
* ida_hexrays.VDI_TAIL
* ida_hexrays.cexpr_t
* ida_hexrays.cit_if
* ida_hexrays.ctree_visitor_t
* ida_hexrays.get_widget_vdui
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.lnot
* ida_hexrays.qswap
* ida_idaapi.PLUGIN_HIDE
* ida_idaapi.PLUGIN_KEEP
* ida_idaapi.plugin_t
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_PSEUDOCODE
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_popup
* ida_kernwin.register_action
* ida_netnode.netnode

#### See also

</blockquote>

  </details>

#### vds4
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds4.py">hexrays/vds4.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_bytes.get_radix
* ida_hexrays.CIT_COLLAPSED
* ida_hexrays.decompile
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.lvar_uservec_t
* ida_hexrays.restore_user_cmts
* ida_hexrays.restore_user_iflags
* ida_hexrays.restore_user_labels
* ida_hexrays.restore_user_lvar_settings
* ida_hexrays.restore_user_numforms
* ida_hexrays.user_cmts_free
* ida_hexrays.user_iflags_free
* ida_hexrays.user_labels_free
* ida_hexrays.user_numforms_free
* ida_kernwin.get_screen_ea

#### See also

</blockquote>

  </details>

#### vds5
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds5.py">hexrays/vds5.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_gdl.display_gdl
* ida_hexrays.Hexrays_Hooks
* ida_hexrays.USE_KEYBOARD
* ida_hexrays.cit_asm
* ida_hexrays.cit_goto
* ida_hexrays.cot_helper
* ida_hexrays.cot_memptr
* ida_hexrays.cot_memref
* ida_hexrays.cot_num
* ida_hexrays.cot_obj
* ida_hexrays.cot_ptr
* ida_hexrays.cot_str
* ida_hexrays.cot_var
* ida_hexrays.ctree_parentee_t
* ida_hexrays.get_ctype_name
* ida_hexrays.get_widget_vdui
* ida_hexrays.init_hexrays_plugin
* ida_idaapi.PLUGIN_HIDE
* ida_idaapi.PLUGIN_KEEP
* ida_idaapi.plugin_t
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_PSEUDOCODE
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_popup
* ida_kernwin.register_action
* ida_kernwin.warning
* ida_lines.tag_remove
* ida_pro.str2user

#### See also

</blockquote>

  </details>

#### vds6
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds6.py">hexrays/vds6.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.Hexrays_Hooks
* ida_hexrays.init_hexrays_plugin
* ida_idaapi.PLUGIN_HIDE
* ida_idaapi.PLUGIN_KEEP
* ida_idaapi.plugin_t
* ida_lines.tag_advance
* ida_lines.tag_skipcodes

#### See also

</blockquote>

  </details>

#### vds7
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds7.py">hexrays/vds7.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.CMAT_BUILT
* ida_hexrays.CV_FAST
* ida_hexrays.Hexrays_Hooks
* ida_hexrays.cit_block
* ida_hexrays.ctree_visitor_t
* ida_hexrays.init_hexrays_plugin

#### See also

</blockquote>

  </details>

#### vds8
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds8.py">hexrays/vds8.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_allins.ARM_svc
* ida_hexrays.get_widget_vdui
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.install_microcode_filter
* ida_hexrays.udc_filter_t
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_PSEUDOCODE
* ida_kernwin.UI_Hooks
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_popup
* ida_kernwin.get_widget_type
* ida_kernwin.register_action

#### See also

</blockquote>

  </details>

#### vds_create_hint
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds_create_hint.py">hexrays/vds_create_hint.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.Hexrays_Hooks
* ida_hexrays.USE_MOUSE
* ida_hexrays.VDI_EXPR
* ida_hexrays.VDI_LVAR
* ida_hexrays.cit_if
* ida_hexrays.cot_call

#### See also

</blockquote>

  </details>

#### vds_hooks
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds_hooks.py">hexrays/vds_hooks.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.Hexrays_Hooks

#### See also

</blockquote>

  </details>

#### vds_modify_user_lvars
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds_modify_user_lvars.py">hexrays/vds_modify_user_lvars.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_hexrays.modify_user_lvars
* ida_hexrays.user_lvar_modifier_t
* ida_typeinf.parse_decl
* ida_typeinf.tinfo_t
* idc.here

#### See also

</blockquote>

  </details>

#### vds_xrefs
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/hexrays/vds_xrefs.py">hexrays/vds_xrefs.py</a>

#### Category
hexrays

#### Description


#### Keywords

#### Uses
* ida_funcs.get_func_name
* ida_hexrays.Hexrays_Hooks
* ida_hexrays.USE_KEYBOARD
* ida_hexrays.VDI_EXPR
* ida_hexrays.VDI_FUNC
* ida_hexrays.cexpr_t
* ida_hexrays.cfunc_t
* ida_hexrays.cinsn_t
* ida_hexrays.decompile
* ida_hexrays.get_widget_vdui
* ida_hexrays.init_hexrays_plugin
* ida_hexrays.open_pseudocode
* ida_hexrays.qstring_printer_t
* ida_idaapi.BADADDR
* ida_kernwin.AST_DISABLE
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE
* ida_kernwin.BWN_PSEUDOCODE
* ida_kernwin.PluginForm
* ida_kernwin.PluginForm.Show
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_popup
* ida_kernwin.register_action
* ida_struct.get_member
* ida_struct.get_struc
* ida_struct.get_struc_id
* ida_typeinf.PRTYPE_1LINE
* ida_typeinf.print_tinfo
* idautils.Functions
* idautils.XrefsTo

#### See also

</blockquote>

  </details>

## Category: idbhooks

#### operand_changed
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/idbhooks/operand_changed.py">idbhooks/operand_changed.py</a>

#### Category
idbhooks

#### Description


#### Keywords

#### Uses
* ida_bytes.ALOPT_IGNCLT
* ida_bytes.ALOPT_IGNHEADS
* ida_bytes.get_flags
* ida_bytes.get_max_strlit_length
* ida_bytes.get_opinfo
* ida_bytes.get_strlit_contents
* ida_bytes.is_custfmt
* ida_bytes.is_custom
* ida_bytes.is_enum
* ida_bytes.is_off
* ida_bytes.is_strlit
* ida_bytes.is_stroff
* ida_bytes.is_struct
* ida_enum.get_enum_name
* ida_idp.IDB_Hooks
* ida_nalt.STRENC_DEFAULT
* ida_nalt.get_default_encoding_idx
* ida_nalt.get_encoding_name
* ida_nalt.get_str_encoding_idx
* ida_nalt.get_strtype_bpu
* ida_nalt.opinfo_t
* ida_struct.get_struc_name

#### See also

</blockquote>

  </details>

#### replay_prototypes_changes
<details>
  <summary>Record and replay changes in function prototypes</summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/idbhooks/replay_prototypes_changes.py">idbhooks/replay_prototypes_changes.py</a>

#### Category
idbhooks

#### Description
This is a sample script, that will record (in memory) all changes in
functions prototypes, in order to re-apply them later.

To use this script:
 - open an IDB (say, "test.idb")
 - modify some functions prototypes (e.g., by triggering the 'Y'
   shortcut when the cursor is placed on the first address of a
   function)
 - reload that IDB, *without saving it first*
 - call rpc.replay(), to re-apply the modifications.

Note: 'ti_changed' is also called for changes to the function
frames, but we'll only record function prototypes changes.

#### Keywords

#### Uses
* ida_funcs.get_func
* ida_idp.IDB_Hooks
* ida_typeinf.PRTYPE_1LINE
* ida_typeinf.TINFO_DEFINITE
* ida_typeinf.apply_tinfo
* ida_typeinf.get_idati
* ida_typeinf.tinfo_t

#### See also

</blockquote>

  </details>

## Category: idphooks

#### ana_emu_out
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/idphooks/ana_emu_out.py">idphooks/ana_emu_out.py</a>

#### Category
idphooks

#### Description


#### Keywords

#### Uses
* ida_bytes.get_wide_dword
* ida_bytes.get_wide_word
* ida_idp.CUSTOM_INSN_ITYPE
* ida_idp.IDP_Hooks
* ida_idp.PLFM_ARM
* ida_idp.ph.id
* ida_idp.str2reg
* ida_segregs.get_sreg

#### See also

</blockquote>

  </details>

#### assemble
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/idphooks/assemble.py">idphooks/assemble.py</a>

#### Category
idphooks

#### Description


#### Keywords

#### Uses
* ida_idp.IDP_Hooks
* idautils.DecodeInstruction

#### See also

</blockquote>

  </details>

## Category: pyqt

#### inject_command
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/pyqt/inject_command.py">pyqt/inject_command.py</a>

#### Category
pyqt

#### Description


#### Keywords

#### Uses
* ida_kernwin.PluginForm.TWidgetToPyQtWidget
* ida_kernwin.disabled_script_timeout_t
* ida_kernwin.find_widget
* ida_kernwin.process_ui_action

#### See also

</blockquote>

  </details>

#### paint_over_navbar
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/pyqt/paint_over_navbar.py">pyqt/paint_over_navbar.py</a>

#### Category
pyqt

#### Description


#### Keywords

#### Uses
* ida_kernwin.PluginForm.FormToPyQtWidget
* ida_kernwin.get_navband_pixel
* ida_kernwin.open_navband_window
* ida_segment.get_segm_qty
* ida_segment.getnseg
* idc.here

#### See also

</blockquote>

  </details>

#### populate_pluginform_with_pyqt_widgets
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/pyqt/populate_pluginform_with_pyqt_widgets.py">pyqt/populate_pluginform_with_pyqt_widgets.py</a>

#### Category
pyqt

#### Description


#### Keywords

#### Uses
* ida_kernwin.PluginForm

#### See also

</blockquote>

  </details>

## Category: uihooks

#### func_chooser_coloring
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/uihooks/func_chooser_coloring.py">uihooks/func_chooser_coloring.py</a>

#### Category
uihooks

#### Description


#### Keywords

#### Uses
* ida_funcs.get_func
* ida_kernwin.UI_Hooks
* ida_kernwin.enable_chooser_item_attrs

#### See also

</blockquote>

  </details>

#### lines_rendering
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/uihooks/lines_rendering.py">uihooks/lines_rendering.py</a>

#### Category
uihooks

#### Description


#### Keywords

#### Uses
* ida_bytes.next_head
* ida_idaapi.BADADDR
* ida_kernwin.CK_EXTRA1
* ida_kernwin.CK_EXTRA10
* ida_kernwin.CK_EXTRA11
* ida_kernwin.CK_EXTRA12
* ida_kernwin.CK_EXTRA13
* ida_kernwin.CK_EXTRA14
* ida_kernwin.CK_EXTRA15
* ida_kernwin.CK_EXTRA16
* ida_kernwin.CK_EXTRA2
* ida_kernwin.CK_EXTRA3
* ida_kernwin.CK_EXTRA4
* ida_kernwin.CK_EXTRA5
* ida_kernwin.CK_EXTRA6
* ida_kernwin.CK_EXTRA7
* ida_kernwin.CK_EXTRA8
* ida_kernwin.CK_EXTRA9
* ida_kernwin.CK_TRACE
* ida_kernwin.CK_TRACE_OVL
* ida_kernwin.LROEF_CPS_RANGE
* ida_kernwin.UI_Hooks
* ida_kernwin.get_screen_ea
* ida_kernwin.line_rendering_output_entry_t
* ida_kernwin.refresh_idaview_anyway

#### See also

</blockquote>

  </details>

#### log_misc_events
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/uihooks/log_misc_events.py">uihooks/log_misc_events.py</a>

#### Category
uihooks

#### Description


#### Keywords

#### Uses
* ida_kernwin.UI_Hooks

#### See also

</blockquote>

  </details>

#### prevent_jump
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/uihooks/prevent_jump.py">uihooks/prevent_jump.py</a>

#### Category
uihooks

#### Description


#### Keywords

#### Uses
* ida_kernwin.UI_Hooks

#### See also

</blockquote>

  </details>

## Category: widgets

#### add_menus
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/misc/add_menus.py">widgets/misc/add_menus.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* ida_kernwin.AST_ENABLE_ALWAYS
* ida_kernwin.SETMENU_INS
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_menu
* ida_kernwin.create_menu
* ida_kernwin.register_action

#### See also

</blockquote>

  </details>

#### askusingform
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/forms/askusingform.py">widgets/forms/askusingform.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* ida_kernwin.Choose
* ida_kernwin.Choose.CH_MULTI
* ida_kernwin.Form
* ida_kernwin.PluginForm.FORM_TAB
* ida_kernwin.ask_str

#### See also

</blockquote>

  </details>

#### choose
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/tabular_views/custom/choose.py">widgets/tabular_views/custom/choose.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* Choose
* Choose.ALL_CHANGED
* Choose.CH_CAN_DEL
* Choose.CH_CAN_EDIT
* Choose.CH_CAN_INS
* Choose.CH_CAN_REFRESH
* Choose.CH_RESTORE
* Choose.NOTHING_CHANGED
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_popup
* ida_kernwin.is_chooser_widget
* ida_kernwin.register_action
* ida_kernwin.unregister_action

#### See also

</blockquote>

  </details>

#### choose_multi
<details>
  <summary>choose multi</summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/tabular_views/custom/choose_multi.py">widgets/tabular_views/custom/choose_multi.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* Choose
* Choose.ALL_CHANGED
* Choose.CHCOL_HEX
* Choose.CH_MULTI
* Choose.NOTHING_CHANGED

#### See also

</blockquote>

  </details>

#### chooser_with_folders
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/tabular_views/custom/chooser_with_folders.py">widgets/tabular_views/custom/chooser_with_folders.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* ida_dirtree.DTE_OK
* ida_dirtree.direntry_t
* ida_dirtree.direntry_t.BADIDX
* ida_dirtree.dirspec_t
* ida_dirtree.dirtree_t
* ida_dirtree.dirtree_t.isdir
* ida_kernwin.CH_CAN_DEL
* ida_kernwin.CH_CAN_EDIT
* ida_kernwin.CH_CAN_INS
* ida_kernwin.CH_HAS_DIRTREE
* ida_kernwin.CH_MULTI
* ida_kernwin.CH_NOIDB
* ida_kernwin.Choose
* ida_kernwin.Choose.ALL_CHANGED
* ida_kernwin.Choose.CHCOL_DRAGHINT
* ida_kernwin.Choose.CHCOL_INODENAME
* ida_kernwin.Choose.CHCOL_PLAIN
* ida_kernwin.ask_str
* ida_netnode.BADNODE
* ida_netnode.netnode

#### See also

</blockquote>

  </details>

#### custom_graph_with_actions
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/graphs/custom_graph_with_actions.py">widgets/graphs/custom_graph_with_actions.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* ida_funcs.get_func
* ida_funcs.get_func_name
* ida_graph.GraphViewer
* ida_graph.get_graph_viewer
* ida_graph.screen_graph_selection_t
* ida_graph.viewer_get_selection
* ida_idp.is_call_insn
* ida_kernwin.AST_ENABLE_ALWAYS
* ida_kernwin.View_Hooks
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_dynamic_action_to_popup
* ida_kernwin.get_screen_ea
* ida_ua.decode_insn
* ida_ua.insn_t
* ida_xref.XREF_FAR
* idautils.FuncItems
* idautils.XrefsFrom

#### See also

</blockquote>

  </details>

#### custom_viewer
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/listings/custom_viewer.py">widgets/listings/custom_viewer.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* ida_kernwin.AST_ENABLE_ALWAYS
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.ask_long
* ida_kernwin.ask_str
* ida_kernwin.attach_action_to_popup
* ida_kernwin.register_action
* ida_kernwin.simplecustviewer_t
* ida_kernwin.simplecustviewer_t.Create
* ida_kernwin.simplecustviewer_t.Show
* ida_kernwin.unregister_action
* ida_lines.COLOR_DEFAULT
* ida_lines.COLOR_DNAME
* ida_lines.COLSTR
* ida_lines.SCOLOR_PREFIX
* ida_lines.SCOLOR_VOIDOP

#### See also

</blockquote>

  </details>

#### func_chooser
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/tabular_views/custom/func_chooser.py">widgets/tabular_views/custom/func_chooser.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* Choose
* Choose.ALL_CHANGED
* Choose.CHCOL_HEX
* Choose.CHCOL_PLAIN
* Choose.NOTHING_CHANGED
* idautils.Functions
* idc.del_func
* idc.jumpto

#### See also

</blockquote>

  </details>

#### jump_next_comment
<details>
  <summary> This example illustrates how one can implement a "jump to next comment" action within IDA's disassembly view.</summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/listings/jump_next_comment.py">widgets/listings/jump_next_comment.py</a>

#### Category
widgets

#### Description
We want our action not only to find the next line containing a comment,
but to also place the cursor at the right horizontal position.

#### Keywords

#### Uses
* ida_bytes.next_head
* ida_idaapi.BADADDR
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_DISASM
* ida_kernwin.CVNF_LAZY
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.custom_viewer_jump
* ida_kernwin.get_custom_viewer_location
* ida_kernwin.place_t_as_idaplace_t
* ida_kernwin.register_action
* ida_kernwin.unregister_action
* ida_lines.SCOLOR_AUTOCMT
* ida_lines.SCOLOR_ON
* ida_lines.SCOLOR_REGCMT
* ida_lines.SCOLOR_RPTCMT
* ida_lines.generate_disassembly
* ida_lines.tag_strlen
* ida_moves.lochist_entry_t

#### See also
* [save_and_restore_listing_pos](#save_and_restore_listing_pos)

</blockquote>

  </details>

#### save_and_restore_listing_pos
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/listings/save_and_restore_listing_pos.py">widgets/listings/save_and_restore_listing_pos.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_CUSTVIEW
* ida_kernwin.BWN_DISASM
* ida_kernwin.BWN_ENUMS
* ida_kernwin.BWN_PSEUDOCODE
* ida_kernwin.BWN_STRUCTS
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.custom_viewer_jump
* ida_kernwin.find_widget
* ida_kernwin.get_custom_viewer_location
* ida_kernwin.register_action
* ida_kernwin.unregister_action
* ida_moves.lochist_entry_t

#### See also

</blockquote>

  </details>

#### show_and_hide_waitbox
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/waitbox/show_and_hide_waitbox.py">widgets/waitbox/show_and_hide_waitbox.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* ida_funcs.get_func
* ida_hexrays.DecompilationFailure
* ida_hexrays.decompile
* ida_kernwin.hide_wait_box
* ida_kernwin.replace_wait_box
* ida_kernwin.show_wait_box
* ida_kernwin.user_cancelled
* idautils.Functions

#### See also

</blockquote>

  </details>

#### show_selected_strings
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/tabular_views/string_window/show_selected_strings.py">widgets/tabular_views/string_window/show_selected_strings.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* ida_bytes.get_strlit_contents
* ida_idaapi.BADADDR
* ida_kernwin.AST_DISABLE_FOR_WIDGET
* ida_kernwin.AST_ENABLE_FOR_WIDGET
* ida_kernwin.BWN_STRINGS
* ida_kernwin.action_desc_t
* ida_kernwin.action_handler_t
* ida_kernwin.attach_action_to_popup
* ida_kernwin.find_widget
* ida_kernwin.get_chooser_data
* ida_kernwin.open_strings_window
* ida_kernwin.register_action
* ida_kernwin.unregister_action
* ida_strlist.get_strlist_item
* ida_strlist.string_info_t

#### See also

</blockquote>

  </details>

#### sync_two_graphs
<details>
  <summary></summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/graphs/sync_two_graphs.py">widgets/graphs/sync_two_graphs.py</a>

#### Category
widgets

#### Description


#### Keywords

#### Uses
* ida_graph.GLICTL_CENTER
* ida_graph.viewer_fit_window
* ida_graph.viewer_get_gli
* ida_graph.viewer_set_gli
* ida_kernwin.DP_RIGHT
* ida_kernwin.IDAViewWrapper
* ida_kernwin.MFF_FAST
* ida_kernwin.TCCRT_GRAPH
* ida_kernwin.execute_sync
* ida_kernwin.find_widget
* ida_kernwin.get_custom_viewer_place
* ida_kernwin.jumpto
* ida_kernwin.open_disasm_window
* ida_kernwin.set_dock_pos
* ida_kernwin.set_view_renderer_type
* ida_moves.graph_location_info_t

#### See also

</blockquote>

  </details>

#### wrap_idaview
<details>
  <summary>manipulate IDAView and graph</summary>

<blockquote>

#### Source code
<a href="https://github.com/idapython/src/blob/master/examples/widgets/idaview/wrap_idaview.py">widgets/idaview/wrap_idaview.py</a>

#### Category
widgets

#### Description
This is an example illustrating how to manipulate an existing IDA-provided
view (and thus its graph), in Python.

#### Keywords
idaview
graph

#### Uses
* ida_graph.NIF_BG_COLOR
* ida_graph.NIF_FRAME_COLOR
* ida_graph.node_info_t
* ida_kernwin.IDAViewWrapper
* ida_kernwin.MFF_FAST
* ida_kernwin.TCCRT_FLAT
* ida_kernwin.TCCRT_GRAPH
* ida_kernwin.execute_sync

#### See also
* [custom_graph_with_actions](#custom_graph_with_actions)
* [sync_two_graphs](#sync_two_graphs)

</blockquote>

  </details>

