
# Examples

## IDAPython examples

This collection of examples organizes all IDAPython sample code into [categories](#example-categories-overview) for easy reference. Each example demonstrates practical implementation for the IDAPython API, complementing the [reference documentation](https://python.docs.hex-rays.com/) with a real-world usage scenario.

### How to run the examples?

#### Load the script via File Loader

1. Navigate to **File -> Script file...**.
2. In the new dialog, select the `.py` script you want to run and click **Open**.

#### Load the script via Script command

1. Navigate to **File -> Script command...**.
2. Paste the code into _Please enter script body_ field and click **Run**.

#### Load the script via output window/console

1. In the output window/IDAPython console, type the following command: `exec(open("path/to/your_script.py").read())` to execute the script.

## Example Categories: Overview

<table data-full-width="false">
<thead><tr><th width="256"></th><th></th></tr></thead>
<tbody>

  <tr>
    <td><a href="#ui">User interface</a></td>
    <td>Creating & manipulating user-interface widgets, prompting the user with forms, enriching existing widgets, or creating your own UI through Python Qt bindings.</td>
  </tr>
  <tr>
    <td><a href="#disassembler">Disassembly</a></td>
    <td>Various ways to query, or modify the disassembly listing, alter the way analysis is performed, or be notified of changes made to the IDB.</td>
  </tr>
  <tr>
    <td><a href="#decompiler">Decompilation</a></td>
    <td>Querying the decompiler, manipulating the decompilation trees (either at the microcode level, or the C-tree), and examples showing how to intervene in the decompilation output.</td>
  </tr>
  <tr>
    <td><a href="#debugger">Debuggers</a></td>
    <td>Driving debugging sessions, be notified of debugging events.</td>
  </tr>
  <tr>
    <td><a href="#types">Working with types</a></td>
    <td>These samples utilize our Type APIs, which allow you to manage the types and perform various operations on them, like creating the structures or enums and adding their members programmatically.</td>
  </tr>
  <tr>
    <td><a href="#misc">Miscellaneous</a></td>
    <td>Miscellaneous examples that don't quite fall into another category, but don't really justify one of their own.</td>
  </tr>

</tbody>
</table>



## User interface {#ui}

<table>
<thead>
<tr>
<th width="150">Level</th>
<th>Examples</th>
</tr>
</thead>
<tbody>

<tr>
  <td>Beginner</td>
  <td><ul><li><a href='#add_hotkey'>Assign a shortcut to a custom function</a></li><li><a href='#add_menus'>Add custom menus to IDA</a></li><li><a href='#colorize_disassembly'>Assign a background color to an address, function & segment</a></li><li><a href='#func_chooser_coloring'>Override the default "Functions" chooser colors</a></li><li><a href='#populate_pluginform_with_pyqt_widgets'>Create a dockable container, and populate it with Qt widgets</a></li><li><a href='#prevent_jump'>Prevent an action from being triggered</a></li><li><a href='#register_timer'>Use timers for delayed execution</a></li><li><a href='#show_and_hide_waitbox'>Show, update & hide the progress dialog</a></li></ul></td>
</tr>
<tr>
  <td>Intermediate</td>
  <td><ul><li><a href='#actions'>Custom actions, with icons & tooltips</a></li><li><a href='#choose'>Show tabular data</a></li><li><a href='#choose_multi'>Show tabular data, with multiple selection</a></li><li><a href='#custom_viewer'>Create custom listings in IDA</a></li><li><a href='#func_chooser'>Implement an alternative "Functions" window</a></li><li><a href='#jump_next_comment'>Implement a "jump to next comment" action within IDA's listing</a></li><li><a href='#lines_rendering'>Dynamically colorize [parts of] lines</a></li><li><a href='#log_misc_events'>React to UI events/notifications</a></li><li><a href='#paint_over_navbar'>Paint on top of the navigation band</a></li><li><a href='#save_and_restore_listing_pos'>Save, and then restore, positions in a listing</a></li><li><a href='#show_selected_strings'>Retrieve the selection from the "Strings" window</a></li><li><a href='#sync_two_graphs'>Follow the movements of one graph, in another</a></li><li><a href='#trigger_actions_programmatically'>Trigger actions programmatically</a></li></ul></td>
</tr>
<tr>
  <td>Advanced</td>
  <td><ul><li><a href='#askusingform'>Advanced usage of the form API</a></li><li><a href='#auto_instantiate_widget_plugin'>Restore custom widgets across sessions</a></li><li><a href='#chooser_with_folders'>Showing tabular data in a flat, or tree-like fashion</a></li><li><a href='#colorize_disassembly_on_the_fly'>Colorize lines interactively</a></li><li><a href='#custom_cli'>Add a custom command-line interpreter</a></li><li><a href='#custom_graph_with_actions'>Draw custom graphs</a></li><li><a href='#dump_selection'>Retrieve & dump current selection</a></li><li><a href='#inject_command'>Inject commands in the "Output" window</a></li><li><a href='#lazy_loaded_chooser'>A lazy-loaded, tree-like data view</a></li><li><a href='#paint_over_graph'>Paint text on graph view edges</a></li><li><a href='#wrap_idaview'>Programmatically manipulate disassembly and graph widgets</a></li></ul></td>
</tr>

</tbody>
</table>


## Disassembly {#disassembler}

<table>
<thead>
<tr>
<th width="150">Level</th>
<th>Examples</th>
</tr>
</thead>
<tbody>

<tr>
  <td>Beginner</td>
  <td><ul><li><a href='#dump_flowchart'>Dump function flowchart</a></li><li><a href='#install_user_defined_prefix'>Insert information into listing prefixes</a></li><li><a href='#list_imports'>Enumerate file imports</a></li><li><a href='#list_patched_bytes'>Enumerate patched bytes</a></li><li><a href='#list_problems'>Enumerate known problems</a></li><li><a href='#list_segment_functions'>List segment functions (and cross-references to them)</a></li><li><a href='#list_segment_functions_using_idautils'>List all functions (and cross-references) in segment</a></li><li><a href='#list_strings'>Dump the strings that are present in the file</a></li><li><a href='#produce_lst_file'>Produce disassembly listing for the entire file</a></li></ul></td>
</tr>
<tr>
  <td>Intermediate</td>
  <td><ul><li><a href='#ana_emu_out'>Rewrite the representation of some instructions</a></li><li><a href='#assemble'>Implement assembly of instructions</a></li><li><a href='#dump_extra_comments'>Retrieve comments surrounding instructions</a></li><li><a href='#dump_func_info'>Dump function information</a></li><li><a href='#dump_line_sections'>Parse listing line, and dump some information</a></li><li><a href='#find_string'>Using "ida_bytes.find_string"</a></li><li><a href='#func_ti_changed_listener'>Print notifications about function prototype changes</a></li><li><a href='#list_bookmarks'>List listing bookmarks</a></li><li><a href='#list_function_items'>Showcase (some of) the iterators available on a function</a></li><li><a href='#log_idb_events'>React to database events/notifications</a></li><li><a href='#log_idp_events'>React to processor events/notifications</a></li><li><a href='#replay_prototypes_changes'>Record and replay changes in function prototypes</a></li></ul></td>
</tr>
<tr>
  <td>Advanced</td>
  <td><ul><li><a href='#add_frame_member'>Add a new member to an existing function frame</a></li><li><a href='#custom_data_types_and_formats'>Custom data types & printers</a></li><li><a href='#list_struct_accesses'>List operands representing a "path" to a (possibly nested) structure member</a></li><li><a href='#operand_changed'>Notify the user when an instruction operand changes</a></li></ul></td>
</tr>

</tbody>
</table>


## Decompilation {#decompiler}

<table>
<thead>
<tr>
<th width="150">Level</th>
<th>Examples</th>
</tr>
</thead>
<tbody>

<tr>
  <td>Beginner</td>
  <td><ul><li><a href='#produce_c_file'>Produce C listing for the entire file</a></li><li><a href='#vds1'>Decompile & print current function</a></li><li><a href='#vds13'>Generate microcode for the selected range of instructions</a></li><li><a href='#vds7'>Dump statement blocks</a></li><li><a href='#vds_create_hint'>Provide custom decompiler hints</a></li></ul></td>
</tr>
<tr>
  <td>Intermediate</td>
  <td><ul><li><a href='#colorize_pseudocode_lines'>Interactively color decompilation lines</a></li><li><a href='#decompile_entry_points'>Decompile entrypoint automatically</a></li><li><a href='#vds10'>Add custom microcode instruction optimization rule</a></li><li><a href='#vds21'>Dynamically provide a custom call type</a></li><li><a href='#vds4'>Dump user-defined information for a function</a></li><li><a href='#vds6'>Superficially modify the decompilation output</a></li><li><a href='#vds8'>Improve decompilation by turning specific patterns into custom function calls</a></li><li><a href='#vds_hooks'>React to decompiler events/notifications</a></li><li><a href='#vds_modify_user_lvars'>Modifying function local variables</a></li></ul></td>
</tr>
<tr>
  <td>Advanced</td>
  <td><ul><li><a href='#curpos_details'>Print information about the current position in decompilation</a></li><li><a href='#vds11'>Add a custom microcode block optimization rule</a></li><li><a href='#vds12'>List instruction registers</a></li><li><a href='#vds17'>Invoke the structure offset-choosing dialog from decompilation</a></li><li><a href='#vds19'>Add a custom microcode instruction optimization rule</a></li><li><a href='#vds3'>Invert if/else blocks in decompilation</a></li><li><a href='#vds5'>Dump C-tree graph</a></li><li><a href='#vds_xrefs'>Show decompiler cross-references</a></li></ul></td>
</tr>

</tbody>
</table>


## Debuggers {#debugger}

<table>
<thead>
<tr>
<th width="150">Level</th>
<th>Examples</th>
</tr>
</thead>
<tbody>

<tr>
  <td>Beginner</td>
  <td><ul><li><a href='#print_registers'>Print all registers, for all threads in the debugged process</a></li><li><a href='#show_debug_names'>Dump symbols from a process being debugged</a></li></ul></td>
</tr>
<tr>
  <td>Intermediate</td>
  <td><ul><li><a href='#print_call_stack'>Print call stack</a></li><li><a href='#registers_context_menu'>Add a custom action to the "registers" widget</a></li></ul></td>
</tr>
<tr>
  <td>Advanced</td>
  <td><ul><li><a href='#automatic_steps'>Programmatically drive a debugging session</a></li><li><a href='#dbg_trace'>React to trace notifications</a></li><li><a href='#simple_appcall_linux'>Execute code into the application being debugged (on Linux)</a></li><li><a href='#simple_appcall_win'>Execute code into the application being debugged (on Windows)</a></li></ul></td>
</tr>

</tbody>
</table>


## Working with types {#types}

<table>
<thead>
<tr>
<th width="150">Level</th>
<th>Examples</th>
</tr>
</thead>
<tbody>

<tr>
  <td>Beginner</td>
  <td><ul><li><a href='#create_struct_by_parsing'>Create a structure by parsing its definition</a></li><li><a href='#del_struct_members'>Delete structure members that fall within an offset range</a></li><li><a href='#list_enum_member'>Print enumeration members</a></li><li><a href='#list_frame_info'>Print function stack frame information</a></li><li><a href='#list_func_details'>List database functions prototypes</a></li><li><a href='#list_struct_member'>List structure members</a></li><li><a href='#list_struct_xrefs'>List cross-references to a structure</a></li><li><a href='#list_union_member'>List union members</a></li><li><a href='#mark_func_spoiled'>Mark a register "spoiled" by a function</a></li></ul></td>
</tr>
<tr>
  <td>Intermediate</td>
  <td><ul><li><a href='#apply_callee_tinfo'>Apply function prototype to call sites</a></li><li><a href='#create_array'>Create an array type</a></li><li><a href='#create_bfstruct'>Create a structure with bitfield members</a></li><li><a href='#create_bmenum'>Create a bitmask enumeration</a></li><li><a href='#create_libssh2_til'>Create a type library file</a></li><li><a href='#create_struct_by_member'>Create a structure programmatically</a></li><li><a href='#create_structure_programmatically'>Create & populate a structure</a></li><li><a href='#create_union_by_member'>Create a union</a></li><li><a href='#create_user_shared_data'>Create a segment, and define (complex) data in it</a></li><li><a href='#gap_size_align_snippet'>Utilities to detect structure gaps & alignment</a></li><li><a href='#get_best_fit_member'>Get member by offset, taking into account variable sized structures</a></li><li><a href='#get_innermost_member'>Get information about the "innermost" member of a structure</a></li><li><a href='#import_type_from_til'>Load a type library from a file, and then a type from it</a></li><li><a href='#insert_struct_member'>Inject a member in the middle of a structure</a></li><li><a href='#list_stkvar_xrefs'>List all xrefs to a function stack variable</a></li><li><a href='#modify_struct_member'>Modify structure members attributes programmatically</a></li><li><a href='#print_stkvar_xrefs'>List cross-references to function stack frame variables</a></li><li><a href='#setpehdr'>Assign DOS/PE headers structures to a PE binary</a></li><li><a href='#visit_tinfo'>Recursively visit a type and its members</a></li></ul></td>
</tr>
<tr>
  <td>Advanced</td>
  <td><ul><li><a href='#change_stkvar_name'>Change the name of an existing stack variable</a></li><li><a href='#change_stkvar_type'>Change the type & name of a function stack frame variable</a></li><li><a href='#operand_to_struct_member'>Turn instruction operand into a structure offset</a></li></ul></td>
</tr>

</tbody>
</table>


## Miscellaneous {#misc}

<table>
<thead>
<tr>
<th width="150">Level</th>
<th>Examples</th>
</tr>
</thead>
<tbody>

<tr>
  <td>Beginner</td>
  <td><ul><li><a href='#idapythonrc'>Code to be run right after IDAPython initialization</a></li></ul></td>
</tr>
<tr>
  <td>Intermediate</td>
  <td><ul><li><a href='#extend_idc'>Add functions to the IDC runtime, from IDAPython</a></li></ul></td>
</tr>
<tr>
  <td>Advanced</td>
  <td><ul><li><a href='#py_cvt64_sample'>Add 64-bit (.idb->.i64) conversion capabilities to custom plugins</a></li><li><a href='#py_mex1'>Add merge functionality to a simple plugin</a></li><li><a href='#py_mex3'>Implement merging functionality for custom plugins</a></li></ul></td>
</tr>

</tbody>
</table>



***

## Examples list


### Assign a shortcut to a custom function {#add_hotkey}
`ida_kernwin.add_hotkey` is a simpler, but much less flexible
alternative to `ida_kernwin.register_action` (though it does
use the same mechanism under the hood.)

It's particularly useful during prototyping, but note that the
actions that are created cannot be inserted in menus, toolbars
or cannot provide a custom `ida_kernwin.action_handler_t.update`
callback.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [add_hotkey.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/add_hotkey.py) | actions | Beginner |

**APIs Used:**
* `ida_kernwin.add_hotkey`
* `ida_kernwin.del_hotkey`

***


### Add custom menus to IDA {#add_menus}
It is possible to add custom menus to IDA, either at the
toplevel (i.e., into the menubar), or as submenus of existing
menus.

Notes:

  * the same action can be present in more than 1 menu
  * this example does not deal with context menus

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [add_menus.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/misc/add_menus.py) | actions | Beginner |

**APIs Used:**
* `ida_kernwin.AST_ENABLE_ALWAYS`
* `ida_kernwin.SETMENU_INS`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_menu`
* `ida_kernwin.create_menu`
* `ida_kernwin.register_action`

***


### Assign a background color to an address, function & segment {#colorize_disassembly}
This illustrates the setting/retrieval of background colours
using the IDC wrappers

In order to do so, we'll be assigning colors to specific ranges
(item, function, or segment). Those will be persisted in the
database.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [colorize_disassembly.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/colorize_disassembly.py) | coloring idc | Beginner |

**APIs Used:**
* `idc.CIC_FUNC`
* `idc.CIC_ITEM`
* `idc.CIC_SEGM`
* `idc.get_color`
* `idc.here`
* `idc.set_color`

***


### Override the default "Functions" chooser colors {#func_chooser_coloring}
Color the function in the Function window according to its size.
The larger the function, the darker the color.

The key, is overriding `ida_kernwin.UI_Hooks.get_chooser_item_attrs`

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [func_chooser_coloring.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/uihooks/func_chooser_coloring.py) | UI_Hooks | Beginner |

**APIs Used:**
* `ida_funcs.get_func`
* `ida_kernwin.UI_Hooks`
* `ida_kernwin.enable_chooser_item_attrs`

***


### Create a dockable container, and populate it with Qt widgets {#populate_pluginform_with_pyqt_widgets}
Using `ida_kernwin.PluginForm.FormToPyQtWidget`, this script
converts IDA's own dockable widget into a type that is
recognized by PyQt5, which then enables populating it with
regular Qt widgets.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [populate_pluginform_with_pyqt_widgets.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/pyqt/populate_pluginform_with_pyqt_widgets.py) |  | Beginner |

**APIs Used:**
* `ida_kernwin.PluginForm`

***


### Prevent an action from being triggered {#prevent_jump}
Using `ida_kernwin.UI_Hooks.preprocess_action`, it is possible
to respond to a command instead of the action that would
otherwise do it.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [prevent_jump.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/uihooks/prevent_jump.py) | UI_Hooks | Beginner |

**APIs Used:**
* `ida_kernwin.UI_Hooks`

***


### Use timers for delayed execution {#register_timer}
Register (possibly repeating) timers.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [register_timer.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/register_timer.py) |  | Beginner |

**APIs Used:**
* `ida_kernwin.register_timer`

***


### Show, update & hide the progress dialog {#show_and_hide_waitbox}
Using the progress dialog (aka 'wait box') primitives.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [show_and_hide_waitbox.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/waitbox/show_and_hide_waitbox.py) | actions | Beginner |

**APIs Used:**
* `ida_hexrays.decompile`
* `ida_kernwin.hide_wait_box`
* `ida_kernwin.replace_wait_box`
* `ida_kernwin.show_wait_box`
* `ida_kernwin.user_cancelled`
* `idautils.Functions`

***


### Custom actions, with icons & tooltips {#actions}
How to create user actions, that once created can be
inserted in menus, toolbars, context menus, ...

Those actions, when triggered, will be passed a 'context'
that contains some of the most frequently needed bits of
information.

In addition, custom actions can determine when they want
to be available (through their
`ida_kernwin.action_handler_t.update` callback)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [actions.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/actions.py) | actions ctxmenu UI_Hooks | Intermediate |

**APIs Used:**
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_DISASM`
* `ida_kernwin.SETMENU_APP`
* `ida_kernwin.UI_Hooks`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_menu`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.attach_action_to_toolbar`
* `ida_kernwin.get_widget_type`
* `ida_kernwin.load_custom_icon`
* `ida_kernwin.register_action`
* `ida_kernwin.unregister_action`

***


### Show tabular data {#choose}
Shows how to subclass the ida_kernwin.Choose class to
show data organized in a simple table.
In addition, registers a couple actions that can be applied to it.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [choose.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/tabular_views/custom/choose.py) | actions chooser ctxmenu | Intermediate |

**APIs Used:**
* `Choose`
* `Choose.ALL_CHANGED`
* `Choose.CH_CAN_DEL`
* `Choose.CH_CAN_EDIT`
* `Choose.CH_CAN_INS`
* `Choose.CH_CAN_REFRESH`
* `Choose.CH_RESTORE`
* `Choose.NOTHING_CHANGED`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.is_chooser_widget`
* `ida_kernwin.register_action`
* `ida_kernwin.unregister_action`

***


### Show tabular data, with multiple selection {#choose_multi}
Similar to <a class="ex_link" href="#choose">choose</a>, but with multiple selection

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [choose_multi.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/tabular_views/custom/choose_multi.py) | actions chooser | Intermediate |

**APIs Used:**
* `Choose`
* `Choose.ALL_CHANGED`
* `Choose.CHCOL_HEX`
* `Choose.CH_MULTI`
* `Choose.NOTHING_CHANGED`

***


### Create custom listings in IDA {#custom_viewer}
How to create simple listings, that will share many of the features
as the built-in IDA widgets (highlighting, copy & paste,
notifications, ...)

In addition, creates actions that will be bound to the
freshly-created widget (using `ida_kernwin.attach_action_to_popup`.)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [custom_viewer.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/listings/custom_viewer.py) | actions ctxmenu listing | Intermediate |

**APIs Used:**
* `ida_kernwin.AST_ENABLE_ALWAYS`
* `ida_kernwin.IK_DELETE`
* `ida_kernwin.IK_ESCAPE`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.ask_long`
* `ida_kernwin.ask_str`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.register_action`
* `ida_kernwin.simplecustviewer_t`
* `ida_kernwin.simplecustviewer_t.Create`
* `ida_kernwin.simplecustviewer_t.Show`
* `ida_kernwin.unregister_action`
* `ida_lines.COLOR_DEFAULT`
* `ida_lines.COLOR_DNAME`
* `ida_lines.COLSTR`
* `ida_lines.SCOLOR_PREFIX`
* `ida_lines.SCOLOR_VOIDOP`

***


### Implement an alternative "Functions" window {#func_chooser}
Partially re-implements the "Functions" widget present in
IDA, with a custom widget.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [func_chooser.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/tabular_views/custom/func_chooser.py) | chooser functions | Intermediate |

**APIs Used:**
* `ida_funcs.get_func_name`
* `ida_kernwin.Choose`
* `ida_kernwin.Choose.ALL_CHANGED`
* `ida_kernwin.Choose.CHCOL_FNAME`
* `ida_kernwin.Choose.CHCOL_HEX`
* `ida_kernwin.Choose.CHCOL_PLAIN`
* `ida_kernwin.get_icon_id_by_name`
* `idautils.Functions`
* `idc.del_func`

***


### Implement a "jump to next comment" action within IDA's listing {#jump_next_comment}
We want our action not only to find the next line containing a comment,
but to also place the cursor at the right horizontal position.

To find that position, we will have to inspect the text that IDA
generates, looking for the start of a comment.
However, we won't be looking for a comment "prefix" (e.g., "; "),
as that would be too fragile.

Instead, we will look for special "tags" that IDA injects into textual
lines, and that bear semantic information.

Those tags are primarily used for rendering (i.e., switching colors),
but can also be very handy for spotting tokens of interest (registers,
addresses, comments, prefixes, instruction mnemonics, ...)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [jump_next_comment.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/listings/jump_next_comment.py) | actions idaview | Intermediate |

**APIs Used:**
* `ida_bytes.next_head`
* `ida_idaapi.BADADDR`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_DISASM`
* `ida_kernwin.CVNF_LAZY`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.custom_viewer_jump`
* `ida_kernwin.get_custom_viewer_location`
* `ida_kernwin.place_t_as_idaplace_t`
* `ida_kernwin.register_action`
* `ida_kernwin.unregister_action`
* `ida_lines.SCOLOR_AUTOCMT`
* `ida_lines.SCOLOR_ON`
* `ida_lines.SCOLOR_REGCMT`
* `ida_lines.SCOLOR_RPTCMT`
* `ida_lines.generate_disassembly`
* `ida_lines.tag_strlen`
* `ida_moves.lochist_entry_t`

***


### Dynamically colorize [parts of] lines {#lines_rendering}
Shows how one can dynamically alter the lines background
rendering (as opposed to, say, using ida_nalt.set_item_color()),
and also shows how that rendering can be limited to just a few
glyphs, not the whole line.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [lines_rendering.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/uihooks/lines_rendering.py) | UI_Hooks | Intermediate |

**APIs Used:**
* `ida_bytes.next_head`
* `ida_idaapi.BADADDR`
* `ida_kernwin.CK_EXTRA1`
* `ida_kernwin.CK_EXTRA10`
* `ida_kernwin.CK_EXTRA11`
* `ida_kernwin.CK_EXTRA12`
* `ida_kernwin.CK_EXTRA13`
* `ida_kernwin.CK_EXTRA14`
* `ida_kernwin.CK_EXTRA15`
* `ida_kernwin.CK_EXTRA16`
* `ida_kernwin.CK_EXTRA2`
* `ida_kernwin.CK_EXTRA3`
* `ida_kernwin.CK_EXTRA4`
* `ida_kernwin.CK_EXTRA5`
* `ida_kernwin.CK_EXTRA6`
* `ida_kernwin.CK_EXTRA7`
* `ida_kernwin.CK_EXTRA8`
* `ida_kernwin.CK_EXTRA9`
* `ida_kernwin.CK_TRACE`
* `ida_kernwin.CK_TRACE_OVL`
* `ida_kernwin.LROEF_CPS_RANGE`
* `ida_kernwin.UI_Hooks`
* `ida_kernwin.get_screen_ea`
* `ida_kernwin.line_rendering_output_entry_t`
* `ida_kernwin.refresh_idaview_anyway`

***


### React to UI events/notifications {#log_misc_events}
Hooks to be notified about certain UI events, and
dump their information to the "Output" window

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [log_misc_events.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/uihooks/log_misc_events.py) | UI_Hooks | Intermediate |

**APIs Used:**
* `ida_kernwin.UI_Hooks`

***


### Paint on top of the navigation band {#paint_over_navbar}
Using an "event filter", we will intercept paint events
targeted at the navigation band widget, let it paint itself,
and then add our own markers on top.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [paint_over_navbar.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/pyqt/paint_over_navbar.py) |  | Intermediate |

**APIs Used:**
* `ida_kernwin.PluginForm.FormToPyQtWidget`
* `ida_kernwin.get_navband_pixel`
* `ida_kernwin.open_navband_window`
* `ida_segment.get_segm_qty`
* `ida_segment.getnseg`
* `idc.here`

***


### Save, and then restore, positions in a listing {#save_and_restore_listing_pos}
Shows how it is possible re-implement IDA's bookmark capability,
using 2 custom actions: one action saves the current location,
and the other restores it.

Note that, contrary to actual bookmarks, this example:

  * remembers only 1 saved position
  * doesn't save that position in the IDB (and therefore cannot
    be restored if IDA is closed & reopened.)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [save_and_restore_listing_pos.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/listings/save_and_restore_listing_pos.py) | actions listing | Intermediate |

**APIs Used:**
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_CUSTVIEW`
* `ida_kernwin.BWN_DISASM`
* `ida_kernwin.BWN_PSEUDOCODE`
* `ida_kernwin.BWN_TILVIEW`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.custom_viewer_jump`
* `ida_kernwin.find_widget`
* `ida_kernwin.get_custom_viewer_location`
* `ida_kernwin.register_action`
* `ida_kernwin.unregister_action`
* `ida_moves.lochist_entry_t`

***


### Retrieve the selection from the "Strings" window {#show_selected_strings}
In IDA it's possible to write actions that can be applied even to
core (i.e., "standard") widgets. The actions in this example use the
action "context" to know what the current selection is.

This example shows how you can either retrieve string literals data
directly from the chooser (`ida_kernwin.get_chooser_data`), or
by querying the IDB (`ida_bytes.get_strlit_contents`)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [show_selected_strings.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/tabular_views/string_window/show_selected_strings.py) | actions ctxmenu | Intermediate |

**APIs Used:**
* `ida_bytes.get_strlit_contents`
* `ida_idaapi.BADADDR`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_STRINGS`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.find_widget`
* `ida_kernwin.get_chooser_data`
* `ida_kernwin.open_strings_window`
* `ida_kernwin.register_action`
* `ida_kernwin.unregister_action`
* `ida_strlist.get_strlist_item`
* `ida_strlist.string_info_t`

***


### Follow the movements of one graph, in another {#sync_two_graphs}
Since it is possible to be notified of movements that happen
take place in a widget, it's possible to "replay" those
movements in another.

In this case, "IDA View-B" (will be opened if necessary) will
show the same contents as "IDA View-A", slightly zoomed out.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [sync_two_graphs.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/graphs/sync_two_graphs.py) | graph idaview | Intermediate |

**APIs Used:**
* `ida_graph.GLICTL_CENTER`
* `ida_graph.viewer_fit_window`
* `ida_graph.viewer_get_gli`
* `ida_graph.viewer_set_gli`
* `ida_kernwin.DP_RIGHT`
* `ida_kernwin.IDAViewWrapper`
* `ida_kernwin.MFF_FAST`
* `ida_kernwin.TCCRT_GRAPH`
* `ida_kernwin.execute_sync`
* `ida_kernwin.find_widget`
* `ida_kernwin.get_custom_viewer_place`
* `ida_kernwin.jumpto`
* `ida_kernwin.open_disasm_window`
* `ida_kernwin.set_dock_pos`
* `ida_kernwin.set_view_renderer_type`
* `ida_moves.graph_location_info_t`

***


### Trigger actions programmatically {#trigger_actions_programmatically}
It's possible to invoke any action programmatically, by using
either of those two:

  * ida_kernwin.execute_ui_requests()
  * ida_kernwin.process_ui_action()

Ideally, this script should be run through the "File > Script file..."
menu, so as to keep focus on "IDA View-A" and have the
'ProcessUiActions' part work as intended.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [trigger_actions_programmatically.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/trigger_actions_programmatically.py) | actions | Intermediate |

**APIs Used:**
* `ida_kernwin.ask_yn`
* `ida_kernwin.execute_ui_requests`
* `ida_kernwin.msg`
* `ida_kernwin.process_ui_action`

***


### Advanced usage of the form API {#askusingform}
How to query for complex user input, using IDA's built-in forms.

Note: while this example produces full-fledged forms for complex input,
simpler types of inputs might can be retrieved by using
`ida_kernwin.ask_str` and similar functions.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [askusingform.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/forms/askusingform.py) | forms | Advanced |

**APIs Used:**
* `ida_kernwin.Choose`
* `ida_kernwin.Choose.CH_MULTI`
* `ida_kernwin.Form`
* `ida_kernwin.PluginForm.FORM_TAB`
* `ida_kernwin.ask_str`

***


### Restore custom widgets across sessions {#auto_instantiate_widget_plugin}
This is an example demonstrating how one can create widgets from a plugin,
and have them re-created automatically at IDA startup-time or at desktop load-time.

This example should be placed in the 'plugins' directory of the
IDA installation, for it to work.

There are 2 ways to use this example:
1) reloading an IDB, where the widget was opened
   - open the widget ('View > Open subview > ...')
   - save this IDB, and close IDA
   - restart IDA with this IDB
     => the widget will be visible

2) reloading a desktop, where the widget was opened
   - open the widget ('View > Open subview > ...')
   - save the desktop ('Windows > Save desktop...') under, say, the name 'with_auto'
   - start another IDA instance with some IDB, and load that desktop
     => the widget will be visible

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [auto_instantiate_widget_plugin.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/auto_instantiate_widget_plugin.py) | desktop plugin UI_Hooks | Advanced |

**APIs Used:**
* `ida_idaapi.plugin_t`
* `ida_kernwin.AST_ENABLE_ALWAYS`
* `ida_kernwin.SETMENU_APP`
* `ida_kernwin.UI_Hooks`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_menu`
* `ida_kernwin.find_widget`
* `ida_kernwin.register_action`
* `ida_kernwin.simplecustviewer_t`
* `ida_kernwin.simplecustviewer_t.Create`

***


### Showing tabular data in a flat, or tree-like fashion {#chooser_with_folders}
By adding the necessary bits to a ida_kernwin.Choose subclass,
IDA can show the otherwise tabular data, in a tree-like fashion.

The important bits to enable this are:

  * ida_dirtree.dirspec_t (and my_dirspec_t)
  * ida_kernwin.CH_HAS_DIRTREE
  * ida_kernwin.Choose.OnGetDirTree
  * ida_kernwin.Choose.OnIndexToInode

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [chooser_with_folders.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/tabular_views/custom/chooser_with_folders.py) | actions chooser folders | Advanced |

**APIs Used:**
* `ida_dirtree.DTE_OK`
* `ida_dirtree.direntry_t`
* `ida_dirtree.direntry_t.BADIDX`
* `ida_dirtree.dirspec_t`
* `ida_dirtree.dirtree_t`
* `ida_dirtree.dirtree_t.isdir`
* `ida_kernwin.CH_CAN_DEL`
* `ida_kernwin.CH_CAN_EDIT`
* `ida_kernwin.CH_CAN_INS`
* `ida_kernwin.CH_HAS_DIRTREE`
* `ida_kernwin.CH_MULTI`
* `ida_kernwin.Choose`
* `ida_kernwin.Choose.ALL_CHANGED`
* `ida_kernwin.Choose.CHCOL_DRAGHINT`
* `ida_kernwin.Choose.CHCOL_INODENAME`
* `ida_kernwin.Choose.CHCOL_PLAIN`
* `ida_kernwin.ask_str`
* `ida_netnode.BADNODE`
* `ida_netnode.netnode`

***


### Colorize lines interactively {#colorize_disassembly_on_the_fly}
This builds upon the `ida_kernwin.UI_Hooks.get_lines_rendering_info`
feature, to provide a quick & easy way to colorize disassembly
lines.

Contrary to @colorize_disassembly, the coloring is not persisted in
the database, and will therefore be lost after the session.

By triggering the action multiple times, the user can "carousel"
across 4 predefined colors (and return to the "no color" state.)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [colorize_disassembly_on_the_fly.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/colorize_disassembly_on_the_fly.py) | coloring UI_Hooks | Advanced |

**APIs Used:**
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.CK_EXTRA5`
* `ida_kernwin.CK_EXTRA6`
* `ida_kernwin.CK_EXTRA7`
* `ida_kernwin.CK_EXTRA8`
* `ida_kernwin.UI_Hooks`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.get_current_viewer`
* `ida_kernwin.get_custom_viewer_location`
* `ida_kernwin.get_custom_viewer_place_xcoord`
* `ida_kernwin.get_widget_title`
* `ida_kernwin.line_rendering_output_entry_t`
* `ida_kernwin.register_action`
* `ida_moves.lochist_entry_t`

***


### Add a custom command-line interpreter {#custom_cli}
Illustrates how one can add command-line interpreters to IDA

This custom interpreter doesn't actually run any code; it's
there as a 'getting started'.
It provides an example tab completion support.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [custom_cli.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/custom_cli.py) |  | Advanced |

**APIs Used:**
* `ida_idaapi.NW_CLOSEIDB`
* `ida_idaapi.NW_OPENIDB`
* `ida_idaapi.NW_REMOVE`
* `ida_idaapi.NW_TERMIDA`
* `ida_idaapi.notify_when`
* `ida_kernwin.cli_t`

***


### Draw custom graphs {#custom_graph_with_actions}
Showing custom graphs, using `ida_graph.GraphViewer`. In addition,
show how to write actions that can be performed on those.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [custom_graph_with_actions.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/graphs/custom_graph_with_actions.py) | actions graph View_Hooks | Advanced |

**APIs Used:**
* `ida_funcs.get_func`
* `ida_funcs.get_func_name`
* `ida_graph.GraphViewer`
* `ida_graph.get_graph_viewer`
* `ida_graph.screen_graph_selection_t`
* `ida_graph.viewer_get_selection`
* `ida_idp.is_call_insn`
* `ida_kernwin.AST_ENABLE_ALWAYS`
* `ida_kernwin.View_Hooks`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_dynamic_action_to_popup`
* `ida_kernwin.get_screen_ea`
* `ida_ua.decode_insn`
* `ida_ua.insn_t`
* `ida_xref.XREF_FAR`
* `ida_xref.xrefblk_t`

***


### Retrieve & dump current selection {#dump_selection}
Shows how to retrieve the selection from a listing
widget ("IDA View-A", "Hex View-1", "Pseudocode-A", ...) as
two "cursors", and from there retrieve (in fact, generate)
the corresponding text.

After running this script:

  * select some text in one of the listing widgets (i.e.,
    "IDA View-...", "Local Types", "Pseudocode-...")
  * press Ctrl+Shift+S to dump the selection

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [dump_selection.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/dump_selection.py) |  | Advanced |

**APIs Used:**
* `ida_kernwin.ACF_HAS_SELECTION`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_DISASM`
* `ida_kernwin.BWN_PSEUDOCODE`
* `ida_kernwin.BWN_TILVIEW`
* `ida_kernwin.IWID_ANY_LISTING`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.get_last_widget`
* `ida_kernwin.get_viewer_user_data`
* `ida_kernwin.l_compare2`
* `ida_kernwin.linearray_t`
* `ida_kernwin.read_selection`
* `ida_kernwin.register_action`
* `ida_kernwin.twinpos_t`
* `ida_kernwin.unregister_action`
* `ida_lines.tag_remove`

***


### Inject commands in the "Output" window {#inject_command}
This example illustrates how one can execute commands in the
"Output" window, from their own widgets.

A few notes:

* the original, underlying `cli:Execute` action, that has to be
  triggered for the code present in the input field to execute
  and be placed in the history, requires that the input field
  has focus (otherwise it simply won't do anything.)
* this, in turn, forces us to do "delayed" execution of that action,
  hence the need for a `QTimer`
* the IDA/SWiG 'TWidget' type that we retrieve through
  `ida_kernwin.find_widget`, is not the same type as a
  `QtWidgets.QWidget`. We therefore need to convert it using
  `ida_kernwin.PluginForm.TWidgetToPyQtWidget`

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [inject_command.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/pyqt/inject_command.py) |  | Advanced |

**APIs Used:**
* `ida_kernwin.PluginForm.TWidgetToPyQtWidget`
* `ida_kernwin.disabled_script_timeout_t`
* `ida_kernwin.find_widget`
* `ida_kernwin.process_ui_action`

***


### A lazy-loaded, tree-like data view {#lazy_loaded_chooser}
Brings lazy-loading of folders to the tree-like tabular views.

The important bit to enable this are:

  * ida_kernwin.Choose.OnLazyLoadDir

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [lazy_loaded_chooser.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/tabular_views/custom/lazy_loaded_chooser.py) | actions chooser folders | Advanced |


***


### Paint text on graph view edges {#paint_over_graph}
This sample registers an action enabling painting of a recognizable
string of text over horizontal nodes edge sections beyond a
satisfying size threshold.

In a disassembly view, open the context menu and select
"Paint on edges". This should work for both graph disassembly,
and proximity browser.

Using an "event filter", we will intercept paint events
targeted at the disassembly view, let it paint itself, and
then add our own markers along.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [paint_over_graph.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/pyqt/paint_over_graph.py) | ctxmenu UI_Hooks | Advanced |

**APIs Used:**
* `ida_gdl.edge_t`
* `ida_graph.get_graph_viewer`
* `ida_graph.get_viewer_graph`
* `ida_graph.point_t`
* `ida_graph.viewer_get_gli`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_DISASM`
* `ida_kernwin.PluginForm.FormToPyQtWidget`
* `ida_kernwin.UI_Hooks`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.get_widget_type`
* `ida_kernwin.register_action`
* `ida_moves.graph_location_info_t`

***


### Programmatically manipulate disassembly and graph widgets {#wrap_idaview}
This is an example illustrating how to manipulate an existing IDA-provided
view (and thus possibly its graph), in Python.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [wrap_idaview.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/ui/idaview/wrap_idaview.py) | graph idaview | Advanced |

**APIs Used:**
* `ida_graph.NIF_BG_COLOR`
* `ida_graph.NIF_FRAME_COLOR`
* `ida_graph.node_info_t`
* `ida_kernwin.IDAViewWrapper`
* `ida_kernwin.MFF_FAST`
* `ida_kernwin.TCCRT_FLAT`
* `ida_kernwin.TCCRT_GRAPH`
* `ida_kernwin.execute_sync`

***


### Dump function flowchart {#dump_flowchart}
Dumps the current function's flowchart, using 2 methods:

  * the low-level `ida_gdl.qflow_chart_t` type
  * the somewhat higher-level, and slightly more pythonic
    `ida_gdl.FlowChart` type.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [dump_flowchart.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/dump_flowchart.py) |  | Beginner |

**APIs Used:**
* `ida_funcs.get_func`
* `ida_gdl.FlowChart`
* `ida_gdl.qflow_chart_t`
* `ida_kernwin.get_screen_ea`

***


### Insert information into listing prefixes {#install_user_defined_prefix}
By default, disassembly line prefixes contain segment + address
information (e.g., '.text:08047718'), but it is possible to
"inject" other bits of information in there, thanks to the
`ida_lines.user_defined_prefix_t` helper type.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [install_user_defined_prefix.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/install_user_defined_prefix.py) | plugin | Beginner |

**APIs Used:**
* `ida_idaapi.PLUGIN_KEEP`
* `ida_idaapi.plugin_t`
* `ida_lines.SCOLOR_INV`
* `ida_lines.user_defined_prefix_t`

***


### Enumerate file imports {#list_imports}
Using the API to enumerate file imports.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_imports.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/list_imports.py) |  | Beginner |

**APIs Used:**
* `ida_nalt.enum_import_names`
* `ida_nalt.get_import_module_name`
* `ida_nalt.get_import_module_qty`

***


### Enumerate patched bytes {#list_patched_bytes}
Using the API to iterate over all the places in the file,
that were patched using IDA.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_patched_bytes.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/list_patched_bytes.py) |  | Beginner |

**APIs Used:**
* `ida_bytes.visit_patched_bytes`
* `ida_idaapi.BADADDR`

***


### Enumerate known problems {#list_problems}
Using the API to list all problems that IDA
encountered during analysis.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_problems.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/list_problems.py) |  | Beginner |

**APIs Used:**
* `ida_ida.inf_get_min_ea`
* `ida_idaapi.BADADDR`
* `ida_problems.PR_ATTN`
* `ida_problems.PR_BADSTACK`
* `ida_problems.PR_COLLISION`
* `ida_problems.PR_DECIMP`
* `ida_problems.PR_DISASM`
* `ida_problems.PR_FINAL`
* `ida_problems.PR_HEAD`
* `ida_problems.PR_ILLADDR`
* `ida_problems.PR_JUMP`
* `ida_problems.PR_MANYLINES`
* `ida_problems.PR_NOBASE`
* `ida_problems.PR_NOCMT`
* `ida_problems.PR_NOFOP`
* `ida_problems.PR_NONAME`
* `ida_problems.PR_NOXREFS`
* `ida_problems.PR_ROLLED`
* `ida_problems.get_problem`
* `ida_problems.get_problem_name`

***


### List segment functions (and cross-references to them) {#list_segment_functions}
List all the functions in the current segment, as well as
all the cross-references to them.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_segment_functions.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/list_segment_functions.py) | xrefs | Beginner |

**APIs Used:**
* `ida_funcs.get_func`
* `ida_funcs.get_func_name`
* `ida_funcs.get_next_func`
* `ida_kernwin.get_screen_ea`
* `ida_segment.getseg`
* `ida_xref.xrefblk_t`

***


### List all functions (and cross-references) in segment {#list_segment_functions_using_idautils}
List all the functions in the current segment, as well as
all the cross-references to them.

Contrary to @list_segment_functions, this uses the somewhat
higher-level `idautils` module.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_segment_functions_using_idautils.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/list_segment_functions_using_idautils.py) | xrefs | Beginner |

**APIs Used:**
* `ida_funcs.get_func_name`
* `ida_idaapi.BADADDR`
* `ida_kernwin.get_screen_ea`
* `ida_segment.getseg`
* `idautils.CodeRefsTo`
* `idautils.Functions`

***


### Dump the strings that are present in the file {#list_strings}
This uses `idautils.Strings` to iterate over the string literals
that are present in the IDB. Contrary to @show_selected_strings,
this will not require that the "Strings" window is opened & available.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_strings.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/list_strings.py) |  | Beginner |

**APIs Used:**
* `ida_nalt.STRTYPE_C`
* `ida_nalt.STRTYPE_C_16`
* `idautils.Strings`

***


### Produce disassembly listing for the entire file {#produce_lst_file}
Automate IDA to perform auto-analysis on a file and,
once that is done, produce a .lst file with the disassembly.

Run like so:

      ida -A "-S...path/to/produce_lst_file.py" <binary-file>

where:

  * -A instructs IDA to run in non-interactive mode
  * -S holds a path to the script to run (note this is a single token;
       there is no space between '-S' and its path.)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [produce_lst_file.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/produce_lst_file.py) |  | Beginner |

**APIs Used:**
* `ida_auto.auto_wait`
* `ida_fpro.qfile_t`
* `ida_ida.inf_get_max_ea`
* `ida_ida.inf_get_min_ea`
* `ida_loader.OFILE_LST`
* `ida_loader.PATH_TYPE_IDB`
* `ida_loader.gen_file`
* `ida_loader.get_path`
* `ida_pro.qexit`

***


### Rewrite the representation of some instructions {#ana_emu_out}
Implements disassembly of BUG_INSTR used in Linux kernel
BUG() macro, which is architecturally undefined and is not
disassembled by IDA's ARM module

See Linux/arch/arm/include/asm/bug.h for more info

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [ana_emu_out.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/ana_emu_out.py) | IDP_Hooks | Intermediate |

**APIs Used:**
* `ida_bytes.get_wide_dword`
* `ida_bytes.get_wide_word`
* `ida_idp.CUSTOM_INSN_ITYPE`
* `ida_idp.IDP_Hooks`
* `ida_idp.PLFM_ARM`
* `ida_idp.ph.id`
* `ida_idp.str2reg`
* `ida_segregs.get_sreg`

***


### Implement assembly of instructions {#assemble}
We add support for assembling the following pseudo instructions:

* "zero eax" -> xor eax, eax
* "nothing" -> nop

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [assemble.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/assemble.py) | IDP_Hooks | Intermediate |

**APIs Used:**
* `ida_idp.IDP_Hooks`
* `idautils.DecodeInstruction`

***


### Retrieve comments surrounding instructions {#dump_extra_comments}
Use the `ida_lines.get_extra_cmt` API to retrieve anterior
and posterior extra comments.

This script registers two actions, that can be used to dump
the previous and next extra comments.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [dump_extra_comments.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/dump_extra_comments.py) | ctxmenu | Intermediate |

**APIs Used:**
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_DISASM`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.find_widget`
* `ida_kernwin.get_screen_ea`
* `ida_kernwin.register_action`
* `ida_kernwin.unregister_action`
* `ida_lines.E_NEXT`
* `ida_lines.E_PREV`
* `ida_lines.get_extra_cmt`
* `ida_view`

***


### Dump function information {#dump_func_info}
Dump some of the most interesting bits of information about
the function we are currently looking at.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [dump_func_info.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/dump_func_info.py) |  | Intermediate |

**APIs Used:**
* `ida_funcs.FUNC_FRAME`
* `ida_funcs.FUNC_LUMINA`
* `ida_funcs.FUNC_OUTLINE`
* `ida_funcs.FUNC_THUNK`
* `ida_funcs.get_fchunk`
* `ida_funcs.is_func_entry`
* `ida_funcs.is_func_tail`
* `ida_kernwin.get_screen_ea`

***


### Parse listing line, and dump some information {#dump_line_sections}
Using `ida_kernwin.parse_tagged_line_sections`, we will parse
so-called "tagged" listing lines, and extract semantic information
such as instruction mnemonic, operand text, ...

This script registers an actions, that can be used to dump
the line sections.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [dump_line_sections.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/dump_line_sections.py) |  | Intermediate |

**APIs Used:**
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_DISASM`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.get_custom_viewer_curline`
* `ida_kernwin.parse_tagged_line_sections`
* `ida_kernwin.register_action`
* `ida_kernwin.tagged_line_sections_t`
* `ida_lines.COLOR_INSN`
* `ida_lines.COLOR_OPND1`
* `ida_lines.COLOR_OPND8`
* `ida_lines.COLOR_REG`

***


### Using "ida_bytes.find_string" {#find_string}
IDAPython's ida_bytes.find_string can be used to implement
a simple replacement for the 'Search > Sequence of bytes...'
dialog, that lets users search for sequences of bytes that
compose string literals in the binary file (either in the
default 1-byte-per-char encoding, or as UTF-16.)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [find_string.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/find_string.py) |  | Intermediate |

**APIs Used:**
* `ida_bytes.BIN_SEARCH_FORWARD`
* `ida_bytes.BIN_SEARCH_NOBREAK`
* `ida_bytes.BIN_SEARCH_NOSHOW`
* `ida_bytes.find_string`
* `ida_ida.inf_get_max_ea`
* `ida_idaapi.BADADDR`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_DISASM`
* `ida_kernwin.Form`
* `ida_kernwin.Form.ChkGroupControl`
* `ida_kernwin.Form.StringInput`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.get_screen_ea`
* `ida_kernwin.jumpto`
* `ida_kernwin.register_action`
* `ida_nalt.BPU_1B`
* `ida_nalt.BPU_2B`
* `ida_nalt.get_default_encoding_idx`

***


### Print notifications about function prototype changes {#func_ti_changed_listener}
The goal of this script is to demonstrate some usage of the type API.
In this script, we will create an IDB hook that intercepts `ti_changed`
IDB events, and if it is a function prototype that changed, print it.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [func_ti_changed_listener.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/func_ti_changed_listener.py) | IDB_Hooks | Intermediate |

**APIs Used:**
* `ida_funcs.get_func_name`
* `ida_idp.IDB_Hooks`
* `ida_typeinf.tinfo_t`

***


### List listing bookmarks {#list_bookmarks}
This sample shows how to programmatically access the list of
bookmarks placed in a listing widget (e.g., "IDA View-A",
"Pseudocode-", …) using the low-level `ida_moves.bookmarks_t`
type.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_bookmarks.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/list_bookmarks.py) | bookmarks | Intermediate |

**APIs Used:**
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.get_current_viewer`
* `ida_kernwin.get_viewer_user_data`
* `ida_kernwin.get_widget_title`
* `ida_kernwin.register_action`
* `ida_moves.bookmarks_t`

***


### Showcase (some of) the iterators available on a function {#list_function_items}
This demonstrates how to use some of the iterators available on the func_t type.

This example will focus on:

  * `func_t[.__iter__]`: the default iterator; iterates on instructions
  * `func_t.data_items`: iterate on data items contained within a function
  * `func_t.head_items`: iterate on 'heads' (i.e., addresses containing
                         the start of an instruction, or a data item.
  * `func_t.addresses`: iterate on all addresses within function (code
                        and data, beginning of an item or not)

Type `help(ida_funcs.func_t)` for a full list of iterators.

In addition, one can use:

  * `func_tail_iterator_t`: iterate on all the chunks (including
                            the main one) of the function
  * `func_parent_iterator_t`: iterate on all the parent functions,
                              that include this chunk

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_function_items.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/list_function_items.py) | funcs iterator | Intermediate |

**APIs Used:**
* `ida_bytes.get_flags`
* `ida_bytes.is_code`
* `ida_bytes.is_data`
* `ida_bytes.is_tail`
* `ida_bytes.is_unknown`
* `ida_funcs.func_tail_iterator_t`
* `ida_funcs.get_fchunk`
* `ida_funcs.get_func`
* `ida_funcs.get_func_name`
* `ida_kernwin.get_screen_ea`
* `ida_ua.print_insn_mnem`

***


### React to database events/notifications {#log_idb_events}
These hooks will be notified about IDB events, and
dump their information to the "Output" window

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [log_idb_events.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/log_idb_events.py) | IDB_Hooks | Intermediate |

**APIs Used:**
* `ida_idp.IDB_Hooks`

***


### React to processor events/notifications {#log_idp_events}
These hooks will be notified about IDP events, and
dump their information to the "Output" window

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [log_idp_events.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/log_idp_events.py) | IDP_Hooks | Intermediate |

**APIs Used:**
* `ida_idp.IDP_Hooks`

***


### Record and replay changes in function prototypes {#replay_prototypes_changes}
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

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [replay_prototypes_changes.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/replay_prototypes_changes.py) | IDB_Hooks | Intermediate |

**APIs Used:**
* `ida_funcs.get_func`
* `ida_idp.IDB_Hooks`
* `ida_typeinf.PRTYPE_1LINE`
* `ida_typeinf.TINFO_DEFINITE`
* `ida_typeinf.apply_tinfo`
* `ida_typeinf.get_idati`
* `ida_typeinf.tinfo_t`

***


### Add a new member to an existing function frame {#add_frame_member}
The goal of this script is to demonstrate some usage of the type API.
In this script, we show a way to add a new frame member (a pointer to
 an uint64) inside a wide enough gap in the frame:
* Get the function object surrounding cursor location.
* Use this function to retrieve the corresponding frame object.
* Find a wide enough gap to create our new member.
* If found, we use cal_frame_offset() to get the actual
  offset in the frame structure.
* Use the previous result to add the new member.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [add_frame_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/add_frame_member.py) |  | Advanced |

**APIs Used:**
* `ida_frame.add_frame_member`
* `ida_frame.calc_frame_offset`
* `ida_frame.get_func_frame`
* `ida_funcs.get_func`
* `ida_range.rangeset_t`
* `ida_typeinf.BTF_UINT64`
* `ida_typeinf.tinfo_t`
* `idc.here`

***


### Custom data types & printers {#custom_data_types_and_formats}
IDA can be extended to support certain data types that it
does not know about out-of-the-box.

A 'custom data type' provide information about the type &
size of a piece of data, while a 'custom data format' is in
charge of formatting that data (there can be more than
one format for a specific 'custom data type'.)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [custom_data_types_and_formats.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/custom_data_types_and_formats.py) |  | Advanced |

**APIs Used:**
* `ida_bytes.data_format_t`
* `ida_bytes.data_type_t`
* `ida_bytes.find_custom_data_type`
* `ida_bytes.get_byte`
* `ida_bytes.register_data_types_and_formats`
* `ida_bytes.unregister_data_types_and_formats`
* `ida_idaapi.NW_CLOSEIDB`
* `ida_idaapi.NW_OPENIDB`
* `ida_idaapi.NW_REMOVE`
* `ida_idaapi.NW_TERMIDA`
* `ida_idaapi.notify_when`
* `ida_idaapi.struct_unpack`
* `ida_lines.COLSTR`
* `ida_lines.SCOLOR_IMPNAME`
* `ida_lines.SCOLOR_INSN`
* `ida_lines.SCOLOR_NUMBER`
* `ida_lines.SCOLOR_REG`
* `ida_nalt.get_input_file_path`
* `ida_netnode.netnode`
* `ida_typeinf.tinfo_t`

***


### List operands representing a "path" to a (possibly nested) structure member {#list_struct_accesses}
It is possible to assign, to instruction operands, the notion of "structure
offset", which really is a pointer to a specific offset in a type, leading
to a possible N-deep path within types.

E.g., assuming the following types

        struct c
        {
            int foo;
            int bar;
            int baz;
            int quux;
            int trail;
        };

        struct b
        {
            int gap;
            c c_instance;
        };

        struct a
        {
            int count;
            b b_instance;
        };

and assuming an instruction that initially looks like this:

        mov eax, 10h

by pressing `t`, the user will be able set the "structure offset"
to either:

  * `c.trail`
  * `b.c_instance.quux`
  * `a.b_inscance.c_instance.baz`

Here's why IDA offers `a.b_inscance.c_instance.baz`:

        0000   struct a
               {
        0000       int count;
        0004       struct b
                   {
        0004           int gap;
        0008           struct c
                       {
        0008               int foo;
        000C               int bar;
        0010               int baz;
        0014               int quux;
        0018               int trail;
                       };
                   };
               };

This sample shows how to programmatically retrieve information about
that "structure member path" that an operand was made pointing to.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_struct_accesses.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/list_struct_accesses.py) | bookmarks | Advanced |

**APIs Used:**
* `ida_bytes.get_full_flags`
* `ida_bytes.get_stroff_path`
* `ida_bytes.is_stroff`
* `ida_typeinf.get_tid_name`
* `ida_typeinf.tinfo_t`
* `ida_ua.decode_insn`
* `ida_ua.insn_t`
* `ida_ua.o_imm`
* `ida_ua.o_void`

***


### Notify the user when an instruction operand changes {#operand_changed}
Show notifications whenever the user changes
an instruction's operand, or a data item.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [operand_changed.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/disassembler/operand_changed.py) | IDB_Hooks | Advanced |

**APIs Used:**
* `ida_bytes.ALOPT_IGNCLT`
* `ida_bytes.ALOPT_IGNHEADS`
* `ida_bytes.get_flags`
* `ida_bytes.get_max_strlit_length`
* `ida_bytes.get_opinfo`
* `ida_bytes.get_strlit_contents`
* `ida_bytes.is_custfmt`
* `ida_bytes.is_custom`
* `ida_bytes.is_enum`
* `ida_bytes.is_off`
* `ida_bytes.is_strlit`
* `ida_bytes.is_stroff`
* `ida_bytes.is_struct`
* `ida_idp.IDB_Hooks`
* `ida_nalt.STRENC_DEFAULT`
* `ida_nalt.get_default_encoding_idx`
* `ida_nalt.get_encoding_name`
* `ida_nalt.get_str_encoding_idx`
* `ida_nalt.get_strtype_bpu`
* `ida_nalt.opinfo_t`
* `ida_typeinf.get_tid_name`
* `ida_typeinf.tinfo_t`

***


### Produce C listing for the entire file {#produce_c_file}
Automate IDA to perform auto-analysis on a file and,
once that is done, produce a .c file containing the
decompilation of all the functions in that file.

Run like so:

      ida -A "-S...path/to/produce_c_file.py" <binary-file>

where:

  * -A instructs IDA to run in non-interactive mode
  * -S holds a path to the script to run (note this is a single token;
       there is no space between '-S' and its path.)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [produce_c_file.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/produce_c_file.py) |  | Beginner |

**APIs Used:**
* `ida_auto.auto_wait`
* `ida_hexrays.VDRUN_MAYSTOP`
* `ida_hexrays.VDRUN_NEWFILE`
* `ida_hexrays.VDRUN_SILENT`
* `ida_hexrays.decompile_many`
* `ida_loader.PATH_TYPE_IDB`
* `ida_loader.get_path`
* `ida_pro.qexit`

***


### Decompile & print current function {#vds1}
Decompile the function under the cursor

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds1.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds1.py) |  | Beginner |

**APIs Used:**
* `ida_funcs.get_func`
* `ida_hexrays.decompile`
* `ida_hexrays.get_hexrays_version`
* `ida_hexrays.init_hexrays_plugin`
* `ida_kernwin.get_screen_ea`
* `ida_lines.tag_remove`

***


### Generate microcode for the selected range of instructions {#vds13}
Generates microcode for selection and dumps it to the output window.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds13.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds13.py) |  | Beginner |

**APIs Used:**
* `ida_bytes.get_flags`
* `ida_bytes.is_code`
* `ida_hexrays.DECOMP_WARNINGS`
* `ida_hexrays.gen_microcode`
* `ida_hexrays.hexrays_failure_t`
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.mba_ranges_t`
* `ida_hexrays.vd_printer_t`
* `ida_kernwin.read_range_selection`
* `ida_kernwin.warning`
* `ida_range.range_t`

***


### Dump statement blocks {#vds7}
Using a `ida_hexrays.ctree_visitor_t`, search for
`ida_hexrays.cit_block` instances and dump them.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds7.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds7.py) | Hexrays_Hooks | Beginner |

**APIs Used:**
* `ida_hexrays.CMAT_BUILT`
* `ida_hexrays.CV_FAST`
* `ida_hexrays.Hexrays_Hooks`
* `ida_hexrays.cit_block`
* `ida_hexrays.ctree_visitor_t`
* `ida_hexrays.init_hexrays_plugin`

***


### Provide custom decompiler hints {#vds_create_hint}
Handle `ida_hexrays.hxe_create_hint` notification using hooks,
to return our own.

If the object under the cursor is:

* a function call, prefix the original decompiler hint with `==> `
* a local variable declaration, replace the hint with our own in
  the form of `!{varname}` (where `{varname}` is replaced with the
  variable name)
* an `if` statement, replace the hint with our own, saying "condition"

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds_create_hint.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds_create_hint.py) | Hexrays_Hooks | Beginner |

**APIs Used:**
* `ida_hexrays.Hexrays_Hooks`
* `ida_hexrays.USE_MOUSE`
* `ida_hexrays.VDI_EXPR`
* `ida_hexrays.VDI_LVAR`
* `ida_hexrays.cit_if`
* `ida_hexrays.cot_call`

***


### Interactively color decompilation lines {#colorize_pseudocode_lines}
Provides an action that can be used to dynamically alter the
lines background rendering for pseudocode listings (as opposed to
using `ida_hexrays.cfunc_t.pseudocode[N].bgcolor`)

After running this script, pressing 'M' on a line in a
"Pseudocode-?" widget, will cause that line to be rendered
with a special background color.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [colorize_pseudocode_lines.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/colorize_pseudocode_lines.py) | colors UI_Hooks | Intermediate |

**APIs Used:**
* `ida_hexrays.get_widget_vdui`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_PSEUDOCODE`
* `ida_kernwin.CK_EXTRA11`
* `ida_kernwin.UI_Hooks`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.get_custom_viewer_location`
* `ida_kernwin.line_rendering_output_entry_t`
* `ida_kernwin.refresh_custom_viewer`
* `ida_kernwin.register_action`
* `ida_moves.lochist_entry_t`

***


### Decompile entrypoint automatically {#decompile_entry_points}
Attempts to load a decompiler plugin corresponding to the current
architecture right after auto-analysis is performed,
and then tries to decompile the function at the first entrypoint.

It is particularly suited for use with the '-S' flag, for example:
idat -Ldecompile.log -Sdecompile_entry_points.py -c file

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [decompile_entry_points.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/decompile_entry_points.py) |  | Intermediate |

**APIs Used:**
* `ida_auto.auto_wait`
* `ida_entry.get_entry`
* `ida_entry.get_entry_ordinal`
* `ida_entry.get_entry_qty`
* `ida_hexrays.decompile`
* `ida_hexrays.init_hexrays_plugin`
* `ida_idp.PLFM_386`
* `ida_idp.PLFM_ARM`
* `ida_idp.PLFM_MIPS`
* `ida_idp.PLFM_PPC`
* `ida_idp.PLFM_RISCV`
* `ida_idp.ph.id`
* `ida_kernwin.cvar.batch`
* `ida_kernwin.msg`
* `ida_loader.load_plugin`
* `ida_pro.qexit`
* `idc.get_idb_path`

***


### Add custom microcode instruction optimization rule {#vds10}
Installs a custom microcode instruction optimization rule,
to transform:

    call   !DbgRaiseAssertionFailure <fast:>.0

into

    call   !DbgRaiseAssertionFailure <fast:"char *" "assertion text">.0

To see this plugin in action please use arm64_brk.i64

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds10.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds10.py) | plugin | Intermediate |

**APIs Used:**
* `ida_bytes.get_cmt`
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.mop_str`
* `ida_hexrays.optinsn_t`
* `ida_idaapi.PLUGIN_HIDE`
* `ida_idaapi.PLUGIN_KEEP`
* `ida_idaapi.plugin_t`
* `ida_typeinf.STI_PCCHAR`
* `ida_typeinf.tinfo_t.get_stock`

***


### Dynamically provide a custom call type {#vds21}
This plugin can greatly improve decompilation of indirect calls:

    call    [eax+4]

For them, the decompiler has to guess the prototype of the called function.
This has to be done at a very early phase of decompilation because
the function prototype influences the data flow analysis. On the other
hand, we do not have global data flow analysis results yet because
we haven't analyzed all calls in the function. It is a chicked-and-egg
problem.

The decompiler uses various techniques to guess the called function
prototype. While it works very well, it may fail in some cases.

To fix, the user can specify the call prototype manually, using
"Edit, Operand types, Set operand type" at the call instruction.

This plugin illustrates another approach to the problem:
if you happen to be able to calculate the call prototypes dynamically,
this is how to inform the decompiler about them.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds21.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds21.py) | Hexrays_Hooks plugin | Intermediate |

**APIs Used:**
* `ida_hexrays.Hexrays_Hooks`
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.m_call`
* `ida_hexrays.mcallinfo_t`
* `ida_idaapi.PLUGIN_HIDE`
* `ida_idaapi.PLUGIN_KEEP`
* `ida_idaapi.plugin_t`
* `ida_kernwin.msg`
* `ida_kernwin.warning`
* `ida_nalt.get_op_tinfo`
* `ida_typeinf.BT_INT`
* `ida_typeinf.CM_CC_STDCALL`
* `ida_typeinf.CM_N32_F48`
* `ida_typeinf.parse_decl`
* `ida_typeinf.tinfo_t`

***


### Dump user-defined information for a function {#vds4}
Prints user-defined information to the "Output" window.
Namely:

  * user defined label names
  * user defined indented comments
  * user defined number formats
  * user defined local variable names, types, comments

This script loads information from the database without decompiling anything.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds4.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds4.py) |  | Intermediate |

**APIs Used:**
* `ida_bytes.get_radix`
* `ida_funcs.get_func`
* `ida_hexrays.CIT_COLLAPSED`
* `ida_hexrays.NF_NEGATE`
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.lvar_uservec_t`
* `ida_hexrays.restore_user_cmts`
* `ida_hexrays.restore_user_iflags`
* `ida_hexrays.restore_user_labels`
* `ida_hexrays.restore_user_lvar_settings`
* `ida_hexrays.restore_user_numforms`
* `ida_hexrays.user_cmts_free`
* `ida_hexrays.user_iflags_free`
* `ida_hexrays.user_labels_free`
* `ida_hexrays.user_numforms_free`
* `ida_kernwin.get_screen_ea`

***


### Superficially modify the decompilation output {#vds6}
Modifies the decompilation output in a superficial manner,
by removing some white spaces

Note: this is rather crude, not quite "pythonic" code.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds6.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds6.py) | Hexrays_Hooks plugin | Intermediate |

**APIs Used:**
* `ida_hexrays.Hexrays_Hooks`
* `ida_hexrays.init_hexrays_plugin`
* `ida_idaapi.PLUGIN_HIDE`
* `ida_idaapi.PLUGIN_KEEP`
* `ida_idaapi.plugin_t`
* `ida_lines.tag_advance`
* `ida_lines.tag_skipcodes`

***


### Improve decompilation by turning specific patterns into custom function calls {#vds8}
Registers an action that uses a `ida_hexrays.udc_filter_t` to decompile
`svc 0x900001` and `svc 0x9000F8` as function calls to
`svc_exit()` and `svc_exit_group()` respectively.

You will need to have an ARM + Linux IDB for this script to be usable

In addition to having a shortcut, the action will be present
in the context menu.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds8.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds8.py) | ctxmenu UI_Hooks | Intermediate |

**APIs Used:**
* `ida_allins.ARM_svc`
* `ida_hexrays.get_widget_vdui`
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.install_microcode_filter`
* `ida_hexrays.udc_filter_t`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_PSEUDOCODE`
* `ida_kernwin.UI_Hooks`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.get_widget_type`
* `ida_kernwin.register_action`

***


### React to decompiler events/notifications {#vds_hooks}
Shows how to hook to many notifications sent by the decompiler.

This plugin doesn't really accomplish anything: it just prints
the parameters.

The list of notifications handled below should be exhaustive,
and is there to hint at what is possible to accomplish by
subclassing `ida_hexrays.Hexrays_Hooks`

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds_hooks.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds_hooks.py) | Hexrays_Hooks | Intermediate |

**APIs Used:**
* `ida_hexrays.Hexrays_Hooks`
* `ida_hexrays.cfunc_t`
* `ida_hexrays.lvar_t`
* `ida_hexrays.vdui_t`

***


### Modifying function local variables {#vds_modify_user_lvars}
Use a `ida_hexrays.user_lvar_modifier_t` to modify names,
comments and/or types of local variables.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds_modify_user_lvars.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds_modify_user_lvars.py) |  | Intermediate |

**APIs Used:**
* `ida_hexrays.modify_user_lvars`
* `ida_hexrays.user_lvar_modifier_t`
* `ida_typeinf.parse_decl`
* `idc.here`

***


### Print information about the current position in decompilation {#curpos_details}
Shows how user input information can be retrieved during
processing of a notification triggered by that input

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [curpos_details.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/curpos_details.py) | Hexrays_Hooks | Advanced |

**APIs Used:**
* `ida_hexrays.Hexrays_Hooks`
* `ida_kernwin.get_user_input_event`
* `ida_kernwin.iek_key_press`
* `ida_kernwin.iek_key_release`
* `ida_kernwin.iek_mouse_button_press`
* `ida_kernwin.iek_mouse_button_release`
* `ida_kernwin.iek_mouse_wheel`
* `ida_kernwin.iek_shortcut`
* `ida_kernwin.input_event_t`

***


### Add a custom microcode block optimization rule {#vds11}
Installs a custom microcode block optimization rule,
to transform:

      goto L1
      ...
    L1:
      goto L2

into

      goto L2

In other words we fix a goto target if it points to a chain of gotos.
This improves the decompiler output in some cases.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds11.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds11.py) | plugin | Advanced |

**APIs Used:**
* `ida_hexrays.getf_reginsn`
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.m_goto`
* `ida_hexrays.optblock_t`
* `ida_idaapi.PLUGIN_HIDE`
* `ida_idaapi.PLUGIN_KEEP`
* `ida_idaapi.plugin_t`

***


### List instruction registers {#vds12}
Shows a list of direct references to a register from the
current instruction.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds12.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds12.py) |  | Advanced |

**APIs Used:**
* `ida_bytes.get_flags`
* `ida_bytes.is_code`
* `ida_funcs.get_func`
* `ida_hexrays.ACFL_GUESS`
* `ida_hexrays.DECOMP_NO_CACHE`
* `ida_hexrays.DECOMP_WARNINGS`
* `ida_hexrays.GCO_DEF`
* `ida_hexrays.GCO_USE`
* `ida_hexrays.GC_REGS_AND_STKVARS`
* `ida_hexrays.MERR_OK`
* `ida_hexrays.MMAT_PREOPTIMIZED`
* `ida_hexrays.MUST_ACCESS`
* `ida_hexrays.gco_info_t`
* `ida_hexrays.gen_microcode`
* `ida_hexrays.get_current_operand`
* `ida_hexrays.get_merror_desc`
* `ida_hexrays.hexrays_failure_t`
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.mba_ranges_t`
* `ida_hexrays.mlist_t`
* `ida_hexrays.op_parent_info_t`
* `ida_hexrays.voff_t`
* `ida_kernwin.Choose`
* `ida_kernwin.get_screen_ea`
* `ida_kernwin.jumpto`
* `ida_kernwin.warning`
* `ida_lines.GENDSM_REMOVE_TAGS`
* `ida_lines.generate_disasm_line`
* `ida_pro.eavec_t`

***


### Invoke the structure offset-choosing dialog from decompilation {#vds17}
Registers an action opens the "Select offsets" widget
(select_udt_by_offset() call).

This effectively repeats the functionality already available
through Alt+Y.

Place cursor on the union field and press Shift+T

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds17.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds17.py) | plugin | Advanced |

**APIs Used:**
* `ida_hexrays.USE_KEYBOARD`
* `ida_hexrays.cot_add`
* `ida_hexrays.cot_cast`
* `ida_hexrays.cot_memptr`
* `ida_hexrays.cot_memref`
* `ida_hexrays.cot_num`
* `ida_hexrays.cot_ref`
* `ida_hexrays.get_hexrays_version`
* `ida_hexrays.get_widget_vdui`
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.select_udt_by_offset`
* `ida_hexrays.ui_stroff_applicator_t`
* `ida_hexrays.ui_stroff_ops_t`
* `ida_idaapi.BADADDR`
* `ida_idaapi.PLUGIN_HIDE`
* `ida_idaapi.PLUGIN_KEEP`
* `ida_idaapi.plugin_t`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_PSEUDOCODE`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.get_custom_viewer_curline`
* `ida_kernwin.msg`
* `ida_kernwin.register_action`
* `ida_kernwin.warning`
* `ida_lines.tag_remove`
* `ida_typeinf.PRTYPE_1LINE`
* `ida_typeinf.print_tinfo`
* `ida_typeinf.remove_pointer`

***


### Add a custom microcode instruction optimization rule {#vds19}
Installs a custom microcode instruction optimization rule,
to transform:

    x | ~x

into

    -1

To see this plugin in action please use be_ornot_be.idb

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds19.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds19.py) | plugin | Advanced |

**APIs Used:**
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.m_bnot`
* `ida_hexrays.m_mov`
* `ida_hexrays.m_or`
* `ida_hexrays.minsn_visitor_t`
* `ida_hexrays.mop_t`
* `ida_hexrays.optinsn_t`
* `ida_idaapi.PLUGIN_HIDE`
* `ida_idaapi.PLUGIN_KEEP`
* `ida_idaapi.plugin_t`

***


### Invert if/else blocks in decompilation {#vds3}
Registers an action that can be used to invert the `if`
and `else` blocks of a `ida_hexrays.cif_t`.

For example, a statement like

    if ( cond )
    {
      statements1;
    }
    else
    {
      statements2;
    }

will be displayed as

    if ( !cond )
    {
      statements2;
    }
    else
    {
      statements1;
    }

The modifications are persistent: the user can quit & restart
IDA, and the changes will be present.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds3.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds3.py) | ctxmenu Hexrays_Hooks IDP_Hooks plugin | Advanced |

**APIs Used:**
* `ida_hexrays.CMAT_FINAL`
* `ida_hexrays.CV_FAST`
* `ida_hexrays.CV_INSNS`
* `ida_hexrays.Hexrays_Hooks`
* `ida_hexrays.ITP_ELSE`
* `ida_hexrays.USE_KEYBOARD`
* `ida_hexrays.VDI_TAIL`
* `ida_hexrays.cexpr_t`
* `ida_hexrays.cit_if`
* `ida_hexrays.ctree_visitor_t`
* `ida_hexrays.get_widget_vdui`
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.lnot`
* `ida_hexrays.qswap`
* `ida_idaapi.PLUGIN_HIDE`
* `ida_idaapi.PLUGIN_KEEP`
* `ida_idaapi.plugin_t`
* `ida_idp.IDP_Hooks`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_PSEUDOCODE`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.register_action`
* `ida_netnode.netnode`

***


### Dump C-tree graph {#vds5}
Registers an action that can be used to show the graph of the ctree.
The current item will be highlighted in the graph.

The command shortcut is `Ctrl+Shift+G`, and is also added
to the context menu.

To display the graph, we produce a .gdl file, and
request that ida displays that using `ida_gdl.display_gdl`.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds5.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds5.py) | ctxmenu Hexrays_Hooks plugin | Advanced |

**APIs Used:**
* `ida_gdl.display_gdl`
* `ida_hexrays.Hexrays_Hooks`
* `ida_hexrays.USE_KEYBOARD`
* `ida_hexrays.cit_asm`
* `ida_hexrays.cit_goto`
* `ida_hexrays.cot_helper`
* `ida_hexrays.cot_memptr`
* `ida_hexrays.cot_memref`
* `ida_hexrays.cot_num`
* `ida_hexrays.cot_obj`
* `ida_hexrays.cot_ptr`
* `ida_hexrays.cot_str`
* `ida_hexrays.cot_var`
* `ida_hexrays.ctree_parentee_t`
* `ida_hexrays.get_ctype_name`
* `ida_hexrays.get_widget_vdui`
* `ida_hexrays.init_hexrays_plugin`
* `ida_idaapi.PLUGIN_HIDE`
* `ida_idaapi.PLUGIN_KEEP`
* `ida_idaapi.plugin_t`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_PSEUDOCODE`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.register_action`
* `ida_kernwin.warning`
* `ida_lines.tag_remove`
* `ida_pro.str2user`

***


### Show decompiler cross-references {#vds_xrefs}
Show decompiler-style Xref when the `Ctrl+X` key is
pressed in the Decompiler window.

* supports any global name: functions, strings, integers, ...
* supports structure member.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [vds_xrefs.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/decompiler/vds_xrefs.py) | ctxmenu Hexrays_Hooks | Advanced |

**APIs Used:**
* `ida_funcs.get_func_name`
* `ida_hexrays.DECOMP_GXREFS_FORCE`
* `ida_hexrays.Hexrays_Hooks`
* `ida_hexrays.USE_KEYBOARD`
* `ida_hexrays.VDI_EXPR`
* `ida_hexrays.VDI_FUNC`
* `ida_hexrays.cexpr_t`
* `ida_hexrays.cfunc_t`
* `ida_hexrays.cinsn_t`
* `ida_hexrays.decompile`
* `ida_hexrays.get_widget_vdui`
* `ida_hexrays.init_hexrays_plugin`
* `ida_hexrays.open_pseudocode`
* `ida_hexrays.qstring_printer_t`
* `ida_idaapi.BADADDR`
* `ida_kernwin.AST_DISABLE`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE`
* `ida_kernwin.BWN_PSEUDOCODE`
* `ida_kernwin.PluginForm`
* `ida_kernwin.PluginForm.Show`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.register_action`
* `ida_typeinf.PRTYPE_1LINE`
* `ida_typeinf.STRMEM_OFFSET`
* `ida_typeinf.print_tinfo`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udm_t`
* `idautils.Functions`
* `idautils.XrefsTo`

***


### Print all registers, for all threads in the debugged process {#print_registers}
Iterate over the list of threads in the program being
debugged, and dump all registers contents

To use this example:

  * run `ida64` on test program `simple_appcall_linux64`, or
    `ida` on test program `simple_appcall_linux32`, and wait for
    auto-analysis to finish
  * put a breakpoint somewhere in the code
  * select the 'linux debugger' (either local, or remote)
  * start debugging
  * Press Alt+Shift+C at the breakpoint

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [print_registers.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/debugger/misc/print_registers.py) |  | Beginner |

**APIs Used:**
* `ida_dbg.get_reg_vals`
* `ida_dbg.get_thread_qty`
* `ida_dbg.getn_thread`
* `ida_idd.get_dbg`
* `ida_kernwin.AST_ENABLE_ALWAYS`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.register_action`

***


### Dump symbols from a process being debugged {#show_debug_names}
Queries the debugger (possibly remotely) for the list of
symbols that the process being debugged, provides.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [show_debug_names.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/debugger/show_debug_names.py) |  | Beginner |

**APIs Used:**
* `ida_dbg.DSTATE_SUSP`
* `ida_dbg.get_process_state`
* `ida_dbg.is_debugger_on`
* `ida_ida.inf_get_max_ea`
* `ida_ida.inf_get_min_ea`
* `ida_name.get_debug_names`

***


### Print call stack {#print_call_stack}
Print the return addresses from the call stack at a breakpoint,
when debugging a Linux binary.
(and also print the module and the debug name from debugger)

To use this example:

  * run `ida` on test program `simple_appcall_linux64`, or
    `ida` on test program `simple_appcall_linux32`, and wait for
    auto-analysis to finish
  * put a breakpoint where you want to see the call stack
  * select the 'linux debugger' (either local, or remote)
  * start debugging
  * Press Shift+C at the breakpoint

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [print_call_stack.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/debugger/misc/print_call_stack.py) |  | Intermediate |

**APIs Used:**
* `ida_dbg.collect_stack_trace`
* `ida_dbg.get_current_thread`
* `ida_dbg.get_module_info`
* `ida_idd.call_stack_t`
* `ida_idd.modinfo_t`
* `ida_kernwin.AST_ENABLE_ALWAYS`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.register_action`
* `ida_name.GNCN_NOCOLOR`
* `ida_name.GNCN_NOLABEL`
* `ida_name.GNCN_NOSEG`
* `ida_name.GNCN_PREFDBG`
* `ida_name.get_nice_colored_name`

***


### Add a custom action to the "registers" widget {#registers_context_menu}
It's possible to add actions to the context menu of
pretty much all widgets in IDA.

This example shows how to do just that for
registers-displaying widgets (e.g., "General registers")

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [registers_context_menu.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/debugger/misc/registers_context_menu.py) | ctxmenu UI_Hooks | Intermediate |

**APIs Used:**
* `ida_dbg.get_dbg_reg_info`
* `ida_dbg.get_reg_val`
* `ida_idd.register_info_t`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_CPUREGS`
* `ida_kernwin.UI_Hooks`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.attach_action_to_popup`
* `ida_kernwin.get_widget_type`
* `ida_kernwin.register_action`
* `ida_ua.dt_byte`
* `ida_ua.dt_dword`
* `ida_ua.dt_qword`
* `ida_ua.dt_word`

***


### Programmatically drive a debugging session {#automatic_steps}
Start a debugging session, step through the first five
instructions. Each instruction is disassembled after
execution.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [automatic_steps.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/debugger/dbghooks/automatic_steps.py) | DBG_Hooks | Advanced |

**APIs Used:**
* `ida_dbg.DBG_Hooks`
* `ida_dbg.get_reg_val`
* `ida_dbg.request_exit_process`
* `ida_dbg.request_run_to`
* `ida_dbg.request_step_over`
* `ida_dbg.run_requests`
* `ida_ida.inf_get_start_ip`
* `ida_idaapi.BADADDR`
* `ida_lines.generate_disasm_line`
* `ida_lines.tag_remove`

***


### React to trace notifications {#dbg_trace}
This script demonstrates using the low-level tracing hook
(ida_dbg.DBG_Hooks.dbg_trace). It can be run like so:

     ida.exe -B -Sdbg_trace.py -Ltrace.log file.exe

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [dbg_trace.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/debugger/dbghooks/dbg_trace.py) | DBG_Hooks | Advanced |

**APIs Used:**
* `GENDSM_FORCE_CODE`
* `GENDSM_REMOVE_TAGS`
* `NN_call`
* `NN_callfi`
* `NN_callni`
* `generate_disasm_line`
* `ida_dbg.DBG_Hooks`
* `ida_dbg.ST_OVER_DEBUG_SEG`
* `ida_dbg.ST_OVER_LIB_FUNC`
* `ida_dbg.enable_step_trace`
* `ida_dbg.get_process_state`
* `ida_dbg.get_reg_val`
* `ida_dbg.get_step_trace_options`
* `ida_dbg.load_debugger`
* `ida_dbg.refresh_debugger_memory`
* `ida_dbg.request_continue_process`
* `ida_dbg.request_enable_step_trace`
* `ida_dbg.request_set_step_trace_options`
* `ida_dbg.run_requests`
* `ida_dbg.run_to`
* `ida_dbg.set_step_trace_options`
* `ida_dbg.wait_for_next_event`
* `ida_ida.f_ELF`
* `ida_ida.f_MACHO`
* `ida_ida.f_PE`
* `ida_ida.inf_get_filetype`
* `ida_ida.inf_get_max_ea`
* `ida_ida.inf_get_min_ea`
* `ida_ida.inf_get_start_ip`
* `ida_pro.qexit`
* `ida_ua.decode_insn`
* `ida_ua.insn_t`
* `idc.ARGV`

***


### Execute code into the application being debugged (on Linux) {#simple_appcall_linux}
Using the `ida_idd.Appcall` utility to execute code in
the process being debugged.

This example will run the test program and stop wherever
the cursor currently is, and then perform an appcall to
execute the `ref4` and `ref8` functions.

To use this example:

  * run `ida64` on test program `simple_appcall_linux64`, or
    `ida` on test program `simple_appcall_linux32`, and wait for
    auto-analysis to finish
  * select the 'linux debugger' (either local, or remote)
  * run this script

Note: the real body of code is in `simple_appcall_common.py`.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [simple_appcall_linux.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/debugger/appcall/simple_appcall_linux.py) |  | Advanced |

**APIs Used:**
* `ida_dbg.DBG_Hooks`
* `ida_dbg.run_to`
* `ida_idaapi.BADADDR`
* `ida_idd.Appcall`
* `ida_idd.Appcall.byref`
* `ida_idd.Appcall.int64`
* `ida_kernwin.get_screen_ea`
* `ida_name.get_name_ea`
* `ida_name.set_name`
* `ida_typeinf.apply_cdecl`

***


### Execute code into the application being debugged (on Windows) {#simple_appcall_win}
Using the `ida_idd.Appcall` utility to execute code in
the process being debugged.

This example will run the test program and stop wherever
the cursor currently is, and then perform an appcall to
execute the `ref4` and `ref8` functions.

To use this example:

  * run `ida` on test program `simple_appcall_win64.exe`, or
    `ida` on test program `simple_appcall_win32.exe`, and wait for
    auto-analysis to finish
  * select the 'windows debugger' (either local, or remote)
  * run this script

Note: the real body of code is in `simple_appcall_common.py`.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [simple_appcall_win.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/debugger/appcall/simple_appcall_win.py) |  | Advanced |

**APIs Used:**
* `ida_dbg.DBG_Hooks`
* `ida_dbg.run_to`
* `ida_ida.inf_is_64bit`
* `ida_idaapi.BADADDR`
* `ida_idd.Appcall`
* `ida_idd.Appcall.byref`
* `ida_idd.Appcall.int64`
* `ida_kernwin.get_screen_ea`
* `ida_name.get_name_ea`
* `ida_name.set_name`
* `ida_typeinf.apply_cdecl`

***


### Create a structure by parsing its definition {#create_struct_by_parsing}
The goal of this script is to demonstrate some usage of the type API.
In this script, we create a structure using the "parsing" method.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [create_struct_by_parsing.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/create_struct_by_parsing.py) |  | Beginner |

**APIs Used:**
* `ida_typeinf.tinfo_t`

***


### Delete structure members that fall within an offset range {#del_struct_members}
The goal of this script is to demonstrate some usage of the type API.
In this script, we first create a structure with many members, and then
remove all those that fall within a range.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [del_struct_members.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/del_struct_members.py) |  | Beginner |

**APIs Used:**
* `ida_typeinf.STRMEM_OFFSET`
* `ida_typeinf.TERR_OK`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udm_t`

***


### Print enumeration members {#list_enum_member}
In this example, we will first ask the user to provide the name
of an enumeration, and then iterate on it

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_enum_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/list_enum_member.py) |  | Beginner |

**APIs Used:**
* `ida_kernwin.ask_str`

***


### Print function stack frame information {#list_frame_info}
The goal of this script is to demonstrate some usage of the type API.
In this script, we retrieve the function frame structure, and iterate
on the frame members.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_frame_info.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/list_frame_info.py) |  | Beginner |

**APIs Used:**
* `ida_funcs.get_func`
* `ida_kernwin.get_screen_ea`

***


### List database functions prototypes {#list_func_details}
This script demonstrates how to list a function return type
along with its parameters types and name if any.
We do this for all the functions found in the database.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_func_details.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/list_func_details.py) |  | Beginner |

**APIs Used:**
* `ida_funcs.get_func`
* `idautils.Functions`

***


### List structure members {#list_struct_member}
The goal of this script is to demonstrate some usage of the type API.
In this script, we:
* Ask the user for a structure name. It must already be present in the
local types.
* Retrieve the structure type info from the local type
* Extract its type details (udt)
* Iterates it members and prints their names.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_struct_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/list_struct_member.py) |  | Beginner |

**APIs Used:**
* `ida_kernwin.ask_str`
* `ida_typeinf.BTF_STRUCT`
* `ida_typeinf.get_idati`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udt_type_data_t`

***


### List cross-references to a structure {#list_struct_xrefs}
The goal of this script is to demonstrate some usage of the type API.
In this script, we:
* Ask the user for a structure name. It must already be present in the
local types.
* Get its tid
* Create the list of all the reference.
* Print it

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_struct_xrefs.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/list_struct_xrefs.py) |  | Beginner |

**APIs Used:**
* `ida_kernwin.choose_struct`
* `ida_typeinf.tinfo_t`
* `ida_xref.xrefblk_t`

***


### List union members {#list_union_member}
The goal of this script is to demonstrate some usage of the type API.
In this script, we:
* Ask the user for a union name. It must already be present in the
local types.
* Retrieve the union type info from the local type
* Extract its type details (udt)
* Iterates it members and prints their names.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_union_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/list_union_member.py) |  | Beginner |

**APIs Used:**
* `ida_kernwin.ask_str`
* `ida_typeinf.BTF_UNION`
* `ida_typeinf.get_idati`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udt_type_data_t`

***


### Mark a register "spoiled" by a function {#mark_func_spoiled}
At least two possibilies are offered in order to indicate that a function
spoils registers (excluding the "normal" ones):

You can either parse & apply a declaration:

      func_tfinfo = ida_typeinf.tinfo_t("int _spoils<rsi> main();")
      ida_typeinf.apply_tinfo(func.start_ea, func_tinfo, ida_typeinf.TINFO_DEFINITE)

or retrieve & modify the `tinfo_t` object directly.

This script showcases the latter.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [mark_func_spoiled.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/mark_func_spoiled.py) |  | Beginner |

**APIs Used:**
* `ida_funcs.get_func`
* `ida_idp.parse_reg_name`
* `ida_idp.reg_info_t`
* `ida_kernwin.get_screen_ea`
* `ida_nalt.get_tinfo`
* `ida_typeinf.FTI_SPOILED`
* `ida_typeinf.TINFO_DEFINITE`
* `ida_typeinf.apply_tinfo`
* `ida_typeinf.func_type_data_t`
* `ida_typeinf.tinfo_t`

***


### Apply function prototype to call sites {#apply_callee_tinfo}
The goal of this script is to demonstrate some usage of the type API.
In this script, we:
* Open the private type libary.
* Load its declaration in the type library by parsing its declaration and
keep the return tuple for future use.
* Deserialize the type info stored in the returned tuple.
* Get the address of the function.
* Get the address of the code reference to the function and apply
the type info there.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [apply_callee_tinfo.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/apply_callee_tinfo.py) |  | Intermediate |

**APIs Used:**
* `ida_idaapi.BADADDR`
* `ida_name.get_name_ea`
* `ida_typeinf.PT_REPLACE`
* `ida_typeinf.apply_callee_tinfo`
* `ida_typeinf.get_idati`
* `ida_typeinf.idc_parse_decl`
* `ida_typeinf.tinfo_t`
* `idautils.CodeRefsTo`

***


### Create an array type {#create_array}
The goal of this script is to demonstrate some usage of the type API.
In this script, we create an array using both versions of
create_array tinfo_t method.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [create_array.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/create_array.py) |  | Intermediate |

**APIs Used:**
* `ida_typeinf.BTF_INT`
* `ida_typeinf.array_type_data_t`
* `ida_typeinf.tinfo_t`

***


### Create a structure with bitfield members {#create_bfstruct}
The goal of this script is to demonstrate some usage of the type API.
In this script, we:
 * Create a bitfield structure. In the present case the bitfield is an int32
made of three 'members' spanning it entirely:
    bit0->bit19: bf1
    bit20->bit25: bf2
    bit26->bit31: bf3
 * For each member create a repeatable comment.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [create_bfstruct.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/create_bfstruct.py) |  | Intermediate |

**APIs Used:**
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udm_t`
* `ida_typeinf.udt_type_data_t`

***


### Create a bitmask enumeration {#create_bmenum}
The goal of this script is to demonstrate some usage of the type API.
In this script, we create a bitmask enumeration member by member.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [create_bmenum.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/create_bmenum.py) |  | Intermediate |

**APIs Used:**
* `ida_typeinf.BTE_BITMASK`
* `ida_typeinf.BTE_HEX`
* `ida_typeinf.tinfo_t`

***


### Create a type library file {#create_libssh2_til}
The goal of this script is to demonstrate some usage of the type API.
In this script:
 * We create a new libssh2-64.til file holding some libssh2 64-bit structures.
 * Once the file has been created, it can copied in the IDA install
   til directory or in the user IDA til directory.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [create_libssh2_til.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/create_libssh2_til.py) |  | Intermediate |

**APIs Used:**
* `ida_typeinf.HTI_DCL`
* `ida_typeinf.HTI_PAKDEF`
* `ida_typeinf.compact_til`
* `ida_typeinf.free_til`
* `ida_typeinf.new_til`
* `ida_typeinf.parse_decls`
* `ida_typeinf.store_til`

***


### Create a structure programmatically {#create_struct_by_member}
The goal of this script is to demonstrate some usage of the type API.
In this script, we create a structure by building it member by member.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [create_struct_by_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/create_struct_by_member.py) |  | Intermediate |

**APIs Used:**
* `ida_typeinf.BTF_UINT32`
* `ida_typeinf.NTF_TYPE`
* `ida_typeinf.del_named_type`
* `ida_typeinf.tinfo_errstr`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udt_type_data_t`

***


### Create & populate a structure {#create_structure_programmatically}
Usage of the API to create & populate a structure with
members of different types.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [create_structure_programmatically.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/create_structure_programmatically.py) |  | Intermediate |

**APIs Used:**
* `ida_typeinf.BTF_BYTE`
* `ida_typeinf.BTF_DOUBLE`
* `ida_typeinf.BTF_FLOAT`
* `ida_typeinf.BTF_INT`
* `ida_typeinf.BTF_INT128`
* `ida_typeinf.BTF_INT16`
* `ida_typeinf.BTF_INT64`
* `ida_typeinf.BTF_TBYTE`
* `ida_typeinf.BTF_UINT32`
* `ida_typeinf.FRB_NUMO`
* `ida_typeinf.NTF_TYPE`
* `ida_typeinf.PRTYPE_DEF`
* `ida_typeinf.PRTYPE_MULTI`
* `ida_typeinf.PRTYPE_TYPE`
* `ida_typeinf.del_named_type`
* `ida_typeinf.idc_parse_types`
* `ida_typeinf.tinfo_errstr`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udm_t`
* `ida_typeinf.udt_type_data_t`
* `ida_typeinf.value_repr_t`

***


### Create a union {#create_union_by_member}
The goal of this script is to demonstrate some usage of the type API.
In this script, we create a union by building it member after member.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [create_union_by_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/create_union_by_member.py) |  | Intermediate |

**APIs Used:**
* `ida_typeinf.BTF_CHAR`
* `ida_typeinf.BTF_FLOAT`
* `ida_typeinf.BTF_INT32`
* `ida_typeinf.BTF_UNION`
* `ida_typeinf.NTF_TYPE`
* `ida_typeinf.PRTYPE_DEF`
* `ida_typeinf.PRTYPE_MULTI`
* `ida_typeinf.PRTYPE_TYPE`
* `ida_typeinf.del_named_type`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udm_t`
* `ida_typeinf.udt_type_data_t`

***


### Create a segment, and define (complex) data in it {#create_user_shared_data}
The goal of this script is to demonstrate some usage of the type API.
In this script, we show how to create, set type and name of
a user shared data region in an ntdll IDB:
* Load the `_KUSER_SHARED_DATA` data type from a type info
  library shipped with IDA, and import it into the IDB's "local types"
* Create a data segment with UserSharedData as its name.
* Apply the type to the start of the newly created segment base
  address.
* Set the address name.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [create_user_shared_data.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/create_user_shared_data.py) |  | Intermediate |

**APIs Used:**
* `ida_name.set_name`
* `ida_segment.add_segm_ex`
* `ida_segment.saRelPara`
* `ida_segment.scPub`
* `ida_segment.segment_t`
* `ida_segment.setup_selector`
* `ida_typeinf.TINFO_DEFINITE`
* `ida_typeinf.apply_tinfo`
* `ida_typeinf.free_til`
* `ida_typeinf.load_til`

***


### Utilities to detect structure gaps & alignment {#gap_size_align_snippet}
The goal of this script is to illustrate ways to detect gaps & alignments
in structures, from a structure name & (byte) offset.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [gap_size_align_snippet.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/gap_size_align_snippet.py) |  | Intermediate |

**APIs Used:**
* `ida_range.rangeset_t`

***


### Get member by offset, taking into account variable sized structures {#get_best_fit_member}
The goal of this script is to provide a way to figure out
what structure member, is most likely referenced by an offset.

This also works for variable sized types.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [get_best_fit_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/get_best_fit_member.py) |  | Intermediate |

**APIs Used:**
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udt_type_data_t`

***


### Get information about the "innermost" member of a structure {#get_innermost_member}
Assuming the 2 following types:

        struct b
        {
            int low;
            int high;
        };

        struct a
        {
            int foo;
            b b_instance;
            int bar;
        };

looking at an offset of 5 bytes inside an `a` instance, might be
interpreted as pointing somewhere inside member `b_instance`, of type `b`.
Alternatively, that same offset might be intprereted as pointing
somewhere inside `low`, of type `int`.

We refer to that latter interpretation as "innermost", and this sample
shows how the API lets us "drill down" to retrieve that innermost member.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [get_innermost_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/get_innermost_member.py) |  | Intermediate |

**APIs Used:**
* `ida_typeinf.get_idati`
* `ida_typeinf.parse_decls`

***


### Load a type library from a file, and then a type from it {#import_type_from_til}
The goal of this script is to demonstrate some usage of the type API.
 In this script, we:
 * ask the user for a specific til to be lodaed
 * if successfully loaded ask the user for a type name to be imported.
 * append the type to the local types.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [import_type_from_til.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/import_type_from_til.py) |  | Intermediate |

**APIs Used:**
* `ida_kernwin.ask_str`
* `ida_typeinf.load_til`

***


### Inject a member in the middle of a structure {#insert_struct_member}
This sample will retrieve the type info object by its name,
find the member at the specified offset, and insert a
new member right before it

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [insert_struct_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/insert_struct_member.py) |  | Intermediate |

**APIs Used:**
* `ida_typeinf.BT_INT`
* `ida_typeinf.TERR_OK`
* `ida_typeinf.tinfo_t`

***


### List all xrefs to a function stack variable {#list_stkvar_xrefs}
Contrary to (in-memory) data & code xrefs, retrieving stack variables
xrefs requires a bit more work than just using ida_xref's first_to(),
next_to() (or higher level utilities such as idautils.XrefsTo)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [list_stkvar_xrefs.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/list_stkvar_xrefs.py) | xrefs | Intermediate |

**APIs Used:**
* `ida_bytes.get_flags`
* `ida_bytes.is_stkvar`
* `ida_frame.calc_stkvar_struc_offset`
* `ida_funcs.get_func`
* `ida_ida.UA_MAXOP`
* `ida_kernwin.AST_DISABLE_FOR_WIDGET`
* `ida_kernwin.AST_ENABLE_FOR_WIDGET`
* `ida_kernwin.BWN_DISASM`
* `ida_kernwin.action_desc_t`
* `ida_kernwin.action_handler_t`
* `ida_kernwin.get_current_viewer`
* `ida_kernwin.get_highlight`
* `ida_kernwin.get_screen_ea`
* `ida_kernwin.register_action`
* `ida_typeinf.tinfo_t`
* `ida_ua.decode_insn`
* `ida_ua.insn_t`

***


### Modify structure members attributes programmatically {#modify_struct_member}
This example shows how to access & modify certain less-obvious
attributes of structure members (pointer size, representation, ...)

We will first create the structure without those, and then
show how to programmatically modify them.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [modify_struct_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/modify_struct_member.py) |  | Intermediate |

**APIs Used:**
* `ida_nalt.REFINFO_RVAOFF`
* `ida_nalt.REF_OFF64`
* `ida_typeinf.FRB_OFFSET`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.value_repr_t`

***


### List cross-references to function stack frame variables {#print_stkvar_xrefs}
The goal of this script is to demonstrate some usage of the type API.
In this script, we demonstrate how to list each stack variables
xref:
* Get the function object surrounding cursor location.
* Use this function to retrieve the corresponding frame object.
* For each frame element:
    - Build the stack variable xref list
    - Print it.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [print_stkvar_xrefs.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/print_stkvar_xrefs.py) |  | Intermediate |

**APIs Used:**
* `ida_frame.build_stkvar_xrefs`
* `ida_frame.get_func_frame`
* `ida_frame.xreflist_t`
* `ida_funcs.get_func`
* `ida_kernwin.get_screen_ea`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udt_type_data_t`
* `ida_xref.dr_R`
* `ida_xref.dr_W`

***


### Assign DOS/PE headers structures to a PE binary {#setpehdr}
The goal of this script is to demonstrate some usage of the type API.

In this script, we:

* load a PE64 file in binary mode
* import some types from the mssdk64 til
* apply these types at the correct ofsset in the DB
* finally, rebase the program based on the information stored
  in the ImageBase field of the IMAGE_OPTIONAL_HEADER64.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [setpehdr.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/setpehdr.py) |  | Intermediate |

**APIs Used:**
* `ida_bytes.create_struct`
* `ida_bytes.get_dword`
* `ida_bytes.get_qword`
* `ida_bytes.get_word`
* `ida_hexrays.get_type`
* `ida_name.set_name`
* `ida_netnode.BADNODE`
* `ida_segment.MSF_FIXONCE`
* `ida_segment.rebase_program`
* `ida_typeinf.ADDTIL_DEFAULT`
* `ida_typeinf.BTF_STRUCT`
* `ida_typeinf.add_til`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udt_type_data_t`
* `idc.import_type`

***


### Recursively visit a type and its members {#visit_tinfo}
In this script, we show an example of tinfo_visitor_t to list
a user define type members, recursively.

This scripts skips array & pointer members (by calling
`tinfo_visitor_t.prune_now()`)

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [visit_tinfo.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/visit_tinfo.py) |  | Intermediate |

**APIs Used:**
* `ida_netnode.BADNODE`
* `ida_typeinf.ADDTIL_DEFAULT`
* `ida_typeinf.TVST_DEF`
* `ida_typeinf.add_til`
* `ida_typeinf.array_type_data_t`
* `ida_typeinf.get_idati`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.tinfo_visitor_t`
* `idc.import_type`

***


### Change the name of an existing stack variable {#change_stkvar_name}
The goal of this script is to demonstrate some usage of the type API.
In this script, we demonstrate a way to change the name of a
stack variable:
* Get the function object surrounding cursor location.
* Use this function to retrieve the corresponding frame object.
* Find the frame member matching the given name.
* Using its offset in the frame structure object, calculate
  the actual stack delta.
* Use the previous result to redefine the stack variable name if
  it is not a special or argument member.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [change_stkvar_name.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/change_stkvar_name.py) |  | Advanced |

**APIs Used:**
* `ida_frame.define_stkvar`
* `ida_frame.get_func_frame`
* `ida_frame.is_funcarg_off`
* `ida_frame.is_special_frame_member`
* `ida_frame.soff_to_fpoff`
* `ida_funcs.get_func`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udm_t`
* `idc.here`

***


### Change the type & name of a function stack frame variable {#change_stkvar_type}
The goal of this script is to demonstrate some usage of the type API.

In this script, we show a way to change the type and the name
of a stack variable. In this case we will take advantage of the
fact that RtlImageNtHeader calls RtlImageNtHeaderEx which takes
a pointer to PIMAGE_NT_HEADERS as its fourth parameter and, for
this, uses a stack variable of its caller.

* Get the function object for RtlImageNtHeader.
* Iterate through the function item to localize the load of the
  stack variable address before the call to RtlImageNtHeaderEx. We
   keep this information.
* Localize the call and take advantage of the previoulsy stored
  instruction to get the stack variable index in the frame.
* Set the type and rename the stack variable.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [change_stkvar_type.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/change_stkvar_type.py) |  | Advanced |

**APIs Used:**
* `ida_allins.NN_call`
* `ida_allins.NN_lea`
* `ida_frame.get_func_frame`
* `ida_funcs.func_item_iterator_t`
* `ida_funcs.get_func`
* `ida_funcs.get_func_name`
* `ida_ida.inf_get_procname`
* `ida_ida.inf_is_64bit`
* `ida_idaapi.BADADDR`
* `ida_name.get_name_ea`
* `ida_typeinf.BTF_STRUCT`
* `ida_typeinf.TERR_OK`
* `ida_typeinf.tinfo_t`
* `ida_ua.decode_insn`
* `ida_ua.insn_t`
* `ida_ua.o_reg`
* `idautils.procregs.r9.reg`

***


### Turn instruction operand into a structure offset {#operand_to_struct_member}
The goal of this script is to demonstrate some usage of the type API.
In this script, we:
 * ask the user to choose the structure that will be used for
 the conversion.
 * build the structure path and call ida_bytes.op_stroff. In case
 an enum is found a modal chooser is displayed in order to select
 a member.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [operand_to_struct_member.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/types/operand_to_struct_member.py) |  | Advanced |

**APIs Used:**
* `ida_bytes.op_stroff`
* `ida_kernwin.Choose`
* `ida_kernwin.Choose.CHCOL_HEX`
* `ida_kernwin.Choose.CHCOL_PLAIN`
* `ida_kernwin.choose_struct`
* `ida_kernwin.get_opnum`
* `ida_kernwin.get_screen_ea`
* `ida_pro.tid_array`
* `ida_typeinf.STRMEM_OFFSET`
* `ida_typeinf.tinfo_t`
* `ida_typeinf.udm_t`
* `ida_typeinf.udt_type_data_t`
* `ida_ua.decode_insn`
* `ida_ua.insn_t`

***


### Code to be run right after IDAPython initialization {#idapythonrc}
The `idapythonrc.py` file:

  * %APPDATA%\Hex-Rays\IDA Pro\idapythonrc.py (on Windows)
  * ~/.idapro/idapythonrc.py (on Linux & Mac)

can contain any IDAPython code that will be run as soon as
IDAPython is done successfully initializing.

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [idapythonrc.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/misc/idapythonrc.py) |  | Beginner |


***


### Add functions to the IDC runtime, from IDAPython {#extend_idc}
You can add IDC functions to IDA, whose "body" consists of
IDAPython statements!

We'll register a 'pow' function, available to all IDC code,
that when invoked will call back into IDAPython, and execute
the provided function body.

After running this script, try switching to the IDC interpreter
(using the button on the lower-left corner of IDA) and executing
`pow(3, 7)`

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [extend_idc.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/misc/extend_idc.py) |  | Intermediate |

**APIs Used:**
* `ida_expr.VT_LONG`
* `ida_expr.add_idc_func`

***


### Add 64-bit (.idb->.i64) conversion capabilities to custom plugins {#py_cvt64_sample}
For more infortmation see SDK/plugins/cvt64_sample example

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [py_cvt64_sample.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/misc/cvt64/py_cvt64_sample.py) |  | Advanced |

**APIs Used:**
* `ida_idaapi.BADADDR`
* `ida_idaapi.BADADDR32`
* `ida_netnode.atag`
* `ida_netnode.htag`
* `ida_netnode.stag`

***


### Add merge functionality to a simple plugin {#py_mex1}
This is a primitive plugin which asks user for some info and saves it for
some addresses.

We will add a merge functionality to plugin.

An IDA plugin may have two kinds of data with permanent storage:
  1. Data common for entire database (e.g. the options).
     To describe them we will use the idbattr_info_t type.
  2. Data specific to a particular address.
     To describe them we will use the merge_node_info_t type.

Also, see SDK/plugins/mex1 example

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [py_mex1.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/misc/merge/py_mex1.py) | IDP_Hooks plugin | Advanced |

**APIs Used:**
* `ida_funcs.get_func`
* `ida_ida.IDI_ALTVAL`
* `ida_ida.IDI_CSTR`
* `ida_ida.IDI_SCALAR`
* `ida_ida.IDI_SUPVAL`
* `ida_ida.idbattr_info_t`
* `ida_idaapi.BADADDR`
* `ida_idaapi.PLUGIN_MOD`
* `ida_idaapi.PLUGIN_MULTI`
* `ida_idaapi.plugin_t`
* `ida_idaapi.plugmod_t`
* `ida_idp.IDP_Hooks`
* `ida_kernwin.Form`
* `ida_kernwin.Form.ChkGroupControl`
* `ida_kernwin.Form.StringInput`
* `ida_kernwin.get_screen_ea`
* `ida_merge.MERGE_KIND_END`
* `ida_merge.MERGE_KIND_NONE`
* `ida_merge.NDS_IS_STR`
* `ida_merge.NDS_MAP_IDX`
* `ida_merge.merge_handler_params_t`
* `ida_merge.merge_node_info_t`
* `ida_merge.moddata_diff_helper_t`
* `ida_mergemod.create_std_modmerge_handlers`
* `ida_netnode.BADNODE`
* `ida_netnode.SIZEOF_nodeidx_t`
* `ida_netnode.atag`
* `ida_netnode.netnode`
* `ida_netnode.stag`

***


### Implement merging functionality for custom plugins {#py_mex3}
IDA Teams uses a chooser to display the merge conflicts.
To fill the chooser columns IDA Teams uses the following methods from diff_source_t type:

  * print_diffpos_name()
  * print_diffpos_details()

and UI hints from merge_handler_params_t type:

  * ui_has_details()
  * ui_complex_details()
  * ui_complex_name()

In general, chooser columns are filled as following:

          columns.clear()
          NAME = print_diffpos_name()
          if ui_complex_name()
          then
            columns.add(split NAME by ui_split_char())
          else
            columns[0] = NAME
          if not ui_complex_details()
          then
            columns.add(print_diffpos_details())

Also, see SDK/plugins/mex3 example

| Source code                   | Keywords   | Level                              |
|-------------------------------|------------|------------------------------------|
| [py_mex3.py](https://github.com/HexRaysSA/IDAPython/tree/<insert-branch-here>/examples/misc/merge/py_mex3.py) | IDP_Hooks plugin | Advanced |

**APIs Used:**
* `ida_funcs.get_func`
* `ida_ida.IDI_ALTVAL`
* `ida_ida.IDI_CSTR`
* `ida_ida.IDI_SCALAR`
* `ida_ida.IDI_SUPVAL`
* `ida_ida.idbattr_info_t`
* `ida_idaapi.BADADDR`
* `ida_idaapi.PLUGIN_MOD`
* `ida_idaapi.PLUGIN_MULTI`
* `ida_idaapi.plugin_t`
* `ida_idaapi.plugmod_t`
* `ida_idp.IDP_Hooks`
* `ida_kernwin.Form`
* `ida_kernwin.Form.ChkGroupControl`
* `ida_kernwin.Form.StringInput`
* `ida_kernwin.get_screen_ea`
* `ida_merge.MERGE_KIND_END`
* `ida_merge.MERGE_KIND_NONE`
* `ida_merge.MH_UI_COLONNAME`
* `ida_merge.MH_UI_COMMANAME`
* `ida_merge.MH_UI_NODETAILS`
* `ida_merge.NDS_IS_STR`
* `ida_merge.NDS_MAP_IDX`
* `ida_merge.create_nodeval_merge_handlers`
* `ida_merge.get_ea_diffpos_name`
* `ida_merge.merge_handler_params_t`
* `ida_merge.merge_node_helper_t`
* `ida_merge.merge_node_info_t`
* `ida_merge.moddata_diff_helper_t`
* `ida_mergemod.create_std_modmerge_handlers`
* `ida_nalt.node2ea`
* `ida_netnode.BADNODE`
* `ida_netnode.SIZEOF_nodeidx_t`
* `ida_netnode.atag`
* `ida_netnode.netnode`
* `ida_netnode.stag`

***

