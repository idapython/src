"""
summary: interactively color certain pseudocode lines

description:
  Provides an action that can be used to dynamically alter the
  lines background rendering for pseudocode listings (as opposed to
  using `ida_hexrays.cfunc_t.pseudocode[N].bgcolor`)

  After running this script, pressing 'M' on a line in a
  "Pseudocode-?" widget, will cause that line to be rendered
  with a special background color.

keywords: colors
"""

import ida_kernwin
import ida_hexrays
import ida_moves
import ida_idaapi

class pseudo_line_t(object):
    def __init__(self, func_ea, line_nr):
        self.func_ea = func_ea
        self.line_nr = line_nr

    def __hash__(self):
        return hash((self.func_ea, self.line_nr))

    def __eq__(self, r):
        return self.func_ea == r.func_ea \
            and self.line_nr == r.line_nr


def _place_to_line_number(p):
    return ida_kernwin.place_t.as_simpleline_place_t(p).n


class pseudocode_lines_rendering_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)
        self.marked_lines = {}

    def get_lines_rendering_info(self, out, widget, rin):
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu:
            entry_ea = vu.cfunc.entry_ea
            for section_lines in rin.sections_lines:
                for line in section_lines:
                    coord = pseudo_line_t(
                        entry_ea,
                        _place_to_line_number(line.at))
                    color = self.marked_lines.get(coord, None)
                    if color is not None:
                        e = ida_kernwin.line_rendering_output_entry_t(line)
                        e.bg_color = color
                        out.entries.push_back(e)


class toggle_line_marked_ah_t(ida_kernwin.action_handler_t):

    """
    We could very well use an ARGB value, but instead let's go
    go with a color 'key': those can be altered by the user/theme,
    and therefore have a better chance of being appropriate (or at
    least expected.)
    """
    COLOR_KEY = ida_kernwin.CK_EXTRA11

    def __init__(self, hooks):
        ida_kernwin.action_handler_t.__init__(self)
        self.hooks = hooks

    def activate(self, ctx):
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if vu:
            loc = ida_moves.lochist_entry_t()
            if ida_kernwin.get_custom_viewer_location(loc, ctx.widget):
                coord = pseudo_line_t(
                    vu.cfunc.entry_ea,
                    _place_to_line_number(loc.place()))
                if coord in self.hooks.marked_lines.keys():
                    del self.hooks.marked_lines[coord]
                else:
                    self.hooks.marked_lines[coord] = self.COLOR_KEY
                ida_kernwin.refresh_custom_viewer(ctx.widget)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


hooks = pseudocode_lines_rendering_hooks_t()
act_name = "example:colorize_pseudocode_line"
act_shortcut = "M"
if ida_kernwin.register_action(ida_kernwin.action_desc_t(
        act_name,
        "Mark pseudocode line",
        toggle_line_marked_ah_t(hooks),
        act_shortcut)):
    hooks.hook()
    print("Action registered. Please press '%s' in a pseudocode window to mark a line" % act_shortcut)
