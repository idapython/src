"""
summary: an easy-to-use way to colorize lines

description:
  This builds upon the `ida_kernwin.UI_Hooks.get_lines_rendering_info`
  feature, to provide a quick & easy way to colorize disassembly
  lines.

  Contrary to @colorize_disassembly, the coloring is not persisted in
  the database, and will therefore be lost after the session.

  By triggering the action multiple times, the user can "carousel"
  across 4 predefined colors (and return to the "no color" state.)

keywords: coloring

see_also: colorize_disassembly
"""

import ida_kernwin
import ida_moves

class on_the_fly_coloring_hooks_t(ida_kernwin.UI_Hooks):

    # We'll offer the users the ability to carousel around the
    # following colors. Well, note that these are in fact not
    # colors, but rather color "keys": each theme might have its
    # own values for those.
    AVAILABLE_COLORS = [
        ida_kernwin.CK_EXTRA5,
        ida_kernwin.CK_EXTRA6,
        ida_kernwin.CK_EXTRA7,
        ida_kernwin.CK_EXTRA8,
    ]

    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

        # Each view can have on-the-fly coloring.
        # We'll store the custom colors keyed on the widget's title
        self.by_widget = {}

    def get_lines_rendering_info(self, out, widget, rin):
        """
        Called by IDA, at rendering-time.

        We'll look in our set of marked lines, and for those that are
        found, will produce additional rendering information for IDA
        to use.
        """
        title = ida_kernwin.get_widget_title(widget)
        assigned = self.by_widget.get(title, None)
        if assigned is not None:
            for section_lines in rin.sections_lines:
                for line in section_lines:
                    for loc, color in assigned:
                        if self._same_lines(widget, line.at, loc.place()):
                            e = ida_kernwin.line_rendering_output_entry_t(line)
                            e.bg_color = color
                            out.entries.push_back(e)

    def _same_lines(self, viewer, p0, p1):
        return ida_kernwin.get_custom_viewer_place_xcoord(viewer, p0, p1) != -1

    def _find_loc_index(self, viewer, assigned, loc):
        for idx, tpl in enumerate(assigned):
            _loc = tpl[0]
            if self._same_lines(viewer, loc.place(), _loc.place()):
                return idx
        return -1

    def carousel_color(self, viewer, title):
        """
        This performs the work of iterating across the available
        colors (and the 'no-color' state.)
        """
        loc = ida_moves.lochist_entry_t()
        if ida_kernwin.get_custom_viewer_location(loc, viewer):
            assigned = self.by_widget.get(title, [])
            new_color = None

            idx = self._find_loc_index(viewer, assigned, loc)
            if idx > -1:
                prev_color = assigned[idx][1]
                prev_color_idx = self.AVAILABLE_COLORS.index(prev_color)
                new_color = None \
                            if prev_color_idx >= (len(self.AVAILABLE_COLORS) - 1) \
                            else self.AVAILABLE_COLORS[prev_color_idx + 1]
            else:
                new_color = self.AVAILABLE_COLORS[0]

            if idx > -1:
                del assigned[idx]
            if new_color is not None:
                assigned.append((loc, new_color))

            if assigned:
                self.by_widget[title] = assigned
            else:
                if title in self.by_widget:
                    del self.by_widget[title]


class carousel_color_ah_t(ida_kernwin.action_handler_t):
    """
    The action that will be invoked by IDA when the user
    activates its shortcut.
    """
    def __init__(self, hooks):
        ida_kernwin.action_handler_t.__init__(self)
        self.hooks = hooks

    def activate(self, ctx):
        v = ida_kernwin.get_current_viewer()
        if v:
            self.hooks.carousel_color(v, ctx.widget_title)
            return 1 # will cause the widget to redraw

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ida_kernwin.get_current_viewer() \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


ACTION_NAME = "example:colorize_disassembly_on_the_fly"
ACTION_LABEL = "Pick line color"
ACTION_SHORTCUT = "!"
ACTION_HELP = "Press %s to carousel around available colors (or remove a previously-set color)" % ACTION_SHORTCUT

otf_coloring = on_the_fly_coloring_hooks_t()
if ida_kernwin.register_action(ida_kernwin.action_desc_t(
        ACTION_NAME,
        ACTION_LABEL,
        carousel_color_ah_t(otf_coloring),
        ACTION_SHORTCUT)):
    print("Registered action \"%s\". %s" % (ACTION_LABEL, ACTION_HELP))
    otf_coloring.hook()
