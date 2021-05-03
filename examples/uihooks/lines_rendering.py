"""
summary: dynamically colorize lines backgrounds (or parts of them)

description:
  shows how one can dynamically alter the lines background
  rendering (as opposed to, say, using ida_nalt.set_item_color()),
  and also shows how that rendering can be limited to just a few
  glyphs, not the whole line.
"""

import ida_kernwin
import ida_bytes

class lines_rendering_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

        # We'll color all lines starting with the current
        # one, with all available highlights...
        self.instantiated_at = ida_kernwin.get_screen_ea()
        self.color_info = []

        data = [
            ida_kernwin.CK_EXTRA1,
            ida_kernwin.CK_EXTRA2,
            ida_kernwin.CK_EXTRA3,
            ida_kernwin.CK_EXTRA4,
            ida_kernwin.CK_EXTRA5,
            ida_kernwin.CK_EXTRA6,
            ida_kernwin.CK_EXTRA7,
            ida_kernwin.CK_EXTRA8,
            ida_kernwin.CK_EXTRA9,
            ida_kernwin.CK_EXTRA10,
            ida_kernwin.CK_EXTRA11,
            ida_kernwin.CK_EXTRA12,
            ida_kernwin.CK_EXTRA13,
            ida_kernwin.CK_EXTRA14,
            ida_kernwin.CK_EXTRA15,
            ida_kernwin.CK_EXTRA16,
            # let's also try these colors keys, because why not
            ida_kernwin.CK_TRACE,
            ida_kernwin.CK_TRACE_OVL,
            [
                ida_kernwin.CK_TRACE,
                ida_kernwin.CK_TRACE_OVL,
            ],
        ]
        ea = self.instantiated_at
        for one in data:
            self.color_info.append((ea, one))
            ea = ida_bytes.next_head(ea, ida_idaapi.BADADDR)

        # ...and then we'll a few more things, such as
        # overriding parts of a previously-specified overlay,
        # and restricting the override to a few glyphs
        self.color_info.append(
            (
                self.color_info[6][0],
                [
                    (ida_kernwin.CK_EXTRA2, 7, 3),
                    (ida_kernwin.CK_EXTRA4, 2, 1),
                    (ida_kernwin.CK_EXTRA10, 2, 0),
                    (ida_kernwin.CK_EXTRA10, 20, 10),
                ]
            ))
        self.color_info.append(
            (
                self.color_info[7][0],
                [
                    (ida_kernwin.CK_EXTRA1, 1, 1),
                    (ida_kernwin.CK_EXTRA2, 3, 1),
                    (ida_kernwin.CK_EXTRA3, 5, 1),
                    (ida_kernwin.CK_EXTRA4, 7, 1),
                    (ida_kernwin.CK_EXTRA5, 9, 1),
                    (ida_kernwin.CK_EXTRA6, 11, 1),
                    (ida_kernwin.CK_EXTRA7, 13, 1),
                    (ida_kernwin.CK_EXTRA8, 15, 1),
                    (ida_kernwin.CK_EXTRA9, 17, 1),
                    (ida_kernwin.CK_EXTRA10, 19, 1),
                    (ida_kernwin.CK_EXTRA11, 21, 1),
                    (ida_kernwin.CK_EXTRA12, 23, 1),
                    (ida_kernwin.CK_EXTRA13, 25, 1),
                    (ida_kernwin.CK_EXTRA14, 27, 1),
                    (ida_kernwin.CK_EXTRA15, 29, 1),
                    (ida_kernwin.CK_EXTRA16, 31, 1),
                ]
            ))
        self.color_info.append(
            (
                self.color_info[8][0],
                [
                    (ida_kernwin.CK_EXTRA1, 16, 45),
                    (ida_kernwin.CK_EXTRA2, 19, 45),
                    (ida_kernwin.CK_EXTRA3, 22, 45),
                    (ida_kernwin.CK_EXTRA4, 25, 45),
                ]
            ))


    def get_lines_rendering_info(self, out, widget, rin):
        for section_lines in rin.sections_lines:
            for line in section_lines:
                line_ea = line.at.toea()
                for ea, directives in self.color_info:
                    if ea == line_ea:
                        if not isinstance(directives, list):
                            directives = [directives]
                        for directive in directives:
                            e = ida_kernwin.line_rendering_output_entry_t(line)
                            if isinstance(directive, tuple):
                                color, cpx, nchars = directive
                                e.bg_color = color
                                e.cpx = cpx
                                e.nchars = nchars
                                e.flags |= ida_kernwin.LROEF_CPS_RANGE
                            else:
                                e.bg_color = directive
                            out.entries.push_back(e)


lrh = lines_rendering_hooks_t()
lrh.hook()

# Force a refresh of IDA View-A
ida_kernwin.refresh_idaview_anyway()
