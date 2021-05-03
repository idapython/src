"""
summary: implement a "jump to next comment" action within IDA's disassembly view.

description:
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

keywords: idaview, actions

see_also: save_and_restore_listing_pos
"""

import ida_idaapi
import ida_kernwin
import ida_bytes
import ida_moves
import ida_lines

def find_comment_visual_position_in_tagged_line(line):
    """
    We'll look for tags for all types of comments, and if
    found return the visual position of the tag in the line
    (using 'ida_lines.tag_strlen')
    """
    for cmt_type in [
            ida_lines.SCOLOR_REGCMT,
            ida_lines.SCOLOR_RPTCMT,
            ida_lines.SCOLOR_AUTOCMT]:
        cmt_idx = line.find(ida_lines.SCOLOR_ON + cmt_type)
        if cmt_idx > -1:
            return ida_lines.tag_strlen(line[:cmt_idx])
    return -1


def jump_next_comment(v):
    """
    Starting at the current line, keep generating lines until
    a comment is found. When this happens, position the viewer
    at the right coordinates.
    """
    loc = ida_moves.lochist_entry_t()
    if ida_kernwin.get_custom_viewer_location(loc, v):
        place = loc.place()
        idaplace = ida_kernwin.place_t_as_idaplace_t(place)
        ea = idaplace.ea
        while ea != ida_idaapi.BADADDR:
            _, disass = ida_lines.generate_disassembly(
                ea,
                1000,  # maximum number of lines
                False, # as_stack=False
                False) # notags=False - we want tags, in order to spot comments

            found = None

            # If this is the start item, start at the next line
            start_lnnum = (idaplace.lnnum + 1) if ea == idaplace.ea else 0

            for rel_lnnum, line in enumerate(disass[start_lnnum:]):
                vis_cx = find_comment_visual_position_in_tagged_line(line)
                if vis_cx > -1:
                    found = (ea, rel_lnnum, vis_cx)
                    break

            if found is not None:
                idaplace.ea = found[0]
                idaplace.lnnum = start_lnnum + found[1]
                loc.set_place(idaplace)
                loc.renderer_info().pos.cx = found[2]
                ida_kernwin.custom_viewer_jump(v, loc, ida_kernwin.CVNF_LAZY)
                break

            ea = ida_bytes.next_head(ea, ida_idaapi.BADADDR)


class jump_next_comment_ah_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        jump_next_comment(ctx.widget)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type == ida_kernwin.BWN_DISASM \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


ACTION_NAME = "jump_next_comment:jump"
ACTION_LABEL = "Jump to the next comment"
ACTION_SHORTCUT = "Ctrl+Alt+C"
ACTION_HELP = "Press %s to jump to the next comment" % ACTION_SHORTCUT

if ida_kernwin.unregister_action(ACTION_NAME):
    print("Unregistered previously-registered action \"%s\"" % ACTION_LABEL)

if ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_NAME,
            ACTION_LABEL,
            jump_next_comment_ah_t(),
            ACTION_SHORTCUT)):
    print("Registered action \"%s\". %s" % (ACTION_LABEL, ACTION_HELP))

