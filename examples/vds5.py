from __future__ import print_function

import ida_idaapi
import ida_pro
import ida_hexrays
import ida_kernwin
import ida_gdl
import ida_lines

ACTION_NAME = "vds5.py:displaygraph"
ACTION_SHORTCUT = "Ctrl+Shift+G"

CL_WHITE            = ((255)+  (255<<8)+  (255<<16)) #   0
CL_BLUE             = ((0  )+  (0  <<8)+  (255<<16)) #   1
CL_RED              = ((255)+  (0  <<8)+  (0  <<16)) #   2
CL_GREEN            = ((0  )+  (255<<8)+  (0  <<16)) #   3
CL_YELLOW           = ((255)+  (255<<8)+  (0  <<16)) #   4
CL_MAGENTA          = ((255)+  (0  <<8)+  (255<<16)) #   5
CL_CYAN             = ((0  )+  (255<<8)+  (255<<16)) #   6
CL_DARKGREY         = ((85 )+  (85 <<8)+  (85 <<16)) #   7
CL_DARKBLUE         = ((0  )+  (0  <<8)+  (128<<16)) #   8
CL_DARKRED          = ((128)+  (0  <<8)+  (0  <<16)) #   9
CL_DARKGREEN        = ((0  )+  (128<<8)+  (0  <<16)) #  10
CL_DARKYELLOW       = ((128)+  (128<<8)+  (0  <<16)) #  11
CL_DARKMAGENTA      = ((128)+  (0  <<8)+  (128<<16)) #  12
CL_DARKCYAN         = ((0  )+  (128<<8)+  (128<<16)) #  13
CL_GOLD             = ((255)+  (215<<8)+  (0  <<16)) #  14
CL_LIGHTGREY        = ((170)+  (170<<8)+  (170<<16)) #  15
CL_LIGHTBLUE        = ((128)+  (128<<8)+  (255<<16)) #  16
CL_LIGHTRED         = ((255)+  (128<<8)+  (128<<16)) #  17
CL_LIGHTGREEN       = ((128)+  (255<<8)+  (128<<16)) #  18
CL_LIGHTYELLOW      = ((255)+  (255<<8)+  (128<<16)) #  19
CL_LIGHTMAGENTA     = ((255)+  (128<<8)+  (255<<16)) #  20
CL_LIGHTCYAN        = ((128)+  (255<<8)+  (255<<16)) #  21
CL_LILAC            = ((238)+  (130<<8)+  (238<<16)) #  22
CL_TURQUOISE        = ((64 )+  (224<<8)+  (208<<16)) #  23
CL_AQUAMARINE       = ((127)+  (255<<8)+  (212<<16)) #  24
CL_KHAKI            = ((240)+  (230<<8)+  (140<<16)) #  25
CL_PURPLE           = ((160)+  (32 <<8)+  (240<<16)) #  26
CL_YELLOWGREEN      = ((154)+  (205<<8)+  (50 <<16)) #  27
CL_PINK             = ((255)+  (192<<8)+  (203<<16)) #  28
CL_ORANGE           = ((255)+  (165<<8)+  (0  <<16)) #  29
CL_ORCHID           = ((218)+  (112<<8)+  (214<<16)) #  30
CL_BLACK            = ((0  )+  (0  <<8)+  (0  <<16)) #  31

COLORS_LUT = {
    CL_WHITE             : "white",
    CL_BLUE              : "blue",
    CL_RED               : "red",
    CL_GREEN             : "green",
    CL_YELLOW            : "yellow",
    CL_MAGENTA           : "magenta",
    CL_CYAN              : "cyan",
    CL_DARKGREY          : "darkgrey",
    CL_DARKBLUE          : "darkblue",
    CL_DARKRED           : "darkred",
    CL_DARKGREEN         : "darkgreen",
    CL_DARKYELLOW        : "darkyellow",
    CL_DARKMAGENTA       : "darkmagenta",
    CL_DARKCYAN          : "darkcyan",
    CL_GOLD              : "gold",
    CL_LIGHTGREY         : "lightgrey",
    CL_LIGHTBLUE         : "lightblue",
    CL_LIGHTRED          : "lightred",
    CL_LIGHTGREEN        : "lightgreen",
    CL_LIGHTYELLOW       : "lightyellow",
    CL_LIGHTMAGENTA      : "lightmagenta",
    CL_LIGHTCYAN         : "lightcyan",
    CL_LILAC             : "lilac",
    CL_TURQUOISE         : "turquoise",
    CL_AQUAMARINE        : "aquamarine",
    CL_KHAKI             : "khaki",
    CL_PURPLE            : "purple",
    CL_YELLOWGREEN       : "yellowgreen",
    CL_PINK              : "pink",
    CL_ORANGE            : "orange",
    CL_ORCHID            : "orchid",
    CL_BLACK             : "black",
}

def get_color_name(c):
    return COLORS_LUT[c] if c in COLORS_LUT.keys() else "?"

class cfunc_graph_t: # alas we can't inherit gdl_graph_t
    def __init__(self, highlight):
        self.items = [] # list of citem_t
        self.highlight = highlight
        self.succs = [] # list of lists of next nodes
        self.preds = [] # list of lists of previous nodes

    def nsucc(self, n):
        return len(self.succs[n]) if self.size() else 0

    def npred(self, n):
        return len(self.preds[n]) if self.size() else 0

    def succ(self, n, i):
        return self.succs[n][i]

    def pred(self, n, i):
        return self.preds[n][i]

    def size(self):
        return len(self.preds)

    def add_node(self):
        n = self.size()

        def resize(array, new_size):
            if new_size > len(array):
                while len(array) < new_size:
                    array.append([])
            else:
                array = array[:new_size]
            return array

        self.preds = resize(self.preds, n+1)
        self.succs = resize(self.succs, n+1)
        return n

    def add_edge(self, x, y):
        self.preds[y].append(x)
        self.succs[x].append(y)

    def get_expr_name(self, expr):
        name = expr.print1(None)
        name = ida_lines.tag_remove(name)
        name = ida_pro.str2user(name)
        return name

    def get_node_label(self, n):
        item = self.items[n]
        op = item.op
        insn = item.cinsn
        expr = item.cexpr
        parts = [ida_hexrays.get_ctype_name(op)]
        if op == ida_hexrays.cot_ptr:
            parts.append(".%d" % expr.ptrsize)
        elif op == ida_hexrays.cot_memptr:
            parts.append(".%d (m=%d)" % (expr.ptrsize, expr.m))
        elif op == ida_hexrays.cot_memref:
            parts.append(" (m=%d)" % (expr.m,))
        elif op in [
                ida_hexrays.cot_obj,
                ida_hexrays.cot_var]:
            name = self.get_expr_name(expr)
            parts.append(".%d %s" % (expr.refwidth, name))
        elif op in [
                ida_hexrays.cot_num,
                ida_hexrays.cot_helper,
                ida_hexrays.cot_str]:
            name = self.get_expr_name(expr)
            parts.append(" %s" % (name,))
        elif op == ida_hexrays.cit_goto:
            parts.append(" LABEL_%d" % insn.cgoto.label_num)
        elif op == ida_hexrays.cit_asm:
            parts.append("<asm statements; unsupported ATM>")
            # parts.append(" %a.%d" % ())
        parts.append("\\n")
        parts.append("ea: %08X" % item.ea)
        if item.is_expr() and not expr.type.empty():
            parts.append("\\n")
            tstr = expr.type._print()
            parts.append(tstr if tstr else "?")
        return "".join(parts)

    def get_node_color(self, n):
        item = self.items[n]
        if self.highlight is not None and item.obj_id == self.highlight.obj_id:
            return CL_GREEN
        return None

    def gen_gdl(self, fname):
        with open(fname, "wb") as out:
            out.write("graph: {\n")

            out.write("// *** nodes\n")
            for n in xrange(len(self.items)):
                item = self.items[n]
                node_label = self.get_node_label(n)
                node_props = [""]
                if n == 0:
                    node_props.append("vertical_order: 0")
                color = self.get_node_color(n)
                if color is not None:
                    node_props.append("color: %s" % get_color_name(color))
                out.write("""node: { title: "%d" label: "%d: %s" %s}\n""" % (
                    n,
                    n,
                    node_label,
                    " ".join(node_props)))

            out.write("// *** edges\n")
            for n in xrange(len(self.items)):
                item = self.items[n]
                out.write("// edges %d -> ?\n" % n)
                for i in xrange(self.nsucc(n)):
                    t = self.succ(n, i)
                    label = ""
                    if item.is_expr():
                        target = self.items[t]
                        if item.x is not None and item.x == target:
                            label = "x"
                        elif item.y is not None and item.y == target:
                            label = "y"
                        elif item.z is not None and item.z == target:
                            label = "z"
                        if label:
                            label = """ label: "%s" """ % label
                    out.write("""edge: { sourcename: "%s" targetname: "%s"%s}\n""" % (
                        str(n), str(t), label))

            out.write("}\n")

    def dump(self):
        print("%d items:" % len(self.items))
        for i in self.items:
            print("\t%s (%08x)" % (i, i.ea))

        print("succs:")
        for s in self.succs:
            print("\t%s" % s)

        print("preds:")
        for p in self.preds:
            print("\t%s" % p)


class graph_builder_t(ida_hexrays.ctree_parentee_t):

    def __init__(self, cg):
        ida_hexrays.ctree_parentee_t.__init__(self)
        self.cg = cg
        self.reverse = {} # citem_t -> node#

    def add_node(self, i):
        for k in self.reverse.keys():
            if i.obj_id == k.obj_id:
                ida_kernwin.warning("bad ctree - duplicate nodes! (i.ea=%x)" % i.ea)
                self.cg.dump()
                return -1

        n = self.cg.add_node()
        if n <= len(self.cg.items):
            self.cg.items.append(i)
        self.cg.items[n] = i
        self.reverse[i] = n
        return n

    def process(self, i):
        n = self.add_node(i)
        if n < 0:
            return n
        if len(self.parents) > 1:
            lp = self.parents.back().obj_id
            for k, v in self.reverse.items():
                if k.obj_id == lp:
                    p = v
                    break
            self.cg.add_edge(p, n)
        return 0

    def visit_insn(self, i):
        return self.process(i)

    def visit_expr(self, e):
        return self.process(e)


class display_graph_ah_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        vu.get_current_item(ida_hexrays.USE_KEYBOARD)
        highlight = vu.item.e if vu.item.is_citem() else None

        cg = cfunc_graph_t(highlight)
        gb = graph_builder_t(cg)
        gb.apply_to(vu.cfunc.body, None)

        import tempfile
        fname = tempfile.mktemp(suffix=".gdl")
        cg.gen_gdl(fname)
        ida_gdl.display_gdl(fname)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_DISABLE_FOR_WIDGET


class vds5_hooks_t(ida_hexrays.Hexrays_Hooks):
    def populating_popup(self, widget, handle, vu):
        idaapi.attach_action_to_popup(vu.ct, None, ACTION_NAME)
        return 0

if ida_hexrays.init_hexrays_plugin():
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_NAME,
            "Hex-Rays show C graph (IDAPython)",
            display_graph_ah_t(),
            ACTION_SHORTCUT))
    vds5_hooks = vds5_hooks_t()
    vds5_hooks.hook()
else:
    print('hexrays-graph: hexrays is not available.')

