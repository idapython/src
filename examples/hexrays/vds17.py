"""
summary: using the "Select offsets" widget

description:
  Registers an action opens the "Select offsets" widget
  (select_udt_by_offset() call).

  This effectively repeats the functionality already available
  through Alt+Y.

  Place cursor on the union field and press Shift+T
"""

import ida_idaapi
import ida_hexrays
import ida_lines
import ida_typeinf
import ida_kernwin

# --------------------------------------------------------------------------
class func_stroff_ah_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # get the current item
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        vu.get_current_item(ida_hexrays.USE_KEYBOARD)

        # REGION1, will be referenced later
        # check that the current item is a union field
        if not vu.item.is_citem():
            ida_kernwin.warning("Please position the cursor on a union member")
            return 0
        e = vu.item.e
        while True:
            op = e.op
            if op != ida_hexrays.cot_memptr and op != ida_hexrays.cot_memref:
                ida_kernwin.warning("Please position the cursor on a union member")
                return 0
            e = e.x
            if op == ida_hexrays.cot_memptr:
                if e.type.is_union():
                    break
            else:
                if ida_typeinf.remove_pointer(e.type).is_union():
                    break
            if not e.type.is_udt():
                ida_kernwin.warning("Please position the cursor on a union member")
                return 0
        # END REGION1

        # REGION2
        # calculate the member offset
        off = 0
        e = vu.item.e
        while True:
            e2 = e.x
            tif = ida_typeinf.remove_pointer(e2.type)
            if not tif.is_union():
                off += e.m
            e = e2
            if e2.op != ida_hexrays.cot_memptr and e2.op != ida_hexrays.cot_memref:
                break
            if not e2.type.is_udt():
                break
        # END REGION2

        # REGION3
        # go up and collect more member references (in order to calculate the final offset)
        p = vu.item.e
        while True:
            p2 = vu.cfunc.body.find_parent_of(p)
            if p2.op == ida_hexrays.cot_memptr:
                break
            if p2.op == ida_hexrays.cot_memref:
                e2 = p2.cexpr
                tif = ida_typeinf.remove_pointer(e2.x.type)
                if not tif.is_union():
                    off += e2.m
                p = p2
                continue
            if p2.op == ida_hexrays.cot_ref:
                # handle &a.b + N (this expression may appear if the user previously selected
                #                  a wrong field)
                delta = 0
                add = vu.cfunc.body.find_parent_of(p2)
                if add.op == ida_hexrays.cot_cast:
                    add = vu.cfunc.body.find_parent_of(add)
                if add.op == ida_hexrays.cot_add and add.y.op == ida_hexrays.cot_num:
                    delta = add.y.numval()
                    objsize = add.type.get_ptrarr_objsize()
                    nbytes = delta * objsize
                    off += nbytes
            # we could use helpers like WORD/BYTE/... to calculate a more precise offset
            # if ( p2->op == cot_call && (e2->exflags & EXFL_LVALUE) != 0 )
            break
        # END REGION3

        # REGION4
        ea = vu.item.e.ea
        # the item itself may be unaddressable.
        # TODO: find its addressable parent
        if ea == ida_idaapi.BADADDR:
            ida_kernwin.warning("Sorry, the current item is not addressable")
            return 0
        # END REGION4

        # REGION5
        # prepare the text representation for the item,
        # use the neighborhoods of cursor
        line = ida_lines.tag_remove(ida_kernwin.get_custom_viewer_curline(vu.ct, False))
        line_len = len(line)
        x = max(0, vu.cpos.x - 10)
        l = min(10, line_len - vu.cpos.x) + 10
        line = line[x:x+l]
        # END REGION5

        # REGION6
        ops = ida_hexrays.ui_stroff_ops_t()
        op = ops.push_back()
        op.offset = off
        op.text = line
        # END REGION6

        # REGION7
        class set_union_sel_t(ida_hexrays.ui_stroff_applicator_t):
            def __init__(self, ea):
                ida_hexrays.ui_stroff_applicator_t.__init__(self)
                self.ea = ea

            def apply(self, opnum, path, top_tif, spath):
                typename = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, top_tif, '', '')
                ida_kernwin.msg("User selected %s of type %s\n" % (spath, typename))
                if path.empty():
                    return False
                vu.cfunc.set_user_union_selection(self.ea, path)
                vu.cfunc.save_user_unions()
                return True
        # END REGION7

        # REGION8
        su = set_union_sel_t(ea)
        res = ida_hexrays.select_udt_by_offset(None, ops, su)
        if res != 0:
            # regenerate ctree
            vu.refresh_view(True)
        # END REGION8

        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if \
            ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else \
            ida_kernwin.AST_DISABLE_FOR_WIDGET


# --------------------------------------------------------------------------
# a plugin interface, boilerplate code
class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Structure offsets (IDAPython)"
    wanted_hotkey = ""
    comment = "Sample plugin17 for Hex-Rays decompiler"
    help = ""
    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            print("Hex-rays version %s has been detected, Structure offsets ready to use" % ida_hexrays.get_hexrays_version())
            ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    "vds17:strchoose",
                    "Structure offsets",
                    func_stroff_ah_t(),
                    "Shift+T"))
            return ida_idaapi.PLUGIN_KEEP # keep us in the memory
    def term(self):
        pass
    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return my_plugin_t()

"""
# A few notes about the VDS17 sample

You can find two VDS17 samples in the IDA Pro install directory:

    python/examples/hexrays/vds17.py
    plugins/hexrays_sdk/plugins/vds17

The former is an IDAPython plugin and the latter is a C++ IDA Pro plugin.
Actually they have the same functionality.
Just to be more concrete the vds17.py plugin will be used below.


## How the user interface works

Let us suppose that we have the following local types:

    1 C     struct {int c0;int c1;}
    2 U     union {int u0;__int16 u1;}
    3 D     struct {int d0;C d1;U d2;}
    4 E     struct {int e0;D e1;}
    5 res_t struct {int r0;int r1;__int16 r2;}

and the decompiler generates the following pseudocode:

    void __cdecl f(res_t *r)
    {
      r->r0 = e->e1.d1.c0;
      r->r1 = e->e1.d2.u0;
      r->r2 = e->e1.d2.u1;
    }

As we see, it looks good, the decompiler did a really good job.

But let us imagine that we need reference to the ```e1.d2.u0``` union member on the last line.

At first we need to load the VDS17 plugin. For that,
place the cursor at the ```u1``` union member on the last line
and use ```Shift-T```.

The "Structure offsets" dialog appears on the screen.
The left pane of the dialog contains the available local types
and the right pane has the following view:

    [checked] e->e1.d2.u1; | 10h | |

Use the left pane to select ```E```, expand it, and select (Double-click) on the ```u0``` member.

The right pane will change to:

    [checked] e->e1.d2.u1; | 10h | [checke] E.e1.d2.u0 |

Since this is what we want, press the ```OK``` button and the pseudocode gets changed:

    void __cdecl f(res_t *r)
    {
      r->r0 = e->e1.d1.c0;
      r->r1 = e->e1.d2.u0;
      r->r2 = e->e1.d2.u0;
    }


### What do we need this plugin for?

All union members have the same offset in the parent structure.
The decompiler selects the first suitable union member.
Sometimes we need to change this selection and use another union member.


## API details

Let us look into ```python/examples/hexrays/vds17.py```.

* REGION1: check that the cursor points to the union member
* REGION2: calculate the member offset
* REGION3: sometimes there is a need to adjust the offset
* REGION4: the pointed item must be addressable

Then the magic begins:

* REGION5: we need something to show in the ```Operand``` column of the right pane.
    The text around the cursor looks like a good compromise.
* REGION6: we are ready to fill the right pane: we have calculated the offset and
    have prepared the descriptive text for the operand.
* REGION7: it is a callback that informs us about the user selection (will be described later)
* REGION8: activate the "Structure offsets" dialog, let the user select,
    the callback specified above will update the union member, refresh pseudocode


### The devil is in the details

The main part of callback is the ```apply``` method (REGION7).
It receives two arguments:

1. ```opnum``` is the number of the selected operand (line) in the right pane of the dialog.
     We need something to map the line number to our operand.
     In the case of VDS17 ```ea``` performs this role.
2. ```path```  the path that describes the union selection.
3. ```top_tif``` typeinfo of the top-level UDT which user selected
4. ```spath``` the field names path to the selected member

The union selection path is denotes a concrete member inside a UDT.

For structure types there is no need in the union selection path because the member
offset uniquely denotes the desired member.

For unions, on the other hand, the member offset is not enough because all union
members start at the same offset zero. For them, we remember the ordinal number of the
union member in the path. E.g., for the local types given above, the following holds:

* e1.d1.c0 is denoted by an empty path because it does not have any unions
* e1.d2.u0 is denoted by path consisting of 0: we use the first member of U
* e1.d2.u1 is denoted by path consisting of 1: we use the second member of U

You can retrieve the union selection path using API call ```get_user_union_selection```
or apply it using ```set_user_union_selection```.
"""
