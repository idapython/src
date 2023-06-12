"""
summary: superficially modify the decompilation output

description:
  modifies the decompilation output in a superficial manner,
  by removing some white spaces

  Note: this is rather crude, not quite "pythonic" code.
"""

import idautils
import idc
import ida_idaapi
import ida_hexrays
import ida_lines

def dbg(msg):
    #print(msg)
    pass

def is_cident_char(c):
    return c.isalnum() or c == '_'

def my_tag_skipcodes(l, storage):
    n = ida_lines.tag_skipcodes(l)
    dbg("Skipping %d chars ('%s')" % (n, l[0:n]))
    storage.append(l[0:n])
    return l[n:]

def remove_spaces(sl):
    dbg("*" * 80)
    l = sl.line
    out = []

    def push(c):
        dbg("Appending '%s'" % c)
        out.append(c)

    # skip initial spaces, do not compress them
    while True:
        l = my_tag_skipcodes(l, out)
        if not l:
            break
        c = l[0]
        if not c.isspace():
            break
        push(c)
        l = l[1:]

    # remove all spaces except in string and char constants
    delim = None # if not None, then we are skipping until 'delim'
    last = None # last seen character
    while True:
        # go until comments
        if l.startswith("//"):
            push(l)
            break
        dbg("-" * 60)
        nchars = ida_lines.tag_advance(l, 1)
        push(l[0:nchars])
        l = l[nchars:]
        l = my_tag_skipcodes(l, out)
        if not l:
            break
        c = l[0]
        dbg("c: '%s', last: '%s', l: '%s'" % (c, last, l))
        if delim:
            # we're inside a literal.
            if c == delim:
                delim = None # literal ended
        elif c == '"' or c == "'":
            delim = c # string/char literal started
        elif c.isspace():
            end = l.lstrip()
            nptr = my_tag_skipcodes(end, out)
            dbg("end: '%s', nptr: '%s'" % (end, nptr))
            # do not concatenate idents
            if not is_cident_char(last) or not is_cident_char(nptr[0]):
                l = end
                c = l[0] if l else ''
                dbg("new l: '%s'" % l)
        last = l[0] if l else ''

    sl.line = "".join(out)


class vds6_hooks_t(ida_hexrays.Hexrays_Hooks):
    def func_printed(self, cfunc):
        for sl in cfunc.get_pseudocode():
            remove_spaces(sl);
        return 0

# a plugin interface, boilerplate code
class my_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Hex-Rays space remover (IDAPython)"
    wanted_hotkey = ""
    comment = "Sample plugin6 for Hex-Rays decompiler"
    help = ""
    def init(self):
        if ida_hexrays.init_hexrays_plugin():
            self.vds6_hooks = vds6_hooks_t()
            self.vds6_hooks.hook()
            return ida_idaapi.PLUGIN_KEEP # keep us in the memory
    def term(self):
        self.vds6_hooks.unhook()
    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return my_plugin_t()
