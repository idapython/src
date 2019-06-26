
"""
This is a crude (and not very pythonic) reimplementation of the example
hexrays plugin 'hexrays_sample6.cpp', shipped with the Hex-Rays decompiler.

It modifies the decompilation output: removes some space characters.
"""
from __future__ import print_function

import idautils
import idc
import ida_idaapi
import ida_hexrays
import ida_lines

def dbg(msg):
    #print msg
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
        dbg("-" * 60)
        nchars = ida_lines.tag_advance(l, 1)
        push(l[0:nchars])
        l = l[nchars:]
        l = my_tag_skipcodes(l, out)
        if not l:
            break
        if l.startswith("//"):
            push(l)
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

if ida_hexrays.init_hexrays_plugin():
    vds6_hooks = vds6_hooks_t()
    vds6_hooks.hook()
else:
    print('remove spaces: hexrays is not available.')
