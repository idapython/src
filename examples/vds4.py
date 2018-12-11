""" Print user-defined details to the output window.

Author: EiNSTeiN_ <einstein@g3nius.org>

This is a rewrite in Python of the vds4 example that comes with hexrays sdk.
"""
from __future__ import print_function

import idautils
import idaapi
import idc

import traceback

def run():

    cfunc = idaapi.decompile(idaapi.get_screen_ea())
    if not cfunc:
        print('Please move the cursor into a function.')
        return

    entry_ea = cfunc.entry_ea
    print("Dump of user-defined information for function at %x" % (entry_ea, ))

    # Display user defined labels.
    labels = idaapi.restore_user_labels(entry_ea);
    if labels is not None:
        print("------- %u user defined labels" % (len(labels), ))
        for org_label, name in labels.iteritems():
            print("Label %d: %s" % (org_label, str(name)))
        idaapi.user_labels_free(labels)

    # Display user defined comments
    cmts = idaapi.restore_user_cmts(entry_ea);
    if cmts is not None:
        print("------- %u user defined comments" % (len(cmts), ))
        for tl, cmt in cmts.iteritems():
            print("Comment at %x, preciser %x:\n%s\n" % (tl.ea, tl.itp, str(cmt)))
        idaapi.user_cmts_free(cmts)

    # Display user defined citem iflags
    iflags = idaapi.restore_user_iflags(entry_ea)
    if iflags is not None:
        print("------- %u user defined citem iflags" % (len(iflags), ))
        for cl, f in iflags.iteritems():
            print("%x(%d): %08X%s" % (cl.ea, cl.op, f, " CIT_COLLAPSED" if f & idaapi.CIT_COLLAPSED else ""))
        idaapi.user_iflags_free(iflags)

    # Display user defined number formats
    numforms = idaapi.restore_user_numforms(entry_ea)
    if numforms is not None:
        print("------- %u user defined number formats" % (len(numforms), ))
        for ol, nf in numforms.iteritems():

            print("Number format at %a, operand %d: %s" % (ol.ea, ol.opnum, "negated " if (nf.props & NF_NEGATE) != 0 else ""))

            if nf.is_enum():
                print("enum %s (serial %d)" % (str(nf.type_name), nf.serial))

            elif nf.is_char():
                print("char")

            elif nf.is_stroff():
                print("struct offset %s" % (str(nf.type_name), ))

            else:
                print("number base=%d" % (idaapi.get_radix(nf.flags, ol.opnum), ))

        idaapi.user_numforms_free(numforms)

    # Display user-defined local variable information
    lvinf = idaapi.lvar_uservec_t()
    if idaapi.restore_user_lvar_settings(lvinf, entry_ea):
        print("------- User defined local variable information\n")
        for lv in lvinf.lvvec:
            print("Lvar defined at %x" % (lv.ll.defea, ))

            if len(str(lv.name)):
                print("  Name: %s" % (str(lv.name), ))

            if len(str(lv.type)):
                #~ print_type_to_one_line(buf, sizeof(buf), idati, .c_str());
                print("  Type: %s" % (str(lv.type), ))

            if len(str(lv.cmt)):
                print("  Comment: %s" % (str(lv.cmt), ))


    return


if idaapi.init_hexrays_plugin():
    run()
else:
    print('dump user info: hexrays is not available.')
