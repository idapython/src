"""
summary: dump user-defined information

description:
  Prints user-defined information to the "Output" window.
  Namely:

    * user defined label names
    * user defined indented comments
    * user defined number formats
    * user defined local variable names, types, comments

  This script loads information from the database without decompiling anything.

author: EiNSTeiN_ (einstein@g3nius.org)
"""

import ida_kernwin
import ida_hexrays
import ida_bytes

def run():
    f = ida_funcs.get_func(ida_kernwin.get_screen_ea());
    if f is None:
        print("Please position the cursor within a function")
        return True
    entry_ea = f.start_ea
    print("Dump of user-defined information for function at %x" % entry_ea)

    # Display user defined labels.
    labels = ida_hexrays.restore_user_labels(entry_ea);
    if labels is not None:
        print("------- %u user defined labels" % len(labels))
        for org_label, name in labels.items():
            print("Label %d: %s" % (org_label, str(name)))
        ida_hexrays.user_labels_free(labels)

    # Display user defined comments
    cmts = ida_hexrays.restore_user_cmts(entry_ea);
    if cmts is not None:
        print("------- %u user defined comments" % (len(cmts), ))
        for tl, cmt in cmts.items():
            print("Comment at %x, preciser %x:\n%s\n" % (tl.ea, tl.itp, str(cmt)))
        ida_hexrays.user_cmts_free(cmts)

    # Display user defined citem iflags
    iflags = ida_hexrays.restore_user_iflags(entry_ea)
    if iflags is not None:
        print("------- %u user defined citem iflags" % (len(iflags), ))
        for cl, f in iflags.items():
            print("%x(%d): %08X%s" % (cl.ea, cl.op, f, " CIT_COLLAPSED" if f & ida_hexrays.CIT_COLLAPSED else ""))
        ida_hexrays.user_iflags_free(iflags)

    # Display user defined number formats
    numforms = ida_hexrays.restore_user_numforms(entry_ea)
    if numforms is not None:
        print("------- %u user defined number formats" % (len(numforms), ))
        for ol, nf in numforms.items():
            print("Number format at %a, operand %d: %s" % \
                  (ol.ea,
                   ol.opnum,
                   "negated " if (ord(nf.props) & ida_hexrays.NF_NEGATE) != 0 else ""))

            if nf.is_enum():
                print("enum %s (serial %d)" % (str(nf.type_name), nf.serial))

            elif nf.is_char():
                print("char")

            elif nf.is_stroff():
                print("struct offset %s" % (str(nf.type_name), ))

            else:
                print("number base=%d" % (ida_bytes.get_radix(nf.flags, ol.opnum), ))

        ida_hexrays.user_numforms_free(numforms)

    # Display user-defined local variable information
    lvinf = ida_hexrays.lvar_uservec_t()
    if ida_hexrays.restore_user_lvar_settings(lvinf, entry_ea):
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


if ida_hexrays.init_hexrays_plugin():
    run()
else:
    print('dump user info: hexrays is not available.')
