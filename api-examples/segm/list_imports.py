"""
summary: List the .idata section content and the corresponding
    data and code references when it applies.

description:
    In this script, we iterate through the .idata PE section.
    For each imported function we display:
    * its name
    * the data references to it (when applying)
    * the code references to it (when applying,
"""
import ida_segment
import ida_name
import idautils
import ida_kernwin
import ida_funcs

def is_code(ea):
    return ida_segment.segtype(ea) == ida_segment.SEG_CODE

def newline():
    print('')

def list_refs(refs, code):
    first = True
    if code:
        type = 'code'
    else:
        type = 'data'
    
    idx = 1
    for ref in refs:
        if first:
            print(f'\tList of {type} references:')
            first = False
        ida_kernwin.msg(f'\t* [{idx}] @ {ref:x}')
        if is_code(ref):
            name = ida_funcs.get_func_name(ref)
            if name:
                print(f' ({name})')
            else:
                newline()
        else:
            newline()
        idx += 1


def main():
    import_seg = ida_segment.get_segm_by_name('.idata')

    if import_seg:
        curr_ea = import_seg.start_ea
        end_ea = import_seg.end_ea
        idx = 1
        while curr_ea < end_ea:
            name = ida_name.get_ea_name(curr_ea)
            print(f'Imported function [{idx}]: {name}')

            list_refs(idautils.DataRefsTo(curr_ea), False)

            list_refs(idautils.CodeRefsTo(curr_ea, 0), True)

            if import_seg.is_64bit():
                curr_ea += 8
            else:
                curr_ea += 4
            idx += 1


if __name__ == '__main__':
    main()