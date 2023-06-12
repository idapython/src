"""
summary: showcasing `ida_bytes.bin_search`

description:
  IDAPython's ida_bytes.bin_search function is pretty powerful,
  but can be tough to figure out at first. This example introduces

   * `ida_bytes.bin_search`, and
   * `ida_bytes.parse_binpat_str`

  in order to implement a simple replacement for the
  'Search > Sequence of bytes...' dialog, that lets users
  search for sequences of bytes that compose string literals
  in the binary file (either in the default 1-byte-per-char
  encoding, or as UTF-16.)
"""

import ida_kernwin
import ida_bytes
import ida_ida
import ida_idaapi
import ida_nalt

class search_strlit_form_t(ida_kernwin.Form):
    def __init__(self):
        ida_kernwin.Form.__init__(
            self,
            r"""Please enter string literal

<Text: {Text}>
<#UTF16-BE if file is big-endian, UTF16-LE otherwise#As UTF-16: {UTF16}>{Encoding}>
""",
            {
                "Text" : ida_kernwin.Form.StringInput(),
                "Encoding" : ida_kernwin.Form.ChkGroupControl(("UTF16",)),
            })

class search_strlit_ah_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        f = search_strlit_form_t()
        f, args = f.Compile()
        ok = f.Execute()
        if ok:
            current_ea = ida_kernwin.get_screen_ea()
            patterns = ida_bytes.compiled_binpat_vec_t()
            encoding = ida_nalt.get_default_encoding_idx(
                ida_nalt.BPU_2B if f.Encoding.value else ida_nalt.BPU_1B)
            # string literals must be quoted. That's how parse_binpat_str
            # recognizes them (we want to be careful though: the user
            # might type in something like 'L"hello"', which should
            # decode to the IDB-specific wide-char set of bytes)
            text = f.Text.value
            if text.find('"') < 0:
                text = '"%s"' % text
            err = ida_bytes.parse_binpat_str(
                patterns,
                current_ea,
                text,
                10, # radix (not that it matters though, since we're all about string literals)
                encoding)
            if not err:
                ea = ida_bytes.bin_search(
                    current_ea,
                    ida_ida.inf_get_max_ea(),
                    patterns,
                    ida_bytes.BIN_SEARCH_FORWARD
                  | ida_bytes.BIN_SEARCH_NOBREAK
                  | ida_bytes.BIN_SEARCH_NOSHOW)
                ok = ea != ida_idaapi.BADADDR
                if ok:
                    ida_kernwin.jumpto(ea)
            else:
                print("Failed parsing binary pattern: \"%s\"" % err)
        return ok

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type == ida_kernwin.BWN_DISASM \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


ACTION_NAME = "bin_search:search"
ACTION_SHORTCUT = "Ctrl+Shift+S"

if ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            ACTION_NAME,
            "Search for string literal",
            search_strlit_ah_t(),
            ACTION_SHORTCUT)):
    print("Please use \"%s\" to search for string literals" % ACTION_SHORTCUT)
