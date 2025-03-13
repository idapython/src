
import recipe_idphooks
import recipe_idbhooks
import recipe_dbghooks
import recipe_uihooks
import recipe_viewhooks
import recipe_hexrays

class hooks_info_t(object):
    def __init__(
            self,
            class_name,
            toplevel_xml_fname,
            enum_name,
            discard_prefixes,
            discard_doc,
            strip_prefixes,
            recipe_module):
        self.class_name = class_name
        self.toplevel_xml_fname = toplevel_xml_fname
        self.enum_name = enum_name
        self.discard_prefixes = discard_prefixes or ()
        self.discard_doc = discard_doc
        self.strip_prefixes = strip_prefixes or []
        self.recipe_module = recipe_module


hooks = {
    "ida_idp" : [
        hooks_info_t(
            "IDP_Hooks",
            "structprocessor__t.xml",
            "event_t",
            None,
            None,
            None,
            recipe_idphooks
        ),
        hooks_info_t(
            "IDB_Hooks",
            "namespaceidb__event.xml",
            "event_code_t",
            None,
            None,
            None,
            recipe_idbhooks
        ),
    ],
    "ida_dbg" : [
        hooks_info_t(
            "DBG_Hooks",
            "dbg_8hpp.xml",
            "dbg_notification_t",
            None,
            None,
            None,
            recipe_dbghooks
        ),
    ],
    "ida_kernwin" : [
        hooks_info_t(
            "UI_Hooks",
            "kernwin_8hpp.xml",
            "ui_notification_t",
            ("ui_dbg_", "ui_obsolete"),
            "ui:",
            ["ui_"],
            recipe_uihooks
        ),
        hooks_info_t(
            "View_Hooks",
            "kernwin_8hpp.xml",
            "view_notification_t",
            None,
            None,
            None,
            recipe_viewhooks
        ),
    ],
    "ida_hexrays" : [
        hooks_info_t(
            "Hexrays_Hooks",
            "hexrays_8hpp.xml",
            "hexrays_event_t",
            None,
            None,
            ["hxe_", "lxe_"],
            recipe_hexrays
        )
    ],
}
