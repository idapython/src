
import recipe_idphooks
import recipe_idbhooks
import recipe_dbghooks
import recipe_uihooks
import recipe_viewhooks
import recipe_hexrays

# filename
# enum name
# discard enum names with prefixes
# discard docs with prefixes
# remove prefixes from enum value names
# module with recipes

hooks = {
    "IDP_Hooks" : (
        "structprocessor__t.xml",
        "event_t",
        [],
        None,
        [],
        recipe_idphooks
    ),
    "IDB_Hooks" : (
        "namespaceidb__event.xml",
        "event_code_t",
        [],
        None,
        [],
        recipe_idbhooks
    ),
    "DBG_Hooks" : (
        "dbg_8hpp.xml",
        "dbg_notification_t",
        [],
        None,
        [],
        recipe_dbghooks
    ),
    "UI_Hooks" : (
        "kernwin_8hpp.xml",
        "ui_notification_t",
        ["ui_dbg_", "ui_obsolete"],
        "ui:",
        ["ui_"],
        recipe_uihooks
    ),
    "View_Hooks" : (
        "kernwin_8hpp.xml",
        "view_notification_t",
        [],
        None,
        [],
        recipe_viewhooks
    ),
    "Hexrays_Hooks" : (
        "hexrays_8hpp.xml",
        "hexrays_event_t",
        [],
        None,
        ["hxe_", "lxe_"],
        recipe_hexrays
    )
}
