# -----------------------------------------------------------------------
#<pycode(py_kernwin)>

# ----------------------------------------------------------------------
def load_custom_icon(file_name=None, data=None, format=None):
    """
    Loads a custom icon and returns an identifier that can be used with other APIs

    If file_name is passed then the other two arguments are ignored.

    @param file_name: The icon file name
    @param data: The icon data
    @param format: The icon data format

    @return: Icon id or 0 on failure.
             Use free_custom_icon() to free it
    """
    if file_name is not None:
       return _ida_kernwin.py_load_custom_icon_fn(file_name)
    elif not (data is None and format is None):
       return _ida_kernwin.py_load_custom_icon_data(data, format)
    else:
      return 0

# ----------------------------------------------------------------------
def ask_long(defval, format):
    res, val = _ida_kernwin._ask_long(defval, format)

    if res == 1:
        return val
    else:
        return None

# ----------------------------------------------------------------------
def ask_addr(defval, format):
    res, ea = _ida_kernwin._ask_addr(defval, format)

    if res == 1:
        return ea
    else:
        return None

# ----------------------------------------------------------------------
def ask_seg(defval, format):
    res, sel = _ida_kernwin._ask_seg(defval, format)

    if res == 1:
        return sel
    else:
        return None

# ----------------------------------------------------------------------
def ask_ident(defval, format):
    return ask_str(defval, HIST_IDENT, format)

# ----------------------------------------------------------------------
class action_handler_t(object):
    def __init__(self):
        pass

    def activate(self, ctx):
        return 0

    def update(self, ctx):
        pass

# ----------------------------------------------------------------------
# This provides an alternative to register_action()+attach_action_to_popup_menu()
class quick_widget_commands_t:

    class _cmd_t:
        def __init__(self, caption, flags, menu_index, icon, emb, shortcut):
            self.caption = caption
            self.flags = flags
            self.menu_index = menu_index
            self.icon = icon
            self.emb = emb
            self.shortcut = shortcut

    class _ah_t(action_handler_t):
        def __init__(self, parent, cmd_id):
            action_handler_t.__init__(self)
            self.parent = parent
            self.cmd_id = cmd_id

        def activate(self, ctx):
            self.parent.callback(ctx, self.cmd_id)

        def update(self, ctx):
            return AST_ENABLE_ALWAYS


    def __init__(self, callback):
        self.callback = callback
        self.cmds = []

    def add(self, caption, flags, menu_index, icon, emb, shortcut):
        for idx, cmd in enumerate(self.cmds):
            if cmd.caption == caption:
                return idx
        self.cmds.append(
            quick_widget_commands_t._cmd_t(
                caption, flags, menu_index, icon, emb, shortcut))
        return len(self.cmds) - 1

    def populate_popup(self, widget, popup):
        for idx, cmd in enumerate(self.cmds):
            if (cmd.flags & CHOOSER_POPUP_MENU) != 0:
                desc = action_desc_t(None,
                                     cmd.caption,
                                     quick_widget_commands_t._ah_t(self, idx),
                                     cmd.shortcut,
                                     None,
                                     cmd.icon)
                attach_dynamic_action_to_popup(None, popup, desc)

class disabled_script_timeout_t(object):
    def __enter__(self):
        import _ida_idaapi
        self.was_timeout = _ida_idaapi.set_script_timeout(0)

    def __exit__(self, type, value, tb):
        import _ida_idaapi
        _ida_idaapi.set_script_timeout(self.was_timeout)

import ida_ida
ida_ida.__wrap_hooks_callback(
    UI_Hooks,
    "database_closed",
    "term",
    lambda cb, *args: cb(*args))


# ----------------------------------------------------------------------
# bw-compat/deprecated. You shouldn't rely on this in new code
from ida_pro import str2user
SETMENU_IF_ENABLED = 4

#</pycode(py_kernwin)>
