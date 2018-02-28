# -----------------------------------------------------------------------
#<pycode(py_kernwin)>
DP_LEFT           = 0x0001
DP_TOP            = 0x0002
DP_RIGHT          = 0x0004
DP_BOTTOM         = 0x0008
DP_INSIDE         = 0x0010
# if not before, then it is after
# (use DP_INSIDE | DP_BEFORE to insert a tab before a given tab)
# this flag alone cannot be used to determine orientation
DP_BEFORE         = 0x0020
# used with combination of other flags
DP_TAB            = 0x0040
DP_FLOATING       = 0x0080

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
# bw-compat/deprecated. You shouldn't rely on this in new code
from ida_pro import str2user

#</pycode(py_kernwin)>

#<pycode_BC695(py_kernwin)>
AST_DISABLE_FOR_FORM=AST_DISABLE_FOR_WIDGET
AST_ENABLE_FOR_FORM=AST_ENABLE_FOR_WIDGET
CB_CLOSE_IDB=CB_INVISIBLE
chtype_generic2=chtype_generic
chtype_segreg=chtype_srcp
close_tform=close_widget
find_tform=find_widget
get_current_tform=get_current_widget
def get_highlighted_identifier():
    thing = get_highlight(get_current_widget())
    if thing and thing[1]:
        return thing[0]
get_tform_title=get_widget_title
get_tform_type=get_widget_type
is_chooser_tform=is_chooser_widget
open_tform=display_widget
pyscv_get_tcustom_control=pyscv_get_widget
pyscv_get_tform=pyscv_get_widget
__read_selection70 = read_selection
def read_selection(*args):
    if len(args) == 0:
        # bw-compat
        t0, t1, view = twinpos_t(), twinpos_t(), get_current_viewer()
        sel = __read_selection70(view, t0, t1)
        import ida_idaapi
        a0, a1 = ida_idaapi.BADADDR, ida_idaapi.BADADDR
        if sel:
            a0, a1 = t0.place(view).toea(), t1.place(view).toea()
        return sel, a0, a1
    else:
        return __read_selection70(*args)

readsel2=read_selection
switchto_tform=activate_widget
umsg=msg

import ida_ida
def __wrap_uihooks_callback(name, do_call):
    return ida_ida.__wrap_hooks_callback(UI_Hooks, name, name.replace("widget", "tform"), do_call)


__wrap_uihooks_callback("widget_visible", lambda cb, *args: cb(args[0], args[0]))
__wrap_uihooks_callback("widget_invisible", lambda cb, *args: cb(args[0], args[0]))
__wrap_uihooks_callback("populating_widget_popup", lambda cb, *args: cb(*args))
__wrap_uihooks_callback("finish_populating_widget_popup", lambda cb, *args: cb(*args))
__wrap_uihooks_callback("current_widget_changed", lambda cb, *args: cb(*args))

AskUsingForm=ask_form
HIST_ADDR=0
HIST_NUM=0
KERNEL_VERSION_MAGIC1=0
KERNEL_VERSION_MAGIC2=0
OpenForm=open_form
_askaddr=_ida_kernwin._ask_addr
_asklong=_ida_kernwin._ask_long
_askseg=_ida_kernwin._ask_seg
askaddr=ask_addr
askbuttons_c=ask_buttons
askfile_c=ask_file
@bc695redef
def askfile2_c(forsave, defdir, filters, fmt):
    if filters:
        fmt = "FILTER %s\n%s" % (filters, fmt)
    return ask_file(forsave, defdir, fmt)
askident=ask_ident
asklong=ask_long
@bc695redef
def askqstr(defval, fmt):
    return ask_str(defval, 0, fmt)
askseg=ask_seg
@bc695redef
def askstr(hist, defval, fmt):
    return ask_str(defval, hist, fmt)
asktext=ask_text
askyn_c=ask_yn
choose2_activate=choose_activate
choose2_close=choose_close
choose2_create=choose_create
choose2_find=choose_find
choose2_get_embedded=choose_get_embedded
choose2_get_embedded_selection=choose_get_embedded_selection
choose2_refresh=choose_refresh
clearBreak=clr_cancelled
py_get_AskUsingForm=py_get_ask_form
py_get_OpenForm=py_get_open_form
setBreak=set_cancelled
wasBreak=user_cancelled
refresh_lists=refresh_choosers

#--------------------------------------------------------------------------
class BC695_control_cmd:
    def __init__(self, cmd_id, caption, flags, menu_index, icon, emb, shortcut, is_chooser):
        self.cmd_id = cmd_id
        self.caption = caption
        self.flags = flags
        self.menu_index = menu_index
        self.icon = icon
        self.emb = emb
        self.shortcut = shortcut
        self.is_chooser = is_chooser

    @staticmethod
    def add_to_control(control, caption, flags, menu_index, icon, emb, shortcut, is_chooser):
        if getattr(control, "commands", None) is None:
            setattr(control, "commands", [])
        found = filter(lambda x: x.caption == caption, control.commands)
        if len(found) == 1:
            cmd_id = found[0].cmd_id
        else:
            cmd_id = len(control.commands)
            cmd = BC695_control_cmd(cmd_id, caption, flags, menu_index, icon, emb, shortcut, is_chooser)
            control.commands.append(cmd)
        return cmd_id

    @staticmethod
    def populate_popup(control, widget, popup):
        cmds = getattr(control, "commands", [])
        for cmd in cmds:
            if (cmd.flags & CHOOSER_POPUP_MENU) != 0:
                desc = action_desc_t(None, cmd.caption, BC695_control_cmd_ah_t(control, cmd), cmd.shortcut, None, cmd.icon)
                attach_dynamic_action_to_popup(widget, popup, desc)

class BC695_control_cmd_ah_t(action_handler_t):
    def __init__(self, control, cmd):
        action_handler_t.__init__(self)
        self.control = control
        self.cmd = cmd

    def activate(self, ctx):
        if self.cmd.is_chooser:
            idx = ctx.chooser_selection[0]
            self.control.OnCommand(idx, self.cmd.cmd_id)
        else:
            self.control.OnCommand(self.cmd.cmd_id)

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class Choose2(object):
    """v.6.95 compatible chooser wrapper class."""

    CH_MODAL        = 0x01
    CH_MULTI        = 0x04
    CH_MULTI_EDIT   = 0x08
    """
    The OnEditLine() callback will be called for all
    selected items using the START_SEL/END_SEL
    protocol.
    This bit implies #CH_MULTI.
    """
    CH_NOBTNS       = 0x10
    CH_ATTRS        = 0x20
    CH_NOIDB        = 0x40
    CH_BUILTIN_SHIFT = 19
    CH_BUILTIN_MASK = 0x1F << CH_BUILTIN_SHIFT

    # column flags (are specified in the widths array)
    CHCOL_PLAIN  =  0x00000000
    CHCOL_PATH   =  0x00010000
    CHCOL_HEX    =  0x00020000
    CHCOL_DEC    =  0x00030000
    CHCOL_FORMAT =  0x00070000

    # special values of the chooser index
    NO_SELECTION   = -1
    """there is no selected item"""
    START_SEL      = -2
    """before calling the first selected item"""
    END_SEL        = -3
    """after calling the last selected item"""


    # the v.7.0 chooser object implementing the v.6.95 chooser
    class ChooseWrapper(Choose):

        def __init__(self, v695_chooser):
            self.link = v695_chooser
            # check what non-base callbacks we have
            forbidden_cb = 0
            for cb in [("OnInsertLine", Choose.CHOOSE_HAVE_INS    ),
                       ("OnDeleteLine", Choose.CHOOSE_HAVE_DEL    ),
                       ("OnEditLine",   Choose.CHOOSE_HAVE_EDIT   ),
                       ("OnSelectLine", Choose.CHOOSE_HAVE_ENTER  ),
                       ("OnRefresh",    Choose.CHOOSE_HAVE_REFRESH),
                       ("OnSelectionChange", Choose.CHOOSE_HAVE_SELECT)]:
                if not hasattr(self.link, cb[0]) or \
                   not callable(getattr(self.link, cb[0])):
                    forbidden_cb |= cb[1]
            Choose.__init__(
                    self, self.link.title, self.link.cols,
                    forbidden_cb = forbidden_cb)

        # redirect base callbacks to the v.6.95 chooser
        def __getattr__(self, attr):
            if attr in ["OnGetSize",
                        "OnGetLine",
                        "OnGetIcon",
                        "OnGetLineAttr",
                        "OnClose"]:
                return getattr(self.link, attr)
            return getattr(self.link, attr)

        def Show(self, modal = False):
            # set `flags` and `deflt`
            self.flags = self.link.flags
            if self.link.deflt == -1:
                self.deflt = 0
            else:
                self.deflt = self.link.deflt - 1
                self.flags |= Choose.CH_FORCE_DEFAULT
            if (self.flags & Choose.CH_MULTI) != 0:
                self.deflt = [self.deflt]
            # copy simple attributes from v.6.95
            for attr in ["title", "cols", "popup_names", "icon",
                         "x1", "y1", "x2", "y2",
                         "embedded", "width", "height"]:
                if hasattr(self.link, attr):
                    setattr(self, attr, getattr(self.link, attr))
                else:
                    delattr(self, attr)
            return Choose.Show(self, modal)

        def OnInsertLine(self, n):
            # assert: hasattr(self.link, "OnInsertLine")
            self.link.OnInsertLine()
            # we preserve the selection
            return (Choose.ALL_CHANGED, n)
            if (self.link.flags & Choose2.CH_MULTI) == 0:
                return (Choose.ALL_CHANGED, n)
            else:
                return [Choose.ALL_CHANGED] + n

        def OnDeleteLine(self, n):
            # assert: hasattr(self.link, "OnDeleteLine")
            res = None
            if (self.link.flags & Choose2.CH_MULTI) == 0:
                res = self.link.OnDeleteLine(n)
            else:
              # assert: n is iterable and n
              # call the callback multiple times
              self.link.OnDeleteLine(Choose2.START_SEL)
              res = None
              for idx in n:
                  new_idx = self.link.OnDeleteLine(idx)
                  if res == None:
                      res = new_idx
              self.link.OnDeleteLine(Choose2.END_SEL)
            return [Choose.ALL_CHANGED] + self.adjust_last_item(res)

        def OnEditLine(self, n):
            # assert: hasattr(self.link, "OnEditLine")
            if (self.link.flags & Choose2.CH_MULTI) == 0:
                self.link.OnEditLine(n)
                return (Choose.ALL_CHANGED, n) # preserve the selection
            # assert: n is iterable and n
            if (self.link.flags & Choose2.CH_MULTI_EDIT) == 0:
                self.link.OnEditLine(n[0])
                return [Choose.ALL_CHANGED] + n # preserve the selection
            # call the callback multiple times
            self.link.OnEditLine(Choose2.START_SEL)
            for idx in n:
                self.link.OnEditLine(idx)
            self.link.OnEditLine(Choose2.END_SEL)
            return [Choose.ALL_CHANGED] + n # preserve the selection

        def OnSelectLine(self, n):
            # assert: hasattr(self.link, "OnSelectLine")
            if (self.link.flags & Choose2.CH_MULTI) == 0:
                self.link.OnSelectLine(n)
                return (Choose.ALL_CHANGED, n)
            # assert: n is iterable and n
            self.link.OnSelectLine(n[0])
            return [Choose.ALL_CHANGED] + n # preserve the selection

        def OnRefresh(self, n):
            # assert: hasattr(self.link, "OnRefresh")
            if (self.link.flags & Choose2.CH_MULTI) != 0:
              # ignore all but the first item
              n = n[0] if n else Choose.NO_SELECTION
            res = self.link.OnRefresh(n)
            return (Choose.ALL_CHANGED, res)

        def OnSelectionChange(self, n):
            # assert: hasattr(self.link, "OnSelectionChange")
            if (self.link.flags & Choose2.CH_MULTI) == 0:
              n = [n] if n != Choose.NO_SELECTION else []
            self.link.OnSelectionChange(n)

        def OnPopup(self, widget, popup_handle):
            BC695_control_cmd.populate_popup(
                self.link,
                widget,
                popup_handle)


    def __init__(self, title, cols, flags=0, popup_names=None,
                 icon=-1, x1=-1, y1=-1, x2=-1, y2=-1, deflt=-1,
                 embedded=False, width=None, height=None):
        """
        Constructs a chooser window.
        @param title: The chooser title
        @param cols: a list of colums; each list item is a list of two items
            example: [ ["Address", 10 | Choose2.CHCOL_HEX],
                       ["Name", 30 | Choose2.CHCOL_PLAIN] ]
        @param flags: One of CH_XXXX constants
        @param deflt: Default starting item (1-based).
            0 means that no item is selected,
            -1 means that the first item selected for a new window and
            that the selection is not updated for an existing window
        @param popup_names: list of new captions to replace this list
            ["Insert", "Delete", "Edit", "Refresh"]
        @param icon: Icon index (the icon should exist in ida resources or
            an index to a custom loaded icon)
        @param x1, y1, x2, y2: The default location (for txt-version)
        @param embedded: Create as embedded chooser
        @param width: Embedded chooser width
        @param height: Embedded chooser height
        """
        # remember attributes
        self.title = title
        self.flags = flags
        self.cols = cols
        self.deflt = deflt
        self.popup_names = popup_names
        self.icon = icon
        self.x1 = x1
        self.y1 = y1
        self.x2 = x2
        self.y2 = y2
        self.embedded = embedded
        self.width = width
        self.height = height
        # construct the v.7.0 chooser object
        self.chobj = Choose2.ChooseWrapper(self)


    # redirect methods to the v.7.0 chooser
    def __getattr__(self, attr):
        if attr not in ["GetEmbSelection",
                        "Activate",
                        "Refresh",
                        "Close",
                        "GetWidget"]:
            raise AttributeError(attr)
        return getattr(self.chobj, attr)

    def Embedded(self):
        """
        Creates an embedded chooser (as opposed to Show())
        @return: Returns 1 on success
        """
        return 1 if self.chobj.Embedded() == 0 else 0


    def Show(self, modal=False):
        """
        Activates or creates a chooser window
        @param modal: Display as modal dialog
        @return: For modal choosers it will return the selected item index (0-based)
                 or -1 in the case of error,
                 For non-modal choosers it will return 0
                 or -1 if the chooser was already open and is active now
        """
        ret = self.chobj.Show(modal)
        return -1 if ret < 0 else ret


    def AddCommand(self,
                   caption,
                   flags = _ida_kernwin.CHOOSER_POPUP_MENU,
                   menu_index = -1,
                   icon = -1,
                   emb=None,
                   shortcut=None):
        # Use the 'emb' as a sentinel. It will be passed the correct value
        # from the EmbeddedChooserControl
        if self.embedded and ((emb is None) or (emb != 2002)):
            raise RuntimeError("Please add a command through "
                               "EmbeddedChooserControl.AddCommand()")
        return BC695_control_cmd.add_to_control(
                   self, caption, flags, menu_index, icon, emb, None,
                   is_chooser=True)

    # callbacks
    # def OnGetSize(self):
    # def OnGetLine(self, n):
    # def OnGetIcon(self, n):
    # def OnGetLineAttr(self, n):
    # def OnInsertLine(self):
    # def OnDeleteLine(self, n):
    # def OnEditLine(self, n):
    # def OnSelectLine(self, n):
    # def OnRefresh(self, n):
    # def OnSelectionChange(self, sel_list):
    # def OnClose(self):
    # def OnCommand(self, n, cmd_id):
#</pycode_BC695(py_kernwin)>

