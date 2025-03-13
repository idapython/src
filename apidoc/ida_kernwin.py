
class simplecustviewer_t(object):
    def OnClick(self, shift):
        """
        User clicked in the view
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        print("OnClick, shift=%d" % shift)
        return True

    def OnDblClick(self, shift):
        """
        User dbl-clicked in the view
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        print("OnDblClick, shift=%d" % shift)
        return True

    def OnCursorPosChanged(self):
        """
        Cursor position changed.
        @return: Nothing
        """
        print("OnCurposChanged")

    def OnClose(self):
        """
        The view is closing. Use this event to cleanup.
        @return: Nothing
        """
        print("OnClose")

    def OnKeydown(self, vkey, shift):
        """
        User pressed a key
        @param vkey: Virtual key code
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        print("OnKeydown, vk=%d shift=%d" % (vkey, shift))
        return False

    def OnHint(self, lineno):
        """
        Hint requested for the given line number.
        @param lineno: The line number (zero based)
        @return:
            - tuple(number of important lines, hint string)
            - None: if no hint available
        """
        return (1, "OnHint, line=%d" % lineno)

    def OnPopupMenu(self, menu_id):
        """
        A context (or popup) menu item was executed.
        @param menu_id: ID previously registered with add_popup_menu()
        @return: Boolean
        """
        print("OnPopupMenu, menu_id=" % menu_id)
        return True

def register_timer(interval, callback):
    """
    Register a timer

    @param interval: Interval in milliseconds
    @param callback: A Python callable that takes no parameters and returns an integer.
                     The callback may return:
                     -1   : to unregister the timer
                     >= 0 : the new or same timer interval
    @return: None or a timer object
    """
    pass

def unregister_timer(timer_obj):
    """
    Unregister a timer

    @param timer_obj: a timer object previously returned by a register_timer()
    @return: Boolean
    @note: After the timer has been deleted, the timer_obj will become invalid.
    """
    pass

def choose_idasgn():
    """
    Opens the signature chooser

    @return: None or the selected signature name
    """
    pass

def get_highlight(v, flags=0):
    """
    Returns the currently highlighted identifier and flags

    @param v: The UI widget to operate on
    @param flags: Optionally specify a slot (see kernwin.hpp), current otherwise
    @return: a tuple (text, flags), or None if nothing
             is highlighted or in case of error.
    """
    pass

def free_custom_icon(icon_id):
    """
    Frees an icon loaded with load_custom_icon()

    @param icon_id: The ID of the icon to free
    """
    pass

def read_selection(v, p1, p2):
    """
    Read the user selection, and store its information in p1 (from) and p2 (to).

    This can be used as follows:


    >>> p1 = ida_kernwin.twinpos_t()
    p2 = ida_kernwin.twinpos_t()
    view = ida_kernwin.get_current_viewer()
    ida_kernwin.read_selection(view, p1, p2)


    At that point, p1 and p2 hold information for the selection.
    But, the 'at' property of p1 and p2 is not properly typed.
    To specialize it, call #place() on it, passing it the view
    they were retrieved from. Like so:


    >>> place0 = p1.place(view)
    place1 = p2.place(view)


    This will effectively "cast" the place into a specialized type,
    holding proper information, depending on the view type (e.g.,
    disassembly, structures, enums, ...)

    @param v: The view to retrieve the selection for.
    @param p1: Storage for the "from" part of the selection.
    @param p2: Storage for the "to" part of the selection.
    @return: a bool value indicating success.
    """
    pass


def ask_text(max_size: int, defval: str, prompt: str) -> Union[str, None]:
    """
    Asks for a long text

    @param max_size: Maximum text length, 0 for unlimited
    @param defval: The default value
    @param prompt: The prompt value
    @return: None or the entered string
    """
    pass

def ask_str(defval, hist, prompt):
    """
    Asks for a long text

    @param defval: The default value
    @param hist:   history id
    @param prompt: The prompt value
    @return: None or the entered string
    """
    pass

def process_ui_action(name: str, flags: int=0):
    """
    Invokes an IDA UI action by name

    @param name:  action name
    @param flags: reserved
    @return: Boolean
    """
    pass

def del_hotkey(ctx):
    """
    Deletes a previously registered function hotkey

    @param ctx: Hotkey context previously returned by add_hotkey()

    @return: Boolean.
    """
    pass

def add_hotkey(hotkey, callable):
    """
    Associates a function call with a hotkey.
    Callable 'callable' will be called each time the hotkey is pressed

    @param hotkey: The hotkey
    @param callable: Callable

    @return: Context object on success or None on failure.
    """
    pass


MFF_FAST = 0x0000
"""execute code as soon as possible
this mode is ok call ui related functions
that do not query the database."""

MFF_READ = 0x0001
"""execute code only when ida is idle and it is safe to query the database.
this mode is recommended only for code that does not modify the database.
(nb: ida may be in the middle of executing another user request, for example it may be waiting for him to enter values into a modal dialog box)"""

MFF_WRITE = 0x0002
"""execute code only when ida is idle and it is safe to modify the database. in particular, this flag will suspend execution if there is
a modal dialog box on the screen this mode can be used to call any ida api function. MFF_WRITE implies MFF_READ"""

MFF_NOWAIT = 0x0004
"""Do not wait for the request to be executed.
he caller should ensure that the request is not
destroyed until the execution completes.
if not, the request will be ignored.
the return code of execute_sync() is meaningless
in this case.
This flag can be used to delay the code execution
until the next UI loop run even from the main thread"""

def execute_sync(callable, reqf):
    """
    Executes a function in the context of the main thread.
    If the current thread not the main thread, then the call is queued and
    executed afterwards.

    @param callable: A python callable object, must return an integer value
    @param reqf: one of MFF_ flags
    @return: -1 or the return value of the callable
    """
    pass

def execute_ui_requests(callable_list):
    """
    Inserts a list of callables into the UI message processing queue.
    When the UI is ready it will call one callable.
    A callable can request to be called more than once if it returns True.

    @param callable_list: A list of python callable objects.
    @note: A callable should return True if it wants to be called more than once.
    @return: Boolean. False if the list contains a non callable item
    """
    pass

def set_dock_pos(src_ctrl, dest_ctrl, orient, left = 0, top = 0, right = 0, bottom = 0):
    """
    Sets the dock orientation of a window relatively to another window.

    Use the left, top, right, bottom parameters if DP_FLOATING is used,
    or if you want to specify the width of docked windows.

    @param src_ctrl: Source docking control
    @param dest_ctrl: Destination docking control
    @param orient: One of DP_XXXX constants
    @return: Boolean

    Example:
        set_dock_pos('Structures', 'Enums', DP_RIGHT) <- docks the Structures window to the right of Enums window
    """
    pass

def is_idaq():
    """
    Returns True or False depending if IDAPython is hosted by IDAQ
    """
    pass

def attach_dynamic_action_to_popup(
        unused,
        popup_handle,
        desc,
        popuppath = None,
        flags = 0):
    """
    Create & insert an action into the widget's popup menu
    (::ui_attach_dynamic_action_to_popup).
    Note: The action description in the 'desc' parameter is modified by
          this call so you should prepare a new description for each call.
    For example:
        desc = ida_kernwin.action_desc_t(None, 'Dynamic popup action', Handler())
        ida_kernwin.attach_dynamic_action_to_popup(form, popup, desc)

    @param unused:       deprecated; should be None
    @param popup_handle: target popup
    @param desc:         action description of type action_desc_t
    @param popuppath:    can be None
    @param flags:        a combination of SETMENU_ constants
    @return: success
    """
    pass

def set_nav_colorizer(callback):
    """
    Set a new colorizer for the navigation band.

    The 'callback' is a function of 2 arguments:
       - ea (the EA to colorize for)
       - nbytes (the number of bytes at that EA)
    and must return a 'long' value.

    The previous colorizer is returned, allowing
    the new 'callback' to use 'call_nav_colorizer'
    with it.

    Note that the previous colorizer is returned
    only the first time set_nav_colorizer() is called:
    due to the way the colorizers API is defined in C,
    it is impossible to chain more than 2 colorizers
    in IDAPython: the original, IDA-provided colorizer,
    and a user-provided one.

    Example: colorizer inverting the color provided by the IDA colorizer:
        def my_colorizer(ea, nbytes):
            global ida_colorizer
            orig = ida_kernwin.call_nav_colorizer(ida_colorizer, ea, nbytes)
            return long(~orig)

        ida_colorizer = ida_kernwin.set_nav_colorizer(my_colorizer)

    @param callback: the new colorizer
    """
    pass

def call_nav_colorizer(colorizer, ea: ida_idaapi.ea_t, nbytes: int):
    """
    To be used with the IDA-provided colorizer, that is
    returned as result of the first call to set_nav_colorizer().

    @param colorizer: the Python colorizer to call
    @param ea: the address to colorize
    @param nbytes: the size of the range to colorize
    """
    pass

def msg(message):
    """
    Display a message in the message window

    @param message: message to print
    """
    pass

def warning(message):
    """
    Display a message in a warning message box

    @param message: message to print
    """
    pass

def error(message):
    """
    Display a fatal message in a message box and quit IDA

    @param format: message to print
    """
    pass

def get_navband_pixel(ea):
    """
    Maps an address, onto a pixel coordinate within the navigation band

    @param ea: The address to map
    @return: a list [pixel, is_vertical]
    """
    pass

def choose_find(title: str) -> Union[object, None]:
    """
    Retrieve the chooser object by title

    @param title the chooser title
    @return the chooser, or None
    """
    pass

class chooser_base_t(object):
    def get_row(self, n: int) -> Tuple[List[str], int, chooser_item_attrs_t]:
        """
        Get data & attributes for a row in a chooser.

        @param n The row number
        @return a tuple (list-of-strings, icon-id, row-attributes)
        """
        pass

def get_chooser_data(title: str, n: int) -> List[str]:
    """
    Get the text corresponding to the index N in the chooser data.
    Use -1 to get the header.

    @param title The chooser title
    @return a list of strings, or None
    """
    pass

def get_registered_actions() -> List[str]:
    """
    Get a list with the names of all currently-registered actions.

    @return the list of action names
    """
    pass

class jobj_wrapper_t(object):
    def get_dict(self) -> dict:
        """
        Retrieve the contents of this object, as a dict

        @return a dict containing all kvp's in this object
        """
        pass

class place_t(object):
    def generate(self, ud, maxsize: int) -> Tuple[List[str], int, int, int]:
        """
        Generate text lines for the current location.

        @param ud The user data object
        @param maxsize The maximum number of lines to generate
        @return a tuple (lines-of-text, default-line-number, prefix-color, background-color)
        """
        pass

def restore_database_snapshot(snapshot, callback, userdata) -> bool:
    """
    Restore a database snapshot.

    Note: This call is asynchronous. When it is completed, the callback will be triggered.

    @param snapshot the snapshot object
    @param callback a callback function
    @param userdata payload to pass to the callback
    @return success
    """
    pass

def take_database_snapshot(snapshot) -> Tuple[bool, str]:
    """
    Take a database snapshot.

    @param snapshot the snapshot object
    @return a tuple (success, error-message)
    """
    pass

def get_custom_viewer_location(*args) -> bool:
    """
    Get information about the current location in a listing

    This function has the following signatures:

        1. get_custom_viewer_location(out_entry: ida_moves.lochist_entry_t, widget: TWidget, mouse: bool=False) -> bool
        2. get_custom_viewer_location(out_entry: ida_kernwin.listing_location_t, widget: TWidget, flags: int=0) -> bool

    The 2nd form is a superset of the 1st, and retrieves
    the text (and tags) of the text.
    """
    pass
