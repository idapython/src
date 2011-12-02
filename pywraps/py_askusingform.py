# --------------------------------------------------------------------------
import os
import gc
import sys

try:
    import _idaapi
    from _idaapi import set_script_timeout
    import idaapi
    from idaapi import py_clinked_object_t
    from idaapi import qstrvec_t
    stdalone = False
except:
    stdalone = True

print("Standalone: %s" % stdalone)

pywraps_there = False

try:
    if stdalone:
        class object_t(object): pass
        class py_clinked_object_t(object): pass
        _idaapi = object_t()
        _idaapi.choose2_get_embedded = lambda obj: (id(obj), 0)
        _idaapi.choose2_get_embedded_selection = lambda obj: None

        _idaapi.textctrl_info_t_set_text = lambda self, v: None
        _idaapi.CHOOSER_POPUP_MENU = 1
        pywraps = object_t()
        pywraps.py_get_AskUsingForm = lambda: 0

        class Choose2(object):
            CH_MULTI = 1
            def __init__(self, title, cols, flags=0, popup_names=None,
                         icon=-1, x1=-1, y1=-1, x2=-1, y2=-1, deflt=-1,
                         embedded=False, width=None, height=None):
                pass

            def Close(self):
                print("Chooser closing...")

            Embedded = lambda self: 1

        set_script_timeout = lambda x: x

    else:
        import pywraps
        pywraps_there = True
        from py_choose2 import *
        py_clinked_object_t = idaapi.py_clinked_object_t
        textctrl_info_t     = idaapi.textctrl_info_t
        qstrvec_t           = idaapi.qstrvec_t

    _idaapi.BADADDR = 0xFFFFFFFF
    _idaapi.MAXSTR  = 1024
    set_script_timeout = _idaapi.set_script_timeout

    if not hasattr(_idaapi, 'formchgcbfa_enable_field'):
        _idaapi.formchgcbfa_enable_field = pywraps.py_formchgcbfa_enable_field

except Exception as e:
   pass
#   print("exception: %s" % str(e))


print("Using PyWraps: %s" % pywraps_there)

# --------------------------------------------------------------------------
#<pycode(py_kernwin)>
#ICON WARNING|QUESTION|INFO|NONE
#AUTOHIDE NONE|DATABASE|REGISTRY|SESSION
#HIDECANCEL
#BUTTON YES|NO|CANCEL "Value|NONE"
#STARTITEM {id:ItemName}
#HELP / ENDHELP
try:
    import types
    from ctypes import *
    # On Windows, we use stdcall

    # Callback for buttons
    # typedef void (idaapi *formcb_t)(TView *fields[], int code);

    _FORMCB_T = WINFUNCTYPE(None, c_void_p, c_int)

    # Callback for form change
    # typedef int (idaapi *formchgcb_t)(int field_id, form_actions_t &fa);
    _FORMCHGCB_T = WINFUNCTYPE(c_int, c_int, c_void_p)
except:
    try:
        _FORMCB_T    = CFUNCTYPE(None, c_void_p, c_int)
        _FORMCHGCB_T = CFUNCTYPE(c_int, c_int, c_void_p)
    except:
        _FORMCHGCB_T = _FORMCB_T = None


# -----------------------------------------------------------------------
# textctrl_info_t clinked object
class textctrl_info_t(py_clinked_object_t):
    """Class representing textctrl_info_t"""

    # Some constants
    TXTF_AUTOINDENT = 0x0001
    """Auto-indent on new line"""
    TXTF_ACCEPTTABS = 0x0002
    """Tab key inserts 'tabsize' spaces"""
    TXTF_READONLY   = 0x0004
    """Text cannot be edited (but can be selected and copied)"""
    TXTF_SELECTED   = 0x0008
    """Shows the field with its text selected"""
    TXTF_MODIFIED   = 0x0010
    """Gets/sets the modified status"""
    TXTF_FIXEDFONT  = 0x0020
    """The control uses IDA's fixed font"""

    def __init__(self, text="", flags=0, tabsize=0):
        py_clinked_object_t.__init__(self)
        if text:
            self.text = text
        if flags:
            self.flags = flags
        if tabsize:
            self.tabsize = tabsize

    def _create_clink(self):
        return _idaapi.textctrl_info_t_create()

    def _del_clink(self, lnk):
        return _idaapi.textctrl_info_t_destroy(lnk)

    def _get_clink_ptr(self):
        return _idaapi.textctrl_info_t_get_clink_ptr(self)

    def assign(self, other):
        """Copies the contents of 'other' to 'self'"""
        return _idaapi.textctrl_info_t_assign(self, other)

    def __set_text(self, s):
        """Sets the text value"""
        return _idaapi.textctrl_info_t_set_text(self, s)

    def __get_text(self):
        """Sets the text value"""
        return _idaapi.textctrl_info_t_get_text(self)

    def __set_flags__(self, flags):
        """Sets the flags value"""
        return _idaapi.textctrl_info_t_set_flags(self, flags)

    def __get_flags__(self):
        """Returns the flags value"""
        return _idaapi.textctrl_info_t_get_flags(self)

    def __set_tabsize__(self, tabsize):
        """Sets the tabsize value"""
        return _idaapi.textctrl_info_t_set_tabsize(self, tabsize)

    def __get_tabsize__(self):
        """Returns the tabsize value"""
        return _idaapi.textctrl_info_t_get_tabsize(self)

    value   = property(__get_text, __set_text)
    """Alias for the text property"""
    text    = property(__get_text, __set_text)
    """Text value"""
    flags   = property(__get_flags__, __set_flags__)
    """Flags value"""
    tabsize = property(__get_tabsize__, __set_tabsize__)

# -----------------------------------------------------------------------
class Form(object):

    FT_ASCII = 'A'
    """Ascii string - char *"""
    FT_SEG = 'S'
    """Segment - sel_t *"""
    FT_HEX = 'N'
    """Hex number - uval_t *"""
    FT_SHEX = 'n'
    """Signed hex number - sval_t *"""
    FT_COLOR = 'K'
    """Color button - bgcolor_t *"""
    FT_ADDR = '$'
    """Address - ea_t *"""
    FT_UINT64 = 'L'
    """default base uint64 - uint64"""
    FT_INT64 = 'l'
    """default base int64 - int64"""
    FT_RAWHEX = 'M'
    """Hex number, no 0x prefix - uval_t *"""
    FT_FILE = 'f'
    """File browse - char * at least QMAXPATH"""
    FT_DEC = 'D'
    """Decimal number - sval_t *"""
    FT_OCT = 'O'
    """Octal number, C notation - sval_t *"""
    FT_BIN = 'Y'
    """Binary number, 0b prefix - sval_t *"""
    FT_CHAR = 'H'
    """Char value -- sval_t *"""
    FT_IDENT = 'I'
    """Identifier - char * at least MAXNAMELEN"""
    FT_BUTTON = 'B'
    """Button - def handler(code)"""
    FT_DIR = 'F'
    """Path to directory - char * at least QMAXPATH"""
    FT_TYPE = 'T'
    """Type declaration - char * at least MAXSTR"""
    _FT_USHORT = '_US'
    """Unsigned short"""
    FT_FORMCHG = '%/'
    """Form change callback - formchgcb_t"""
    FT_ECHOOSER = 'E'
    """Embedded chooser - idaapi.Choose2"""
    FT_MULTI_LINE_TEXT = 't'
    """Multi text control - textctrl_info_t"""
    FT_DROPDOWN_LIST   = 'b'
    """Dropdown list control - Form.DropdownControl"""

    FT_CHKGRP = 'C'
    FT_CHKGRP2= 'c'
    FT_RADGRP = 'R'
    FT_RADGRP2= 'r'

    @staticmethod
    def fieldtype_to_ctype(tp, i64 = False):
        """
        Factory method returning a ctype class corresponding to the field type string
        """
        if tp in (Form.FT_SEG, Form.FT_HEX, Form.FT_RAWHEX, Form.FT_ADDR):
            return c_ulonglong if i64 else c_ulong
        elif tp in (Form.FT_SHEX, Form.FT_DEC, Form.FT_OCT, Form.FT_BIN, Form.FT_CHAR):
            return c_longlong if i64 else c_long
        elif tp == Form.FT_UINT64:
            return c_ulonglong
        elif tp == Form.FT_INT64:
            return c_longlong
        elif tp == Form.FT_COLOR:
            return c_ulong
        elif tp == Form._FT_USHORT:
            return c_ushort
        elif tp in (Form.FT_FORMCHG, Form.FT_ECHOOSER):
            return c_void_p
        else:
            return None


    #
    # Generic argument helper classes
    #
    class NumericArgument(object):
        """
        Argument representing various integer arguments (ushort, uint32, uint64, etc...)
        @param tp: One of Form.FT_XXX
        """
        DefI64 = False
        def __init__(self, tp, value):
            cls = Form.fieldtype_to_ctype(tp, self.DefI64)
            if cls is None:
                raise TypeError("Invalid numeric field type: %s" % tp)
            # Get a pointer type to the ctype type
            self.arg = pointer(cls(value))

        def __set_value(self, v):
            self.arg.contents.value = v
        value = property(lambda self: self.arg.contents.value, __set_value)


    class StringArgument(object):
        """
        Argument representing a character buffer
        """
        def __init__(self, size=None, value=None):
            if size is None:
                raise SyntaxError("The string size must be passed")

            if value is None:
                self.arg = create_string_buffer(size)
            else:
                self.arg = create_string_buffer(value, size)
            self.size = size

        def __set_value(self, v):
            self.arg.value = v
        value = property(lambda self: self.arg.value, __set_value)


    #
    # Base control class
    #
    class Control(object):
        def __init__(self):
            self.id = 0
            """Automatically assigned control ID"""

            self.arg = None
            """Control argument value. This could be one element or a list/tuple (for multiple args per control)"""

            self.form = None
            """Reference to the parent form. It is filled by Form.Add()"""


        def get_tag(self):
            """
            Control tag character. One of Form.FT_XXXX.
            The form class will expand the {} notation and replace them with the tags
            """
            pass

        def get_arg(self):
            """
            Control returns the parameter to be pushed on the stack
            (Of AskUsingForm())
            """
            return self.arg

        def free(self):
            """
            Free the control
            """
            # Release the parent form reference
            self.form = None


    #
    # Label controls
    #
    class LabelControl(Control):
        """
        Base class for static label control
        """
        def __init__(self, tp):
            Form.Control.__init__(self)
            self.tp = tp

        def get_tag(self):
            return '%%%d%s' % (self.id, self.tp)


    class StringLabel(LabelControl):
        """
        String label control
        """
        def __init__(self, value, tp=None, sz=1024):
            """
            Type field can be one of:
            A - ascii string
            T - type declaration
            I - ident
            F - folder
            f - file
            X - command
            """
            if tp is None:
                tp = Form.FT_ASCII
            Form.LabelControl.__init__(self, tp)
            self.size  = sz
            self.arg = create_string_buffer(value, sz)


    class NumericLabel(LabelControl, NumericArgument):
        """
        Numeric label control
        """
        def __init__(self, value, tp=None):
            if tp is None:
                tp = Form.FT_HEX
            Form.LabelControl.__init__(self, tp)
            Form.NumericArgument.__init__(self, tp, value)


    #
    # Group controls
    #
    class GroupItemControl(Control):
        """
        Base class for group control items
        """
        def __init__(self, tag, parent):
            Form.Control.__init__(self)
            self.tag = tag
            self.parent = parent
            # Item position (filled when form is compiled)
            self.pos = 0

        def assign_pos(self):
            self.pos = self.parent.next_child_pos()

        def get_tag(self):
            return "%s%d" % (self.tag, self.id)


    class ChkGroupItemControl(GroupItemControl):
        """
        Checkbox group item control
        """
        def __init__(self, tag, parent):
            Form.GroupItemControl.__init__(self, tag, parent)

        def __get_value(self):
            return (self.parent.value & (1 << self.pos)) != 0

        def __set_value(self, v):
            pv = self.parent.value
            if v:
                pv = pv | (1 << self.pos)
            else:
                pv = pv & ~(1 << self.pos)

            self.parent.value = pv

        checked = property(__get_value, __set_value)
        """Get/Sets checkbox item check status"""


    class RadGroupItemControl(GroupItemControl):
        """
        Radiobox group item control
        """
        def __init__(self, tag, parent):
            Form.GroupItemControl.__init__(self, tag, parent)

        def __get_value(self):
            return self.parent.value == self.pos

        def __set_value(self, v):
            self.parent.value = self.pos

        selected = property(__get_value, __set_value)
        """Get/Sets radiobox item selection status"""


    class GroupControl(Control, NumericArgument):
        """
        Base class for group controls
        """
        def __init__(self, children_names, tag, value=0):
            Form.Control.__init__(self)
            self.children_names = children_names
            self.tag = tag
            self._reset()
            Form.NumericArgument.__init__(self, Form._FT_USHORT, value)

        def _reset(self):
            self.childpos = 0

        def next_child_pos(self):
            v = self.childpos
            self.childpos += 1
            return v

        def get_tag(self):
            return "%d" % self.id


    class ChkGroupControl(GroupControl):
        """
        Checkbox group control class.
        It holds a set of checkbox controls
        """
        ItemClass = None
        """
        Group control item factory class instance
        We need this because later we won't be treating ChkGroupControl or RadGroupControl
        individually, instead we will be working with GroupControl in general.
        """
        def __init__(self, children_names, value=0, secondary=False):
            # Assign group item factory class
            if Form.ChkGroupControl.ItemClass is None:
                Form.ChkGroupControl.ItemClass = Form.ChkGroupItemControl

            Form.GroupControl.__init__(
                self,
                children_names,
                Form.FT_CHKGRP2 if secondary else Form.FT_CHKGRP,
                value)


    class RadGroupControl(GroupControl):
        """
        Radiobox group control class.
        It holds a set of radiobox controls
        """
        ItemClass = None
        def __init__(self, children_names, value=0, secondary=False):
            """
            Creates a radiogroup control.
            @param children_names: A tuple containing group item names
            @param value: Initial selected radio item
            @param secondory: Allows rendering one the same line as the previous group control.
                              Use this if you have another group control on the same line.
            """
            # Assign group item factory class
            if Form.RadGroupControl.ItemClass is None:
                Form.RadGroupControl.ItemClass = Form.RadGroupItemControl

            Form.GroupControl.__init__(
                self,
                children_names,
                Form.FT_RADGRP2 if secondary else Form.FT_RADGRP,
                value)


    #
    # Input controls
    #
    class InputControl(Control):
        """
        Generic form input control.
        It could be numeric control, string control, directory/file browsing, etc...
        """
        def __init__(self, tp, width, swidth, hlp = None):
            """
            @param width: Display width
            @param swidth: String width
            """
            Form.Control.__init__(self)
            self.tp = tp
            self.width = width
            self.switdh = swidth
            self.hlp = hlp

        def get_tag(self):
            return "%s%d:%s:%s:%s" % (
                self.tp, self.id,
                self.width,
                self.switdh,
                ":" if self.hlp is None else self.hlp)


    class NumericInput(InputControl, NumericArgument):
        """
        A composite class serving as a base numeric input control class
        """
        def __init__(self, tp=None, value=0, width=50, swidth=10, hlp=None):
            if tp is None:
                tp = Form.FT_HEX
            Form.InputControl.__init__(self, tp, width, swidth, hlp)
            Form.NumericArgument.__init__(self, self.tp, value)


    class ColorInput(NumericInput):
        """
        Color button input control
        """
        def __init__(self, value = 0):
            """
            @param value: Initial color value in RGB
            """
            Form.NumericInput.__init__(self, tp=Form.FT_COLOR, value=value)


    class StringInput(InputControl, StringArgument):
        """
        Base string input control class.
        This class also constructs a StringArgument
        """
        def __init__(self,
                     tp=None,
                     width=1024,
                     swidth=40,
                     hlp=None,
                     value=None,
                     size=None):
            """
            @param width: String size. But in some cases it has special meaning. For example in FileInput control.
                          If you want to define the string buffer size then pass the 'size' argument
            @param swidth: Control width
            @param value: Initial value
            @param size: String size
            """
            if tp is None:
                tp = Form.FT_ASCII
            if not size:
                size = width
            Form.InputControl.__init__(self, tp, width, swidth, hlp)
            Form.StringArgument.__init__(self, size=size, value=value)


    class FileInput(StringInput):
        """
        File Open/Save input control
        """
        def __init__(self,
                     width=512,
                     swidth=80,
                     save=False, open=False,
                     hlp=None, value=None):

            if save == open:
                raise ValueError("Invalid mode. Choose either open or save")
            if width < 512:
                raise ValueError("Invalid width. Must be greater than 512.")

            # The width field is overloaded in this control and is used
            # to denote the type of the FileInput dialog (save or load)
            # On the other hand it is passed as is to the StringArgument part
            Form.StringInput.__init__(
                self,
                tp=Form.FT_FILE,
                width="1" if save else "0",
                swidth=swidth,
                hlp=hlp,
                size=width,
                value=value)


    class DirInput(StringInput):
        """
        Directory browsing control
        """
        def __init__(self,
                     width=512,
                     swidth=80,
                     hlp=None,
                     value=None):

            if width < 512:
                raise ValueError("Invalid width. Must be greater than 512.")

            Form.StringInput.__init__(
                self,
                tp=Form.FT_DIR,
                width=width,
                swidth=swidth,
                hlp=hlp,
                size=width,
                value=value)


    class ButtonInput(InputControl):
        """
        Button control.
        A handler along with a 'code' (numeric value) can be associated with the button.
        This way one handler can handle many buttons based on the button code (or in other terms id or tag)
        """
        def __init__(self, handler, code="", swidth="", hlp=None):
            """
            @param handler: Button handler. A callback taking one argument which is the code.
            @param code: A code associated with the button and that is later passed to the handler.
            """
            Form.InputControl.__init__(
                self,
                Form.FT_BUTTON,
                code,
                swidth,
                hlp)
            self.arg = _FORMCB_T(lambda view, code, h=handler: h(code))


    class FormChangeCb(Control):
        """
        Form change handler.
        This can be thought of like a dialog procedure.
        Everytime a form action occurs, this handler will be called along with the control id.
        The programmer can then call various form actions accordingly:
          - EnableField
          - ShowField
          - MoveField
          - GetFieldValue
          - etc...

        Special control IDs: -1 (The form is initialized) and -2 (Ok has been clicked)

        """
        def __init__(self, handler):
            """
            Constructs the handler.
            @param handler: The handler (preferrably a member function of a class derived from the Form class).
            """
            Form.Control.__init__(self)

            # Save the handler
            self.handler = handler

            # Create a callback stub
            # We use this mechanism to create an intermediate step
            # where we can create an 'fa' adapter for use by Python
            self.arg = _FORMCHGCB_T(self.helper_cb)

        def helper_cb(self, fid, p_fa):
            # Remember the pointer to the forms_action in the parent form
            self.form.p_fa = p_fa

            # Call user's handler
            r = self.handler(fid)
            return 0 if r is None else r

        def get_tag(self):
            return Form.FT_FORMCHG

        def free(self):
            Form.Control.free(self)
            # Remove reference to the handler
            # (Normally the handler is a member function in the parent form)
            self.handler = None


    class EmbeddedChooserControl(InputControl):
        """
        Embedded chooser control.
        This control links to a Chooser2 control created with the 'embedded=True'
        """
        def __init__(self,
                     chooser=None,
                     swidth=40,
                     hlp=None):
            """
            Embedded chooser control

            @param chooser: A chooser2 instance (must be constructed with 'embedded=True')
            """

            # !! Make sure a chooser instance is passed !!
            if chooser is None or not isinstance(chooser, Choose2):
                raise ValueError("Invalid chooser passed.")

            # Create an embedded chooser structure from the Choose2 instance
            if chooser.Embedded() != 1:
                raise ValueError("Failed to create embedded chooser instance.")

            # Construct input control
            Form.InputControl.__init__(self, Form.FT_ECHOOSER, "", swidth)

            # Get a pointer to the chooser_info_t and the selection vector
            # (These two parameters are the needed arguments for the AskUsingForm())
            emb, sel = _idaapi.choose2_get_embedded(chooser)

            # Get a pointer to a c_void_p constructed from an address
            p_embedded = pointer(c_void_p.from_address(emb))
            p_sel      = pointer(c_void_p.from_address(sel))

            # - Create the embedded chooser info on control creation
            # - Do not free the embeded chooser because after we get the args
            #   via Compile() the user can still call Execute() which relies
            #   on the already computed args
            self.arg   = (p_embedded, p_sel)

            # Save chooser instance
            self.chooser = chooser

            # Add a bogus 'size' attribute
            self.size = 0


        value = property(lambda self: self.chooser)
        """Returns the embedded chooser instance"""


        def AddCommand(self,
                       caption,
                       flags = _idaapi.CHOOSER_POPUP_MENU,
                       menu_index = -1,
                       icon = -1):
            """
            Adds a new embedded chooser command
            Save the returned value and later use it in the OnCommand handler

            @return: Returns a negative value on failure or the command index
            """
            if not self.form.title:
                raise ValueError("Form title is not set!")

            # Encode all information for the AddCommand() in the 'caption' parameter
            caption = "%s:%d:%s" % (self.form.title, self.id, caption)
            return self.chooser.AddCommand(caption, flags=flags, menu_index=menu_index, icon=icon, emb=2002)


        def free(self):
            """
            Frees the embedded chooser data
            """
            self.chooser.Close()
            self.chooser = None
            Form.Control.free(self)


    class DropdownListControl(InputControl, qstrvec_t):
        """
        Dropdown control
        This control allows manipulating a dropdown control
        """
        def __init__(self, items=[], readonly=True, selval=0, width=50, swidth=50, hlp = None):
            """
            @param items: A string list of items used to prepopulate the control
            @param readonly: Specifies whether the dropdown list is editable or not
            @param selval: The preselected item index (when readonly) or text value (when editable)
            @param width: the control width (n/a if the dropdown list is readonly)
            @param swidth: string width
            """

            # Ignore the width if readonly was set
            if readonly:
                width = 0

            # Init the input control base class
            Form.InputControl.__init__(
                self,
                Form.FT_DROPDOWN_LIST,
                width,
                swidth,
                hlp)

            # Init the associated qstrvec
            qstrvec_t.__init__(self, items)

            # Remember if readonly or not
            self.readonly = readonly

            if readonly:
                # Create a C integer and remember it
                self.__selval = c_int(selval)
                val_addr      = addressof(self.__selval)
            else:
                # Create an strvec with one qstring
                self.__selval = qstrvec_t([selval])
                # Get address of the first element
                val_addr      = self.__selval.addressof(0)

            # Two arguments:
            # - argument #1: a pointer to the qstrvec containing the items
            # - argument #2: an integer to hold the selection
            #         or
            #            #2: a qstring to hold the dropdown text control value
            self.arg = (
                pointer(c_void_p.from_address(self.clink_ptr)),
                pointer(c_void_p.from_address(val_addr))
            )


        def __set_selval(self, val):
            if self.readonly:
                self.__selval.value = val
            else:
                self.__selval[0] = val

        def __get_selval(self):
            # Return the selection index
            # or the entered text value
            return self.__selval.value if self.readonly else self.__selval[0]

        value  = property(__get_selval, __set_selval)
        selval = property(__get_selval, __set_selval)
        """
        Read/write the selection value.
        The value is used as an item index in readonly mode or text value in editable mode
        This value can be used only after the form has been closed.
        """

        def free(self):
            self._free()


        def set_items(self, items):
            """Sets the dropdown list items"""
            self.from_list(items)


    class MultiLineTextControl(InputControl, textctrl_info_t):
        """
        Multi line text control.
        This class inherits from textctrl_info_t. Thus the attributes are also inherited
        This control allows manipulating a multilinetext control
        """
        def __init__(self, text="", flags=0, tabsize=0, width=50, swidth=50, hlp = None):
            """
            @param text: Initial text value
            @param flags: One of textctrl_info_t.TXTF_.... values
            @param tabsize: Tab size
            @param width: Display width
            @param swidth: String width
            """
            # Init the input control base class
            Form.InputControl.__init__(self, Form.FT_MULTI_LINE_TEXT, width, swidth, hlp)

            # Init the associated textctrl_info base class
            textctrl_info_t.__init__(self, text=text, flags=flags, tabsize=tabsize)

            # Get the argument as a pointer from the embedded ti
            self.arg = pointer(c_void_p.from_address(self.clink_ptr))


        def free(self):
            self._free()


    #
    # Form class
    #
    def __init__(self, form, controls):
        """
        Contruct a Form class.
        This class wraps around AskUsingForm() and provides an easier / alternative syntax for describing forms.
        The form control names are wrapped inside the opening and closing curly braces and the control themselves are
        defined and instantiated via various form controls (subclasses of Form).

        @param form: The form string
        @param controls: A dictionary containing the control name as a _key_ and control object as _value_
        """
        self._reset()
        self.form = form
        """Form string"""
        self.controls = controls
        """Dictionary of controls"""
        self.__args = None

        self.title = None
        """The Form title. It will be filled when the form is compiled"""


    def Free(self):
        """
        Frees all resources associated with a compiled form.
        Make sure you call this function when you finish using the form.
        """

        # Free all the controls
        for ctrl in self.__controls.values():
             ctrl.free()

        # Reset the controls
        # (Note that we are not removing the form control attributes, no need)
        self._reset()


    def _reset(self):
        """
        Resets the Form class state variables
        """
        self.__controls = {}
        self.__ctrl_id = 1


    def __getitem__(self, name):
        """Returns a control object by name"""
        return self.__controls[name]


    def Add(self, name, ctrl, mkattr = True):
        """
        Low level function. Prefer AddControls() to this function.
        This function adds one control to the form.

        @param name: Control name
        @param ctrl: Control object
        @param mkattr: Create control name / control object as a form attribute
        """
        # Assign a unique ID
        ctrl.id = self.__ctrl_id
        self.__ctrl_id += 1

        # Create attribute with control name
        if mkattr:
            setattr(self, name, ctrl)

        # Remember the control
        self.__controls[name] = ctrl

        # Link the form to the control via its form attribute
        ctrl.form = self

        # Is it a group? Add each child
        if isinstance(ctrl, Form.GroupControl):
            self._AddGroup(ctrl, mkattr)


    def FindControlById(self, id):
        """
        Finds a control instance given its id
        """
        for ctrl in self.__controls.values():
            if ctrl.id == id:
                return ctrl
        return None


    @staticmethod
    def _ParseFormTitle(form):
        """
        Parses the form's title from the form text
        """
        help_state = 0
        for i, line in enumerate(form.split("\n")):
            if line.startswith("STARTITEM ") or line.startswith("BUTTON "):
                continue
            # Skip "HELP" and remember state
            elif help_state == 0 and line == "HELP":
                help_state = 1 # Mark inside HELP
                continue
            elif help_state == 1 and line == "ENDHELP":
                help_state = 2 # Mark end of HELP
                continue
            return line.strip()

        return None


    def _AddGroup(self, Group, mkattr=True):
        """
        Internal function.
        This function expands the group item names and creates individual group item controls

        @param Group: The group class (checkbox or radio group class)
        """

        # Create group item controls for each child
        for child_name in Group.children_names:
            self.Add(
                child_name,
                # Use the class factory
                Group.ItemClass(Group.tag, Group),
                mkattr)


    def AddControls(self, controls, mkattr=True):
        """
        Adds controls from a dictionary.
        The dictionary key is the control name and the value is a Form.Control object
        @param controls: The control dictionary
        """
        for name, ctrl in controls.items():
            # Add the control
            self.Add(name, ctrl, mkattr)


    def CompileEx(self, form):
        """
        Low level function.
        Compiles (parses the form syntax and adds the control) the form string and
        returns the argument list to be passed the argument list to AskUsingForm().

        The form controls are wrapped inside curly braces: {ControlName}.

        A special operator can be used to return the ID of a given control by its name: {id:ControlName}.
        This is useful when you use the STARTITEM form keyword to set the initially focused control.

        @param form: Compiles the form and returns the arguments needed to be passed to AskUsingForm()
        """
        # First argument is the form string
        args = [None]
        ctrlcnt = 1

        # Reset all group control internal flags
        for ctrl in self.__controls.values():
            if isinstance(ctrl, Form.GroupControl):
                ctrl._reset()

        p = 0
        while True:
            i1 = form.find("{", p)
            # No more items?
            if i1 == -1:
                break

            # Check if escaped
            if (i1 != 0) and form[i1-1] == "\\":
                # Remove escape sequence and restart search
                form = form[:i1-1] + form[i1:]

                # Skip current marker
                p = i1

                # Continue search
                continue

            i2 = form.find("}", i1)
            if i2 == -1:
                raise SyntaxError("No matching closing brace '}'")

            # Parse control name
            ctrlname = form[i1+1:i2]
            if not ctrlname:
                raise ValueError("Control %d has an invalid name!" % ctrlcnt)

            # Is it the IDOF operator?
            if ctrlname.startswith("id:"):
                idfunc = True
                # Take actual ctrlname
                ctrlname = ctrlname[3:]
            else:
                idfunc = False

            # Find the control
            ctrl = self.__controls.get(ctrlname, None)
            if ctrl is None:
                raise ValueError("No matching control '%s'" % ctrlname)

            # Replace control name by tag
            if idfunc:
                tag = str(ctrl.id)
            else:
                tag = ctrl.get_tag()
            taglen = len(tag)
            form = form[:i1] + tag + form[i2+1:]

            # Set new position
            p = i1 + taglen

            # Was it an IDOF() ? No need to push parameters
            # Just ID substitution is fine
            if idfunc:
                continue


            # For GroupItem controls, there are no individual arguments
            # The argument is assigned for the group itself
            if isinstance(ctrl, Form.GroupItemControl):
                # GroupItem controls will have their position dynamically set
                ctrl.assign_pos()
            else:
                # Push argument(s)
                # (Some controls need more than one argument)
                arg = ctrl.get_arg()
                if isinstance(arg, (types.ListType, types.TupleType)):
                    # Push all args
                    args.extend(arg)
                else:
                    # Push one arg
                    args.append(arg)

            ctrlcnt += 1

        # Patch in the final form string
        args[0] = form

        self.title = self._ParseFormTitle(form)
        return args


    def Compile(self):
        """
        Compiles a form and returns the form object (self) and the argument list.
        The form object will contain object names corresponding to the form elements

        @return: It will raise an exception on failure. Otherwise the return value is ignored
        """

        # Reset controls
        self._reset()

        # Insert controls
        self.AddControls(self.controls)

        # Compile form and get args
        self.__args = self.CompileEx(self.form)

        return (self, self.__args)


    def Compiled(self):
        """
        Checks if the form has already been compiled

        @return: Boolean
        """
        return self.__args is not None


    def Execute(self):
        """
        Displays a compiled form.
        @return: 1 - ok ; 0 - cancel
        """
        if not self.Compiled():
            raise SyntaxError("Form is not compiled")

        # Call AskUsingForm()
        return AskUsingForm(*self.__args)


    def EnableField(self, ctrl, enable):
        """
        Enable or disable an input field
        @return: False - no such control
        """
        return _idaapi.formchgcbfa_enable_field(self.p_fa, ctrl.id, enable)


    def ShowField(self, ctrl, show):
        """
        Show or hide an input field
        @return: False - no such control
        """
        return _idaapi.formchgcbfa_show_field(self.p_fa, ctrl.id, show)


    def MoveField(self, ctrl, x, y, w, h):
        """
        Move/resize an input field

        @return: False - no such fiel
        """
        return _idaapi.formchgcbfa_move_field(self.p_fa, ctrl.id, x, y, w, h)


    def GetFocusedField(self):
        """
        Get currently focused input field.
        @return: None if no field is selected otherwise the control ID
        """
        id = _idaapi.formchgcbfa_get_focused_field(self.p_fa)
        return self.FindControlById(id)


    def SetFocusedField(self, ctrl):
        """
        Set currently focused input field
        @return: False - no such control
        """
        return _idaapi.formchgcbfa_set_focused_field(self.p_fa, ctrl.id)


    def RefreshField(self, ctrl):
        """
        Refresh a field
        @return: False - no such control
        """
        return _idaapi.formchgcbfa_refresh_field(self.p_fa, ctrl.id)


    def Close(self, close_normally):
        """
        Close the form
        @param close_normally:
                   1: form is closed normally as if the user pressed Enter
                   0: form is closed abnormally as if the user pressed Esc
        @return: None
        """
        return _idaapi.formchgcbfa_close(self.p_fa, close_normally)


    def GetControlValue(self, ctrl):
        """
        Returns the control's value depending on its type
        @param ctrl: Form control instance
        @return:
            - color button, radio controls: integer
            - file/dir input, string input and string label: string
            - embedded chooser control (0-based indices of selected items): integer list
            - for multilinetext control: textctrl_info_t
            - dropdown list controls: string (when editable) or index (when readonly)
            - None: on failure
        """
        tid, sz = self.ControlToFieldTypeIdAndSize(ctrl)
        r = _idaapi.formchgcbfa_get_field_value(
                    self.p_fa,
                    ctrl.id,
                    tid,
                    sz)
        # Multilinetext? Unpack the tuple into a new textctrl_info_t instance
        if r is not None and tid == 7:
            return textctrl_info_t(text=r[0], flags=r[1], tabsize=r[2])
        else:
            return r


    def SetControlValue(self, ctrl, value):
        """
        Set the control's value depending on its type
        @param ctrl: Form control instance
        @param value:
            - embedded chooser: a 0-base indices list to select embedded chooser items
            - multilinetext: a textctrl_info_t
            - dropdown list: an integer designating the selection index if readonly
                             a string designating the edit control value if not readonly
        @return: Boolean true on success
        """
        tid, _ = self.ControlToFieldTypeIdAndSize(ctrl)
        return _idaapi.formchgcbfa_set_field_value(
                    self.p_fa,
                    ctrl.id,
                    tid,
                    value)


    @staticmethod
    def ControlToFieldTypeIdAndSize(ctrl):
        """
        Converts a control object to a tuple containing the field id
        and the associated buffer size
        """
        # Input control depend on the associated buffer size (supplied by the user)

        # Make sure you check instances types taking into account inheritance
        if isinstance(ctrl, Form.DropdownListControl):
            return (8, 1 if ctrl.readonly else 0)
        elif isinstance(ctrl, Form.MultiLineTextControl):
            return (7, 0)
        elif isinstance(ctrl, Form.EmbeddedChooserControl):
            return (5, 0)
        # Group items or controls
        elif isinstance(ctrl, (Form.GroupItemControl, Form.GroupControl)):
            return (2, 0)
        elif isinstance(ctrl, Form.StringLabel):
            return (3, min(_idaapi.MAXSTR, ctrl.size))
        elif isinstance(ctrl, Form.ColorInput):
            return (4, 0)
        elif isinstance(ctrl, Form.NumericInput):
            # Pass the numeric control type
            return (6, ord(ctrl.tp[0]))
        elif isinstance(ctrl, Form.InputControl):
            return (1, ctrl.size)
        else:
            raise NotImplementedError, "Not yet implemented"

# --------------------------------------------------------------------------
# Instantiate AskUsingForm function pointer
try:
    import ctypes
    # Setup the numeric argument size
    Form.NumericArgument.DefI64 = _idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL
    AskUsingForm__ = ctypes.CFUNCTYPE(ctypes.c_long)(_idaapi.py_get_AskUsingForm())
except:
    def AskUsingForm__(*args):
        warning("AskUsingForm() needs ctypes library in order to work")
        return 0


def AskUsingForm(*args):
    """
    Calls the AskUsingForm()
    @param: Compiled Arguments obtain through the Form.Compile() function
    @return: 1 = ok, 0 = cancel
    """
    old = set_script_timeout(0)
    r = AskUsingForm__(*args)
    set_script_timeout(old)
    return r


#</pycode(py_kernwin)>

#<pycode(ex_askusingform)>
# --------------------------------------------------------------------------
class TestEmbeddedChooserClass(Choose2):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, nb = 5, flags=0):
        Choose2.__init__(self,
                         title,
                         [ ["Address", 10], ["Name", 30] ],
                         embedded=True, width=30, height=20, flags=flags)
        self.n = 0
        self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.icon = 5
        self.selcount = 0

    def make_item(self):
        r = [str(self.n), "func_%04d" % self.n]
        self.n += 1
        return r

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        print("getsize -> %d" % n)
        return n

# --------------------------------------------------------------------------
class MyForm(Form):
    def __init__(self):
        self.invert = False
        self.EChooser = TestEmbeddedChooserClass("E1", flags=Choose2.CH_MULTI)
        Form.__init__(self, r"""STARTITEM {id:rNormal}
BUTTON YES* Yeah
BUTTON NO Nope
BUTTON CANCEL Nevermind
Form Test

{FormChangeCb}
This is a string: +{cStr1}+
This is an address: +{cAddr1}+

Escape\{control}
This is a string: '{cStr2}'
This is a number: {cVal1}

<#Hint1#Enter name:{iStr1}>
<#Hint2#Select color:{iColor1}>
Browse test
<#Select a file to open#Browse to open:{iFileOpen}>
<#Select a file to save#Browse to save:{iFileSave}>
<#Select dir#Browse for dir:{iDir}>
Type
<#Select type#Write a type:{iType}>
Numbers
<##Enter a selector value:{iSegment}>
<##Enter a raw hex:{iRawHex}>
<##Enter a character:{iChar}>
<##Enter an address:{iAddr}>
Button test
<##Button1:{iButton1}> <##Button2:{iButton2}>

Check boxes:
<Error output:{rError}>
<Normal output:{rNormal}>
<Warnings:{rWarnings}>{cGroup1}>

Radio boxes:
<Green:{rGreen}>
<Red:{rRed}>
<Blue:{rBlue}>{cGroup2}>
<Embedded chooser:{cEChooser}>
The end!
""", {
            'cStr1': Form.StringLabel("Hello"),
            'cStr2': Form.StringLabel("StringTest"),
            'cAddr1': Form.NumericLabel(0x401000, Form.FT_ADDR),
            'cVal1' : Form.NumericLabel(99, Form.FT_HEX),
            'iStr1': Form.StringInput(),
            'iColor1': Form.ColorInput(),
            'iFileOpen': Form.FileInput(open=True),
            'iFileSave': Form.FileInput(save=True),
            'iDir': Form.DirInput(),
            'iType': Form.StringInput(tp=Form.FT_TYPE),
            'iSegment': Form.NumericInput(tp=Form.FT_SEG),
            'iRawHex': Form.NumericInput(tp=Form.FT_RAWHEX),
            'iAddr': Form.NumericInput(tp=Form.FT_ADDR),
            'iChar': Form.NumericInput(tp=Form.FT_CHAR),
            'iButton1': Form.ButtonInput(self.OnButton1),
            'iButton2': Form.ButtonInput(self.OnButton2),
            'cGroup1': Form.ChkGroupControl(("rNormal", "rError", "rWarnings")),
            'cGroup2': Form.RadGroupControl(("rRed", "rGreen", "rBlue")),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            'cEChooser' : Form.EmbeddedChooserControl(self.EChooser)
        })


    def OnButton1(self, code=0):
        print("Button1 pressed")


    def OnButton2(self, code=0):
        print("Button2 pressed")


    def OnFormChange(self, fid):
        if fid == self.iButton1.id:
            print("Button1 fchg;inv=%s" % self.invert)
            self.SetFocusedField(self.rNormal)
            self.EnableField(self.rError, self.invert)
            self.invert = not self.invert
        elif fid == self.iButton2.id:
            g1 = self.GetControlValue(self.cGroup1)
            g2 = self.GetControlValue(self.cGroup2)
            d = self.GetControlValue(self.iDir)
            f = self.GetControlValue(self.iFileOpen)
            print("cGroup2:%x;Dir=%s;fopen=%s;cGroup1:%x" % (g1, d, f, g2))
        elif fid == self.cEChooser.id:
            l = self.GetControlValue(self.cEChooser)
            print("Chooser: %s" % l)
        else:
            print(">>fid:%d" % fid)
        return 1



# --------------------------------------------------------------------------
def stdalone_main():
    f = MyForm()
    f, args = f.Compile()
    print args[0]
    print args[1:]
    f.rNormal.checked = True
    f.rWarnings.checked = True
    print hex(f.cGroup1.value)

    f.rGreen.selected = True
    print f.cGroup2.value
    print "Title: '%s'" % f.title

    f.Free()

# --------------------------------------------------------------------------
def ida_main():
    # Create form
    global f
    f = MyForm()

    # Compile (in order to populate the controls)
    f.Compile()

    f.iColor1.value = 0x5bffff
    f.iDir.value = os.getcwd()
    f.rNormal.checked = True
    f.rWarnings.checked = True
    f.rGreen.selected = True
    f.iStr1.value = "Hello"
    f.iFileSave.value = "*.*"
    f.iFileOpen.value = "*.*"
    # Execute the form
    ok = f.Execute()
    print("r=%d" % ok)
    if ok == 1:
        print("f.str1=%s" % f.iStr1.value)
        print("f.color1=%x" % f.iColor1.value)
        print("f.openfile=%s" % f.iFileOpen.value)
        print("f.savefile=%s" % f.iFileSave.value)
        print("f.dir=%s" % f.iDir.value)
        print("f.type=%s" % f.iType.value)
        print("f.seg=%s" % f.iSegment.value)
        print("f.rawhex=%x" % f.iRawHex.value)
        print("f.char=%x" % f.iChar.value)
        print("f.addr=%x" % f.iAddr.value)
        print("f.cGroup1=%x" % f.cGroup1.value)
        print("f.cGroup2=%x" % f.cGroup2.value)

        sel = f.EChooser.GetEmbSelection()
        if sel is None:
            print("No selection")
        else:
            print("Selection: %s" % sel)

    # Dispose the form
    f.Free()

# --------------------------------------------------------------------------
def ida_main_legacy():
    # Here we simply show how to use the old style form format using Python

    # Sample form from kernwin.hpp
    s = """Sample dialog box


This is sample dialog box for %A
using address %$

<~E~nter value:N:32:16::>
"""

    # Use either StringArgument or NumericArgument to pass values to the function
    num = Form.NumericArgument('N', value=123)
    ok = idaapi.AskUsingForm(s,
           Form.StringArgument("PyAskUsingForm").arg,
           Form.NumericArgument('$', 0x401000).arg,
           num.arg)
    if ok == 1:
        print("You entered: %x" % num.value)

# --------------------------------------------------------------------------
def test_multilinetext_legacy():
    # Here we text the multi line text control in legacy mode

    # Sample form from kernwin.hpp
    s = """Sample dialog box

This is sample dialog box
<Enter multi line text:t40:80:50::>
"""
    # Use either StringArgument or NumericArgument to pass values to the function
    ti = textctrl_info_t("Some initial value")
    ok = idaapi.AskUsingForm(s, pointer(c_void_p.from_address(ti.clink_ptr)))
    if ok == 1:
        print("You entered: %s" % ti.text)

    del ti

# --------------------------------------------------------------------------
class MyForm2(Form):
    """Simple Form to test multilinetext and combo box controls"""
    def __init__(self):
        Form.__init__(self, r"""STARTITEM 0
BUTTON YES* Yeah
BUTTON NO Nope
BUTTON CANCEL NONE
Form Test

{FormChangeCb}
<Multilinetext:{txtMultiLineText}>
""", {
            'txtMultiLineText': Form.MultiLineTextControl(text="Hello"),
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
        })


    def OnFormChange(self, fid):
        if fid == self.txtMultiLineText.id:
            pass
        elif fid == -2:
            ti = self.GetControlValue(self.txtMultiLineText)
            print "ti.text = %s" % ti.text
        else:
            print(">>fid:%d" % fid)
        return 1

# --------------------------------------------------------------------------
def test_multilinetext(execute=True):
    """Test the multilinetext and combobox controls"""
    f = MyForm2()
    f, args = f.Compile()
    if execute:
        ok = f.Execute()
    else:
        print args[0]
        print args[1:]
        ok = 0

    if ok == 1:
        assert f.txtMultiLineText.text == f.txtMultiLineText.value
        print f.txtMultiLineText.text

    f.Free()

# --------------------------------------------------------------------------
class MyForm3(Form):
    """Simple Form to test multilinetext and combo box controls"""
    def __init__(self):
        self.__n = 0
        Form.__init__(self,
r"""BUTTON YES* Yeah
BUTTON NO Nope
BUTTON CANCEL NONE
Dropdown list test

{FormChangeCb}
<Dropdown list (readonly):{cbReadonly}> <Add element:{iButtonAddelement}> <Set index:{iButtonSetIndex}>
<Dropdown list (editable):{cbEditable}> <Set string:{iButtonSetString}>
""", {
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            'cbReadonly': Form.DropdownListControl(
                        items=["red", "green", "blue"],
                        readonly=True,
                        selval=1),
            'cbEditable': Form.DropdownListControl(
                        items=["1MB", "2MB", "3MB", "4MB"],
                        readonly=False,
                        selval="4MB"),
            'iButtonAddelement': Form.ButtonInput(self.OnButtonNop),
            'iButtonSetIndex': Form.ButtonInput(self.OnButtonNop),
            'iButtonSetString': Form.ButtonInput(self.OnButtonNop),
        })


    def OnButtonNop(self, code=0):
        """Do nothing, we will handle events in the form callback"""
        pass

    def OnFormChange(self, fid):
        if fid == self.iButtonSetString.id:
            s = idc.AskStr("none", "Enter value")
            if s:
                self.SetControlValue(self.cbEditable, s)
        elif fid == self.iButtonSetIndex.id:
            s = idc.AskStr("1", "Enter index value:")
            if s:
                try:
                    i = int(s)
                except:
                    i = 0
                self.SetControlValue(self.cbReadonly, i)
        elif fid == self.iButtonAddelement.id:
            # add a value to the string list
            self.__n += 1
            self.cbReadonly.add("some text #%d" % self.__n)
            # Refresh the control
            self.RefreshField(self.cbReadonly)
        elif fid == -2:
            s = self.GetControlValue(self.cbEditable)
            print "user entered: %s" % s
            sel_idx = self.GetControlValue(self.cbReadonly)

        return 1

# --------------------------------------------------------------------------
def test_dropdown(execute=True):
    """Test the combobox controls"""
    f = MyForm3()
    f, args = f.Compile()
    if execute:
        ok = f.Execute()
    else:
        print args[0]
        print args[1:]
        ok = 0

    if ok == 1:
        print "Editable: %s" % f.cbEditable.value
        print "Readonly: %s" % f.cbReadonly.value

    f.Free()

#</pycode(ex_askusingform)>
# --------------------------------------------------------------------------

#<pycode(ex_formchooser)>
# --------------------------------------------------------------------------
class MainChooserClass(Choose2):
    def __init__(self, title, icon):
        Choose2.__init__(self,
                         title,
                         [ ["Item", 10] ],
                         icon=icon,
                         flags=Choose2.CH_NOIDB,
                         embedded=True, width=30, height=20)

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return ["Option %d" % n]

    def OnGetSize(self):
        return 10

    def OnCommand(self, n, cmd_id):
        if cmd_id == self.cmd_id1:
            print("Context menu on: %d" % n)

        return 0


# --------------------------------------------------------------------------
class AuxChooserClass(Choose2):
    def __init__(self, title, icon):
        Choose2.__init__(self,
                         title,
                         [ ["Item", 10] ],
                         icon=icon,
                         flags=Choose2.CH_NOIDB | Choose2.CH_MULTI,
                         embedded=True, width=30, height=20)

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return ["Item %d" % n]

    def OnGetSize(self):
        t = self.form.main_current_index
        return 0 if t < 0 else t+1


# --------------------------------------------------------------------------
class MyChooserForm(Form):

    # Custom icon data
    icon_data = (
        "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52"
        "\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1F\xF3\xFF"
        "\x61\x00\x00\x00\x7D\x49\x44\x41\x54\x78\xDA\x63\x64\xC0\x0E\xFE"
        "\xE3\x10\x67\x24\x28\x00\xD2\xFC\xF3\xAF\x36\x56\xDD\xEC\xCC\x57"
        "\x31\xF4\x20\x73\xC0\xB6\xE2\xD2\x8C\x66\x08\x5C\x2F\x8A\x01\x84"
        "\x34\x63\x73\x09\x23\xA9\x9A\xD1\x0D\x61\x44\xD7\xCC\xCF\x02\x71"
        "\xE2\xC7\x3F\xA8\x06\x62\x13\x07\x19\x42\x7D\x03\x48\xF5\xC6\x20"
        "\x34\x00\xE4\x57\x74\xFF\xE3\x92\x83\x19\xC0\x40\x8C\x21\xD8\x34"
        "\x33\x40\xA3\x91\x01\x97\x21\xC8\x00\x9B\x66\x38\x01\x33\x00\x44"
        "\x50\x92\x94\xB1\xBA\x04\x8B\x66\x9C\x99\x09\xC5\x10\x1C\xE2\x18"
        "\xEA\x01\xA3\x65\x55\x0B\x33\x14\x07\x63\x00\x00\x00\x00\x49\x45"
        "\x4E\x44\xAE\x42\x60\x82")


    def Free(self):
        # Call the base
        Form.Free(self)

        # Free icon
        if self.icon_id != 0:
            idaapi.free_custom_icon(self.icon_id)
            self.icon_id = 0


    def __init__(self):
        # Load custom icon
        self.icon_id = idaapi.load_custom_icon(data=MyChooserForm.icon_data)
        if self.icon_id == 0:
            raise RuntimeError("Failed to load icon data!")

        self.main_current_index = -1
        self.EChMain = MainChooserClass("MainChooser", self.icon_id)
        self.EChAux  = AuxChooserClass("AuxChooser", self.icon_id)

        # Link the form to the EChooser
        self.EChMain.form = self
        self.EChAux.form = self

        Form.__init__(self, r"""STARTITEM 0
Form with choosers

    {FormChangeCb}
    Select an item in the main chooser:

    <Main chooser:{ctrlMainChooser}><Auxiliar chooser (multi):{ctrlAuxChooser}>


    <Selection:{ctrlSelectionEdit}>

""", {
            'ctrlSelectionEdit' : Form.StringInput(),
            'FormChangeCb'      : Form.FormChangeCb(self.OnFormChange),
            'ctrlMainChooser'   : Form.EmbeddedChooserControl(self.EChMain),
            'ctrlAuxChooser'    : Form.EmbeddedChooserControl(self.EChAux),
        })


    def refresh_selection_edit(self):
        if self.main_current_index < 0:
            s = "No selection in the main chooser"
        else:
            s = "Main %d" % self.main_current_index

            # Get selection in the aux chooser
            sel = self.GetControlValue(self.ctrlAuxChooser)
            if sel:
                s = "%s - Aux item(s): %s" % (s, ",".join(str(x) for x in sel))

        # Update string input
        self.SetControlValue(self.ctrlSelectionEdit, s)


    def OnFormChange(self, fid):
        if fid == -1:
            print("Initialization")
            self.refresh_selection_edit()

            # Add an item to the context menu of the main chooser
            id = self.ctrlMainChooser.AddCommand("Test", icon=self.icon_id)
            print "id=%d" % id
            if id < 0:
                print("Failed to install menu for main embedded chooser")
            else:
                self.EChMain.cmd_id1 = id

        elif fid == -2:
            print("Terminating");

        elif fid == self.ctrlMainChooser.id:
            print("main chooser selection change");
            l = self.GetControlValue(self.ctrlMainChooser);
            if not l:
                self.main_current_index = -1
            else:
                self.main_current_index = l[0]

            # Refresh auxiliar chooser
            self.RefreshField(self.ctrlAuxChooser)
            self.refresh_selection_edit()

        elif fid == self.ctrlAuxChooser.id:
            self.refresh_selection_edit()

        elif fid == self.ctrlSelectionEdit.id:
            pass
        else:
            print("unknown id %d" % fid)

        return 1

#</pycode(ex_formchooser)>

# --------------------------------------------------------------------------
def main_formchooser():
    global f
    f = MyChooserForm()
    try:
        f.Compile()
        r = f.Execute()
        print("Execute returned: %d" % r)
        f.Free()
    except Exception as e:
        print("Failed to show form: %s" % str(e))

# --------------------------------------------------------------------------
if __name__=='__main__':
    #stdalone_main() if stdalone else main_formchooser()
    #stdalone_main() if stdalone else test_multilinetext()
    test_dropdown()
    #test_multilinetext(False)

