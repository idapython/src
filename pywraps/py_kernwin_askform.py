# --------------------------------------------------------------------------
#<pycode(py_kernwin_askform)>
import sys

import ida_idaapi, _ida_idaapi
import ida_pro

#ICON WARNING|QUESTION|INFO|NONE
#AUTOHIDE NONE|DATABASE|REGISTRY|SESSION
#HIDECANCEL
#BUTTON YES|NO|CANCEL "Value|NONE"
#STARTITEM {id:ItemName}
#HELP / ENDHELP
try:
    import types
    import ctypes
    # On Windows, we use stdcall

    # Callback for buttons
    # typedef int (idaapi *buttoncb_t)(int button_code, form_actions_t &fa);

    _BUTTONCB_T = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p)

    # Callback for form change
    # typedef int (idaapi *formchgcb_t)(int field_id, form_actions_t &fa);
    _FORMCHGCB_T = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
except:
    try:
        _BUTTONCB_T = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
        _FORMCHGCB_T = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
    except:
        _BUTTONCB_T = _FORMCHGCB_T = None


# -----------------------------------------------------------------------
# textctrl_info_t clinked object
class textctrl_info_t(ida_idaapi.py_clinked_object_t):
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
        ida_idaapi.py_clinked_object_t.__init__(self)
        if text:
            self.text = text
        if flags:
            self.flags = flags
        if tabsize:
            self.tabsize = tabsize

    def _create_clink(self):
        return _ida_kernwin.textctrl_info_t_create()

    def _del_clink(self, lnk):
        return _ida_kernwin.textctrl_info_t_destroy(lnk)

    def _get_clink_ptr(self):
        return _ida_kernwin.textctrl_info_t_get_clink_ptr(self)

    def assign(self, other):
        """Copies the contents of 'other' to 'self'"""
        return _ida_kernwin.textctrl_info_t_assign(self, other)

    def __set_text(self, s):
        """Sets the text value"""
        return _ida_kernwin.textctrl_info_t_set_text(self, s)

    def __get_text(self):
        """Sets the text value"""
        return _ida_kernwin.textctrl_info_t_get_text(self)

    def __set_flags__(self, flags):
        """Sets the flags value"""
        return _ida_kernwin.textctrl_info_t_set_flags(self, flags)

    def __get_flags__(self):
        """Returns the flags value"""
        return _ida_kernwin.textctrl_info_t_get_flags(self)

    def __set_tabsize__(self, tabsize):
        """Sets the tabsize value"""
        return _ida_kernwin.textctrl_info_t_set_tabsize(self, tabsize)

    def __get_tabsize__(self):
        """Returns the tabsize value"""
        return _ida_kernwin.textctrl_info_t_get_tabsize(self)

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
    """Embedded chooser - idaapi.Choose"""
    FT_MULTI_LINE_TEXT = 't'
    """Multi text control - textctrl_info_t"""
    FT_DROPDOWN_LIST   = 'b'
    """Dropdown list control - Form.DropdownControl"""
    FT_HTML_LABEL = 'h'
    """HTML label to display (only for GUI version, and for dynamic labels; no input)"""

    FT_CHKGRP = 'C'
    FT_CHKGRP2= 'c'
    FT_RADGRP = 'R'
    FT_RADGRP2= 'r'

    @staticmethod
    def create_string_buffer(value, size=None):
        if value is None:
            assert(size is not None)
            return ctypes.create_string_buffer(size)
        else:
            if sys.version_info.major >= 3:
                return ctypes.create_string_buffer(value.encode("UTF-8"), size)
            else:
                return ctypes.create_string_buffer(value, size)

    @staticmethod
    def fieldtype_to_ctype(tp, i64 = False):
        """
        Factory method returning a ctype class corresponding to the field type string
        """
        if tp in (Form.FT_SEG, Form.FT_HEX, Form.FT_RAWHEX, Form.FT_ADDR):
            return ctypes.c_uint64 if i64 else ctypes.c_ulong
        elif tp in (Form.FT_SHEX, Form.FT_DEC, Form.FT_OCT, Form.FT_BIN, Form.FT_CHAR):
            return ctypes.c_int64 if i64 else ctypes.c_long
        elif tp == Form.FT_UINT64:
            return ctypes.c_uint64
        elif tp == Form.FT_INT64:
            return ctypes.c_int64
        elif tp == Form.FT_COLOR:
            return ctypes.c_ulong
        elif tp == Form._FT_USHORT:
            return ctypes.c_ushort
        elif tp in (Form.FT_FORMCHG, Form.FT_ECHOOSER):
            return ctypes.c_void_p
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
            self.arg = ctypes.pointer(cls(value))

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
            if isinstance(size, str):
                value, size = size, None
            self.size = size
            self.arg = Form.create_string_buffer(value, size)

        def __get_value(self):
            return self.arg.value.decode("UTF-8")

        def __set_value(self, v):
            self.arg.value = v.encode("UTF-8")
        value = property(__get_value, __set_value)


    #
    # Base control class
    #
    class Control(object):
        def __init__(self):
            self.id = 0
            """Automatically assigned control ID"""

            self.input_field_index = None
            """If this control is an input field, once Compile() returns this will hold its index. This is used only to compute the possible STARTITEM index"""

            self.arg = None
            """Control argument value. This could be one element or a list/tuple (for multiple args per control)"""

            self.form = None
            """Reference to the parent form. It is filled by Form.Add()"""

            self.form_hasattr = False

        def get_tag(self):
            """
            Control tag character. One of Form.FT_XXXX.
            The form class will expand the {} notation and replace them with the tags
            """
            pass

        def get_arg(self):
            """
            Control returns the parameter to be pushed on the stack
            (Of ask_form())
            """
            return self.arg

        def free(self):
            """
            Free the control
            """
            # Release the parent form reference
            self.form = None

        def is_input_field(self):
            """
            Return True if this field acts as an input
            """
            return False

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
        def __init__(self, value, tp=None, size=ida_pro.MAXSTR):
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
            self.size = size
            self.arg = Form.create_string_buffer(value, size)


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

        def is_input_field(self):
            return True


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
        def __init__(self,
                     tp,
                     width,
                     swidth,
                     hlp=None,
                     is_relative_offset=False):
            """
            @param width:  The maximum possible number of characters that
                           can be entered into the input field
            @param swidth: The width of visible part of the input field
            """
            Form.Control.__init__(self)
            self.tp = tp
            self.width = width
            self.swidth = swidth
            self.hlp = hlp
            self.is_relative_offset = is_relative_offset

        def get_tag(self):
            return "%s%d:%s%s:%s:%s" % (
                self.tp, self.id,
                "+" if self.is_relative_offset else "",
                self.width,
                self.swidth,
                ":" if self.hlp is None else self.hlp)

        def is_input_field(self):
            return True


    class NumericInput(InputControl, NumericArgument):
        """
        A composite class serving as a base numeric input control class
        """
        def __init__(self,
                     tp=None,
                     value=0,
                     width=50,
                     swidth=10,
                     hlp=None,
                     is_relative_offset=False):
            if tp is None:
                tp = Form.FT_HEX
            Form.InputControl.__init__(self,
                tp, width, swidth, hlp, is_relative_offset)
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
                     width=ida_pro.MAXSTR,
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
            self.handler = handler
            self.arg = _BUTTONCB_T(self.helper_cb)

        def helper_cb(self, button_code, p_fa):
            # Remember the pointer to the forms_action in the parent form
            self.form.p_fa = p_fa

            # Call user's handler
            r = self.handler(button_code)
            return 0 if r is None else r

        def is_input_field(self):
            return False


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
            if chooser is None or not isinstance(chooser, Choose):
                raise ValueError("Invalid chooser passed.")

            # Create an embedded chooser structure from the Choose instance,
            # and retrieve the pointer to the chooser_base_t.
            emb = chooser.Embedded(create_chobj=True)
            # if chooser.Embedded() != 0:
            if emb is None:
                raise ValueError("Failed to create embedded chooser instance.")

            # Construct input control
            Form.InputControl.__init__(self, Form.FT_ECHOOSER, "", swidth)

            self.selobj = ida_pro.sizevec_t()

            # Get a pointer to the selection vector
            if sys.version_info.major >= 3:
                sel = self.selobj.this.__int__()
            else:
                sel = self.selobj.this.__long__()

            # Get a pointer to a c_void_p constructed from an address
            p_embedded = ctypes.pointer(ctypes.c_void_p.from_address(emb))
            p_sel      = ctypes.pointer(ctypes.c_void_p.from_address(sel))

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

        def __get_selection__(self):
            if len(self.selobj):
                out = []
                for item in self.selobj:
                    out.append(int(item))
                return out
        selection = property(__get_selection__)
        """Returns the selection"""

        def free(self):
            """
            Frees the embedded chooser data
            """
            self.chooser.Close()
            self.chooser = None
            Form.Control.free(self)


    class DropdownListControl(InputControl, ida_pro._qstrvec_t):
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
            ida_pro._qstrvec_t.__init__(self, items)

            # Remember if readonly or not
            self.readonly = readonly

            if readonly:
                # Create a C integer and remember it
                self.__selval = ctypes.c_int(selval)
                val_addr      = ctypes.addressof(self.__selval)
            else:
                # Create an strvec with one qstring
                self.__selval = ida_pro._qstrvec_t([selval])
                # Get address of the first element
                val_addr      = self.__selval.addressof(0)

            # Two arguments:
            # - argument #1: a pointer to the qstrvec containing the items
            # - argument #2: an integer to hold the selection
            #         or
            #            #2: a qstring to hold the dropdown text control value
            self.arg = (
                ctypes.pointer(ctypes.c_void_p.from_address(self.clink_ptr)),
                ctypes.pointer(ctypes.c_void_p.from_address(val_addr))
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
            self.arg = ctypes.pointer(ctypes.c_void_p.from_address(self.clink_ptr))


        def free(self):
            self._free()


    #
    # Form class
    #
    def __init__(self, form, controls):
        """
        Contruct a Form class.
        This class wraps around ask_form() or open_form() and provides an easier / alternative syntax for describing forms.
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

        self.modal = True
        """By default, forms are modal"""

        self.openform_flags = 0
        """
        If non-modal, these flags will be passed to open_form.
        This is an OR'ed combination of the PluginForm.FORM_* values.
        """


    def Free(self):
        """
        Frees all resources associated with a compiled form.
        Make sure you call this function when you finish using the form.
        """

        # Free all the controls
        for name, ctrl in self.__controls.items():
            if ctrl.parent_hasattr:
                delattr(self, name)
                ctrl.parent_hasattr = False
            ctrl.free()

        # Reset the controls
        # (Note that we are not removing the form control attributes, no need)
        self._reset()

        # Unregister, so we don't try and free it again at closing-time.
        _ida_kernwin.py_unregister_compiled_form(self)


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
            ctrl.parent_hasattr = True

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
        for child_name in sorted(Group.children_names):
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
        for name in sorted(controls.keys()):
            # Add the control
            self.Add(name, controls[name], mkattr)


    def CompileEx(self, form):
        """
        Low level function.
        Compiles (parses the form syntax and adds the control) the form string and
        returns the argument list to be passed the argument list to ask_form().

        The form controls are wrapped inside curly braces: {ControlName}.

        A special operator can be used to return the index of a given control by its name: {id:ControlName}.
        This is useful when you use the STARTITEM form keyword to set the initially focused control.
        (note that, technically, the index is not the same as the ID; that's because STARTITEM
        uses raw, 0-based indexes rather than control IDs to determine the focused widget.)

        @param form: Compiles the form and returns the arguments needed to be passed to ask_form()
        """
        # First argument is the form string
        args = [None]

        # Second argument, if form is not modal, is the set of flags
        if not self.modal:
            args.append(self.openform_flags | 0x80) # Add FORM_QWIDGET

        ctrlcnt = 1

        # Reset all group control internal flags
        for ctrl in self.__controls.values():
            if isinstance(ctrl, Form.GroupControl):
                ctrl._reset()

        def next_control(form, p, first_pass):
            i1 = form.find("{", p)
            if i1 < 0:
                return form, None, None, None
            if form[i1 - 1] == '\\' and i1 > 0:
                if first_pass:
                    return next_control(form, i1 + 1, first_pass)
                else:
                    # Remove escape sequence and restart search
                    form = form[:i1 - 1] + form[i1:]
                    return next_control(form, i1, first_pass)
            i2 = form.find("}", i1)
            if i2 < 0:
                raise SyntaxError("No matching closing brace '}'")
            ctrlname = form[i1 + 1:i2]
            if not ctrlname:
                raise ValueError("Control %d has an invalid name!" % ctrlcnt)
            return form, i1, i2, ctrlname


        control_count = 0
        last_input_field_index = 0
        # First pass: assign input_field_index values to controls
        p = 0
        while True:
            form, i1, i2, ctrlname = next_control(form, p, first_pass=True)
            if ctrlname is None:
                break
            p = i2

            if ctrlname.startswith("id:"):
                continue

            ctrl = self.__controls.get(ctrlname, None)
            if ctrl is None:
                raise ValueError("No matching control '%s'" % ctrlname)

            if isinstance(ctrl, Form.FormChangeCb) and control_count > 0:
                raise SyntaxError("Control '%s' should be the first control in the form" % ctrlname)

            # If this control is an input, assign its index
            if ctrl.is_input_field():
                ctrl.input_field_index = last_input_field_index
                last_input_field_index += 1

            control_count += 1


        p = 0
        while True:
            form, i1, i2, ctrlname = next_control(form, p, first_pass=False)
            if ctrlname is None:
                break

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
                tag = str(ctrl.input_field_index if ctrl.input_field_index is not None else ctrl.id)
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
                if isinstance(arg, (list, tuple)):
                    # Push all args
                    args.extend(arg)
                else:
                    # Push one arg
                    args.append(arg)

            ctrlcnt += 1

        # If no FormChangeCb instance was passed, and thus there's no '%/'
        # in the resulting form string, let's provide a minimal one, so that
        # we will retrieve 'p_fa', and thus actions that rely on it will work.
        if form.find(Form.FT_FORMCHG) < 0:
            form = form + Form.FT_FORMCHG
            fccb = Form.FormChangeCb(lambda *args: 1)
            self.Add("___dummyfchgcb", fccb)
            # Regardless of the actual position of '%/' in the form
            # string, a formchange callback _must_ be right after
            # the form string.
            if self.modal:
                inspos = 1
            else:
                inspos = 2
            args.insert(inspos, fccb.get_arg())

        # Patch in the final form string

        if sys.version_info.major >= 3:
            args[0] = form.encode("UTF-8")
        else:
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

        # Register this form, to make sure it will be freed at closing-time.
        _ida_kernwin.py_register_compiled_form(self)

        return (self, self.__args)


    def Compiled(self):
        """
        Checks if the form has already been compiled

        @return: Boolean
        """
        return self.__args is not None


    def _ChkCompiled(self):
        if not self.Compiled():
            raise SyntaxError("Form is not compiled")


    def Execute(self):
        """
        Displays a modal dialog containing the compiled form.
        @return: 1 - ok ; 0 - cancel
        """
        self._ChkCompiled()
        if not self.modal:
            raise SyntaxError("Form is not modal. Open() should be instead")

        return ask_form(*self.__args)


    def Open(self):
        """
        Opens a widget containing the compiled form.
        """
        self._ChkCompiled()
        if self.modal:
            raise SyntaxError("Form is modal. Execute() should be instead")

        open_form(*self.__args)


    def EnableField(self, ctrl, enable):
        """
        Enable or disable an input field
        @return: False - no such control
        """
        return _ida_kernwin.formchgcbfa_enable_field(self.p_fa, ctrl.id, enable)


    def ShowField(self, ctrl, show):
        """
        Show or hide an input field
        @return: False - no such control
        """
        return _ida_kernwin.formchgcbfa_show_field(self.p_fa, ctrl.id, show)


    def MoveField(self, ctrl, x, y, w, h):
        """
        Move/resize an input field

        @return: False - no such fiel
        """
        return _ida_kernwin.formchgcbfa_move_field(self.p_fa, ctrl.id, x, y, w, h)


    def GetFocusedField(self):
        """
        Get currently focused input field.
        @return: None if no field is selected otherwise the control ID
        """
        id = _ida_kernwin.formchgcbfa_get_focused_field(self.p_fa)
        return self.FindControlById(id)


    def SetFocusedField(self, ctrl):
        """
        Set currently focused input field
        @return: False - no such control
        """
        return _ida_kernwin.formchgcbfa_set_focused_field(self.p_fa, ctrl.id)


    def RefreshField(self, ctrl):
        """
        Refresh a field
        @return: False - no such control
        """
        return _ida_kernwin.formchgcbfa_refresh_field(self.p_fa, ctrl.id)


    def Close(self, close_normally):
        """
        Close the form
        @param close_normally:
                   1: form is closed normally as if the user pressed Enter
                   0: form is closed abnormally as if the user pressed Esc
        @return: None
        """
        return _ida_kernwin.formchgcbfa_close(self.p_fa, close_normally)


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
        tid, size = self.ControlToFieldTypeIdAndSize(ctrl)
        r = _ida_kernwin.formchgcbfa_get_field_value(
                    self.p_fa,
                    ctrl.id,
                    tid,
                    size)
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
        return _ida_kernwin.formchgcbfa_set_field_value(
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
            return (3, min(ida_pro.MAXSTR, ctrl.size))
        elif isinstance(ctrl, Form.ColorInput):
            return (4, 0)
        elif isinstance(ctrl, Form.NumericInput):
            # Pass the numeric control type
            return (6, ord(ctrl.tp[0]))
        elif isinstance(ctrl, Form.InputControl):
            return (1, ctrl.size)
        else:
            raise NotImplementedError("Not yet implemented")

# --------------------------------------------------------------------------
# Instantiate ask_form/open_form function pointers
try:
    import ctypes
# Setup the numeric argument size
    Form.NumericArgument.DefI64 = _ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF
# int ask_form(const char *form, ...)
    __ask_form_callable = ctypes.CFUNCTYPE(ctypes.c_int)(_ida_kernwin.py_get_ask_form())
# specify types of the fixed arguments explicitly so that varargs are passed correctly on arm macOS
# https://bugs.python.org/issue42880
    __ask_form_callable.argtypes = [ ctypes.c_char_p ]
#  TWidget *open_form(const char *form, uint32 flags, ...)
    __open_form_callable = ctypes.CFUNCTYPE(ctypes.c_void_p )(_ida_kernwin.py_get_open_form())
    __open_form_callable.argtypes = [ ctypes.c_char_p, ctypes.c_uint32 ]
except:
    def __ask_form_callable(*args):
        warning("ask_form() needs ctypes library in order to work")
        return 0
    def __open_form_callable(*args):
        warning("open_form() needs ctypes library in order to work")

def __call_form_callable(call, *args):
    assert(len(args))
    with disabled_script_timeout_t():
        if sys.version_info.major >= 3 and isinstance(args[0], str):
            largs = list(args)
            largs[0] = largs[0].encode("UTF-8")
            args = tuple(largs)
        r = call(*args)
    return r

def ask_form(*args):
    return __call_form_callable(__ask_form_callable, *args)

def open_form(*args):
    if len(args) == 1:
        args = (args[0], 0) # add default flags
    return __call_form_callable(__open_form_callable, *args)

#</pycode(py_kernwin_askform)>
