# -----------------------------------------------------------------------
# This is an example illustrating how to use customview in Python
# The sample will allow you to open an assembly file and display it in color
# (c) Hex-Rays
#
import idaapi
import idautils
import idc
import os

# ----------------------------------------------------------------------
class asm_colorizer_t(object):
    def is_id(self, ch):
        return ch == '_' or ch.isalpha() or '0' <= ch <= '9'

    def get_identifier(self, line, x, e):
        i = x
        is_digit = line[i].isdigit()
        while i < e:
            ch = line[i]
            if not self.is_id(ch):
                if ch != '.' or not is_digit:
                    break
            i += 1
        return (i, line[x:i])

    def get_quoted_string(self, line, x, e):
        quote = line[x]
        i = x + 1
        while i < e:
            ch = line[i]
            if ch == '\\' and line[i+1] == quote:
                i += 1
            elif ch == quote:
                i += 1 # also take the quote
                break
            i += 1
        return (i, line[x:i])

    def colorize(self, lines):
        for line in lines:
            line = line.rstrip()
            if not line:
                self.add_line()
                continue
            x = 0
            e = len(line)
            s = ""
            while x < e:
                ch = line[x]
                # String?
                if ch == '"' or ch == "'":
                    x, w = self.get_quoted_string(line, x, e)
                    s += self.as_string(w)
                # Tab?
                elif ch == '\t':
                    s += ' ' * 4
                    x += 1
                # Comment?
                elif ch == ';':
                    s += self.as_comment(line[x:])
                    # Done with this line
                    break
                elif ch == '.' and x + 1 < e:
                    x, w = self.get_identifier(line, x + 1, e)
                    s += self.as_directive(ch + w)
                # Identifiers?
                elif self.is_id(ch):
                    x, w = self.get_identifier(line, x, e)
                    # Number?
                    if ch.isdigit():
                        s += self.as_num(w)
                    # Other identifier
                    else:
                        s += self.as_id(w)
                # Output as is
                else:
                    s += ch
                    x += 1
            self.add_line(s)

# -----------------------------------------------------------------------
class asmview_t(idaapi.simplecustviewer_t, asm_colorizer_t):
    def Create(self, fn):
        # Create the customview
        if not idaapi.simplecustviewer_t.Create(self, "Viewing file - %s" % os.path.basename(fn)):
            return False

        self.instruction_list = idautils.GetInstructionList()
        self.instruction_list.extend(["ret"])
        self.register_list    = idautils.GetRegisterList()
        self.register_list.extend(["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"])

        self.fn = fn
        if not self.reload_file():
            return False

        self.id_refresh = self.AddPopupMenu("Refresh")
        self.id_close   = self.AddPopupMenu("Close")

        return True

    def reload_file(self):
        if not self.colorize_file(self.fn):
            self.Close()
            return False
        return True

    def colorize_file(self, fn):
        try:
            f = open(fn, "r")
            lines = f.readlines()
            f.close()
            self.ClearLines()
            self.colorize(lines)
            return True
        except:
            return False

    def add_line(self, s=None):
        if not s:
            s = ""
        self.AddLine(s)

    def as_comment(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_RPTCMT)

    def as_id(self, s):
        t = s.lower()
        if t in self.register_list:
            return idaapi.COLSTR(s, idaapi.SCOLOR_REG)
        elif t in self.instruction_list:
            return idaapi.COLSTR(s, idaapi.SCOLOR_INSN)
        else:
            return s

    def as_string(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_STRING)

    def as_num(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_NUMBER)

    def as_directive(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_KEYWORD)

    def OnPopupMenu(self, menu_id):
        """
        A context (or popup) menu item was executed.
        @param menu_id: ID previously registered with AddPopupMenu()
        @return: Boolean
        """
        if self.id_refresh == menu_id:
            return self.reload_file()
        elif self.id_close == menu_id:
            self.Close()
            return True
        return False

    def OnKeydown(self, vkey, shift):
        """
        User pressed a key
        @param vkey: Virtual key code
        @param shift: Shift flag
        @return Boolean. True if you handled the event
        """
        # ESCAPE
        if vkey == 27:
            self.Close()
        elif vkey == ord('H'):
            lineno = self.GetLineNo()
            if lineno is not None:
                line, fg, bg = self.GetLine(lineno)
                if line and line[0] != idaapi.SCOLOR_INV:
                    s = idaapi.SCOLOR_INV + line + idaapi.SCOLOR_INV
                    self.EditLine(lineno, s, fg, bg)
                    self.Refresh()
        elif vkey == ord('C'):
            self.ClearLines()
            self.Refresh()
        elif vkey == ord('S'):
            print "Selection (x1, y1, x2, y2) = ", self.GetSelection()
        elif vkey == ord('I'):
            print "Position (line, x, y) = ", self.GetPos(mouse = 0)
        else:
            return False
        return True

# -----------------------------------------------------------------------
class asmviewplg(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "ASM viewer"
    help = "This is help"
    wanted_name = "ASM file viewer"
    wanted_hotkey = "Alt-F8"
    def __init__(self):
        self.view = None

    def init(self):
        return idaapi.PLUGIN_KEEP
    def run(self, arg):
        if self.view:
            self.Close()
        fn = idc.AskFile(0, "*.asm", "Select ASM file to view")
        if not fn:
            return
        self.view = asmview_t()
        if not self.view.Create(fn):
            return
        self.view.Show()

    def term(self):
        if self.view:
            self.view.Close()

def PLUGIN_ENTRY():
    return asmviewplg()