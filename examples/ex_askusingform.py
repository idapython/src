# -----------------------------------------------------------------------
# This is an example illustrating how to use the Form class
# (c) Hex-Rays
#
from idaapi import Form

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

#</pycode(ex_askusingform)>


# --------------------------------------------------------------------------
ida_main()