# -----------------------------------------------------------------------
# VirusTotal IDA Plugin
# By Elias Bachaalany <elias at hex-rays.com>
# (c) Hex-Rays 2011
#
# Special thanks:
# - VirusTotal team
# - Bryce Boe for his VirusTotal Python code
#
import idaapi
import idc
from idaapi import Choose2, plugin_t
import BboeVt as vt
import webbrowser
import urllib
import os


PLUGIN_TEST = 0

# -----------------------------------------------------------------------
# Configuration file
VT_CFGFILE = idaapi.get_user_idadir() + os.sep + "virustotal.cfg"

# -----------------------------------------------------------------------
# VirusTotal Icon in PNG format
VT_ICON = (
    "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52"
    "\x00\x00\x00\x10\x00\x00\x00\x10\x04\x03\x00\x00\x00\xED\xDD\xE2"
    "\x52\x00\x00\x00\x30\x50\x4C\x54\x45\x03\x8B\xD3\x5C\xB4\xE3\x9C"
    "\xD1\xED\xF7\xFB\xFD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\xD3\xF2\x42\x61\x00\x00\x00"
    "\x4B\x49\x44\x41\x54\x78\x9C\x2D\xCA\xC1\x0D\x80\x30\x0C\x43\x51"
    "\x27\x2C\x50\x89\x05\x40\x2C\x40\xEB\xFD\x77\xC3\x76\xC9\xE9\xEB"
    "\xC5\x20\x5F\xE8\x1A\x0F\x97\xA3\xD0\xE4\x1D\xF9\x49\xD1\x59\x29"
    "\x4C\x43\x9B\xD0\x15\x01\xB5\x4A\x9C\xE4\x70\x14\x39\xB3\x31\xF8"
    "\x15\x70\x04\xF4\xDA\x20\x39\x02\x8A\x0D\xA8\x0F\x94\xA7\x09\x0E"
    "\xC5\x16\x2D\x54\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82")


# -----------------------------------------------------------------------
class VirusTotalConfig(object):
    def __init__(self):
        self.Default()


    def Default(self):
        self.md5sum = GetInputMD5()
        self.infile = idaapi.dbg_get_input_path()
        if not self.infile:
            self.infile = ""

        # Persistent options
        self.apikey = ""
        self.options = 1 | 2


    def Read(self):
        """
        Read configuration from file
        """
        if not os.path.exists(VT_CFGFILE):
            return
        f = open(VT_CFGFILE, 'r')
        lines = f.readlines()
        for i, line in enumerate(lines):
            line = line.strip()
            if i == 0:
                self.apikey = line
            elif i == 1:
                self.options = int(line)
            else:
                break


    def Write(self):
        """
        Write configuration to file
        """
        lines = (self.apikey.strip(), str(self.options))
        try:
            f = open(VT_CFGFILE, 'w')
            f.write("\n".join(lines))
            f.close()
        except:
            pass


# -----------------------------------------------------------------------
def VtReport(apikey, filename=None, md5sum=None):
    if filename is None and md5sum is None:
        return (False, "No parameters passed!")

    # Check filename existance
    if filename is not None and not os.path.exists(filename):
        return (False, "Input file '%s' does not exist!" % filename)

    #print("fn=%s md5=%s" % (filename, md5sum))
    # Get file report from VirusTotal
    try:
        vt.set_apikey(apikey)
        result = vt.get_file_report(filename=filename, md5sum=md5sum)
    except Exception as e:
        return (False, "Exception:\n%s" % str(e))

    # Already analyzed?
    if result is not None:
        # Transform the results
        items = []
        for av, mwname in result.items():
            mwname = str(mwname) if mwname else "n/a"
            av = str(av)
            items.append([av, mwname])
        result = items

    return (True, result)


# -----------------------------------------------------------------------
class VirusTotalChooser(Choose2):
    """
    Chooser class to display results from VT
    """
    def __init__(self, title, items, icon, embedded=False):
        Choose2.__init__(self,
                         title,
                         [ ["Antivirus", 20], ["Result", 40] ],
                         embedded=embedded)
        self.items = items
        self.icon = icon


    def GetItems(self):
        return self.items


    def SetItems(self, items):
        self.items = [] if items is None else items


    def OnClose(self):
        pass


    def OnGetLine(self, n):
        return self.items[n]


    def OnGetSize(self):
        return len(self.items)


    def OnSelectLine(self, n):
        # Google search for the malware name and the antivirus name
        s = urllib.urlencode({"q" : " ".join(self.items[n])})
        webbrowser.open_new_tab("http://www.google.com/search?%s" % s)


# --------------------------------------------------------------------------
class VirusTotalForm(Form):
    def __init__(self, icon):
        self.EChooser = VirusTotalChooser("E1", [], icon, embedded=True)
        Form.__init__(self, r"""STARTITEM {id:txtInput}
VirusTotal - IDAPython plugin v1.0 (c) Hex-Rays

{FormChangeCb}
<#API key#~A~pi key:{txtApiKey}>

Options:
<#Open results in a chooser when form closes#~P~opout results on close:{rOptRemember}>
<#Use MD5 checksum#~M~D5Sum:{rOptMD5}>
<#Use file on disk#~F~ile:{rOptFile}>{grpOptions}>

<#Type input (file or MD5 string)#~I~nput:{txtInput}>
<Results:{cEChooser}>
<#Get reports from VT#~R~eport:{btnReport}>
""", {
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            'txtApiKey'   : Form.StringInput(swidth=80),
            'grpOptions'  : Form.ChkGroupControl(("rOptRemember", "rOptMD5", "rOptFile")),
            'txtInput'    : Form.FileInput(open=True),
            'btnReport'   : Form.ButtonInput(self.OnReportClick),
            'cEChooser'   : Form.EmbeddedChooserControl(self.EChooser)
        })



    def OnReportClick(self, code=0):
        pass


    def OnFormChange(self, fid):
        if fid == self.rOptMD5.id or fid == self.rOptFile.id:
            input = (self.cfg.md5sum, self.cfg.infile)
            if fid == self.rOptMD5.id:
                c1 = self.rOptMD5
                c2 = self.rOptFile
                idx = 0
            else:
                c1 = self.rOptFile
                c2 = self.rOptMD5
                idx = 1

            v = not self.GetControlValue(c1)
            if v: idx = not idx

            # Uncheck the opposite input type
            self.SetControlValue(c2, v)

            # Set input field depending on input type
            self.SetControlValue(self.txtInput, input[idx])
        #
        # Report button
        #
        elif fid == self.btnReport.id:
            input = self.GetControlValue(self.txtInput)
            as_file = self.GetControlValue(self.rOptFile)
            apikey = self.GetControlValue(self.txtApiKey)

            ok, r = VtReport(self.cfg.apikey,
                        filename=input if as_file else None,
                        md5sum=None if as_file else input)

            # Error?
            if not ok:
                idc.Warning(r)
                return 1

            # Pass the result
            self.EChooser.SetItems(r)

            # We have results and it was a file? Print its MD5
            if r and as_file:
                print("%s: %s" % (vt.LAST_FILE_HASH, input))

            # Refresh the embedded chooser control
            # (Could also clear previous results if not were retrieved during this run)
            self.RefreshField(self.cEChooser)

            # Store the input for the caller
            self.cfg.input = input

            # No results and file as input was supplied?
            if r is None:
                if as_file:
                    # Propose to upload
                    if idc.AskYN(0, "HIDECANCEL\nNo previous results. Do you want to submit the file:\n\n'%s'\n\nto VirusTotal?" % input) == 0:
                        return 1

                    try:
                        r = vt.scan_file(input)
                    except Exception as e:
                        idc.Warning("Exceptio during upload: %s" % str(e))
                    else:
                        if r is None:
                            idc.Warning("Failed to upload the file!")
                        else:
                            idc.Warning("File uploaded. Check again later to get the analysis report. Scan id: %s" % r)
                else:
                    idc.Warning("No results found for hash: %s" % input)

        return 1


    def Show(self, cfg):
        # Compile the form once
        if not self.Compiled():
            _, args = self.Compile()
            #print args[0]

        # Populate the form
        self.txtApiKey.value  = cfg.apikey
        self.grpOptions.value = cfg.options
        self.txtInput.value   = cfg.infile if self.rOptFile.checked else cfg.md5sum

        # Remember the config
        self.cfg = cfg

        # Execute the form
        ok = self.Execute()

        # Forget the cfg
        del self.cfg

        # Success?
        if ok != 0:
            # Update config
            cfg.options = self.grpOptions.value
            cfg.apikey  = self.txtApiKey.value

            # Popup results?
            if self.rOptRemember.checked:
                ok = 2

        return ok


# -----------------------------------------------------------------------
class VirusTotalPlugin_t(plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "VirusTotal plugin for IDA"
    help = ""
    wanted_name = "VirusTotal report"
    wanted_hotkey = "Alt-F8"


    def init(self):
        # Some initialization
        self.icon_id = 0
        return idaapi.PLUGIN_OK


    def run(self, arg=0):
        # Load icon from the memory and save its id
        self.icon_id = idaapi.load_custom_icon(data=VT_ICON, format="png")
        if self.icon_id == 0:
            raise RuntimeError("Failed to load icon data!")

        # Create config object
        cfg = VirusTotalConfig()

        # Read previous config
        cfg.Read()

        # Create form
        f = VirusTotalForm(self.icon_id)

        # Show the form
        ok = f.Show(cfg)
        if ok == 0:
            f.Free()
            return

        # Save configuration
        cfg.Write()

        # Spawn a non-modal chooser w/ the results if any
        if ok == 2 and f.EChooser.GetItems():
            VirusTotalChooser(
                "VirusTotal results [%s]" % cfg.input,
                f.EChooser.GetItems(),
                self.icon_id).Show()

        f.Free()
        return


    def term(self):
        # Free the custom icon
        if self.icon_id != 0:
            idaapi.free_custom_icon(self.icon_id)


# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return VirusTotalPlugin_t()

# --------------------------------------------------------------------------
if PLUGIN_TEST:
    # Create form
    f = PLUGIN_ENTRY()
    f.init()
    f.run()
    f.term()


