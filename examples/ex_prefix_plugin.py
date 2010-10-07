import idaapi

PREFIX = idaapi.SCOLOR_INV + ' ' + idaapi.SCOLOR_INV

class prefix_plugin_t(idaapi.plugin_t):
    flags = 0
    comment = "This is a user defined prefix sample plugin"
    help = "This is help"
    wanted_name = "user defined prefix"
    wanted_hotkey = ""


    def user_prefix(self, ea, lnnum, indent, line, bufsize):
        #print("ea=%x lnnum=%d indent=%d line=%s bufsize=%d" % (ea, lnnum, indent, line, bufsize))

        if (ea % 2 == 0) and indent == -1:
            return PREFIX
        else:
            return ""


    def init(self):
        self.prefix_installed = idaapi.set_user_defined_prefix(8, self.user_prefix)
        if self.prefix_installed:
            print("prefix installed")

        return idaapi.PLUGIN_KEEP


    def run(self, arg):
        pass


    def term(self):
        if self.prefix_installed:
            idaapi.set_user_defined_prefix(0, None)
            print("prefix uninstalled!")


def PLUGIN_ENTRY():
    return prefix_plugin_t()

