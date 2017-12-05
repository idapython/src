"""
User contributed script: MSDN API HELP plugin

This script fetches the API reference (from MSDN) of a given highlighted identifier
and returns the results in a new web browser page.

This script depends on the feedparser package: http://code.google.com/p/feedparser/
"""

# -----------------------------------------------------------------------
import ida_kernwin
import ida_name
import ida_idaapi

try:
    import feedparser
except:
    ida_kernwin.warning('Feedparser package not installed')

# -----------------------------------------------------------------------
class msdnapihelp_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Online MSDN API Help"
    help = "Help me"
    wanted_name = "MSDN API Help"
    wanted_hotkey = "F3"

    def init(self):
        return ida_idaapi.PLUGIN_OK


    @staticmethod
    def sanitize_name(name):
        t = ida_name.FUNC_IMPORT_PREFIX
        if name.startswith(t):
            return name[len(t):]
        return name


    def run(self, arg):
        # Get the highlighted identifier
        v = ida_kernwin.get_current_viewer()
        ident, ok = ida_kernwin.get_highlight(v)
        if not ok:
            print "No identifier was highlighted"
            return

        ident = self.sanitize_name(ident)
        print "Looking up '%s' in MSDN online" % ident
        qurl = "https://social.msdn.microsoft.com/search/en-US/feed?query=%s&format=RSS&theme=feed%%2fen-us"
        d = feedparser.parse(qurl % ident)
        if len(d['entries']) > 0:
            url = d['entries'][0].link
            if arg > 0:
                print("URL: %s" % url)
            else:
                import webbrowser
                webbrowser.open_new_tab(url)
        else:
            print "API documentation not found for: %s" % ident


    def term(self):
        pass


# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return msdnapihelp_plugin_t()
