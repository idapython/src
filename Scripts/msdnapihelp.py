"""
User contributed script: MSDN API HELP plugin

This script fetches the API reference (from MSDN) of a given highlighted identifier
and returns the results in a new web browser page.

This script depends on the feedparser package: http://code.google.com/p/feedparser/

10/05/2010
- initial version


"""

import idaapi

# -----------------------------------------------------------------------
class msdnapihelp_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Online MSDN API Help"
    help = "Help me"
    wanted_name = "MSDN API Help"
    wanted_hotkey = "F3"

    def init(self):
        return idaapi.PLUGIN_OK


    @staticmethod
    def sanitize_name(name):
        t = idaapi.FUNC_IMPORT_PREFIX
        if name.startswith(t):
            return name[len(t):]
        return name


    def run(self, arg):
        # Get the highlighted identifier
        id = idaapi.get_highlighted_identifier()
        if not id:
            print "No identifier was highlighted"
            return

        import webbrowser

        try:
            import feedparser
        except:
            idaapi.warning('Feedparser package not installed')
            return

        id = self.sanitize_name(id)
        print "Looking up '%s' in MSDN online" % id
        d = feedparser.parse("http://social.msdn.microsoft.com/Search/Feed.aspx?locale=en-us&format=RSS&Query=%s" % id)
        if len(d['entries']) > 0:
            url = d['entries'][0].link
            webbrowser.open_new_tab(url)
        else:
            print "API documentation not found for: %s" % id


    def term(self):
        pass


# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return msdnapihelp_plugin_t()
