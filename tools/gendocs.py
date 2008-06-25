#------------------------------------------------------------
# gendoc.py: Generate an API cross-reference for IDAPython
#------------------------------------------------------------
__author__ = "Gergely Erdelyi <dyce@d-dome.net>"

import epydoc.cli

# This is a small hack to prevent epydoc from exiting the whole
# IDA process in case something goes wrong.
def exit(eval):
    print "not exiting"
epydoc.cli.sys.exit = exit

# Fill in the command-line arguments
epydoc.cli.optparse.sys.argv = [ 'epydoc', 
                                 '--no-sourcecode', 
                                 '-u', 'http://www.d-dome.net/idapython/',
                                 '--navlink', '<a href="http://www.d-dome.net/idapython/reference/">IDAPython Reference</a>',
                                 '--no-private',
                                 '--simple-term',
                                 '-o', 'idapython-reference-%d.%d.%d' % (IDAPYTHON_VERSION[:3]),
                                 '--html', 
                                 'idc', 'idautils', 'idaapi' ]
# Generate the documentation
epydoc.cli.cli()
