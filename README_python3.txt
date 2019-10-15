
IDAPython comes in two flavors:

* IDAPython-for-Python2
* IDAPython-for-Python3

# Switching between Python 2 and Python 3.

Depending on your choice at the install time, your "plugins" directory will have 
one version of plugin installed as idapython.[dll|so|dylib] (and/or idapython64) and
the other will be present with the ".disabled" extension. To switch, just rename the 
current version to .disabled and the disabled one back to the .dll/.so/.dylib 
(depending on your OS)

For example, to swith from Python 3 to Python 2 on Windows:

1. rename idapython.dll to idapython.3.disabled and idapython64.dll to idapython64.3.disabled
2. rename idapython2.disabled to idapython.dll and idapython642.disabled to idapython64.dll


# Selecting a Python install to use

The situation for IDAPython-for-Python2 is simple: it uses Python 2.7,
and will expect that [lib]python2.7.[dll|so|dylib] is present in the system 
library path so that IDA can find it.

When it comes to IDAPython-for-Python3, it gets more complex: because
different users might have different (and possibly multiple) versions
of Python3 installed, IDA comes with a tool called `idapyswitch`, that
can be run to select the desired Python3 runtime to tailor
IDAPython-for-Python3 to.

If you selected IDAPython-for-Python3 at installation-time,
`idapyswitch` utility should already have been run, and selected
the most appropriate Python3 version.

Should you want to switch to another Python3 install after installation,
please run `idapyswitch` from IDA's directory. It will scan for Python 
installs present in the system's standard locations and offer you to choose one. 
It also supports optional command-line switches to handle non-standard installs.
Run `idapyswitch -h` to see them.


