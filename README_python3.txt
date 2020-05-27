
IDAPython comes in two flavors:

* IDAPython-for-Python2.7
* IDAPython-for-Python3.x

# Switching between IDAPython-for-Python2.7, and IDAPython-for-Python3.x.

IDA ships with two versions of IDAPython:
* one that runs using the Python2.7 runtime
* one that runs using the Python3.x runtime

By default, IDA will load the one that runs using the Python3.x runtime.
In order to have IDA use IDAPython-on-Python2.7, the file
'use_python2' needs to be present in the 'python' subdirectory.

That file will be looked for in the following places:
* IDA's install path:  path/to/ida_install/python/use_python2
* The 'IDAUSR' directory:
   +  ~/.idapro/python/use_python2 (on Linux/OSX)
   + %APPDATA%\Hex-Rays\IDA Pro\python\use_python2 (on Windows)
   + [...or any other directory if the environment variable $IDAUSR is set]

# Selecting which Python3.x install runtime to use

The situation for IDAPython-for-Python2.7 is simple: it uses Python 2.7,
and will expect that [lib]python2.7.[dll|so|dylib] is present in the system
library path so that IDA can find it.

But when it comes to IDAPython-for-Python3.x, things gets more complex:
because different users might have different (and possibly multiple)
versions of Python3.x installed, IDA comes with a tool called `idapyswitch`
that can be run to select the desired Python3.x runtime.

If you selected IDAPython-for-Python3.x at the installation time,
the `idapyswitch` utility should already have been run and selected
the most appropriate Python3.x version.

Should you want to switch to another Python3.x install after installation,
please run `idapyswitch` from the IDA directory. It will scan for Python
installs present in the system's standard locations and offer you to choose one.
It also supports optional command-line switches to handle non-standard installs.
Run `idapyswitch -h` to see them.

On Windows, you may need to run it as administrator
so it can patch sip.pyd (library required for PyQt bindings).


