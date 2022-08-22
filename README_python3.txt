IDAPython requires a Python3.x installation in order to work.

Because different users might have different (and possibly multiple)
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


