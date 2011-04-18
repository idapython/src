----------------------------------------------------------
IDAPython - Python plugin for Interactive Disassembler Pro
----------------------------------------------------------

WHAT IS IDAPTYHON?
------------------

IDAPython is an IDA plugin which makes it possible to write scripts
for IDA in the Python programming language. IDAPython provides full
access to both the IDA API and any installed Python module.

Check the scripts in the examples directory to get an quick glimpse.


AVAILABILITY
------------

Latest stable versions of IDAPython are available from
  http://code.google.com/p/idapython/downloads/list

Development builds are available from
  http://code.google.com/p/idapython/


RESOURCES
---------

The full function cross-reference is readable online at
  http://www.hex-rays.com/idapro/idapython_docs/

Bugs and enhancement requests should be submitted to
  http://code.google.com/p/idapython/issues/list

Mailing list for the project is hosted by Google Groups at
  http://groups.google.com/group/idapython


INSTALLATION FROM BINARIES
--------------------------

1. Install 2.6 or 2.7 from http://www.python.org/
2. Copy "python" directory to %IDADIR%
3. Copy "plugins" directory to the %IDADIR%\plugins\
4. Copy "python.cfg" to %IDADIR%\cfg

USAGE
-----

 - Run script: File / Script file (Alt-F7)
 - Execute Python statement(s) (Ctrl-F3)
 - Run previously executed script again: View / Recent Scripts (Alt+F9)

Batch mode execution:

Start IDA with the following command line options:

 -A -OIDAPython:yourscript.py file_to_work_on
or
-Syourscript.py
or
-S"yourscript.py arg1 arg2 arg3"

(Please see http://www.hexblog.com/?p=128)

If you want fully unattended execution mode, make sure your script
exits with a qexit() call.

By default scripts run after the database is opened. Extended option
format is:

  -OIDAPython:[N;]script.py

Where N can be:
  0: run script after opening database (default)
  1: run script when UI is ready
  2: run script immediately on plugin load (shortly after IDA starts and before processor modules and loaders)

User init file:

You can place your custom settings to a file called 'idapythonrc.py'
that should be placed to

${HOME}/.idapro/

or

%AppData%\Hex-Rays\IDA Pro

The user init file is read and executed at the end of the init process.

Please note that IDAPython can be configured with "python.cfg" file.
