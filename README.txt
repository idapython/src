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
  http://www.d-dome.net/idapython/

Development builds are available from
  http://code.google.com/p/idapython/


RESOURCES
---------

The full function cross-reference is readable online at
  http://www.d-dome.net/idapython/reference/

Bugs and enhancement requests should be submitted to
  http://code.google.com/p/idapython/issues/list

Mailing list for the project is hosted by Google Groups at
  http://groups.google.com/group/idapython


INSTALLATION FROM BINARIES
--------------------------

1, Install Python 2.5 from http://www.python.org/
2, Copy the directory python\ to the IDA install directory
3. Copy the plugin to the %IDADIR%\plugins\


USAGE
-----

The plugin has three hotkeys: 

 - Run script (Alt-9)
 - Execute Python statement(s) (Alt-8)
 - Run previously executed script again (Alt-7)

Batch mode execution:

Start IDA with the following command line options:

 -A -OIDAPython:yourscript.py file_to_work_on

If you want fully unattended execution mode, make sure your script
exits with a qexit() call.


User init file:

You can place your custom settings to a file called 'idapythonrc.py'
that should be placed to 

${HOME}/.idapro/

or 

C:\Documents and Settings\%USER%\Application Data\Datarescue\IDA Pro

The user init file is read and executed at the end of the init process.

