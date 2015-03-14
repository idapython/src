# Changes between IDAPython test builds #

## Changes between IDAPython version 0.9.56 and 0.9.57 ##
  * idc.py: Added missing idaapi. to GetMemberStrId()
  * dbg.i: First implementation of debug event callback
  * Added small test script for debug event notification hooks

## Changes between IDAPython version 0.9.55 and 0.9.56 ##

  * idc.py: Implemented Compile()
  * idautils.py: Do not import all symbols from idaapi to keep the namespace clean
  * init.py: Import the required symbols from idaapi
  * expr.i: Fixed Compile functions to return proper error messages
  * python.cpp: Added RunPythonStatement() function to IDC
  * expr.i: Added CompileEx() Compile() and CompileLine()
  * idaapi.i: Added sval\_pointer() type
  * idc.py: Fixed documentation for GetMarkedPos(), returns BADADDR on error
  * idc.py: Removed UNIMPLEMENTED marker from atoa()
  * Removed extra parameter from Get{First|Next}Member(). Thanks Rodrigo Bogossian Wang for the report.


## Changes between IDAPython version 0.9.54 and 0.9.55 ##

  * BUILDING.txt: Updated the building instructions for Mac
  * build.py: Suppressed warning messages about const char pointers
  * idp.i: Removed static keyword from IDB\_Callback
  * idp.i: Ignore all function pointer in structures
  * idc.py: Implmented {First|Next}FuncFChunk()
  * build.py: Version bumped to 0.9.55
  * idp.i: Fixed IDP\_Callback() prototype
  * idc.py: SetType() implemented. Thanks to plusvic.
  * idc.py: Structure offset member can also be 16-bit. Thanks plusvic
  * bytes.i: Added is\_debugger\_on()
  * bytes.i: Added {put|get}