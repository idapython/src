# IDAPython in a Nutshell #

IDAPython is an IDA Pro plugin that integrates the Python programming language, allowing scripts to run in IDA Pro. These programs have access to IDA Plugin API, IDC and all modules available for Python. The power of IDA Pro and Python provides a platform for easy prototyping of reverse engineering and other research tools.

# News #

**2015-02-07**: Version 1.7.1
```
* IDA Pro 6.7 support - Thanks to the Hex-Rays team for contributing this new release!

* Added support for the new set of functions for dealing with user-provided actions
* add idaapi.get_kernel_version() 
* added ability to build IDAPython with Hex-Rays bindings by specifying a path to a directory where to find the 'hexrays.hpp' file 
* added APIs for accessing the registry 
* added APIs for working with breakpoint groups 
* added umsg() for printing UTF-8 text into the Output Window 
* construct_macro() is now available to IDAPython processor modules 
* export get_custom_viewer_place(), and allow place_t clone() & related functions 
* expose QueueDel(qtype_t, ea_t), to complete APIs for manipulating entries from the "known list of problems" 
* get_tform_type()/get_tform_title(), & current_tform_changed callback 
* give users the ability to access the underlying TForm/TCutsomControl objects that back higher-level Pythony wrappers, so that the rest of the SDK API can be used as well 
* improve stability and error reporting for Python processor modules 
* Scripts can use OnViewMouseMoved() callback to be notified of mouse movement on views (both user-created, as well as core IDA views) 
* User graphs: double-clicking on a graph edge, will (by default) jump to the node on the other side of that edge 
* Various bug fixes

```

**2014-07-01**: Version 1.7.0
```
* IDA Pro 6.6 support - Thanks to the Hex-Rays team for contributing this new release!

* added the decompiler bindings
* Expose simpleline_t type to IDAPython. That lets the user to set the bgcolor &
text for each line in the decompilation.
* Wrapped new functions from the IDA SDK
* Various bug fixes
```

**2013-12-30**: Version 1.6.0
```
* IDA Pro 6.5 support - Thanks to Arnaud Diederen and the Hex-Rays team for contributing this new release!
* Proper multi-threaded support
* Better PyObject reference counting with ref_t and newref_t helper classes
* Introduced the idaapi.require() - blog post http://www.hexblog.com/?p=749
* Various additions and bugfixes - see https://code.google.com/p/idapython/source/detail?r=382
* Hex-Rays decompiler wrappings provided by EiNSTeiN - see https://github.com/EiNSTeiN-/hexrays-python
```

**2013-03-06**: Version 1.5.6
```
* IDA Pro 6.4 support
* Bug fixes
* Wrapped more debugger functions
```


**2012-06-24**: Version 1.5.5
```
* IDA Pro 6.3 support
* The Functions() generator function now accepts function tail start parameter
* Added into idc.py: DbgRead/DbgWrite/SetTargetAssembler and stack pointer
related functions
* Wrapped more type info related functions
```

**2011-10-15**: Version 1.5.3 - IDA Pro 6.2 support, hotkey functions, multiline/combo form controls and [other changes](http://code.google.com/p/idapython/source/detail?r=365).

**2011-07-27**: Version 1.5.2.3 - Vuln fix to prevent arbitrary code execution via swig\_runtime\_data4.py? when placed in the current directory (
[details](http://code.google.com/p/idapython/source/detail?r=361)).

**2011-06-10**: Version 1.5.2 - Few features and mostly bug fixes.

**2011-04-21**: Version 1.5.1 - Added the '?' and '!' pseudo commands and fixed some bugs [other changes](http://code.google.com/p/idapython/source/detail?r=348).

**2011-04-18**: Version 1.5.0 - IDA Pro 6.1 support, AskUsingForm support, added UI notification hooks and [other changes](http://code.google.com/p/idapython/source/detail?r=344).

**2010-11-10**: Version 1.4.3 - IDA Pro 6.0 support, PluginForms class to work with PySide or PyQt4 and [other changes](http://code.google.com/p/idapython/source/detail?r=335).

**2010-08-10**: Version 1.4.2 - Fixed some bugs and made sure it works fine with Python 2.7

**2010-07-19**: Version 1.4.1 - Added basic command completion feature.

**2010-06-30**: Version 1.4.0 with IDA Pro 5.7 support is now out. See the SVN repository for the [detailed changelog](http://code.google.com/p/idapython/source/list).

**2009-07-12**: Version 1.2.0 with 64-bit support is now out. See the SVN repository for the [detailed changelog](http://code.google.com/p/idapython/source/list).

# Documentation #

  * [Building](Building.md)
  * InstallationInstructions
  * UsageInstructions
  * KnownUses

# Getting Involved #

All contributions are welcome. The preferred way of submitting bug reports and patches is through the
Issue Tracker. The project also has a [discussion group](http://groups.google.com/group/idapython).

For anything else, just drop an email to the [project owner](http://code.google.com/u/elias.bachaalany/).