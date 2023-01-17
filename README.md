# IDAPython
## Python plugin for Interactive Disassembler

IDAPython is an IDA plugin which makes it possible to write scripts
for IDA in the Python programming language. IDAPython provides full
access to both the IDA API and any installed Python module.

Check the scripts in the examples directory to get an quick glimpse.

## Availability

Latest stable versions of IDAPython are available from
  https://github.com/idapython/src

## Resources

The full function cross-reference is readable online at
  https://www.hex-rays.com/products/ida/support/idapython_docs/

Mailing list for the project is hosted by Google Groups at
  https://groups.google.com/g/idapython

## Installation from binaries

1. Install latest Python 3.x version from https://www.python.org/
2. Copy the whole "python" directory to `%IDADIR%`
3. Copy "idapython.cfg" to `%IDADIR%\cfg`

## Usage

 - Run script: File / Script file (`Alt+F7`)
 - Execute Python statement(s) (`Shift+F2`)
 - Run previously executed script again: View / Recent Scripts (`Alt+F9`)

### Batch mode execution:

Start IDA with the following command line options:
```
 -A -OIDAPython:yourscript.py file_to_work_on
 ```
or
```
-Syourscript.py
```
or
```
-S"yourscript.py arg1 arg2 arg3"
```

(Please see https://hex-rays.com/blog/running-scripts-from-the-command-line-with-idascript/)

If you want fully unattended execution mode, make sure your script
exits with a `qexit()` call.

By default scripts run after the database is opened. Extended option
format is:
```
  -OIDAPython:[N;]script.py
```
Where N can be:
  0: run script after opening database (default)
  1: run script when UI is ready
  2: run script immediately on plugin load (shortly after IDA starts and before processor modules and loaders)

### User init file

You can place your custom settings to a file called `idapythonrc.py`
that should be placed to
```sh
${HOME}/.idapro/
```
or
```cmd
%AppData%\Hex-Rays\IDA Pro
```
The user init file is read and executed at the end of the init process.

Please note that IDAPython can be configured with `idapython.cfg` file.

### Invoking Python from IDC

The IDAPython plugin exposes a new IDC function `exec_python(string python_code)` that allows execution
of Python code from IDC.

### Invoking IDC from Python

It is possible to use the `idc.eval_idc()` to evaluate IDC expressions from Python.

### Switching the default language between Python and IDC

By default, IDA will use IDC to evaluate expressions in dialog boxes and in `eval_expr()`.  
It is possible to change the default language to Python.

In order to do that, use the following (IDC/Python) code:
```c
load_and_run_plugin("idapython", 3)
```
To go back to IDC, use the following code:
```c
load_and_run_plugin("idapython", 4)
```
