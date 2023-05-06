"""
summary: code to be run right after IDAPython initialization

description:
  The `idapythonrc.py` file:

    * %APPDATA%\Hex-Rays\IDA Pro\idapythonrc.py (on Windows)
    * ~/.idapro/idapythonrc.py (on Linux & Mac)

  can contain any IDAPython code that will be run as soon as
  IDAPython is done successfully initializing.
"""

# Add your favourite script to ScriptBox for easy access
# scriptbox.addscript("/here/is/my/favourite/script.py")

# Uncomment if you want to set Python as default interpreter in IDA
# import ida_idaapi
# ida_idaapi.enable_extlang_python(True)

# Disable the Python from interactive command-line
# import ida_idaapi
# ida_idaapi.enable_python_cli(False)

# Set the timeout for the script execution cancel dialog
# import ida_idaapi
# ida_idaapi.set_script_timeout(10)
