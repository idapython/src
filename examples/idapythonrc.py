#---------------------------------------------------------------------
# Example user initialisation script: idapythonrc.py
#
# Place this script to ~/.idapro/ or to 
# %APPDATA%\Hex-Rays\IDA Pro
#---------------------------------------------------------------------
import idaapi

# Add your favourite script to ScriptBox for easy access
# scriptbox.addscript("/here/is/my/favourite/script.py")

# Uncomment if you want to set Python as default interpreter in IDA
# idaapi.enable_extlang_python(True)

# Disable the Python from interactive command-line
# idaapi.enable_python_cli(False)

# Set the timeout for the script execution cancel dialog
# idaapi.set_script_timeout(10)
