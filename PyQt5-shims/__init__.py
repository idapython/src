print("#" * 70)
print("""# Please note that IDA is now using Qt 6, and PyQt5
# support will be dropped eventually.
# It is recommended to port your scripts/plugins to PySide6
# as soon as possible.
# Essentially, that means rewriting statement such as:
#
#   import PyQt5
#   import PyQt5.QtWidgets
#   from PyQt5.QtGui import QGuiApplication
#
# into:
#
#   import PySide6
#   import PySide6.QtWidgets
#   from PySide6.QtGui import QGuiApplication""")
print("#" * 70)
