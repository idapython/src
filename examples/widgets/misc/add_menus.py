"""
summary: adding custom menus to IDA

description:
  It is possible to add custom menus to IDA, either at the
  toplevel (i.e., into the menubar), or as submenus of existing
  menus.

  Notes:

    * the same action can be present in more than 1 menu
    * this example does not deal with context menus

keywords: actions
"""

import ida_kernwin

# Create custom menus
ida_kernwin.create_menu("MyToplevelMenu", "&Custom menu", "View")
ida_kernwin.create_menu("MySubMenu", "Custom s&ubmenu", "View/Print internal flags")

# Create some actions
class greeter_t(ida_kernwin.action_handler_t):
    def __init__(self, greetings):
        ida_kernwin.action_handler_t.__init__(self)
        self.greetings = greetings

    def activate(self, ctx):
        print(self.greetings)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

ACTION_NAME_0 = "my_action_0"
ACTION_NAME_1 = "my_action_1"
for action_name, greetings in [
        (ACTION_NAME_0, "Hello, world"),
        (ACTION_NAME_1, "Hi there"),
]:
    desc = ida_kernwin.action_desc_t(
        action_name, "Say \"%s\"" % greetings, greeter_t(greetings))
    if ida_kernwin.register_action(desc):
        print("Registered action \"%s\"" % action_name)


# Then, let's attach some actions to them - both core actions
# and custom ones is allowed (also, any action can be attached
# to multiple menus.)
for action_name, path in [
        (ACTION_NAME_0, "Custom menu"),
        (ACTION_NAME_0, "View/Custom submenu/"),
        (ACTION_NAME_1, "Custom menu"),
        (ACTION_NAME_1, "View/Custom submenu/"),
        ("About", "Custom menu"),
        ("About", "View/Custom submenu/"),
]:
    ida_kernwin.attach_action_to_menu(
        path,
        action_name,
        ida_kernwin.SETMENU_INS)
