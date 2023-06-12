"""
summary: execute existing actions programmatically

description:
  It's possible to invoke any action programmatically, by using
  either of those two:

    * ida_kernwin.execute_ui_requests()
    * ida_kernwin.process_ui_action()

  Ideally, this script should be run through the "File > Script file..."
  menu, so as to keep focus on "IDA View-A" and have the
  'ProcessUiActions' part work as intended.

keywords: actions
"""

import ida_kernwin

# --------------------------------------------------------------------------
class __process_ui_actions_helper(object):
    def __init__(self, actions, flags = 0):
        """Expect a list or a string with a list of actions"""
        if isinstance(actions, str):
            lst = actions.split(";")
        elif isinstance(actions, (list, tuple)):
            lst = actions
        else:
            raise ValueError("Must pass a string, list or a tuple")

        # Remember the action list and the flags
        self.__action_list = lst
        self.__flags = flags

        # Reset action index
        self.__idx = 0

    def __len__(self):
        return len(self.__action_list)

    def __call__(self):
        if self.__idx >= len(self.__action_list):
            return False

        # Execute one action
        aname = self.__action_list[self.__idx]
        print("executing: %s (flags=0x%x)" % (aname, self.__flags))
        print("=> %s" % ida_kernwin.process_ui_action(aname, self.__flags))

        # Move to next action
        self.__idx += 1
        print("index=%d" % self.__idx)

        # Reschedule
        return True

# --------------------------------------------------------------------------
def ProcessUiActions(actions, flags=0):
    """
    @param actions: A string containing a list of actions separated by semicolon, a list or a tuple
    @param flags: flags to be passed to process_ui_action()
    @return: Boolean. Returns False if the action list was empty or execute_ui_requests() failed.
    """

    # Instantiate a helper
    helper = __process_ui_actions_helper(actions, flags)
    return False if len(helper) < 1 else ida_kernwin.execute_ui_requests((helper,))


# --------------------------------------------------------------------------
class print_req_t(object):
    def __init__(self, s):
        self.s = s
    def __call__(self):
        ida_kernwin.msg("%s" % self.s)
        return False # Don't reschedule


if ida_kernwin.ask_yn(
        1, ("HIDECANCEL\nDo you want to run execute_ui_requests() example?\n"
            "Press NO to execute ProcessUiActions() example\n")):
    ida_kernwin.execute_ui_requests(
        (print_req_t("Hello"),
         print_req_t(" world\n")) )
else:
    ProcessUiActions("JumpQ;Breakpoints")
