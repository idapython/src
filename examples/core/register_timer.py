"""
summary: using timers for delayed execution

description:
  Register (possibly repeating) timers.
"""

import ida_kernwin

# -------------------------------------------------------------------------
class timercallback_t(object):
    def __init__(self):
        self.interval = 1000
        self.obj = ida_kernwin.register_timer(self.interval, self)
        if self.obj is None:
            raise RuntimeError("Failed to register timer")
        self.times = 5

    def __call__(self):
        print("Timer invoked. %d time(s) left" % self.times)
        self.times -= 1
        # Unregister the timer when the counter reaches zero
        return -1 if self.times == 0 else self.interval

    def __del__(self):
        print("Timer object disposed %s" % self)


# -------------------------------------------------------------------------
def main():
    try:
        t = timercallback_t()
        # No need to unregister the timer.
        # It will unregister itself in the callback when it returns -1
    except Exception as e:
        print("Error: %s" % e)


# -------------------------------------------------------------------------
if __name__ == '__main__':
    main()
