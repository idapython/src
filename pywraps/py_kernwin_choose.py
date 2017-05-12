
#<pycode(py_kernwin_choose)>
import _ida_idaapi

class Choose(object):
  """
  Choose - class for choose() with callbacks
  """
  def __init__(self, list, title, flags=0, deflt=1, icon=37):
    self.list = list
    self.title = title

    self.flags = flags
    self.x0 = -1
    self.x1 = -1
    self.y0 = -1
    self.y1 = -1

    self.width = -1
    self.deflt = deflt
    self.icon = icon

    # HACK: Add a circular reference for non-modal choosers. This prevents the GC
    # from collecting the class object the callbacks need. Unfortunately this means
    # that the class will never be collected, unless refhack is set to None explicitly.
    if (flags & Choose2.CH_MODAL) == 0:
      self.refhack = self


  def sizer(self):
    """
    Callback: sizer - returns the length of the list
    """
    return len(self.list)


  def getl(self, n):
    """
    Callback: getl - get one item from the list
    """
    if n == 0:
       return self.title
    if n <= self.sizer():
      return str(self.list[n-1])
    else:
      return "<Empty>"


  def enter(self, n):
    print "enter(%d) called" % n


  def choose(self):
    """
    choose - Display the choose dialogue
    """
    old = _ida_idaapi.set_script_timeout(0)
    n = _ida_kernwin.choose_choose(
        self,
        self.flags,
        self.x0,
        self.y0,
        self.x1,
        self.y1,
        self.width,
        self.deflt,
        self.icon)
    _ida_idaapi.set_script_timeout(old)
    return n
#</pycode(py_kernwin_choose)>
