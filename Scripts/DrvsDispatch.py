"""

A script to demonstrate how to send commands to the debugger and then parse and use the output in IDA

Copyright (c) 1990-2009 Hex-Rays
ALL RIGHTS RESERVED.

"""

import re
from idaapi import Choose

# -----------------------------------------------------------------------
def CmdDriverList():
  s = Eval('WinDbgCommand("lm o");')
  if "IDC_FAILURE" in s: return False
  return s

# -----------------------------------------------------------------------
def CmdDrvObj(drvname, flag=2):
  return Eval('WinDbgCommand("!drvobj %s %d");' % (drvname, flag))

# -----------------------------------------------------------------------
def CmdReloadForce():
  s = Eval('WinDbgCommand(".reload /f");')
  if "IDC_FAILURE" in s: return False
  return True

# -----------------------------------------------------------------------
# class to hold dispatch entry information
class DispatchEntry:
    def __init__(self, addr, name):
        self.addr = addr
        self.name = name
    def __repr__(self):
        return "%08X: %s" % (self.addr, self.name)

# -----------------------------------------------------------------------
def GetDriverDispatch():

  # return a list of arrays of the form: [addr, name]
  ret_list = []
  
  # build the RE for parsing output from the "lm o" command
  re_drv = re.compile('^[a-f0-9]+\s+[a-f0-9]+\s+(\S+)', re.I)

  # build the RE for parsing output from the "!drvobj DRV_NAME 2" command
  re_tbl = re.compile('^\[\d{2}\]\s+IRP_MJ_(\S+)\s+([0-9a-f]+)', re.I)

  # force reloading of module symbols
  if not CmdReloadForce():
    print "Could not communicate with WinDbg, make sure the debugger is running!"
    return None

  # get driver list
  lm_out = CmdDriverList()
  if not lm_out: 
    return "Failed to get driver list!"

  # for each line
  for line in lm_out.split("\n"):
    # parse
    r = re_drv.match(line)
    if not r: continue

    # extract driver name
    drvname = r.group(1).strip()

    # execute "drvobj" command
    tbl_out = CmdDrvObj(drvname)

    if not tbl_out: 
      print "Failed to get driver object for", drvname
      continue

    # for each line
    for line in tbl_out.split("\n"):
      # parse
      r = re_tbl.match(line)
      if not r: continue
      disp_addr = int(r.group(2), 16) # convert hex string to number
      disp_name = "Dispatch" + r.group(1)
      ret_list.append(DispatchEntry(disp_addr, drvname + "_" + disp_name))

  return ret_list

# -----------------------------------------------------------------------
# Chooser class
class DispatchChoose(Choose):
    def __init__(self, list, title):
        Choose.__init__(self, list, title)
        self.width = 250

    def enter(self, n):
        o = self.list[n-1]
        idc.Jump(o.addr)

# -----------------------------------------------------------------------
# main
r = GetDriverDispatch()
if r:
    c = DispatchChoose(r, "Dispatch table browser")
    c.choose()
else:
  print "Failed to retrieve dispatchers list!"