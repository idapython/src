#!/usr/bin/env python
#------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler Pro
#
# Copyright (c) 2004-2007 Gergely Erdelyi <dyce@d-dome.net> 
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#------------------------------------------------------------
# init.py - Essential init routines
#------------------------------------------------------------
import sys, os, os.path, traceback, warnings
import _idaapi

# FIXME: Should fix the offending constant instead
warnings.filterwarnings('ignore', category=FutureWarning)


def addscriptpath(script):
	"""
	Add the path part of the scriptfile to the system path to
	allow modules to be loaded from the same place.

	Each path is added only once.
	"""
	pathfound = 0

	scriptpath = os.path.dirname(script)

	for pathitem in sys.path:
		if pathitem == scriptpath:
			pathfound = 1
			break
	
	if pathfound == 0:
		sys.path.append(scriptpath)

	# Add the script to ScriptBox if it's not there yet
	if not script in ScriptBox_instance.list:
		ScriptBox_instance.list.insert(0, script)


def runscript(script):
	"""
	Run the specified script after adding its directory path to
	system path.

	This function is used by the low-level plugin code.
	"""
	addscriptpath(script)
	argv = sys.argv
	sys.argv = [ script ]
	execfile(script, globals())
	sys.argv = argv

def print_banner():
	version1 = "IDAPython version %d.%d.%d %s (serial %d) initialized" % IDAPYTHON_VERSION
	version2 = "Python interpreter version %d.%d.%d %s (serial %d)" % sys.version_info
	linelen  = max(len(version1), len(version2))

	print '-' * linelen
	print version1
	print version2
	print '-' * linelen


#-----------------------------------------------------------
# Take over the standard text outputs
#-----------------------------------------------------------
class MyStdOut:
	"""
	Dummy file-like class that receives stout and stderr
	"""
	def write(self, text):
		_idaapi.msg(text.replace("%", "%%"))

	def flush(self):
		pass


# Redirect stderr and stdout to the IDA message window
sys.stdout = sys.stderr = MyStdOut()

# Assign a default sys.argv
sys.argv = [ "" ]

# Have to make sure Python finds our modules
sys.path.append(_idaapi.idadir("python"))

print_banner()

#-----------------------------------------------------------
# Import all the required modules
#-----------------------------------------------------------
from idaapi import Choose, get_user_idadir, cvar
from idc import *
from idautils import *


#-----------------------------------------------------------
# Build up the ScriptBox tool
#-----------------------------------------------------------
class ScriptBox(Choose):
	def __init__(self, list=[]):
		Choose.__init__(self, list, "ScriptBox", 1)
		self.width = 50

	def run(self):
		if len(self.list) == 0:
			Warning("ScriptBox history is empty.\nRun some script with Alt-9 and try again.")
			return None

		n = self.choose()
	
		if n > 0:
			return self.list[n-1]
		else:
			return None

	def addscript(self, scriptpath):
			self.list.append(scriptpath)

ScriptBox_instance = ScriptBox([])

# Load the users personal init file
userrc = get_user_idadir() + os.sep + "idapythonrc.py"

if os.path.exists(userrc):
	runscript(userrc)
	# Remove the user script from the history
	del ScriptBox_instance.list[0]


# All done, ready to rock.
