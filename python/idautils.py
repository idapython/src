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
"""
idautils.py - High level utility functions for IDA
"""
from idaapi import *

def refs(ea, funcfirst, funcnext):
	"""
	Generic reference collector - INTERNAL USE ONLY.
	"""
	reflist = []

	ref = funcfirst(ea)

	if ref != BADADDR:
		reflist.append(ref)

		while 1:
			ref = funcnext(ea, ref)

			if ref == BADADDR:
				break
			else:
				reflist.append(ref)
	
	return reflist
	

def CodeRefsTo(ea, flow):
	"""
	Get a list of code references to 'ea'

	@param ea:   Target address
	@param flow: Follow normal code flow or not 
	@type  flow: Boolean (0/1, False/True)

	@return: list of references (may be empty list)

	Example::
	
		for ref in CodeRefsTo(ScreenEA(), 1):
			print ref
	"""
	if flow == 1:
		return refs(ea, get_first_cref_to, get_next_cref_to)	
	else:
		return refs(ea, get_first_fcref_to, get_next_fcref_to)	


def CodeRefsFrom(ea, flow):
	"""
	Get a list of code references from 'ea'

	@param ea:   Target address
	@param flow: Follow normal code flow or not 
	@type  flow: Boolean (0/1, False/True)

	@return: list of references (may be empty list)

	Example::
	
		for ref in CodeRefsFrom(ScreenEA(), 1):
			print ref
	"""
	if flow == 1:
		return refs(ea, get_first_cref_from, get_next_cref_from)	
	else:
		return refs(ea, get_first_fcref_from, get_next_fcref_from)	


def DataRefsTo(ea):
	"""
	Get a list of data references to 'ea'

	@param ea:   Target address

	@return: list of references (may be empty list)

	Example::
	
		for ref in DataRefsTo(ScreenEA(), 1):
			print ref
	"""
	return refs(ea, get_first_dref_to, get_next_dref_to)	


def DataRefsFrom(ea):
	"""
	Get a list of data references from 'ea'

	@param ea:   Target address

	@return: list of references (may be empty list)

	Example::
	
		for ref in DataRefsFrom(ScreenEA(), 1):
			print ref
	"""
	return refs(ea, get_first_dref_from, get_next_dref_from)	


def Heads(start, end):
	"""
	Get a list of heads (instructions or data)

	@param start: start address (this one is always included)
	@param end:   end address

	@return: list of heads between start and end
	"""
	headlist = []
	headlist.append(start)

	ea = start

	while 1:
		ea = next_head(ea, end)

		if ea == BADADDR:
			break
		else:
			headlist.append(ea)
	
	return headlist
	

def Functions(start, end):
	"""
	Get a list of functions

	@param start: start address
	@param end:   end address

	@return: list of heads between start and end

	@note: The last function that starts before 'end' is included even
	if it extends beyond 'end'.
	"""
	startaddr = start
	endaddr = end

	funclist = []

	func = get_func(start)

	if func:
		funclist.append(func.startEA)

	ea = start

	while 1:
		func = get_next_func(ea)

		if not func: break

		if func.startEA < end:
			funclist.append(func.startEA)
			ea = func.startEA
		else:
			break

	return funclist
	

def Segments():
	"""
	Get list of segments (sections) in the binary image

	@return: List of segment start addresses.
	"""
	seglist = []

	for n in range(get_segm_qty()):
		seg = getnseg(n)

		if not seg:
			break
		else:
			seglist.append(seg.startEA)
	
	return seglist


def GetDataList(ea, count, itemsize=1):
	"""
	Get data list - INTERNAL USE ONLY
	"""
	getdata = None

	if itemsize == 1:
		getdata = get_byte
	if itemsize == 2:
		getdata = get_word
	if itemsize == 4:
		getdata = get_dword

	if getdata == None:
		raise ValueError, "Invalid data size! Must be 1, 2 or 4"

	list = []

	for offs in range(count):
		list.append(getdata(ea))
		ea = ea + itemsize

	return list


def PutDataList(ea, list, itemsize=1):
	"""
	Put data list - INTERNAL USE ONLY
	"""
	putdata = None

	if itemsize == 1:
		putdata = patch_byte
	if itemsize == 2:
		putdata = patch_word
	if itemsize == 4:
		putdata = patch_dword

	if putdata == None:
		raise ValueError, "Invalid data size! Must be 1, 2 or 4"

	for val in list:
		putdata(ea, val)
		ea = ea + itemsize


def MapDataList(ea, length, func, wordsize=1):
	"""
	Map through a list of data words in the database

	@param ea:       start address
	@param length:   number of words to map
	@param func:     mapping function
	@param wordsize: size of words to map [default: 1 byte]

	@return: None
	"""
	PutDataList(ea, map(func, GetDataList(ea, length, wordsize)), wordsize)


def GetInputFileMD5():
	"""
	Return the MD5 hash of the input binary file

	@return: MD5 string or None on error
	"""
	ua=ucharArray(16)
	if retrieve_input_file_md5(ua.cast()):
		md5str=""
		for i in range(16):
			md5str += "%02x" % ua[i]
		return md5str
	else:
		return None

