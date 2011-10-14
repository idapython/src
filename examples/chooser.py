#---------------------------------------------------------------------
# Chooser test
#
# This script demonstrates the usage of the class-based chooser.
#
# Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#---------------------------------------------------------------------
from idaapi import Choose

#
# Modal chooser
#

# Get a modal Choose instance
chooser = Choose([], "MyChooser", 1)
# List to choose from
chooser.list = [ "First", "Second", "Third" ]
# Set the width
chooser.width = 50
# Run the chooser
ch = chooser.choose()
# Print the results
if ch > 0:
    print "You chose %d which is %s" % (ch, chooser.list[ch-1])
else:
    print "Escape from chooser"

#
# Normal chooser
#
class MyChoose(Choose):
    """
    You have to subclass Chooser to override the enter() method
    """
    def __init__(self, list=[], name="Choose"):
        Choose.__init__(self, list, name)
        # Set the width
        self.width = 50
        self.deflt = 1

    def enter(self, n):
        print "Enter called. Do some stuff here."
        print "The chosen item is %d = %s" % (n, self.list[n-1])
        print "Now press ESC to leave."

# Get a Choose instance
chooser = MyChoose([ "First", "Second", "Third" ], "MyChoose")

# Run the chooser
ch = chooser.choose()
