from __future__ import print_function
#---------------------------------------------------------------------
# Colour test
#
# This script demonstrates the usage of background colours.
#
# Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#---------------------------------------------------------------------

# Set the colour of the current segment to BLUE
set_color(here(), CIC_SEGM, 0xc02020)
# Set the colour of the current function to GREEN
set_color(here(), CIC_FUNC, 0x208020)
# Set the colour of the current item to RED
set_color(here(), CIC_ITEM, 0x2020c0)

# Print the colours just set
print("%x" % get_color(here(), CIC_SEGM))
print("%x" % get_color(here(), CIC_FUNC))
print("%x" % get_color(here(), CIC_ITEM))
