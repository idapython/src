#---------------------------------------------------------------------
# Colour test
#
# This script demonstrates the usage of background colours.
#
# Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#---------------------------------------------------------------------

# Set the colour of the current segment to BLUE
SetColor(here(), CIC_SEGM, 0xc02020)
# Set the colour of the current function to GREEN
SetColor(here(), CIC_FUNC, 0x208020)
# Set the colour of the current item to RED
SetColor(here(), CIC_ITEM, 0x2020c0)

# Print the colours just set
print "%x" % GetColor(here(), CIC_SEGM)
print "%x" % GetColor(here(), CIC_FUNC)
print "%x" % GetColor(here(), CIC_ITEM)
