"""
summary: create a structure by parsing its definition

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we create a structure using the "parsing" method.

level: beginner
"""
import ida_typeinf

# Create a struct with parsing.
struct_name = "pcap_hdr_s"
struct_str = """
typedef int int32_t;
typedef unsigned int uint32_t;

struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
};
"""


tif = ida_typeinf.tinfo_t(struct_str)

# Persist it to the "Local types" type library
tif.set_named_type(None, struct_name)
