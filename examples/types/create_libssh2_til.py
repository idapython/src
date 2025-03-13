"""
summary: create a type library file

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script:
     * We create a new libssh2-64.til file holding some libssh2 64-bit structures.
     * Once the file has been created, it can copied in the IDA install
       til directory or in the user IDA til directory.

level: intermediate
"""
import ida_typeinf
import ida_kernwin

libssh2_types = """
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef __int64 size_t;

struct _LIBSSH2_USERAUTH_KBDINT_PROMPT
{
    unsigned char *text;
    size_t length;
    unsigned char echo;
};
typedef struct _LIBSSH2_USERAUTH_KBDINT_PROMPT LIBSSH2_USERAUTH_KBDINT_PROMPT;

struct _LIBSSH2_USERAUTH_KBDINT_RESPONSE
{
    char *text;
    unsigned int length;
};
typedef struct _LIBSSH2_USERAUTH_KBDINT_RESPONSE LIBSSH2_USERAUTH_KBDINT_RESPONSE;

struct _LIBSSH2_SK_SIG_INFO {
    uint8_t flags;
    uint32_t counter;
    unsigned char *sig_r;
    size_t sig_r_len;
    unsigned char *sig_s;
    size_t sig_s_len;
};
typedef struct _LIBSSH2_SK_SIG_INFO LIBSSH2_SK_SIG_INFO;

"""


def create_libssh2_til():

    # Create a new til file.
    til = ida_typeinf.new_til("libssh2-64.til", "Some libssh2 types")

    # Parse the declaratiion, ignoring redeclaration warnings and applying default packing/
    if ida_typeinf.parse_decls(til, libssh2_types, None, ida_typeinf.HTI_DCL | ida_typeinf.HTI_PAKDEF) != 0:
        raise Exception("Failed to parse the libssh2 declarations.\n")

    ida_typeinf.compact_til(til)

    return til


if __name__ == "__main__":
    til = create_libssh2_til()

    print("Create type library with the following types")
    for tif in til.named_types():
        print("\t%s" % str(tif))

    # The save the til in the current working directory.
    if ida_typeinf.store_til(til, None, "libssh2-64.til"):
        print("TIL file stored on disk.\n")

    ida_typeinf.free_til(til)
