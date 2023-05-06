# pylint: disable=line-too-long,invalid-name,import-error

"""
summary: This example uses the mex1 example and improves the user-interface for it.

description:
  IDA Teams uses a chooser to display the merge conflicts.
  To fill the chooser columns IDA Teams uses the following methods from diff_source_t type:
    * print_diffpos_name()
    * print_diffpos_details()
  and UI hints from merge_handler_params_t type:
    * ui_has_details()
    * ui_complex_details()
    * ui_complex_name()

  In general, chooser columns are filled as following:
    columns.clear()
    NAME = print_diffpos_name()
    if ui_complex_name()
    then
      columns.add(split NAME by ui_split_char())
    else
      columns[0] = NAME
    if not ui_complex_details()
    then
      columns.add(print_diffpos_details())

  Also, see SDK/plugins/mex3 example
"""


import ida_idaapi
import ida_ida
import ida_kernwin
import ida_netnode
import ida_funcs
import ida_merge
import ida_mergemod
import ida_idp
import ida_nalt


# --------------------------------------------------------------------------
class idp_listener_t(ida_idp.IDP_Hooks):
    """
    we need an event listener to catch processor_t::ev_create_merge_handlers
    """

    def __init__(self, ctx):
        # by default IDP_Hooks uses ida_idp.HKCB_GLOBAL hkcb_flags,
        # in that case IDP events are sent to all DB instances.
        # Such behaviour does not matter for IDA Pro
        # but IDA Teams needs to have only one IDP event sent to plugin.
        # We set hkcb_flags to 0
        ida_idp.IDP_Hooks.__init__(self, 0, 0)
        self.ctx = ctx

    def ev_ending_undo(self):
        """
        A well behaving plugin should restore its state from the database
        upon ev_ending_undo. Otherwise its state may be conflicting with the
        database.
        """
        self.ctx.restore_from_idb()
        return 0

    def ev_create_merge_handlers(self, md):
        """
        This event occurs when IDA is performing a 3-way merge (for IDA Teams)
        Our plugins should create and register merge handler(s) for its data.
        """
        self.ctx.create_merge_handlers(md)
        return 0


# --------------------------------------------------------------------------
# netnode to store plugin data
MEX_NODE_NAME = "$ idapython mex3"
# user input
MEX_OPTION_FLAGS_IDX = ida_idaapi.BADADDR & -1   # atag
MEX_OPTION_IDENT_IDX = ida_idaapi.BADADDR & -2   # stag
# EA marks
MEX_EA_TAG = 'm'

# mex_ctx_t::flags bits
MEX_FLAGS_0 = 0x01
MEX_FLAGS_1 = 0x02

class mex_ctx_t(ida_idaapi.plugmod_t):
    """
    Regular plugin implementation below.
    For example, in our case the plugin asks for 2 bit values and a string value.
    Then the plugin stores this data in the database.
    And mark the start address of the current function.
    These data will be merged later.
    """

    def __init__(self):
        # bit flags, see above MEX_FLAGS_0/MEX_FLAGS_1
        self.flags = 0
        # unique database ident
        self.ident = ""
        # Restore the plugin data from the database into the memory.
        self.restore_from_idb()
        # Hook an event listener, to catch the merge-related event(s).
        self.idp_listener = idp_listener_t(self)
        self.idp_listener.hook()
        # MERGE: the following data must exist during plugin lifetime
        self.modmerger_helper = None
        self.idpopts_info = None
        self.node_helper = None
        self.merge_node_info = None

    def save_to_idb(self):
        """ Save the plugin state to the idb. """
        nn = ida_netnode.netnode(MEX_NODE_NAME, 0, True)
        nn.altset(MEX_OPTION_FLAGS_IDX, self.flags)
        nn.supset(MEX_OPTION_IDENT_IDX, self.ident)

    def restore_from_idb(self):
        """ Restore plugin variables from the idb. """
        nn = ida_netnode.netnode(MEX_NODE_NAME)
        if nn != ida_netnode.BADNODE:
            self.flags = nn.altval(MEX_OPTION_FLAGS_IDX)
            self.ident = nn.supstr(MEX_OPTION_IDENT_IDX)

    def run(self, _):
        """
        Ask user for the data and save them to database.
        Add mark for current EA.
        """
        if self._ask_form():
            self.save_to_idb()
        # Our plugin stores a string for the current function.
        # Just for illustration purposes of how plugins should merge address-specific info
        # stored in a netnode.
        ea = ida_kernwin.get_screen_ea()
        pfn = ida_funcs.get_func(ea)
        if pfn:
            one = ""
            if (self.flags & MEX_FLAGS_0) != 0:
                one = " one"
            two = ""
            if (self.flags & MEX_FLAGS_1) != 0:
                one = " two"
            mark = "IPMEX1" + one + two
            nn = ida_netnode.netnode(MEX_NODE_NAME, 0, True)
            nn.supset_ea(pfn.start_ea, mark, MEX_EA_TAG)

    def _ask_form(self):
        class MexForm(ida_kernwin.Form):
            def __init__(self):
                ida_kernwin.Form.__init__(self,
                r"""
IDAPython: merge example 1

<Flag 0:{optFlag0}>
<Flag 1:{optFlag1}>{grpFlags}>
<Ident prefix:{ident}>
                """,
                {
                    "grpFlags": ida_kernwin.Form.ChkGroupControl(("optFlag0", "optFlag1")),
                    "ident"   : ida_kernwin.Form.StringInput(swidth=10),
                })

        form = MexForm()
        form, _ = form.Compile()
        form.grpFlags.value = self.flags
        form.ident.value = self.ident
        ok = form.Execute()
        if ok == 1:
            self.flags = form.grpFlags.value
            self.ident = form.ident.value
        form.Free()
        return ok == 1

    def create_merge_handlers(self, md):
        """
        Create merge handlers for plugin
        """

        #-------------------------------------------------------------------------
        # 1. Data common for entire database (e.g. the options).
        #
        # This example shows how to merge the data from database.
        # We will describe the items to merge and pass the description
        # to create_std_modmerge_handlers(), which will do all the work for us.
        sizeof_flags = ida_netnode.SIZEOF_nodeidx_t
        self.idpopts_info = [
            # Describe both flags
            ida_ida.idbattr_info_t("MEX flag 0", MEX_OPTION_FLAGS_IDX, sizeof_flags, MEX_FLAGS_0, ida_netnode.atag, ida_ida.IDI_ALTVAL|ida_ida.IDI_SCALAR),
            ida_ida.idbattr_info_t("MEX flag 1", MEX_OPTION_FLAGS_IDX, sizeof_flags, MEX_FLAGS_1, ida_netnode.atag, ida_ida.IDI_ALTVAL|ida_ida.IDI_SCALAR),
            # Describe ident
            ida_ida.idbattr_info_t("MEX ident",  MEX_OPTION_IDENT_IDX, 0,            0,           ida_netnode.stag, ida_ida.IDI_SUPVAL|ida_ida.IDI_CSTR),
        ]

        # The descriptions are ready. Now create an instance of the standard helper
        # class to be passed to the kernel, and the kernel will take care of organizing
        # the merge process for them.

        # helper instance name
        self.modmerger_helper = ida_merge.moddata_diff_helper_t(
            "Sample merge data", # label: prefix for the attribute names, e.g. "Sample merge data.MEX flag 0"
            MEX_NODE_NAME,       # netnode name for idpopts_info and merge_node_info
            self.idpopts_info)   # field descriptions

        # Merge handler created from idbattr_info_t with the MH_UI_NODETAILS UI hint.
        # Its linear_diff_source_t::get_diffpos_name() method returns NAME constructed as following:
        #   * prefix if any, f.e. "Sample merge data", concatenated with "."
        #   * add item name, f.e. "MEX flag 0"
        #   * add ": "
        #   * add item value
        # You might have noticed this when checking the mex1 and mex2 examples
        #
        # In this case we can improve UI look if add MH_UI_COLONNAME UI hint to merge_handler_params_t.

        #-------------------------------------------------------------------------
        # 2. Data specific to a particular address.
        #
        # To improve UI look for this merge handler we can create a subclass of merge_node_helper_t type.
        class node_helper_t(ida_merge.merge_node_helper_t):
            def __init__(self):
                ida_merge.merge_node_helper_t.__init__(self)
            def print_entry_name(self, tag, ndx, _):
                """ is called from print_diffpos_name() """
                if  tag != ord(MEX_EA_TAG):
                    return ""
                # get item value
                eanode = ida_netnode.netnode(MEX_NODE_NAME)
                ea = ida_nalt.node2ea(ndx)
                mark = eanode.supstr_ea(ea, MEX_EA_TAG)
                # prepare NAME
                ea_nice_name = ida_merge.get_ea_diffpos_name(ea)
                return "%s,%s" % (ea_nice_name, mark)
            def get_column_headers(self, _1, tag, _2):
                """ column headers for chooser """
                return ["Address", "Mark"] if tag == ord(MEX_EA_TAG) else []
        self.node_helper = node_helper_t()

        # We describe how the data is stored in a netnode.
        self.merge_node_info = [
            ida_merge.merge_node_info_t(
                "Function marks",       # label of the merge handler, e.g. "Plugins/Merge example 3/Function marks"
                MEX_EA_TAG,             # netnode tag
                ida_merge.NDS_MAP_IDX|ida_merge.NDS_IS_STR,
                                        # netnode value descriptors and modificators, see \ref nds_flags_t
                self.node_helper
            ),
        ]

        #-------------------------------------------------------------------------
        # Now we should combine together in function create_merge_handlers.
        # This function will be called on processor_t::ev_create_merge_handlers event.
        # As a result, two merge handlers with labels
        #   "Plugins/Merge example 3/Database attributes"
        #   "Plugins/Merge example 3/Function marks"
        # will be created.
        mhp = ida_merge.merge_handler_params_t(
            md,                                  # merge handler data
            "Plugins/IDAPython merge example 3", # Label of the merge handler
            ida_merge.MERGE_KIND_NONE,           # allocate a merge kind
            ida_merge.MERGE_KIND_END,            # insert to the end of handler list
            ida_merge.MH_UI_COLONNAME)           # Create multi-column chooser, split diffpos names using ':'

        # create merge handler for idbattr_info_t, it will use MH_UI_COLONNAME.
        # MH_UI_COLONNAME will ensure that the diffpos names will be split by ':'
        # and displayed as separate columns in a chooser. Multi-column choosers
        # are easier to work with for the user.
        ida_mergemod.create_std_modmerge_handlers(mhp, self.modmerger_helper)

        # create merge handlers for merge_node_info_t, it will use MH_UI_NODETAILS.
        mhp.mh_flags = (ida_merge.MH_UI_COMMANAME  # Create multi-column chooser, split diffpos names using ','
                      | ida_merge.MH_UI_NODETAILS) # do not display the detail pane
        ida_merge.create_nodeval_merge_handlers(
              None,
              mhp,
              MEX_NODE_NAME,
              self.merge_node_info)


# --------------------------------------------------------------------------
class mex3_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_MOD
    wanted_name = "IDAPython: Merge example 3"
    comment = "IDAPython: An example 1 how to implement IDA merge functionality"
    wanted_hotkey = ""
    help = ""
    def init(self):
        return mex_ctx_t()
    def term(self):
        pass
    def run(self, arg):
        pass
def PLUGIN_ENTRY():
    return mex3_plugin_t()
