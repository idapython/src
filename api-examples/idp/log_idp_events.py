"""
summary: being notified, and logging some IDP events

description:
  hooks to be notified about certain IDP events, and
  dump their information to the "Output" window
  See enum event_t in idp.hpp for additional.
"""
import inspect
import ida_idp
import ida_ua

class idp_logger_hooks_t(ida_idp.IDP_Hooks):
    def __init__(self):
        ida_idp.IDP_Hooks.__init__(self)
        self.inhibit_log = 0
    
    def _format_value(self, v):
        return str(v)
    
    def _log(self, msg=None):
        if self.inhibit_log <= 0:
            if msg:
                print(f'>>> idp_logger_hooks_f: {msg}')
            else:
                stack = inspect.stack()
                frame, _, _, _, _, _ = stack[1]
                args, _, _, values = inspect.getargvalues(frame)
                method_name = inspect.getframeinfo(frame)[2]
                argstrs = []
                for arg in args[1:]:
                    argstrs.append("%s=%s" % (arg, self._format_value(values[arg])))
                print(f'>>> idp_logger_hooks_t.{method_name}: {", ".join(args)}')
        return 0
    
    def ev_init(self, idp_modname):
        """
        The IDP module is just loaded.
        idp_modname - processor module name
        Returns: <0 on failure
        """
        return self._log(f'idp_logger_hooks_t.ev_init(self, {idp_modname})')

    def ev_term(self):
        """
        The IDP module is being unloaded
        """
        return self._log()
    
    def ev_newprc(self, nproc, keep_cfg):
        """
        Before changing proccesor type
        nproc - processor number in the array of processor names
        Returns: >=0-ok,<0-prohibit
        """
        return self._log()
    
    def ev_newasm(self, asmnum):
        """
        Before setting a new assembler.
        """
        return self._log()
    
    def ev_newfile(self, fname):
        """
        A new file has been loaded.
        """
        return self._log()
    
    def ev_oldfile(self, filename):
        """
        An old file has been loaded.
        """
        return self._log()
    
    def ev_newbinary(self, filename, fileoff, basepara, binoff, nbytes):
        """
        Before loading a binary file
        """
        return self._log()
    
    def ev_endbinary(self, ok):
        """
        After loading a binary file
        Returns: >=0-ok
        """
        return self._log()
    
    def ev_set_idp_options(self, keyword, value_type, value, idb_loaded):
        """
        Set IDP-specific option
        Returns: 1-ok, 0-not implemented, -1-error
        """
        #msg = f'KEY: {keyword}, TYPE: {value_type}, value: {value}, loaded: {idb_loaded}'
        return self._log()
    
    def ev_set_proc_options(self, options, confidence):
        """
        Called if the user specified an option string in the command line:
        Returns: <0-bad option string
        """
        return self._log()
    
    def ev_ana_insn(self, insn):
        """
        Decodes an instruction into insn
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        self._log()
        return insn.size
    
    def ev_emu_insn(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        Returns: -1, the kernel will delete the instruction.
        """
        return self._log()
    
    def ev_out_header(self, ctx):
        """
        Function to produce start of disassembled text
        """
        self._log()

    def ev_out_footer(self, ctx):
        """
        Function to produce end of disassembled text
        """
        self._log()
    
    def ev_out_segstart(self, ctx, segment):
        """
        Function to produce start of segment
        Returns: 1-ok, 0-not implemented
        """
        return self._log()
    
    def ev_out_insn(self, ctx):
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        self._log()

    def ev_out_segstart(self, ctx, segment):
        """
        Function to produce start of segment
        Returns: 1-ok, 0-not implemented
        """
        return self._log()

    def ev_out_segend(self, ctx, segment):
        """
        Function to produce end of segment
        Returns: 1-ok, 0-not implemented
        """
        return self._log()

    def ev_out_assumes(self, ctx):
        """
        Function to produce assume directives
        Returns: 1-ok, 0-not implemented
        """
        return self._log()
    
    def ev_out_mnem(self, ctx):
        """
        Generate text representation of an instruction in 'ctx.insn'
        Returns: 1-if appended the mnemonics, 0-not implemented.
        """
        return self._log()
    
    def ev_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: 1-ok, -1-operand is hidden
        """
        return self._log()
    
    def ev_out_data(self, ctx, analyze_only):
        """
        Generate text represenation of data items
        This function MAY change the database and create cross-references, etc.
        Returns: 1-ok, 0-not implemented
        """
        return self._log()
    
    def ev_out_label(self, ctx, label):
        """
        The kernel is going to generate an instruction label line
        or a function header.
        Returns: <0-the kernel should not generate the label, 0-not implemented/continue
        """
        return self._log()
    
    def ev_out_special_item(self, ctx, segtype):
        """
        Generate text representation of an item in a special segment
        i.e. absolute symbols, externs, communal definitions etc.
        Returns: 1-ok, 0-not implemented, -1-overflow
        """
        return self._log()
    
    def ev_gen_stkvar_def(self, ctx, mptr, v):
        """
        Generate stack variable definition line.
        Default line is varname = type ptr value,
        where 'type' is one of byte,word,dword,qword,tbyte.
        Returns: 1-ok, 0-not implemented.
        """
        return self._log()
    
    def ev_gen_regvar_def(self, ctx, v):
        """
        Generate register variable definition line.
        Returns: >0-ok, 0-not implemented.
        """
        return self._log()

    def ev_gen_src_file_lnnum(self, ctx, filename, lnnum):
        """
        Callback: generate analog of#line "file.c" 123
        directive.
        Returns: 1-ok, 0-not implemented
        """
        return self._log()
    
    def ev_creating_segm(self, s):
        """
        A new segment is about to be created.
        Returns 1-ok, <0-should not be created
        """
        return self._log()
    
    def ev_moving_segm(self, segment, to, flags):
        """
        May the kernel move the segment?
        returns: 0-yes, <0-the kernel should stop
        """
        return self._log()
    
    def ev_coagulate(self, start_ea):
        """
        Try to define some unexplored bytes
        This notification will be called if the
        kernel tried all possibilities and could
        not find anything more useful than to
        convert to array of bytes.
        The module can help the kernel and convert
        the bytes into something more useful.
        Returns: number of converted bytes
        """
        return self._log()
    
    def ev_undefine(self, ea):
        """
        An item in the database (insn or data) is being deleted.
        Returns: >=0-ok, <0-the kernel should stop
        """
        return self._log()
    
    def ev_treat_hindering_item(self, hindering_item_ea, new_item_flags, new_item_ea, new_item_length):
        """
        An item hinders creation of another item
        Returns: 0-no reaction, <0-the kernel may delete the hindering item
        """
        return self._log()
    
    def ev_rename(self, ea, new_name):
        """
        The kernel is going to rename a byte
        Returns: <0-then the kernel should not rename it
        """
        return self._log()
    
    def ev_is_far_jump(self, icode):
        """
        Is indirect far jump or call instruction?
        meaningful only if the processor has 'near' and 'far' reference types.
        Returns: 0-not implemented, 1-yes, -1-no
        """
        return self._log()
    
    def ev_is_sane_insn(self, insn, no_crefs):
        """
        Is the instruction sane for the current file type? 
        Returns: >=0-ok, <0-no
        """
        return self._log()
    
    def ev_is_cond_insn(self, insn):
        """
        Is conditional instruction?
        Returns: 1-yes, -1-no, 0-not implemented.
        """
        return self._log()
    
    def ev_is_call_insn(self, insn):
        """
        Is the instruction a "call"?
        Returns: 0-unknown, <0-no, 1-yes
        """
        return self._log()
    
    def ev_is_ret_insn(self, insn, flags):
        """
        Is the instruction a "return"?
        Returns: 0-unknown, <0-no, 1-yes
        """
        return self._log()
    
    def ev_may_be_func(self, insn, state):
        """
        Can a function start here?
        Returns: probability 0..100
        """
        return self._log()
    
    def ev_is_basic_block_end(self, insn, call_insn_stops_block):
        """
        Is the current instruction end of a basic block?
        Returns: 0-unknown, -1-no, 1-yes
        """
        return self._log()
    
    def ev_is_indirect_jump(self, insn):
        """
        Callback: determine if instruction is an indrect jump
        If CF_JUMP bit cannot describe all jump types
        jumps, please define this callback.
        Returns: 0-use CF_JUMP, 1-no, 2-yes
        """
        return self._log()
    
    def ev_is_switch(self, swi, insn):
        """
        Find 'switch' idiom or override processor module's 
        decision.
        Returns: 1-switch found, -1-no switch found, 0-not implmented
        """
        return self._log()
    
    def ev_calc_switch_cases(self, casevec, targets, insn_ea, si):
        """
        Calculate case values and targets for a custom jump table.
        Returns: 1-ok, <=0-failed
        """
        return self._log()
    
    def ev_create_switch_xrefs(self, jumpea, swi):
        """
        Create xrefs for a custom jump table
        Must return 1
        """
        self._log()
        return 1
    
    def ev_is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """
        return self._log()
    
    def ev_is_alloca_probe(self, ea):
        """
        Does the function at 'ea' behave as __alloca_probe?
        Returns: 1-yes, 0-no
        """
        return self._log()
    
    def ev_delay_slot_insn(self, ea, bexec, fexec):
        """
        Get delay slot instruction.
        Returns 1-yes, <=O-ordianry insn.
        """
        return self._log()
    
    def ev_is_sp_based(self, mode, insn, op):
        """
        Check whether the operand is relative to stack pointer or frame pointer.
        This function is used to determine how to output a stack variable
        This function may be absent. If it is absent, then all operands
        are sp based by default.
        Define this function only if some stack references use frame pointer
        instead of stack pointer.
        Returns: 0-not implemented, 1-ok
        """
        return self._log()
    
    def ev_can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc?
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: 0-unknown, <0-no, 1-yes
        """
        return self._log()
    
    def ev_cmp_operands(self, op1, op2):
        """
        Compare instruction operands.
        Returns 1-equal, -1-not equal, 0-not implemented
        """
        return self._log()
    
    def ev_adjust_refinfo(self, ri, ea, n, fd):
        """
        Called from apply_fixup before converting operand to reference.
        Can be used for changing the reference info.
        Returns: <0-do not create an offset, 0-not implemented
        """
        return self._log()
    
    def ev_get_operand_string(self, buf, insn, opnum):
        """
        Request text string for operand.
        Returns: 0-no string (or empty), >0-original string length (without final 0)
        """
        return self._log()
    
    def ev_get_reg_name(self, buf, reg, width, reghi):
        """
        Generate text representation of a register.
        Most processor modules do not need to implement this callback.
        Returns: -1-error, strlen(buf)-success
        """
        return self._log()
    
    def ev_str2reg(self, regname):
        """
        Convert a register name to a register number
        Returns: 0-not implemented, register number + 1
        """
        return self._log()
    
    def ev_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: 1-new comment has been generated, 0-not been handled.
        """
        return self._log()
    
    def ev_get_bg_color(self, color, ea):
        """
        Get item background color.
        Plugins can hook this callback to color disassembly lines dynamically.
        Returns: 0-not implemented, 1-color set
        """
        return self._log()
    
    def ev_is_jump_func(self, pfn, jump_target, func_pointer):
        """
        Is the function a trivial "jump" function?
        Returns: <0-no, 0-don't know, 1-yes
        """
        return self._log()
    
    def ev_func_bounds(self, possible_return_code, pfn, max_func_end_ea):
        """
        Find_func_bounds() finished its work.
        The module may fine tune the function bounds.
        Returns: None
        """
        return self._log()

    def ev_verify_sp(self, pfn):
        """
        All function instructions have been analyzed.
        Now the processor module can analyze the stack pointer
        for the whole function
        Returns: 0-ok, <0-bad stack pointer
        """
        return self._log()
    
    def ev_verify_noreturn(self, pfn):
        """
        The kernel wants to set 'noreturn' flags for a function
        Returns: 0-ok, <0-do not set 'noreturn' flag
        """
        return self._log()
    
    def ev_create_func_frame(self, pfn):
        """
        Create a function frame for a newly created function.
        Set up frame size, its attributes etc.
        Returns: 1-ok, 0-not implemented
        """
        return self._log()
    
    def ev_get_frame_retsize(self, frsize, pfn):
        """
        Get size of function return address in bytes
        If this function is absent, the kernel will assume
        8 bytes for 64-bit function,4 bytes for 32-bit 
        function, c2 bytes otherwise.
        Returns 1-ok, 0-not implemented
        """
        return self._log()
    
    def ev_get_stkvar_scale_factor(self):
        """
        Should stack variable references be multiplied by
        a coefficient before being used in the stack frame?
        Currently used by TMS320C55 because the references into
        the stack should be multiplied by 2.
        Returns: 0-not implemented, >0-scaling factor
        """
        return self._log()
    
    def ev_demangle_name(self, out, res , demreq):
        """
        Demangle a C++ (or another language) name into a user-readable string.
        This event is called by ::demangle_name().
        Returns: 0-not implemented, 1-success
        """
        return self._log()
    
    def ev_add_cref(self, frm, to, type):
        """
        A code reference is being created.
        Returns: 0-not implemented, <0-cancel cref creation
        """
        return self._log()
    
    def ev_add_dref(self, frm, to, type):
        """
        A data reference is being created.
        Returns: 0-not implemented, <0-cancel dref creation
        """
        return self._log()
    
    def ev_del_cref(self, frm, to, expand):
        """
        A code reference is being deleted.
        Returns: 0-not implemented, <0-cancel cref deletion
        """
        return self._log()
    
    def ev_del_dref(self, frm, to):
        """
        A data reference is being deleted.
        Retuns: 0-not implemented, <0-cancel dref deletion
        """
        return self._log()
    
    def ev_coagulate_dref(self, from_ea, to_ea, may_define, code_ea):
        """
        Data reference is being analyzed.
        plugin may correct code_ea (e.g. for thumb mode refs, we clear the last bit)
        Returns: >0-new code_ea, -1-cancel dref analysis
        """
        return self._log()
    
    def ev_may_show_sreg(self, current_ea):
        """
        The kernel wants to display the segment registers
        in the messages window.
        Returns: 0-not implemented, <0-kernel should not show.
        """
        return self._log()
    
    def ev_loader_elf_machine(self, li, machine_type, p_procname, p_pd, loader, reader):
        """
        ELF loader machine type checkpoint.
        A plugin check of the 'machine_type'. If it is the desired one,
        the the plugin fills 'p_procname' with the processor name.
        Returns: e_machine value
        """
        pass

    def ev_auto_queue_empty(self, atype):
        """
        One analysis queue is empty.
        Returns: an int (?)
        """
        return self._log()
    
    def ev_validate_flirt_func(self, start_ea, func_name):
        """
        FLIRT has recognized a library function.
        This callback can be used by a plugin or proc module
        to intercept it and validate such a function.
        Returns: -1-do not create, 0-validated
        """
        return self._log()
    
    def ev_adjust_libfunc_ea(self, sig, libfun, ea):
        """
        Called when a signature module has been matched against
        bytes in the database. This is used to compute the
        offset at which a particular module's libfunc should
        be applied.
        Returns: 1-ea has been modified, <=0 not modified
        """
        return self._log()
    
    def ev_assemble(self, ea, cs, ip, use32, line):
        """
        Assemble an instruction
        (make sure that PR_ASSEMBLE flag is set in the processor flags)
        (display a warning if an error occurs)
        Returns opcode string-ok, None-failed
        """
        return self._log()
    
    def ev_extract_address(self, out_ea, screen_ea, string, position):
        """
        Extract address from a string.
        Returns: 1-ok, 0-use standard algorithm, -1-error
        """
        return self._log()
    
    def ev_realcvt(self, m,e, swt):
        """
        Floating point -> IEEE conversion
        Returns: 1-ok, 0-not implemented, REAL_ERROR_-error
        """
        return self._log()
    
    def ev_gen_asm_or_lst(self, starting, fp, is_asm, flags, outline):
        """
        Callback generating asm orlst file.
        The kernel calls this callback twice, at the beginning
        and at the end of listing generation. The processor
        module can intercept this event and adjust its output.
        Returns: None
        """
        return self._log()
    
    def ev_gen_map_file(self, nlines, fp):
        """
        Generate a map file. If not implemented
        the kernel itself will create the map file.
        Returns: 1-ok, 0-not implemented, -1-write error
        """
        return self._log()
    
    def ev_create_flat_group(self, image_base, bitness, dataseg_sel):
        """
        Create special segment representing the flat group.
        Returns: return value ignored.
        """
        return self._log()
    
    def ev_analyze_prolog(self, ea):
        """
        Analyzes function prolog, epilog, and updates
        purge, and function attributes
        Returns: 1-ok, 0-not implemented.
        """
        return self._log()


# Remove an existing hook on second run
try:
    idp_hook_stat = "un"
    print("IDP hook: checking for hook...")
    idphook
    print("IDP hook: unhooking....")
    idp_hook_stat2 = ""
    idphook.unhook()
    del idphook
except:
    print("IDP hook: not installed, installing now....")
    idp_hook_stat = ""
    idp_hook_stat2 = "un"
    idphook = idp_logger_hooks_t()
    idphook.hook()

print(f'IDP hook {idp_hook_stat}installed. Run the script again to {idp_hook_stat2}install')
