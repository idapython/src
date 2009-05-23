
%include "ua.hpp"

// Small function to get the global cmd pointer
// In Python it returns an insn_t class instance
%inline {
insn_t * get_current_instruction()
{
    return &cmd;
}
}

// Get the nth operand from the insn_t class
%inline {
op_t *get_instruction_operand(insn_t *ins, int n)
{
    if (!ins)
        return NULL;
    return &(ins->Operands[n]);
}
}

