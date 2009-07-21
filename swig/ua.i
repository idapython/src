%apply unsigned char { char n };
%apply unsigned char { char offb };
%apply unsigned char { char offo };
%apply unsigned char { char dtyp };

%include "ua.hpp"

%clear (char n);
%clear (char offb);
%clear (char offo);
%clear (char dtyp);

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

