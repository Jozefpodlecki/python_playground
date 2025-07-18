from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM, CS_OP_MEM
from capstone.x86 import X86_REG_RIP


def dump_functions(md, execution_start, code, base_addr, output_file_path):
   
    instrs = list(md.disasm(code, base_addr))
    function_starts = set()
    function_starts.add(execution_start)

    for instr in instrs:
        if instr.id == 0:
            continue

        if CS_GRP_CALL in instr.groups:
            if len(instr.operands) == 1:
                op = instr.operands[0]
                if op.type == CS_OP_IMM:
                    function_starts.add(op.imm)

    for instr in instrs:
        if instr.mnemonic == 'push' and instr.op_str == 'rbp':
            idx = instrs.index(instr)
            if idx + 1 < len(instrs):
                next_instr = instrs[idx + 1]
                if next_instr.mnemonic == 'mov' and next_instr.op_str == 'rbp, rsp':
                    function_starts.add(instr.address)

    function_starts = sorted(function_starts)
    function_bodies = {}

    for start in function_starts:
        body = []
        for instr in instrs:
            if instr.address >= start:
                body.append(instr)
                if instr.mnemonic == 'ret':
                    break
        function_bodies[start] = body

    with open(output_file_path, 'w') as f:
        for func_addr, body in function_bodies.items():
            f.write(f"\nFunction at 0x{func_addr:x}:\n")
            for instr in body:
                line = f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}\n"
                f.write(line)

    print(f"Functions dumped to: {output_file_path}")