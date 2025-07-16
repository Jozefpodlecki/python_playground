import os
import string
import struct
import pefile
from capstone import *

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM, CS_OP_MEM
from capstone.x86 import X86_REG_RIP

class PeAnalyser:
    def __init__(self, file_path):
        self.pe = pefile.PE(file_path)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.md.skipdata = True
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.ptr_size = 8 if self.pe.OPTIONAL_HEADER.Magic == 0x20b else 4

    def dump_text_section(self, output_file_path):
        for section in self.pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            if name == '.text':
                code = section.get_data()
                virtual_address = self.image_base + section.VirtualAddress

                with open(output_file_path, 'w') as f:
                    for insn in self.md.disasm(code, virtual_address):
                        line = f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}\n"
                        f.write(line)

                print(f"Disassembly of .text section saved to: {output_file_path}")
                return
        raise Exception("No .text section found.")

    def get_call(self):
        code, base_addr = self.dump_text_section()
        calls = []

        for insn in self.md.disasm(code, base_addr):
            if CS_GRP_CALL in insn.groups:
                if len(insn.operands) == 1:
                    op = insn.operands[0]
                    if op.type == CS_OP_IMM:
                        target = op.imm
                    elif op.type == CS_OP_MEM:
                        target = None
                    else:
                        target = None
                    calls.append({
                        'address': insn.address,
                        'mnemonic': insn.mnemonic,
                        'op_str': insn.op_str,
                        'target': target
                    })
        return calls