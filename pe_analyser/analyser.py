
import os
import string
import struct
import pefile
from capstone import *

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM, CS_OP_MEM
from capstone.x86 import X86_REG_RIP

from pe_analyser.dump_functions import dump_functions

class PeAnalyser:
    def __init__(self, file_path):
        self.pe = pefile.PE(file_path)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.md.skipdata = True
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.ptr_size = 8 if self.pe.OPTIONAL_HEADER.Magic == 0x20b else 4

    def dump_data_section(self, raw_output_path):
        for section in self.pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            if name == '.data':
                data = section.get_data()

                with open(raw_output_path, 'wb') as f:
                    f.write(data)

                print(f"Raw bytes of .data section saved to: {raw_output_path}")
                return

        raise Exception("No .data section found.")

    def dump_text_section(self, output_file_path):
        for section in self.pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            if name == '.text':
                code = section.get_data()
                virtual_address = self.image_base + section.VirtualAddress

                with open(output_file_path, 'w') as f:
                    for instr in self.md.disasm(code, virtual_address):
                        line = f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}\n"
                        f.write(line)

                print(f"Disassembly of .text section saved to: {output_file_path}")
                return
        raise Exception("No .text section found.")

    def dump_functions(self, output_file_path):
        for section in self.pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            if name == '.text':
                code = section.get_data()
                base_addr = self.image_base + section.VirtualAddress
                break
        else:
            raise Exception("No .text section found.")

        execution_start = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint + self.image_base
        dump_functions(self.md, execution_start, code, base_addr, output_file_path)

    def resolve_import_name(self, iat_target):
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.address == iat_target:
                    return f"{entry.dll.decode()}!{imp.name.decode()}"
        return None

    def print_dll_calls(self):
        dll_calls = self.find_dll_calls()
        for call in dll_calls:
            name = self.resolve_import_name(call['target'])
            print(f"0x{call['address']:x} calls {name}")

    def find_dll_calls(self):
        dll_calls = []

        iat_rva = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']
        ].VirtualAddress
        iat_size = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']
        ].Size

        iat_start = self.image_base + iat_rva
        iat_end = iat_start + iat_size

        for section in self.pe.sections:
            name = section.Name.decode(errors='ignore').strip('\x00')
            if name == '.text':
                code = section.get_data()
                base_addr = self.image_base + section.VirtualAddress
                break
        else:
            raise Exception("No .text section found.")

        for instr in self.md.disasm(code, base_addr):
            if instr.mnemonic == 'call' and len(instr.operands) == 1:
                op = instr.operands[0]
                if op.type == CS_OP_MEM:
                    if op.mem.base == X86_REG_RIP:
                        target = instr.address + instr.size + op.mem.disp
                        if iat_start <= target < iat_end:
                            dll_calls.append({
                                'address': instr.address,
                                'mnemonic': instr.mnemonic,
                                'target': target
                            })

        return dll_calls

    def get_call(self):
        code, base_addr = self.dump_text_section()
        calls = []

        for instr in self.md.disasm(code, base_addr):
            if CS_GRP_CALL in instr.groups:
                if len(instr.operands) == 1:
                    op = instr.operands[0]
                    if op.type == CS_OP_IMM:
                        target = op.imm
                    elif op.type == CS_OP_MEM:
                        target = None
                    else:
                        target = None
                    calls.append({
                        'address': instr.address,
                        'mnemonic': instr.mnemonic,
                        'op_str': instr.op_str,
                        'target': target
                    })
        return calls