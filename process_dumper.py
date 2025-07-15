import os
import ctypes
import struct
import subprocess
import time
import win32process
import logging

from structs import MEMORY_BASIC_INFORMATION, MODULEINFO

logger = logging.getLogger(__name__)

PROCESS_ALL_ACCESS = 0x1F0FFF
GENERIC_WRITE = 0x40000000
CREATE_ALWAYS = 2
FULL_MEMORY = 0x00000002
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

psapi = ctypes.WinDLL("psapi")
dbghelp = ctypes.WinDLL('Dbghelp')
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll')

VirtualQueryEx = kernel32.VirtualQueryEx
OpenProcess = kernel32.OpenProcess
ReadProcessMemory = kernel32.ReadProcessMemory
CloseHandle = kernel32.CloseHandle

NtSuspendProcess = ntdll.NtSuspendProcess
NtResumeProcess = ntdll.NtResumeProcess

class ProcessDumper:
    def __init__(self, file_path):
        self.file_path = file_path
        self.process = None
        self.hProcess = None

    def run(self, output_dir):
        self._launch_process()
        self.modules = self._wait_for_modules()

        dump_output_path = os.path.join(output_dir, "dump.bin")
        with open(dump_output_path, 'wb') as dump_file:
            self._dump_modules(dump_file, self.modules)
            self._dump_memory_blocks(dump_file)

    def _launch_process(self):
        args = [self.file_path]
        self.process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, self.process.pid)

        if not self.hProcess:
            raise Exception("Failed to open process")

    def _wait_for_modules(self, timeout=10.0, interval=0.1):
        """Wait for the process to load at least one module."""
        elapsed = 0
        time.sleep(0.5)
        logging.info("Waiting for modules...")
        while True:
            modules = win32process.EnumProcessModules(self.hProcess)
            if modules:
                return modules
            time.sleep(interval)
            elapsed += interval
            if elapsed > timeout:
                raise TimeoutError("Process modules not loaded in time.")
            

    def _dump_modules(self, dump_file, modules):
        dump_file.write(struct.pack('<I', len(modules)))
        for mod in modules:
            mi = MODULEINFO()
            hmod = ctypes.wintypes.HMODULE(mod)
            psapi.GetModuleInformation(self.hProcess, hmod, ctypes.byref(mi), ctypes.sizeof(mi))

            entry_point = 0 if mi.EntryPoint is None else ctypes.cast(mi.EntryPoint, ctypes.c_void_p).value
            base_of_dll = ctypes.cast(mi.lpBaseOfDll, ctypes.c_void_p).value

            dump_file.write(struct.pack('<Q', entry_point))
            dump_file.write(struct.pack('<I', mi.SizeOfImage))
            dump_file.write(struct.pack('<Q', base_of_dll))

            filename = win32process.GetModuleFileNameEx(self.hProcess, mod)
            encoded = filename.encode('utf-8')
            dump_file.write(struct.pack('<I', len(encoded)))
            dump_file.write(encoded)

            logger.info(f"Module: {filename}, 0x{entry_point:X}, 0x{base_of_dll:X}, {mi.SizeOfImage}")

    def _dump_memory_blocks(self, dump_file):
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()

        while VirtualQueryEx(self.hProcess, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            logging.info(f"{mbi.State}")
            if mbi.State == MEM_COMMIT:
                base = ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value

                logger.info(f"Block: 0x{mbi.BaseAddress:X}, {mbi.RegionSize}, {mbi.Protect}")

                buffer = ctypes.create_string_buffer(mbi.RegionSize)
                bytes_read = ctypes.c_size_t(0)

                if ReadProcessMemory(self.hProcess, ctypes.c_void_p(address), buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                    dump_file.write(struct.pack('<Q', base))
                    dump_file.write(struct.pack('<Q', mbi.RegionSize))
                    dump_file.write(struct.pack('<I', mbi.Protect))
                    dump_file.write(buffer.raw[:bytes_read.value])

            address += mbi.RegionSize
