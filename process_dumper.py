import ctypes
import subprocess


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

    def run(self):
        args = [self.file_path]
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, False, process.pid)

        if not hProcess:
            raise Exception("Failed to open process")