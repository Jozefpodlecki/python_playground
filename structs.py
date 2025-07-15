from ctypes import wintypes
import ctypes

PROCESS_ALL_ACCESS = 0x1F0FFF
GENERIC_WRITE = 0x40000000
CREATE_ALWAYS = 2
FULL_MEMORY = 0x00000002
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
PAGE_READWRITE = 0x04

PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD             = 0x100
PAGE_NOCACHE           = 0x200
PAGE_WRITECOMBINE      = 0x400


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',       wintypes.LPVOID),
        ('AllocationBase',    wintypes.LPVOID),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize',        ctypes.c_size_t),
        ('State',             wintypes.DWORD),
        ('Protect',           wintypes.DWORD),
        ('Type',              wintypes.DWORD),
    ]

class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ('lpBaseOfDll', wintypes.LPVOID),
        ('SizeOfImage', wintypes.DWORD),
        ('EntryPoint', wintypes.LPVOID),
    ]
