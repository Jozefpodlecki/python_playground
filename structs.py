from ctypes import wintypes
import ctypes


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
