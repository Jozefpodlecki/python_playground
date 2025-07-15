from structs import *

def humanize_state(state):
    if state == MEM_COMMIT:
        return "MEM_COMMIT"
    elif state == MEM_RESERVE:
        return "MEM_RESERVE"
    elif state == MEM_FREE:
        return "MEM_FREE"
    else:
        return f"UNKNOWN_STATE(0x{state:X})"

def humanize_protect(protect):
    flags = []
    if protect & PAGE_NOACCESS:
        flags.append("NOACCESS")
    if protect & PAGE_READONLY:
        flags.append("READONLY")
    if protect & PAGE_READWRITE:
        flags.append("READWRITE")
    if protect & PAGE_WRITECOPY:
        flags.append("WRITECOPY")
    if protect & PAGE_EXECUTE:
        flags.append("EXECUTE")
    if protect & PAGE_EXECUTE_READ:
        flags.append("EXECUTE_READ")
    if protect & PAGE_EXECUTE_READWRITE:
        flags.append("EXECUTE_READWRITE")
    if protect & PAGE_EXECUTE_WRITECOPY:
        flags.append("EXECUTE_WRITECOPY")
    if protect & PAGE_GUARD:
        flags.append("GUARD")
    if protect & PAGE_NOCACHE:
        flags.append("NOCACHE")
    if protect & PAGE_WRITECOMBINE:
        flags.append("WRITECOMBINE")

    if not flags:
        return f"UNKNOWN(0x{protect:X})"
    return "|".join(flags)