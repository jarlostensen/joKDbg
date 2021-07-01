import ctypes
from enum import Enum


class InterruptStackFrame(ctypes.LittleEndianStructure):
    """
    this reflects the layout of interrupt_stack_t in the kernel interrupts.c file
    """
    _pack_ = 1
    _fields_ = [
        ("rdi", ctypes.c_uint64),
        ("rsi", ctypes.c_uint64),
        ("rbp", ctypes.c_uint64),
        ("rdx", ctypes.c_uint64),
        ("rcx", ctypes.c_uint64),
        ("rbx", ctypes.c_uint64),
        ("rax", ctypes.c_uint64),
        ("r15", ctypes.c_uint64),
        ("r14", ctypes.c_uint64),
        ("r13", ctypes.c_uint64),
        ("r12", ctypes.c_uint64),
        ("r11", ctypes.c_uint64),
        ("r10", ctypes.c_uint64),
        ("r9", ctypes.c_uint64),
        ("r8", ctypes.c_uint64),
        ("handler_id", ctypes.c_uint64),
        ("error_code", ctypes.c_uint64),
        ("rip", ctypes.c_uint64),
        ("cs", ctypes.c_uint64),
        ("rflags", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("ss", ctypes.c_uint64),
    ]


class DebuggerBpPacket(ctypes.LittleEndianStructure):
    """
    general breakpoint (and fault) information from kernel
    """
    _pack_ = 1
    _fields_ = [
        ('stack', InterruptStackFrame),
        ('instruction', ctypes.c_uint8 * 15),
        ('cr0', ctypes.c_uint64),
        ('cr2', ctypes.c_uint64),
        ('cr3', ctypes.c_uint64),
        ('cr4', ctypes.c_uint64),
        ('call_stack_size', ctypes.c_uint16)
    ]


class DebuggerSerialPacket(ctypes.LittleEndianStructure):
    """
    header for all serial packets between kernel and debugger
    """
    _pack_ = 1
    _fields_ = [
        ('_id', ctypes.c_uint32),
        ('_length', ctypes.c_uint32)
    ]


class DebuggerReadTargetMemoryPacket(ctypes.LittleEndianStructure):
    """
    request for kernel to read and return length bytes of memory at address
    """
    _pack_ = 1
    _fields_ = [
        ('_address', ctypes.c_uint64),
        ('_length', ctypes.c_uint32)
    ]


class DebuggerGetTaskInfoHeaderPacket(ctypes.LittleEndianStructure):
    """
    TODO
    """
    _pack_ = 1
    _fields_ = [
        ('num_tasks', ctypes.c_uint32),
        ('task_context_size', ctypes.c_uint32)
    ]


class DebuggerTaskInfo(ctypes.LittleEndianStructure):
    """
    TODO
    """
    _pack_ = 1
    _fields_ = [
        ('name', ctypes.c_char * (32+1)),
        ('entry_point', ctypes.c_uint64),
        ('stack', InterruptStackFrame)
    ]


class DebuggerTraversePageTablePacket(ctypes.LittleEndianStructure):
    """
    request for kernel to traverse pagetable for address
    """
    _pack_ = 1
    _fields_ = [
        ('address', ctypes.c_uint64)
    ]


class DebuggerTraversePageTableRespPacket(ctypes.LittleEndianStructure):
    """
    response to DebuggerTraversePageTable from kernel
    contains page-table entries for each level of address
    """
    _pack_ = 1
    _fields_ = [
        ('address', ctypes.c_uint64),
        ('entries', ctypes.c_uint64 * 4)
    ]


class DebuggerRDMSRPacket(ctypes.LittleEndianStructure):
    """
    request for kernel to read MSR
    """
    _pack_ = 1
    _fields_ = [
        ('msr', ctypes.c_uint32)
    ]


class DebuggerRDMSRespPacket(ctypes.LittleEndianStructure):
    """
    RDMSR response packet from kernel
    """
    _pack_ = 1
    _fields_ = [
        ('msr', ctypes.c_uint32),
        ('lo', ctypes.c_uint32),
        ('hi', ctypes.c_uint32)
    ]


class BreakpointStatus(Enum):
    BREAKPOINT_STATUS_ENABLED = 0
    BREAKPOINT_STATUS_DISABLED = 1
    BREAKPOINT_STATUS_CLEARED = 2


class DebuggerBreakpointInfoPacket(ctypes.LittleEndianStructure):
    """
    synchronize breakpoint on kernel
    we send a packet of one of these per bp to the kernel
    """
    _pack_ = 1
    _fields_ = [
        # target address
        ('target', ctypes.c_uint64),
        # enabled/disabled/clear
        ('edc', ctypes.c_uint8)
    ]
