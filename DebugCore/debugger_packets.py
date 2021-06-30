import ctypes


class InterruptStackFrame(ctypes.LittleEndianStructure):
    """this reflects the layout of interrupt_stack_t in the kernel interrupts.c file"""
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

    def __new__(cls, sb=None):
        if sb is not None:
            return cls.from_buffer_copy(sb)
        else:
            return ctypes.BigEndianStructure.__new__(cls)

    def __init__(self, sb=None):
        pass

    def dump(self):
        print(f'rax {hex(self.rax)}\trbx {hex(self.rbx)}\trcx {hex(self.rcx)}\trdx {hex(self.rdx)}')
        print(f'rsi {hex(self.rsi)}\trdi {hex(self.rdi)}')
        print(f'r8 {hex(self.r8)}\tr9 {hex(self.r9)}\tr10 {hex(self.r10)}\tr11 {hex(self.r11)}')
        print(f'r12 {hex(self.r12)}\tr13 {hex(self.r13)}\tr14 {hex(self.r14)}')
        print(f'rip {hex(self.rip)}\trsp {hex(self.rsp)}\trflags {hex(self.rflags)}')


class DebuggerBpPacket(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('stack', InterruptStackFrame),
        ('instruction', ctypes.c_uint8 * 15),
        ('cr0', ctypes.c_uint64),
        ('cr2', ctypes.c_uint64),
        ('cr3', ctypes.c_uint64),
        ('cr4', ctypes.c_uint64)
    ]


class DebuggerSerialPacket(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('_id', ctypes.c_uint32),
        ('_length', ctypes.c_uint32)
    ]


class DebuggerReadTargetMemoryPacket(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('_address', ctypes.c_uint64),
        ('_length', ctypes.c_uint32)
    ]


class DebuggerGetTaskInfoHeaderPacket(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('num_tasks', ctypes.c_uint32),
        ('task_context_size', ctypes.c_uint32)
    ]


class DebuggerTaskInfo(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('name', ctypes.c_char * (32+1)),
        ('entry_point', ctypes.c_uint64),
        ('stack', InterruptStackFrame)
    ]


class DebuggerTraversePageTablePacket(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('address', ctypes.c_uint64)
    ]


class DebuggerTraversePageTableRespPacket(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('address', ctypes.c_uint64),
        ('entries', ctypes.c_uint64 * 4)
    ]


class DebuggerRDMSRPacket(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('msr', ctypes.c_uint32)
    ]


class DebuggerRDMSRespPacket(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('msr', ctypes.c_uint32),
        ('lo', ctypes.c_uint32),
        ('hi', ctypes.c_uint32)
    ]

