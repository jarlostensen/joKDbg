import ctypes
from .interrupt_stack_frame import InterruptStackFrame


class DebuggerBpPacket(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('stack', InterruptStackFrame),
    ]
