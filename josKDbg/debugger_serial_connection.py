import sys
import json
import ctypes


class DebuggerSerialPacket(ctypes.LittleEndianStructure):
    _pack = 1
    _fields_ = [
        ('_id', ctypes.c_uint32),
        ('_length', ctypes.c_uint32)
    ]


def _create_debugger_packet(packet_id, packet_length):
    packet = DebuggerSerialPacket()
    packet._id = packet_id
    packet._length = packet_length
    return ctypes.cast(ctypes.byref(packet), ctypes.POINTER(ctypes.c_char * ctypes.sizeof(packet)))


class DebuggerSerialConnection:
    _CONNECTION_HANDSHAKE = f"josx"

    CONTINUE = 0
    TRACE = 1
    KERNEL_INFO = 2
    INT3 = 3
    READ_TARGET_MEMORY = 4
    READ_TARGET_MEMORY_RESP = 5
    WRITE_TARGET_MEMORY = 6

    def __init__(self):
        self._name = None
        self._kernel_info = None

    def _connect(self, packet_id, packet_len, packet):
        payload_as_string = packet.decode("utf-8")
        self._kernel_info = json.loads(payload_as_string)

    def kernel_connection_info(self):
        return self._kernel_info


def debugger_serial_connection_factory():
    if sys.platform == 'win32':
        from .debugger_serial_connection_win32 import DebuggerSerialConnectionWin32
        return DebuggerSerialConnectionWin32()
    else:
        raise Exception('unsupported platform')
