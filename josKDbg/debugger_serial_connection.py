import sys
import json
import ctypes
from typing import Tuple
from .debugger_packets import DebuggerSerialPacket, DebuggerReadTargetMemoryPacket
from .debugger_commands import *


class DebuggerSerialConnection:
    def __init__(self):
        self._name = None
        self._kernel_info = None

    def _connect(self, packet_id, packet_len, packet):
        payload_as_string = packet.decode("utf-8")
        self._kernel_info = json.loads(payload_as_string)

    def kernel_connection_info(self):
        return self._kernel_info

    def read_avail(self): pass

    def has_packet(self) -> bool: pass

    def read_last_packet(self) -> Tuple[int, int, bytes]: pass

    def _send_kernel_packet_header(self, packet_id, packet_length):
        packet = DebuggerSerialPacket()
        packet._id = packet_id
        packet._length = packet_length
        # cast a a pointer to byte array and send raw
        self._send_packet_impl(ctypes.cast(ctypes.byref(packet),
                                           ctypes.POINTER(ctypes.c_char * ctypes.sizeof(packet))).contents.raw)

    def send_kernel_continue(self):
        self._send_kernel_packet_header(CONTINUE, 0)

    def send_kernel_read_target_memory(self, address, length):
        if length <= 0:
            raise Exception('can\'t read <=0 bytes from target')
        rt_packet = DebuggerReadTargetMemoryPacket()
        rt_packet._address = address
        rt_packet._length = length
        self._send_kernel_packet_header(READ_TARGET_MEMORY, ctypes.sizeof(rt_packet))
        self._send_packet_impl(ctypes.cast(ctypes.byref(rt_packet),
                                           ctypes.POINTER(ctypes.c_char * ctypes.sizeof(rt_packet))).contents.raw)

    def send_kernel_get_task_list(self):
        self._send_kernel_packet_header(GET_TASK_LIST, 0)


def debugger_serial_pipe_connection_factory():
    if sys.platform == 'win32':
        from .debugger_serial_connection_win32 import DebuggerSerialConnectionWin32
        return DebuggerSerialConnectionWin32()
    else:
        raise Exception('unsupported platform')
