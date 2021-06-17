import sys
import json


class DebuggerSerialConnection:
    _CONNECTION_HANDSHAKE = f"josx"

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
