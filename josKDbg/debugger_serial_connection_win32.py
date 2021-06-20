import win32pipe, win32file
from .debugger_serial_connection import DebuggerSerialConnection, DebuggerSerialPacket, _create_debugger_packet
from struct import unpack


class DebuggerSerialConnectionWin32(DebuggerSerialConnection):
    __PIPE_BUFFER_SIZE = 64 * 1024

    def __init__(self):
        super().__init__()
        self._pipe = None
        self._pipe_name = None
        self._buffer = None

    def connect(self, pipe_name):
        self._pipe_name = pipe_name
        self._pipe = win32file.CreateFile(
            self._pipe_name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        # NOTE: vbox creates the named pipe as BYTE
        res = win32pipe.SetNamedPipeHandleState(self._pipe, win32pipe.PIPE_READMODE_BYTE, None, None)
        if res is not None:
            raise Exception('Failed to connect to kernel instance')
        # send back the connection handshake
        win32file.WriteFile(self._pipe, str.encode(self._CONNECTION_HANDSHAKE))
        # read back kernel information JSON data
        packet_id, packet_len, packet = self.read_one_packet_block()
        super()._connect(packet_id, packet_len, packet)

    def read_one_packet_block(self):
        if self._buffer is None or len(self._buffer) < 8:
            # blocking wait until at least a packet of |header|length| is available
            result, buffer = win32file.ReadFile(self._pipe, self.__PIPE_BUFFER_SIZE)
            if self._buffer is not None:
                buffer = self._buffer + buffer
        else:
            buffer = self._buffer
        while len(buffer) < 8:
            _, avail, _ = win32pipe.PeekNamedPipe(self._pipe, 0)
            if avail > 0:
                result, data = win32file.ReadFile(self._pipe, self.__PIPE_BUFFER_SIZE)
                buffer += data
        packet_id, packet_length = unpack('LL', buffer[:8])
        total_read = len(buffer) - 8
        if packet_length > 0:
            while total_read < packet_length:
                _, avail, _ = win32pipe.PeekNamedPipe(self._pipe, 0)
                if avail > 0:
                    result, data = win32file.ReadFile(self._pipe, self.__PIPE_BUFFER_SIZE)
                    buffer += data
                    total_read += len(data)
        # whatever is in excess we store for the next round
        self._buffer = buffer[packet_length+8:]
        return packet_id, packet_length, buffer[8:]

    def send_packet(self, packet_id, packet_length, data):
        packet_header = _create_debugger_packet(packet_id, packet_length)
        win32file.WriteFile(self._pipe, packet_header.contents.raw)
        if packet_length > 0:
            win32file.WriteFile(self._pipe, data)
