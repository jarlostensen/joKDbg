import pywintypes
import win32file
import win32pipe
from struct import unpack
from typing import Tuple


class TestKernelWin32:
    __PIPE_BUFFER_SIZE = 64 * 1024

    def __init__(self):
        self._pipe_handle = None
        self._pipe_name = None
        self._buffer = None

    def wait_for_connection(self, pipe_name):
        self._pipe_name = pipe_name
        sa = pywintypes.SECURITY_ATTRIBUTES()
        sa.SetSecurityDescriptorDacl(1, None, 0)
        self._pipe_handle = win32pipe.CreateNamedPipe(self._pipe_name,
                                                      win32pipe.PIPE_ACCESS_DUPLEX,
                                                      win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
                                                      win32pipe.PIPE_UNLIMITED_INSTANCES,
                                                      0,
                                                      0,
                                                      20000,
                                                      sa)
        # wait for the debugger
        win32pipe.ConnectNamedPipe(self._pipe_handle, None)
        # read the handshake
        result, buffer = win32file.ReadFile(self._pipe_handle, self.__PIPE_BUFFER_SIZE)
        return buffer

    def write_packet(self, raw_data):
        win32file.WriteFile(self._pipe_handle, raw_data)

    def read_packet(self) -> Tuple[int, int, bytes]:
        try:
            if self._buffer is None or len(self._buffer) < 8:
                # blocking wait until at least a packet of |header|length| is available
                result, buffer = win32file.ReadFile(self._pipe_handle, self.__PIPE_BUFFER_SIZE)
                if self._buffer is not None:
                    buffer = self._buffer + buffer
            else:
                buffer = self._buffer
            while len(buffer) < 8:
                _, avail, _ = win32pipe.PeekNamedPipe(self._pipe_handle, 0)
                if avail > 0:
                    result, data = win32file.ReadFile(self._pipe_handle, self.__PIPE_BUFFER_SIZE)
                    buffer += data
            packet_id, packet_length = unpack('LL', buffer[:8])
            total_read = len(buffer) - 8
            if packet_length > 0:
                while total_read < packet_length:
                    _, avail, _ = win32pipe.PeekNamedPipe(self._pipe_handle, 0)
                    if avail > 0:
                        result, data = win32file.ReadFile(self._pipe_handle, self.__PIPE_BUFFER_SIZE)
                        buffer += data
                        total_read += len(data)
            # whatever is in excess we store for the next round
            self._buffer = buffer[packet_length + 8:]
            return packet_id, packet_length, buffer[8:]
        except pywintypes.error as e:
            raise Exception('native pipe exception: ' + str(e))
