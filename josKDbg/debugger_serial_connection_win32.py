import ctypes
from struct import unpack
from threading import Lock
from typing import Tuple
import ctypes

import pywintypes
import win32file
import win32pipe

from .debugger_serial_connection import DebuggerSerialConnection
from .debugger_packets import DebuggerSerialPacket
from .debugger_commands import *


class DebuggerSerialConnectionWin32(DebuggerSerialConnection):
    __PIPE_BUFFER_SIZE = 64 * 1024
    __READING_PACKET = 1
    __READING_BODY = 2

    def __init__(self):
        super().__init__()
        self._pipe = None
        self._pipe_name = None
        self._buffer = None
        self._last_packet_id = 0
        self._last_packet_length = 0
        self._left_to_read = ctypes.sizeof(DebuggerSerialPacket)
        self._read_state = self.__READING_PACKET
        self._has_packet = False
        self._pipe_lock = Lock()

    def connect(self, pipe_name):
        self._pipe_name = pipe_name
        try:
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
            win32file.WriteFile(self._pipe, str.encode(CONNECTION_HANDSHAKE))
            # read back kernel information JSON data
            packet_id, packet_len, packet = self.read_one_packet_block()
            super()._connect(packet_id, packet_len, packet)
        except pywintypes.error as e:
            raise Exception('native pipe exception: ' + str(e))

    def has_packet(self) -> bool:
        return self._has_packet

    def read_avail(self):
        try:
            bytes_read = 0
            _, avail, _ = win32pipe.PeekNamedPipe(self._pipe, 0)
            if avail > 0:
                # read as much as is available
                result, buffer = win32file.ReadFile(self._pipe, self.__PIPE_BUFFER_SIZE)
                bytes_read = len(buffer)
                if self._buffer is not None and len(self._buffer) > 0:
                    self._buffer = self._buffer + buffer
                else:
                    self._buffer = buffer
            self._left_to_read = self._left_to_read - bytes_read
            if self._left_to_read <= 0:
                if self._read_state == self.__READING_PACKET:
                    # unpack the packet header and switch state (if body length>0)
                    self._last_packet_id, self._last_packet_length = unpack('LL', self._buffer[:8])
                    self._buffer = self._buffer[8:]
                    if self._last_packet_length > 0:
                        self._read_state = self.__READING_BODY
                        # delta is <= 0 at this point
                        self._left_to_read = self._last_packet_length + self._left_to_read
                    else:
                        # read the next packet header
                        self._left_to_read = ctypes.sizeof(DebuggerSerialPacket)
                        self._has_packet = True
                elif self._read_state == self.__READING_BODY:
                    self._left_to_read = ctypes.sizeof(DebuggerSerialPacket)
                    self._read_state = self.__READING_PACKET
                    self._has_packet = True
        except pywintypes.error as e:
            raise Exception('native pipe exception: ' + str(e))

    def read_last_packet(self) -> Tuple[int, int, bytes]:
        if not self._has_packet:
            raise Exception("no packet ready")
        packet = self._buffer[:self._last_packet_length]
        self._buffer = self._buffer[self._last_packet_length:]
        self._has_packet = False
        return self._last_packet_id, self._last_packet_length, packet

    def read_one_packet_block(self) -> Tuple[int, int, bytes]:
        try:
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
            self._buffer = buffer[packet_length + 8:]
            return packet_id, packet_length, buffer[8:]
        except pywintypes.error as e:
            raise Exception('native pipe exception: ' + str(e))

    def _send_packet_impl(self, raw_data):
        try:
            win32file.WriteFile(self._pipe, raw_data)
        except pywintypes.error as e:
            raise Exception('native pipe exception: ' + str(e))
