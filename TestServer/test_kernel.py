import ctypes
from .test_kernel_win32 import TestKernelWin32
from josKDbg import debugger_packets
from josKDbg import debugger_commands
import json


class TestKernel:
    # exit_boot_services
    __CODE = bytearray([0x56, 0x57, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0xce, 0x48, 0xb8, 0xf0, 0x3f, 0x00, 0x80,
                        0x01, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0xbf, 0x10, 0xc4, 0x06, 0x80, 0x01, 0x00, 0x00,
                        0x00, 0x48, 0x8b, 0x07, 0x48, 0x8b, 0x98, 0xe8, 0x00, 0x00, 0x00, 0x48, 0xb8, 0xd0, 0x3f, 0x00,
                        0x80, 0x01, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xf1, 0x48, 0x89, 0xc2, 0xff, 0xd3, 0x48,
                        0x85, 0xc0, 0x78, 0x22, 0x48, 0xc7, 0x07, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8, 0xc0, 0x40, 0x00,
                        0x80, 0x01, 0x00, 0x00, 0x00, 0xff, 0xd0, 0xa9, 0x00, 0x00, 0x00, 0x70, 0x75, 0x35, 0x48, 0x83,
                        0xc4, 0x20, 0x5b, 0x5f, 0x5e, 0xc3])

    def __init__(self):
        self._conn = TestKernelWin32()

    def start(self):
        print(f'waiting for debugger connection...')
        read = self._conn.wait_for_connection(r'\\.\pipe\josxDbg')
        as_text = read.decode("utf-8")
        if as_text == debugger_commands.CONNECTION_HANDSHAKE:
            print(f'we are connected')
            kernel_response = {'version': {'minor': 0, 'major': '0', 'patch': 0},
                               'image_info': {'base': 0, 'entry_point': 0x100},
                               'system_info': {'processors': 24, 'memory': 0x10000}
                               }

            self._send_debugger_packet(debugger_commands.KERNEL_INFO,
                                       json.dumps(kernel_response).encode('utf-8'))

            self.trace("we're connected!")
        else:
            raise Exception("invalid debugger connection")

    def trace(self, message):
        message_as_bytes = message.encode('utf-8')
        self._send_debugger_packet(debugger_commands.TRACE, message_as_bytes)

    def breakpoint(self):
        bp_packet = debugger_packets.DebuggerBpPacket()
        ctypes.memset(ctypes.addressof(bp_packet.stack), 0, ctypes.sizeof(bp_packet.stack))
        bp_packet.stack.rip = 0x100
        bp_packet.stack.cs = 1
        bp_packet.stack.ss = 2
        bp_packet.stack.rflags = 0xffffffff
        self._send_debugger_packet(debugger_commands.INT3, bytearray(bp_packet))
        print("in breakpoint loop...")
        while True:
            packet_id, packet_length, packet = self._conn.read_packet()
            if packet_id == debugger_commands.CONTINUE:
                print("continuing ")
                self.trace("continue execution")
                break
            if packet_id == debugger_commands.READ_TARGET_MEMORY:
                rt_packet = debugger_packets.DebuggerReadTargetMemoryPacket.from_buffer_copy(packet)
                print(f'READ_TARGET_MEMORY: {rt_packet._length} bytes from {hex(rt_packet._address)}')
                self._send_debugger_packet(debugger_commands.READ_TARGET_MEMORY_RESP, self.__CODE)


    def _send_debugger_packet(self, packet_id: int, packet_data: bytes):
        self._send_debugger_packet_header(packet_id, len(packet_data))
        self._conn.write_packet(packet_data)

    def _send_debugger_packet_header(self, packet_id, packet_length):
        packet = debugger_packets.DebuggerSerialPacket()
        packet._id = packet_id
        packet._length = packet_length
        self._conn.write_packet(bytearray(packet))
