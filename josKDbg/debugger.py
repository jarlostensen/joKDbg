from .debugger_serial_connection import debugger_serial_pipe_connection_factory
from .debugger_bp_packet import DebuggerBpPacket

class Debugger:
    def __init__(self):
        self._conn = None

    def pipe_connect(self, pipe_name):
        self._conn = debugger_serial_pipe_connection_factory()
        self._conn.connect(pipe_name)
        self._on_connect_impl(self._conn.kernel_connection_info())

    def main_loop(self):
        last_bp_rip = 0
        caught_gpf = False
        # the basic debugger loop
        try:
            packet_id, packet_len, packet = self._conn.read_one_packet_block()
            while True:
                if packet_id == self._conn.TRACE:
                    payload_as_string = packet.decode("utf-8")
                    print(payload_as_string)
                # WIP: we capture int3's as well as GPFs the same way, except we never ask the kernel to continune
                # if it's a GPF
                elif packet_id == self._conn.INT3 or packet_id == self._conn.GPF:
                    bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                    last_bp_rip = bp_packet.stack.rip
                    caught_gpf = packet_id == self._conn.GPF
                    if not caught_gpf:
                        self._on_bp_impl(last_bp_rip, bp_packet)
                    else:
                        self._on_gpf_impl(last_bp_rip, bp_packet)
                    # ask the kernel for the next couple of bytes of instructions
                    self._conn.send_kernel_read_target_memory(last_bp_rip, 64)
                    if not caught_gpf:
                        # tell the kernel to continue execution if it's a bp
                        self._conn.send_kernel_continue()
                elif packet_id == self._conn.READ_TARGET_MEMORY_RESP:
                    # response from last int3 is a bunch of instruction bytes
                    self._disassemble_bytes_impl(packet, last_bp_rip)
                # read the next packet
                packet_id, packet_len, packet = self._conn.read_one_packet_block()
        finally:
            print(">debugger disconnecting")
