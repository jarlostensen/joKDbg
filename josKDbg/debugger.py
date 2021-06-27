import ctypes
import time

from .debugger_serial_connection import debugger_serial_pipe_connection_factory
from .debugger_packets import DebuggerBpPacket, DebuggerGetTaskInfoHeaderPacket, DebuggerTaskInfo
from .debugger_commands import *

import queue
import threading


class Debugger:
    _STATE_WAITING = 0
    _STATE_BREAK = 1
    _STATE_GPF = 2

    def __init__(self):
        self._conn = None
        self._trace_queue = queue.Queue()
        self._command_queue = queue.Queue()
        self._response_queue = queue.Queue()
        self._send_queue = queue.Queue()
        self._rw_thread = None
        self._disconnected = True
        self._state = self._STATE_WAITING
        self._last_rip = 0

    def _rw_thread_func(self):
        try:
            while not self._disconnected:
                # reads are non-blocking
                self._conn.read_avail()
                if self._conn.has_packet():
                    packet_id, packet_len, packet = self._conn.read_last_packet()
                    if packet_id == TRACE:
                        # TODO: this is probably wrong, it shouldn't block?
                        string = packet.decode('utf-8')
                        self._trace_queue.put(packet.decode("utf-8"), block=True, timeout=None)
                    elif (packet_id & RESP_PACKET_MASK) == RESP_PACKET_MASK:
                        # a response packet
                        self._response_queue.put((packet_id, packet), block=True, timeout=None)
                    else:
                        # a command packet
                        self._command_queue.put((packet_id, packet), block=True, timeout=None)
                else:
                    # a latency of 1/10th of a second is fine for our needs
                    time.sleep(0.1)
                # writes are immediate (and technically blocking)
                while not self._send_queue.empty():
                    packet_id, packet_data = self._send_queue.get(block=True, timeout=None)
                    if packet_id == READ_TARGET_MEMORY:
                        self._conn.send_kernel_read_target_memory(packet_data[0], packet_data[1])
                    elif packet_id == GET_TASK_LIST:
                        self._conn.send_kernel_get_task_list()
                    else:
                        pass
        except UnicodeDecodeError:
            # sometimes happens during a TRACE and it appears to be an intermittent VirtualBox issue...
            pass
        except Exception as e:
            # TODO: what do we do now?
            self._disconnected = True

    def _start_threads(self):
        self._rw_thread = threading.Thread(target=self._rw_thread_func, daemon=True)
        self._rw_thread.start()

    def pipe_connect(self, pipe_name):
        self._conn = debugger_serial_pipe_connection_factory()
        self._conn.connect(pipe_name)
        self._disconnected = False
        self._start_threads()
        self._on_connect_impl(self._conn.kernel_connection_info())

    def main_loop(self):
        self._main_loop()

    def update(self):
        if self._disconnected:
            raise Exception("debugger disconnected")
        while not self._command_queue.empty():
            try:
                packet_id, packet = self._command_queue.get_nowait()
                if packet_id == INT3:
                    bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                    self._last_rip = bp_packet.stack.rip
                    self._on_breakpoint(bp_packet)
                    self._state = self._STATE_BREAK
                    self._send_queue.put((READ_TARGET_MEMORY, (self._last_rip, 64)))
                elif packet_id == GPF:
                    bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                    last_rip = bp_packet.stack.rip
                    self._state = self._STATE_GPF
                    self._send_queue.put((READ_TARGET_MEMORY, (self._last_rip, 64)))
                self._command_queue.task_done()
            except queue.Empty:
                # timed out
                pass
        while not self._response_queue.empty():
            try:
                packet_id, packet = self._response_queue.get_nowait()
                if packet_id == READ_TARGET_MEMORY_RESP:
                    if self._state == self._STATE_BREAK or self._state == self._STATE_GPF:
                        self._disassemble_bytes_impl(packet, self._last_rip)
                    else:
                        print(f'unhandled')
                elif packet_id == GET_TASK_LIST_RESP:
                    ti_hdr_packet = DebuggerGetTaskInfoHeaderPacket.from_buffer_copy(packet)
                    print(f'''GET_TASK_LIST_RESP returned {ti_hdr_packet.num_tasks} tasks of '''
                          f'''{ti_hdr_packet.task_context_size} bytes each''')
                    ti_packet = DebuggerTaskInfo.from_buffer_copy(packet,
                                                                  ctypes.sizeof(DebuggerGetTaskInfoHeaderPacket))
                    print(f'task 1 name {ti_packet.name.decode()}, entry point {hex(ti_packet.entry_point)}')
            except queue.Empty:
                # timed out
                pass
        if not self._trace_queue.empty():
            self._process_trace_queue_impl(self._trace_queue)

    def _main_loop(self):
        last_rip = 0
        while not self._disconnected:
            while not self._command_queue.empty():
                try:
                    packet_id, packet = self._command_queue.get_nowait()
                    if packet_id == INT3:
                        bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                        last_rip = bp_packet.stack.rip
                        self._on_breakpoint(bp_packet)
                        self._state = self._STATE_BREAK
                        self._send_queue.put((READ_TARGET_MEMORY, (last_rip, 64)))
                    elif packet_id == GPF:
                        bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                        last_rip = bp_packet.stack.rip
                        self._state = self._STATE_GPF
                        self._send_queue.put((READ_TARGET_MEMORY, (last_rip, 64)))
                    self._command_queue.task_done()
                except queue.Empty:
                    # timed out
                    pass
            while not self._response_queue.empty():
                try:
                    packet_id, packet = self._response_queue.get_nowait()
                    if packet_id == READ_TARGET_MEMORY_RESP:
                        if self._state == self._STATE_BREAK or self._state == self._STATE_GPF:
                            self._disassemble_bytes_impl(packet, last_rip)
                        else:
                            print(f'unhandled')
                    elif packet_id == GET_TASK_LIST_RESP:
                        ti_hdr_packet = DebuggerGetTaskInfoHeaderPacket.from_buffer_copy(packet)
                        print(f'''GET_TASK_LIST_RESP returned {ti_hdr_packet.num_tasks} tasks of '''
                              f'''{ti_hdr_packet.task_context_size} bytes each''')
                        ti_packet = DebuggerTaskInfo.from_buffer_copy(packet,
                                                                      ctypes.sizeof(DebuggerGetTaskInfoHeaderPacket))
                        print(f'task 1 name {ti_packet.name.decode()}, entry point {hex(ti_packet.entry_point)}')
                except queue.Empty:
                    # timed out
                    pass
            if not self._trace_queue.empty():
                self._process_trace_queue_impl(self._trace_queue)
            # wait for 1/4 of a second
            time.sleep(0.25)
        self._send_queue.join()
