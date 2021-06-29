import ctypes
import time

from .debugger_serial_connection import debugger_serial_pipe_connection_factory
from .debugger_packets import *
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
        self._last_bp_packet = None

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
                    time.sleep(0.033)
                # writes are immediate (and technically blocking)
                while not self._send_queue.empty():
                    packet_id, packet_data = self._send_queue.get(block=True, timeout=None)
                    if packet_id == READ_TARGET_MEMORY:
                        self._conn.send_kernel_read_target_memory(packet_data[0], packet_data[1])
                    elif packet_id == GET_TASK_LIST:
                        self._conn.send_kernel_get_task_list()
                    elif packet_id == TRAVERSE_PAGE_TABLE:
                        self._conn.send_kernel_traverse_page_table(packet_data)
                    elif packet_id == READ_MSR:
                        self._conn.send_kernel_read_msr(packet_data)
                    else:
                        pass
        except UnicodeDecodeError:
            # sometimes happens during a TRACE and it appears to be an intermittent VirtualBox issue...
            pass
        except Exception as e:
            print("rw_thread exception: " + str(e))
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

    def _on_target_memory_read(self, packet): pass

    def read_target_memory(self, at, count):
        self._send_queue.put((READ_TARGET_MEMORY, (at, count)))

    def get_task_list(self):
        self._send_queue.put(GET_TASK_LIST)

    def continue_execution(self):
        if self._state == self._STATE_BREAK:
            self._conn.send_kernel_continue()
            self._state == self._STATE_WAITING
        else:
            raise Exception("not in breakpoint")

    def single_step(self):
        if self._state == self._STATE_BREAK:
            self._conn.send_kernel_single_step()
            self._state == self._STATE_WAITING
        else:
            raise Exception("not in breakpoint")

    def traverse_pagetable(self, at):
        self._send_queue.put((TRAVERSE_PAGE_TABLE, at))

    def read_msr(self, msr):
        self._send_queue.put((READ_MSR, msr))

    def update(self):
        if self._disconnected:
            raise Exception("debugger disconnected")
        while not self._command_queue.empty():
            try:
                packet_id, packet = self._command_queue.get_nowait()
                if packet_id == BREAKPOINT:
                    self._last_bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                    self._on_breakpoint()
                    self._state = self._STATE_BREAK
                elif packet_id == GPF:
                    self._last_bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                    self._state = self._STATE_GPF
                    self._on_gpf()
                elif packet_id == ASSERT:
                    import json
                    self._on_assert(json.loads(packet.decode('utf-8')))
                self._command_queue.task_done()
            except queue.Empty:
                # timed out
                pass
        while not self._response_queue.empty():
            try:
                packet_id, packet = self._response_queue.get_nowait()
                if packet_id == READ_TARGET_MEMORY_RESP:
                    self._on_target_memory_read(packet)
                elif packet_id == TRAVERSE_PAGE_TABLE_RESP:
                    table_info = DebuggerTraversePageTableRespPacket.from_buffer_copy(packet)
                    self._on_get_pagetable_info(table_info)
                elif packet_id == READ_MSR_RESP:
                    rdmsr = DebuggerRDMSRespPacket.from_buffer_copy(packet)
                    self._on_read_msr(rdmsr)
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
