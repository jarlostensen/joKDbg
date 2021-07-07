import ctypes
import time

from .debugger_serial_connection import debugger_serial_pipe_connection_factory
from .debugger_packets import *
from .debugger_commands import *
from .pdb_parser import PdbParser

import queue
import threading

from typing import Tuple

# NOTE: https://stackoverflow.com/questions/21048073/install-python-package-from-github-using-pycharm


def breakpoint_marked_for_clear(bp):
    return bp[2]


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
        self._last_bp_callstack = None
        # breakpoints are stored as [enabled, index] and keyed on the target address
        self._breakpoints = {}
        # we keep track of changes so we know if we need to synchronise bps with the kernel
        self._breakpoints_dirty = False
        self._pdb = PdbParser()
        self._pe_path = None
        self._pe = None
        self._image_base = 0
        self._txt_section = None
        self._data_section = None

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
                    # TODO: rewrite all of these to use a map of handlers
                    if packet_id == CONTINUE:
                        self._conn.send_kernel_continue()
                    elif packet_id == TRACE_STEP:
                        self._conn.send_kernel_trace_step()
                    elif packet_id == SINGLE_STEP:
                        self._conn.send_kernel_single_step()
                    elif packet_id == READ_TARGET_MEMORY:
                        self._conn.send_kernel_read_target_memory(packet_data[0], packet_data[1])
                    elif packet_id == GET_TASK_LIST:
                        self._conn.send_kernel_get_task_list()
                    elif packet_id == TRAVERSE_PAGE_TABLE:
                        self._conn.send_kernel_traverse_page_table(packet_data)
                    elif packet_id == READ_MSR:
                        self._conn.send_kernel_read_msr(packet_data)
                    elif packet_id == UPDATE_BREAKPOINTS:
                        self._conn.send_kernel_update_breakpoints(packet_data)
                    elif packet_id == CPUID:
                        self._conn.send_kernel_cpuid(packet_data[0], packet_data[1])
                    else:
                        pass
        except UnicodeDecodeError:
            # sometimes happens during a TRACE and it appears to be an intermittent VirtualBox issue...
            pass
        except Exception as e:
            print("rw_thread exception: " + str(e))
            self._disconnected = True

    def set_paths(self, pe_path, pdb_path):
        self._pe_path = pe_path
        self._pdb_path = pdb_path

    def pipe_connect(self, pipe_name):
        self._conn = debugger_serial_pipe_connection_factory()
        self._conn.connect(pipe_name)
        self._disconnected = False
        self._rw_thread = threading.Thread(target=self._rw_thread_func, daemon=True)
        self._rw_thread.start()
        image_info = self._conn.kernel_connection_info()['image_info']
        self._image_base = image_info['base']
        self._pdb.load(self._image_base, self._pdb_path)
        self._on_connect_impl(self._conn.kernel_connection_info())

    def synchronize_kernel(self):
        if self._breakpoints_dirty:
            breakpoints = DebuggerBreakpointInfoPacket * len(self._breakpoints)
            memory = ctypes.create_string_buffer(ctypes.sizeof(breakpoints))
            packets = breakpoints.from_buffer(memory)
            i = 0
            for key, bp in self._breakpoints.items():
                packets[i].target = key
                packets[i].edc = BreakpointStatus.BREAKPOINT_STATUS_CLEARED.value if bp[2] \
                    else BreakpointStatus.BREAKPOINT_STATUS_ENABLED.value \
                    if bp[0] else BreakpointStatus.BREAKPOINT_STATUS_DISABLED.value
                i = i + 1
            self._send_queue.put((UPDATE_BREAKPOINTS, packets))
            self._breakpoints_dirty = False

    def state_is_waiting(self):
        return self._state == self._STATE_WAITING

    def state_is_break(self):
        return self._state == self._STATE_BREAK

    def process_callstack(self, callstack):
        """
        look up the instruction bytes at the callstack entries from the kernel executable to check if
        the preceeding instruction is a call. If it is then the location is probably part of the callstack
        """
        if self._pe is None:
            import pefile
            self._pe = pefile.PE(self._pe_path, fast_load=True)
        text_section = self._pe.sections[0]
        for entry in callstack:
            rva = (entry - self._image_base) + (text_section.VirtualAddress - text_section.PointerToRawData)
            offset = self._pe.get_offset_from_rva(rva)
            # this is basic but effective; a call instruction can be two or three bytes long
            instruction_bytes = self._pe.get_memory_mapped_image()[offset - 3:offset]
            # TODO: attempt a proper disasm on these bytes to make sure it's not just an im which happens
            # to have 0xff in the right place
            if instruction_bytes[0] == 0xff or instruction_bytes[1] == 0xff:
                lookup = self._pdb.lookup_symbol_at_address(entry)
                self._on_print_callstack_entry(f'{hex(entry)}\t{lookup}\n')

    def rva_to_phys(self, rva, section_idx):
        if self._pe is None:
            import pefile
            self._pe = pefile.PE(self._pe_path, fast_load=True)
        section = self._pe.sections[section_idx]
        phys = self._image_base + (rva + section.VirtualAddress)
        return phys

    def set_breakpoint(self, target) -> bool:
        """
        set breakpoint at address, enabled
        """
        bp = self._breakpoints.get(target)
        if bp is None:
            self._breakpoints[target] = [True, len(self._breakpoints), False]
            self._breakpoints_dirty = True
            return True

    def cpuid(self, leaf: int, subleaf: int):
        self._send_queue.put((CPUID, (leaf, subleaf)))

    def get_breakpoint_from_target(self, target):
        try:
            return self._breakpoints[target]
        except KeyError:
            for key, val in self._breakpoints.items():
                if val[1] == target:
                    return self._breakpoints[key]

    def enable_breakpoint(self, index):
        bp = self.get_breakpoint_from_target(index)
        if not bp[0]:
            bp[0] = True
            self._breakpoints_dirty = True

    def disable_breakpoint(self, index):
        bp = self.get_breakpoint_from_target(index)
        if bp[0]:
            bp[0] = False
            self._breakpoints_dirty = True

    def clear_breakpoint(self, index):
        try:
            bp = self._breakpoints[index]
            bp[2] = True
            self._breakpoints_dirty = True
        except KeyError:
            for key, val in self._breakpoints.items():
                if val[1] == index:
                    bp = self._breakpoints[key]
                    bp[2] = True
                    self._breakpoints_dirty = True
                    break

    def read_target_memory(self, at, count):
        self._send_queue.put((READ_TARGET_MEMORY, (at, count)))

    def get_task_list(self):
        self._send_queue.put(GET_TASK_LIST)

    def continue_execution(self):
        if self._state == self._STATE_BREAK:
            self._send_queue.put((CONTINUE, 0))
            self._state == self._STATE_WAITING
        else:
            raise Exception("not in breakpoint")

    def trace_step(self):
        if self._state == self._STATE_BREAK:
            self._send_queue.put((TRACE_STEP, 0))
            self._state == self._STATE_WAITING
        else:
            raise Exception("not in breakpoint")

    def single_step(self):
        if self._state == self._STATE_BREAK:
            self._send_queue.put((SINGLE_STEP, 0))
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
                    if self._last_bp_packet.call_stack_size > 0:
                        packet_id, packet = self._command_queue.get(block=True)
                        if packet_id != BREAKPOINT_CALLSTACK:
                            raise Exception(f"invalid packet {packet_id}, expected BREAKPOINT_CALLSTACK")
                        self._last_bp_callstack = packet
                    self._on_breakpoint()
                    self._state = self._STATE_BREAK
                elif packet_id == GPF:
                    self._last_bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                    self._state = self._STATE_GPF
                    self._on_gpf()
                    self._state = self._STATE_BREAK
                elif packet_id == PF:
                    self._last_bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                    self._state = self._STATE_GPF
                    self._on_pf()
                    self._state = self._STATE_BREAK
                elif packet_id == UD:
                    self._last_bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                    self._state = self._STATE_GPF
                    self._on_gpf()
                    self._state = self._STATE_BREAK
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
                elif packet_id == CPUID_RESP:
                    self._on_cpuid(packet)
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
