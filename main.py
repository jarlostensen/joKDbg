"""
This is a sandbox of experimental code to use and refine the DebugCore Debugger module
"""
import time
import re
import string

# NOTE: https://stackoverflow.com/questions/21048073/install-python-package-from-github-using-pycharm
import pdbparse
import DebugCore

# disassembler https://pypi.org/project/iced-x86/
import iced_x86
import queue

import tkinter as tk


def _convert_input_number(literal: str):
    if literal.lower().startswith('0x'):
        return int(literal, 16)
    return int(literal)


class DebuggerApp(DebugCore.Debugger):
    """
    The main debugger application
    DebugCore.Debugger drives the connection and commands to and from the kernel while this class
    deals (mostly) with UX and data analysis
    """
    __BASE_FONT = ('Consolas', 9)
    __DARK_BG = 'gray20'
    __DARK_FG = 'lightgray'
    __DARK_FRAME_BG = 'gray30'

    __TOP_PANE_HEIGHT = 600
    __BOTTOM_PANE_HEIGHT = 300
    __PANEL_WIDTH = 500 + 728

    __DEBUGGER_NOT_CONNECTED_MSG = f'Debugger not connected...'

    def __init__(self):
        super().__init__()

        self._root = tk.Tk()
        self._root.title("josKDbg")
        self._root.config(bg="pink")
        # for now
        self._root.resizable(False, False)

        # top
        self._top_pane = tk.Frame(self._root, height=self.__TOP_PANE_HEIGHT, width=self.__PANEL_WIDTH,
                                  bg=self.__DARK_FRAME_BG)
        self._top_pane.pack(fill=tk.BOTH, expand=True, side=tk.TOP)
        self._top_pane.pack_propagate(0)

        # trace
        self.__trace_frame_width = self.__PANEL_WIDTH / 3
        self._trace_frame = tk.LabelFrame(self._top_pane, width=self.__trace_frame_width, text="Trace")
        self._trace_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT)
        self._trace_frame.pack_propagate(0)
        self._trace_pane = tk.Frame(self._trace_frame, bg=self.__DARK_FRAME_BG)
        self._trace_pane.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT)
        self._trace_window = tk.Text(self._trace_pane, wrap=tk.WORD, font=self.__BASE_FONT,
                                     bg=self.__DARK_BG, fg=self.__DARK_FG)
        self._trace_window.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        # self._trace_window['state'] = 'disabled'
        self._trace_sb = tk.Scrollbar(self._trace_window)
        self._trace_sb.pack(side=tk.RIGHT, fill=tk.BOTH)
        self._trace_window.config(yscrollcommand=self._trace_sb.set)
        self._trace_sb.config(command=self._trace_window.yview)

        # output
        self.__output_frame_width = self.__PANEL_WIDTH - self.__trace_frame_width
        self._output_frame = tk.LabelFrame(self._top_pane, width=self.__output_frame_width, text="Command")
        self._output_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        self._output_frame.pack_propagate(0)
        self._output_pane = tk.Frame(self._output_frame, bg=self.__DARK_FRAME_BG)
        self._output_pane.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        self._output_window = tk.Text(self._output_pane, wrap=tk.WORD, font=self.__BASE_FONT,
                                      bg=self.__DARK_BG, fg=self.__DARK_FG)
        self._output_window.tag_configure('assert', foreground='red')
        self._output_window.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        self._output_sb = tk.Scrollbar(self._output_window)
        self._output_sb.pack(side=tk.RIGHT, fill=tk.BOTH)
        self._output_window.config(yscrollcommand=self._output_sb.set)
        self._output_sb.config(command=self._output_window.yview)

        # bottom
        self._bottom_pane = tk.Frame(self._root, height=self.__BOTTOM_PANE_HEIGHT, bg=self.__DARK_FRAME_BG)
        self._bottom_pane.pack(fill=tk.BOTH, expand=True, side=tk.BOTTOM)
        self._bottom_pane.pack_propagate(0)

        # cli pane sits between top and bottom pane, strictly
        self._bottom_top_pane = tk.Frame(self._root, bg=self.__DARK_FRAME_BG)
        self._bottom_top_pane.pack(fill=tk.X, expand=True, side=tk.BOTTOM)

        self._bottom_bottom_pane = tk.Frame(self._bottom_pane, bg=self.__DARK_FRAME_BG)
        self._bottom_bottom_pane.pack(fill=tk.BOTH, expand=True, side=tk.BOTTOM)

        self._cli_frame = tk.LabelFrame(self._bottom_top_pane, text='CMD')
        self._cli_frame.pack(fill=tk.BOTH, expand=True, side=tk.TOP)

        self._stack_frame = tk.LabelFrame(self._bottom_bottom_pane, text='Stack')
        self._stack_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT)

        self._locals_frame = tk.LabelFrame(self._bottom_bottom_pane, text='Locals')
        self._locals_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT)

        # CLI input window
        self._prompt = tk.Label(self._cli_frame, text="> ")
        self._prompt.pack(side=tk.LEFT)
        self._input = tk.StringVar()
        self._cli = tk.Entry(self._cli_frame, text=self._input)
        self._cli.pack(side=tk.LEFT, fill=tk.BOTH, padx=2, expand=True)
        self._cli.bind('<Return>', self._on_cli_enter)
        self._input.set(self.__DEBUGGER_NOT_CONNECTED_MSG)
        self._cli.configure(state=tk.DISABLED)

        # other internals
        self._cli_history = []
        self._asm_formatter = iced_x86.Formatter(iced_x86.FormatterSyntax.NASM)
        self._symbol_lookup = None
        self._pdb_path = ''
        self._target_memory_request_queue = []

    __TM_REQUEST_CODE = 1
    __TM_REQUEST_DATA = 2

    def _on_target_memory_read(self, packet):
        request, at = self._target_memory_request_queue.pop()
        if request == self.__TM_REQUEST_CODE:
            self._disassemble_bytes_impl(packet, at)
        else:
            self._dump_memory_bytes(packet, at)

    def _on_assert(self, json_data):
        import json
        assert_obj = json_data['assert']
        cond = assert_obj['cond']
        file = assert_obj['file']
        line = assert_obj['line']
        self._output_window.insert(tk.END, f'\nASSERT:\n\t{cond}\n\tin {file} @ line {line}\n'
                                           f'EXECUTION WILL NOT CONTINUE', 'assert')

    def _on_get_pagetable_info(self, table_info):
        self._output_window.insert(tk.END, f'\npagetable info for {hex(table_info.address)}:\n')
        pml4e = table_info.entries[0]
        pdpte = table_info.entries[1]
        if (pdpte & 1) == 0:
            self._output_window.insert(tk.END, f'\tNOT PRESENT\n')
        else:
            if pdpte & (1 << 7):
                # 1GB pages
                phys_base = pdpte & ~0x1ff
                flags = pdpte & 0xfff
                self._output_window.insert(tk.END, f'\t(1GB page): phys @ '
                                                   f'{hex(phys_base + (table_info.address & 0x3fffffff))}'
                                                   f' flags {hex(flags)}\n')
            else:
                pde = table_info.entries[2]
                if (pde & 1) == 0:
                    self._output_window.insert(tk.END, f'\tNOT PRESENT\n')
                else:
                    if pde & (1 << 7):
                        # 2MB pages
                        phys_base = pde & ~0x1ff
                        flags = pde & 0xfff
                        self._output_window.insert(tk.END, f'\t(2MB page): phys @ '
                                                           f'{hex(phys_base + (table_info.address & 0x1fffff))}'
                                                           f' flags {hex(flags)}\n')
                    else:
                        # 4KB pages
                        pte = table_info.entries[3]
                        if (pte & 1) == 0:
                            self._output_window.insert(tk.END, f'\tNOT PRESENT\n')
                        else:
                            phys_base = pte & ~0x1ff
                            flags = pte & 0xfff
                            self._output_window.insert(tk.END, f'\t(4KB page): phys @ '
                                                               f'{hex(phys_base + (table_info.address & 0xfff))}'
                                                               f' flags {hex(flags)}\n')

    def _on_read_msr(self, msr_packet):
        self._output_window.insert(tk.END, f'\nMSR info for {hex(msr_packet.msr)}, '
                                           f'lo: {hex(msr_packet.lo)} hi: {hex(msr_packet.hi)}\n')

    def _on_cli_enter(self, e):
        cmd = self._input.get().lstrip()
        next_input_state = ''
        self._cli_history.append(cmd)
        if self._state == self._STATE_BREAK:
            if cmd == 'g':
                next_input_state = self.__DEBUGGER_NOT_CONNECTED_MSG
                self.continue_execution()
            elif cmd == 'r':
                self._dump_registers(self._last_bp_packet)
            elif cmd == 'u':
                self._target_memory_request_queue.append((self.__TM_REQUEST_CODE, self._last_bp_packet.stack.rip))
                self.read_target_memory(self._last_bp_packet.stack.rip, 52)
            elif cmd.startswith('d'):
                parts = cmd.split()
                if len(parts) > 1:
                    target = _convert_input_number(parts[1])
                else:
                    target = self._last_bp_packet.stack.rip
                self._target_memory_request_queue.append((self.__TM_REQUEST_DATA, target))
                self.read_target_memory(target, 8*16)
            elif cmd == 'p':
                self.single_step()
            elif cmd.startswith('.pt'):
                parts = cmd.split()
                if len(parts) > 1:
                    target = _convert_input_number(parts[1])
                else:
                    target = self._last_bp_packet.stack.rip
                self.traverse_pagetable(target)
            elif cmd.startswith('.rdmsr'):
                parts = cmd.split()
                if len(parts) > 1:
                    self.read_msr(_convert_input_number(parts[1]))
            # elif cmd == '~':
            #    self._cli_state = self.__CLI_STATE_TASKS
            #    self.get_task_list()
        self._input.set(next_input_state)
        if self._state == self._STATE_WAITING:
            self._cli.configure(state=tk.DISABLED)

    def run(self, pdb_path):
        self._pdb_path = pdb_path
        try:
            self.pipe_connect(r'\\.\pipe\josxDbg')
            while True:
                self.update()
                self._root.update_idletasks()
                self._root.update()
        except Exception as e:
            print(f'disconnecting : {str(e)}')

    def _dump_memory_bytes(self, raw_bytes, at):
        self._output_window.insert(tk.INSERT, '\n')
        runs = len(raw_bytes) // 16
        i = 0
        # TODO: this is dumb and slow, surely there's a much more pythonic way to do this faster...?
        for j in range(runs):
            run = raw_bytes[i:i + 16]
            literal = ''
            bytes_str = run.hex(' ').lower()
            for b in run:
                if 32 <= b < 127:
                    literal = literal + chr(b)
                else:
                    literal = literal + '.'
            # literal = re.sub(f'[^{re.escape(string.printable)}]', '.', run)
            self._output_window.insert(tk.END, f'{at:016x} {bytes_str}    {literal}\n')
            i = i + 16
        rem = len(raw_bytes) % 16
        if rem:
            run = raw_bytes[i:i + rem]
            bytes_str = run.hex(' ').lower()
            literal = ''
            for b in run:
                if 32 <= b < 127:
                    literal = literal + chr(b)
                else:
                    literal = literal + '.'
            bytes_str = bytes_str.ljust(3*16 - 1, ' ')
            self._output_window.insert(tk.END, f'{at:016x} {bytes_str}    {literal}\n')

    def _disassemble_output_instruction(self, instr: iced_x86.Instruction, bytes_str: str, disasm: str,
                                        lookup_calls: bool):
        if lookup_calls:
            cflow = instr.flow_control
            if cflow == iced_x86.FlowControl.CALL or cflow == iced_x86.FlowControl.INDIRECT_CALL:
                call_target = 0
                if instr.op0_kind == iced_x86.OpKind.REGISTER:
                    # TODO: TESTING ONLY
                    if instr.op0_register == iced_x86.Register.RAX:
                        call_target = self._last_bp_packet.stack.rax
                    elif instr.op0_register == iced_x86.Register.RCX:
                        call_target = self._last_bp_packet.stack.rcx
                    elif instr.op0_register == iced_x86.Register.RDX:
                        call_target = self._last_bp_packet.stack.rdx
                    elif instr.op0_register == iced_x86.Register.R8:
                        call_target = self._last_bp_packet.stack.r8
                    elif instr.op0_register == iced_x86.Register.R9:
                        call_target = self._last_bp_packet.stack.r9
                    elif instr.op0_register == iced_x86.Register.R10:
                        call_target = self._last_bp_packet.stack.r10
                    elif instr.op0_register == iced_x86.Register.R11:
                        call_target = self._last_bp_packet.stack.r11
                    elif instr.op0_register == iced_x86.Register.R12:
                        call_target = self._last_bp_packet.stack.r12
                    elif instr.op0_register == iced_x86.Register.R13:
                        call_target = self._last_bp_packet.stack.r13
                    elif instr.op0_register == iced_x86.Register.R14:
                        call_target = self._last_bp_packet.stack.r14
                    elif instr.op0_register == iced_x86.Register.R15:
                        call_target = self._last_bp_packet.stack.r15
                    elif instr.op0_register == iced_x86.Register.RSI:
                        call_target = self._last_bp_packet.stack.rsi
                    elif instr.op0_register == iced_x86.Register.RDI:
                        call_target = self._last_bp_packet.stack.rdi
                if call_target != 0:
                    lookup = self._symbol_lookup.lookup(call_target)
                    disasm = disasm + ' ==> ' + lookup
        self._output_window.insert(tk.END, f'{instr.ip:016x} {bytes_str:30} {disasm}\n')

    def _disassemble_bytes_impl(self, raw_bytes, at):
        lookup = self._symbol_lookup.lookup(at)
        self._output_window.insert(tk.INSERT, f'\n{lookup}:\n')
        decoder = iced_x86.Decoder(64, raw_bytes, ip=at)
        line = 0
        for instr in decoder:
            if instr.code == iced_x86.Code.INVALID or line == 5:
                break
            disasm = self._asm_formatter.format(instr)
            start_index = instr.ip - at
            bytes_str = raw_bytes[start_index:start_index + instr.len].hex().lower()
            self._disassemble_output_instruction(instr, bytes_str, disasm, False)
            line = line + 1

    def _on_connect_impl(self, kernel_info_json):
        image_info = kernel_info_json['image_info']
        from pdbparse.symlookup import Lookup
        base = image_info['base']
        entry_point = image_info['entry_point']
        self._pdb_lookup_info = [(self._pdb_path, base)]
        version_str = str(kernel_info_json['version']['major']) +\
                      '.' + \
                      str(kernel_info_json['version']['minor']) + \
                      '.' + \
                      str(kernel_info_json['version']['patch'])
        self._output_window.insert(tk.END, f'\nconnected to kernel {version_str}, base is @ {hex(base)}, '
                                           f'entry point @ {hex(entry_point)}\n')
        self._output_window.insert(tk.END, 'kernel reports available RAM ' +
                                   str(kernel_info_json['system_info']['memory'])
                                   + ', and '
                                   + str(kernel_info_json['system_info']['processors']) + ' processors\n\n')

    def _dump_registers(self, bp_packet):
        self._output_window.insert(tk.INSERT,
                                   f'\nrax {bp_packet.stack.rax:016x} rbx {bp_packet.stack.rbx:016x} rcx '
                                   f'{bp_packet.stack.rcx:016x} rdx {bp_packet.stack.rdx:016x}')
        self._output_window.insert(tk.INSERT,
                                   f'\nrsi {bp_packet.stack.rsi:016x} rdi {bp_packet.stack.rdi:016x} rsp '
                                   f'{bp_packet.stack.rsp:016x} rbp {bp_packet.stack.rbp:016x}')
        self._output_window.insert(tk.INSERT,
                                   f'\nr8  {bp_packet.stack.r8:016x} r9  {bp_packet.stack.r9:016x} r10 '
                                   f'{bp_packet.stack.r10:016x} r11 {bp_packet.stack.r11:016x}')
        self._output_window.insert(tk.INSERT,
                                   f'\nr12 {bp_packet.stack.r12:016x} r13 {bp_packet.stack.r13:016x} r14 '
                                   f'{bp_packet.stack.r14:016x} r15 {bp_packet.stack.r15:016x}')
        self._output_window.insert(tk.INSERT,
                                   f'\nrflags {bp_packet.stack.rflags:08x} cs {bp_packet.stack.cs:02x} ss '
                                   f'{bp_packet.stack.ss:02x}\n')
        self._output_window.insert(tk.INSERT,
                                   f'\ncr0 {bp_packet.cr0:08x} cr3 {bp_packet.cr3:08x} cr4 '
                                   f'{bp_packet.cr4:08x}\n')
        if bp_packet.stack.rflags & (1 << 0) != 0:
            self._output_window.insert(tk.INSERT, 'CF ')
        if bp_packet.stack.rflags & (1 << 6) != 0:
            self._output_window.insert(tk.INSERT, 'ZF ')
        if bp_packet.stack.rflags & (1 << 7) != 0:
            self._output_window.insert(tk.INSERT, 'SF ')
        if bp_packet.stack.rflags & (1 << 8) != 0:
            self._output_window.insert(tk.INSERT, 'TF ')
        if bp_packet.stack.rflags & (1 << 9) != 0:
            self._output_window.insert(tk.INSERT, 'IF ')
        if bp_packet.stack.rflags & (1 << 10) != 0:
            self._output_window.insert(tk.INSERT, 'DF ')
        if bp_packet.stack.rflags & (1 << 11) != 0:
            self._output_window.insert(tk.INSERT, 'OF ')
        self._output_window.insert(tk.INSERT, '\n')

    def _on_breakpoint(self):
        try:
            if self._symbol_lookup is None:
                from pdbparse.symlookup import Lookup
                self._symbol_lookup = Lookup(self._pdb_lookup_info)
            lookup = self._symbol_lookup.lookup(self._last_bp_packet.stack.rip)
            self._output_window.insert(tk.INSERT, f'\n>break - code @ {lookup}\n')
            raw_bytes = bytearray(self._last_bp_packet.instruction)
            instr = iced_x86.Decoder(64, raw_bytes, ip=self._last_bp_packet.stack.rip).decode()
            disasm = self._asm_formatter.format(instr)
            bytes_str = raw_bytes[:instr.len].hex().lower()
            self._disassemble_output_instruction(instr, bytes_str, disasm, True)
            # allow input
            self._cli.configure(state=tk.NORMAL)
            self._input.set('')
        except Exception as e:
            print(str(e))

    def _on_gpf(self):
        # TODO:
        self._on_breakpoint()

    def _process_trace_queue_impl(self, trace_queue: queue.Queue):
        self._trace_window.configure(state=tk.NORMAL)
        while not trace_queue.empty():
            self._trace_window.insert(tk.END, f'\n{trace_queue.get_nowait()}')
        trace_queue.task_done()
        self._trace_window.configure(state=tk.DISABLED)


if __name__ == '__main__':
    app = DebuggerApp()
    app.run(f'e:/dev/osdev/josx64/build/bootx64.pdb')
    # app._root.mainloop()
