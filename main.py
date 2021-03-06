"""
This is a sandbox of experimental code to use and refine the DebugCore Debugger module
"""
import ctypes
from datetime import datetime

import DebugCore

# disassembler https://pypi.org/project/iced-x86/
import iced_x86
import queue

import tkinter as tk
import json

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
        self._trace_window.configure(state=tk.DISABLED)
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
        self._output_window.tag_configure('error', foreground='red')
        self._output_window.tag_configure('warning', foreground='orange')
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
        self._stack_frame.pack_propagate(0)
        self._stack_pane = tk.Frame(self._stack_frame, bg=self.__DARK_FRAME_BG)
        self._stack_pane.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT)

        self._locals_frame = tk.LabelFrame(self._bottom_bottom_pane, text='Locals')
        self._locals_frame.pack(fill=tk.BOTH, expand=True, side=tk.RIGHT)

        # stack window
        self._stack_window = tk.Text(self._stack_pane, wrap=tk.WORD,
                                     font=self.__BASE_FONT, bg=self.__DARK_BG, fg=self.__DARK_FG)
        self._stack_window.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        self._stack_sb = tk.Scrollbar(self._stack_window)
        self._stack_sb.pack(side=tk.RIGHT, fill=tk.BOTH)
        self._stack_window.config(yscrollcommand=self._stack_sb)
        self._stack_sb.config(command=self._stack_window.yview)

        # CLI input window
        self._prompt = tk.Label(self._cli_frame, text="> ")
        self._prompt.pack(side=tk.LEFT)
        self._input = tk.StringVar()
        self._cli = tk.Entry(self._cli_frame, text=self._input)
        self._cli.pack(side=tk.LEFT, fill=tk.BOTH, padx=2, expand=True)
        self._cli.bind('<Return>', self._on_cli_enter)
        self._cli.bind('<Up>', self._on_cli_up)
        self._cli.bind('<Down>', self._on_cli_down)
        self._input.set(self.__DEBUGGER_NOT_CONNECTED_MSG)
        self._cli.configure(state=tk.DISABLED)

        # other internals
        self._cli_history = []
        self._cli_history_pos = 0
        self._asm_formatter = iced_x86.Formatter(iced_x86.FormatterSyntax.NASM)
        self._target_memory_request_queue = []
        self._trace_log_file = open('traces.log', 'a')
        self._trace_log_file.write(f'\nstart trace @ {datetime.now()}\n')
        self._kernel_info = None

        # CLI commands and handlers
        self._commands = {'h': ('help', self._cli_cmd_help)}
        self._commands['?'] = self._commands['h']
        self._commands['g'] = ('go', self._cli_cmd_go)
        self._commands['d'] = ('dump memory', self._cli_cmd_d)
        self._commands['r'] = ('dump registers', self._cli_cmd_r)
        self._commands['u'] = ('unassemble', self._cli_cmd_u)
        self._commands['t'] = ('trace step', self._cli_cmd_t)
        self._commands['p'] = ('single step and step over', self._cli_cmd_p)
        self._commands['.pt'] = ('page table traverse', self._cli_cmd_pt)
        self._commands['rdmsr'] = ('read MSR', self._cli_cmd_rdmsr)
        self._commands['bp'] = ('set breakpoint @ address or symbol name', self._cli_cmd_bp)
        self._commands['bl'] = ('list breakpoints', self._cli_cmd_bl)
        self._commands['be'] = ('enable breakpoint', self._cli_cmd_be)
        self._commands['bd'] = ('disable breakpoint', self._cli_cmd_bd)
        self._commands['bc'] = ('clear breakpoint', self._cli_cmd_bc)
        self._commands['ds'] = ('dump structure', self._cli_cmd_ds)
        self._commands['s'] = ('stack dump N levels', self._cli_cmd_s)
        self._commands['cpuid'] = ('cpuid leaf X', self._cli_cmd_cpuid)
        self._commands['di'] = ('dump kernel info', self._cli_cmd_di)
        self._commands['mm'] = ('dump a memory map', self._cli_cmd_mm)

    def _print_output(self, text, tag=None):
        self._output_window.insert(tk.END, text, tag)
        self._output_window.see(tk.END)

    def _print_trace(self, text, tag=None):
        self._trace_window.configure(state=tk.NORMAL)
        self._trace_window.insert(tk.END, text, tag)
        self._trace_window.configure(state=tk.DISABLED)
        self._trace_window.see(tk.END)

    def _on_print_callstack_entry(self, text):
        self._stack_window.configure(state=tk.NORMAL)
        self._stack_window.insert(tk.END, text)
        self._stack_window.configure(state=tk.DISABLED)
        self._stack_window.see(tk.END)

    def _clear_stack(self):
        self._stack_window.configure(state=tk.NORMAL)
        self._stack_window.delete("1.0", "end")
        self._stack_window.configure(state=tk.DISABLED)

    def _cli_disable(self):
        self._cli.configure(state=tk.DISABLED)

    def _cli_enable(self):
        self._cli.configure(state=tk.NORMAL)
        self._input.set('')

    def _on_target_memory_read(self, packet):
        at, handler, extradata = self._target_memory_request_queue.pop()
        handler(packet, at, extradata)

    def _on_assert(self, json_data):
        import json
        assert_obj = json_data['assert']
        cond = assert_obj['cond']
        file = assert_obj['file']
        line = assert_obj['line']
        self._print_output(f'\nASSERT:\n\t{cond}\n\tin {file} @ line {line}\n'
                           f'EXECUTION WILL NOT CONTINUE', 'assert')

    def _on_cpuid(self, packet):
        regs_type = ctypes.c_uint32 * 6
        regs = regs_type.from_buffer_copy(packet)
        self._print_output(f'\nCPUID : {hex(regs[0])} (ecx={hex(regs[1])})\n'
                           f'\teax {hex(regs[2])}\tebx {hex(regs[3])}'
                           f'\tecx {hex(regs[4])}\tedx {hex(regs[5])}\n')

    def _on_get_pagetable_info(self, table_info):
        self._print_output(f'\npagetable info for {hex(table_info.address)}:\n')
        pml4e = table_info.entries[0]
        pdpte = table_info.entries[1]
        if (pdpte & 1) == 0:
            self._print_output(f'\tNOT PRESENT\n')
        else:
            if pdpte & (1 << 7):
                # 1GB pages
                phys_base = pdpte & ~0x1ff
                flags = pdpte & 0xfff
                self._print_output(f'\t(1GB page): phys @ '
                                   f'{hex(phys_base + (table_info.address & 0x3fffffff))}'
                                   f' flags {hex(flags)}\n')
            else:
                pde = table_info.entries[2]
                if (pde & 1) == 0:
                    self._print_output(f'\tNOT PRESENT\n')
                else:
                    if pde & (1 << 7):
                        # 2MB pages
                        phys_base = pde & ~0x1ff
                        flags = pde & 0xfff
                        self._print_output(f'\t(2MB page): phys @ '
                                           f'{hex(phys_base + (table_info.address & 0x1fffff))}'
                                           f' flags {hex(flags)}\n')
                    else:
                        # 4KB pages
                        pte = table_info.entries[3]
                        if (pte & 1) == 0:
                            self._print_output(f'\tNOT PRESENT\n')
                        else:
                            phys_base = pte & ~0x1ff
                            flags = pte & 0xfff
                            self._print_output(f'\t(4KB page): phys @ '
                                               f'{hex(phys_base + (table_info.address & 0xfff))}'
                                               f' flags {hex(flags)}\n')

    def _on_read_msr(self, msr_packet):
        self._print_output(f'\nMSR info for {hex(msr_packet.msr)}, '
                           f'lo: {hex(msr_packet.lo)} hi: {hex(msr_packet.hi)}\n')

    def _cli_cmd_help(self, _):
        self._print_output(f'\nCommands:\n')
        for command, info in self._commands.items():
            self._print_output(f'\t{command}\t\t\t{info[0]}\n')

    def _cli_cmd_di(self, _):
        self._print_output(json.dumps(self._kernel_info))

    def _cli_cmd_go(self, _):
        self._input.set(self.__DEBUGGER_NOT_CONNECTED_MSG)
        self._cli_disable()
        self.synchronize_kernel()
        self.continue_execution()

    def _cli_cmd_cpuid(self, cmd_parts):
        if len(cmd_parts) > 1:
            try:
                leaf = _convert_input_number(cmd_parts[1])
                subleaf = 0
                if len(cmd_parts) > 2:
                    subleaf = _convert_input_number(cmd_parts[2])
                self.cpuid(leaf, subleaf)
            except ValueError:
                pass

    def _cli_cmd_r(self, _):
        self._dump_registers(self._last_bp_packet)

    def _cli_cmd_mm(self, _):
        self.memory_map()

    def _cli_cmd_u(self, cmd_parts):
        target = self._last_bp_packet.stack.rip
        if len(cmd_parts) > 1:
            target = _convert_input_number(cmd_parts[1])
        self._target_memory_request_queue.append((target, self._disassemble_bytes_impl, None))
        self.read_target_memory(target, 52)

    def _cli_cmd_d(self, cmd_parts):
        if len(cmd_parts) > 1:
            target = _convert_input_number(cmd_parts[1])
        else:
            target = self._last_bp_packet.stack.rip
        self._target_memory_request_queue.append((target, self._dump_memory_bytes,
                                                  None if len(cmd_parts) < 3 else cmd_parts))
        self.read_target_memory(target, 8 * 16)

    def _cli_cmd_t(self, _):
        self.synchronize_kernel()
        self.trace_step()

    def _cli_cmd_p(self, _):
        self.synchronize_kernel()
        self.single_step()

    def _cli_cmd_pt(self, cmd_parts):
        if len(cmd_parts) > 1:
            target = _convert_input_number(cmd_parts[1])
        else:
            target = self._last_bp_packet.stack.rip
        self.traverse_pagetable(target)

    def _cli_cmd_rdmsr(self, cmd_parts):
        if len(cmd_parts) > 1:
            self.read_msr(_convert_input_number(cmd_parts[1]))

    def _cli_cmd_ds(self, cmd_parts):
        if len(cmd_parts) > 1:
            # TODO for now the argument has to be a variable name
            try:
                var_info = self._pdb.get_variable_declaration(cmd_parts[1])
                if var_info is None:
                    self._print_output(f'{cmd_parts[1]} is not found in PDB\n')
                    return
                if var_info[1] != 'LF_STRUCTURE':
                    self._print_output(f'{cmd_parts[1]} is not a structure\n')
                    return
                struct_info = self._pdb.get_structure_info(var_info[0])
                packed_size = 0
                for field in struct_info:
                    packed_size = packed_size + field[2]
                target = self.rva_to_phys(var_info[2].offset, var_info[2].segment - 1)
                self._target_memory_request_queue.append((target, self._dump_structure,
                                                          (cmd_parts[1], var_info, struct_info)))
                self.read_target_memory(target, packed_size)
            except Exception as e:
                self._print_output(str(e))

    def _cli_cmd_bp(self, cmd_parts):
        if len(cmd_parts) == 1:
            return
        target = None
        try:
            target = _convert_input_number(cmd_parts[1])
        except ValueError:
            symbol_info = self._pdb.lookup_by_symbol(cmd_parts[1])
            if symbol_info is not None:
                target = symbol_info[2]
        finally:
            if target is not None and self.set_breakpoint(target):
                self._print_output(f'breakpoint {self._breakpoints[target][1]} set @ {hex(target)}\n')

    def _cli_cmd_bl(self, _):
        self._print_output(f'\n#\taddr\tcall site\n')
        for target, bp in self._breakpoints.items():
            if DebugCore.breakpoint_marked_for_clear(bp):
                continue
            lookup = self._pdb.lookup_symbol_at_address(target)
            self._print_output("".join([f'{bp[1]}\t{hex(target)}\t{lookup}\t',
                                        '(enabled)' if bp[0] else '(disabled)', '\n']))

    def _cli_cmd_be(self, cmd_parts):
        if len(cmd_parts) == 1:
            return
        try:
            index = _convert_input_number(cmd_parts[1])
            self.enable_breakpoint(index)
        except KeyError:
            # not found
            pass
        except ValueError:
            # invalid argument
            pass

    def _cli_cmd_bd(self, cmd_parts):
        if len(cmd_parts) == 1:
            return
        try:
            index = _convert_input_number(cmd_parts[1])
            self.disable_breakpoint(index)
        except KeyError or IndexError:
            # not found
            pass
        except ValueError:
            # invalid argument
            pass

    def _cli_cmd_bc(self, cmd_parts):
        if len(cmd_parts) == 1:
            return
        try:
            index = _convert_input_number(cmd_parts[1])
            self.clear_breakpoint(index)
        except KeyError:
            # not found
            pass
        except ValueError:
            # invalid argument
            pass

    def _cli_exec_cmd(self, cmd):
        if len(cmd) == 0:
            return
        cmd_parts = cmd.split()
        try:
            command = self._commands[cmd_parts[0]]
            # execute the command handler
            command[1](cmd_parts)
            self._cli_history.append(cmd)
        except KeyError:
            self._print_output(f'\nunknown command\n', 'warning')
        finally:
            # always clear the command
            self._input.set('')

    def _on_cli_enter(self, _):
        cmd = self._input.get().lstrip()
        self._cli_exec_cmd(cmd)

    def _on_cli_up(self, _):
        if len(self._cli_history) == 0:
            return
        self._cli_history_pos = (self._cli_history_pos - 1) % len(self._cli_history)
        cmd = self._cli_history[self._cli_history_pos]
        self._input.set(cmd)

    def _on_cli_down(self, _):
        if len(self._cli_history) == 0:
            return
        self._cli_history_pos = (self._cli_history_pos + 1) % len(self._cli_history)
        cmd = self._cli_history[self._cli_history_pos]
        self._input.set(cmd)

    def _cli_cmd_s(self, cmd):
        depth = 4
        if len(cmd) > 1:
            try:
                depth = max(depth, _convert_input_number(cmd[1]))
            except ValueError:
                self._print_output(f'\ninvalid argument\n', 'warning')
        self._target_memory_request_queue.append((self._last_bp_packet.stack.rsp, self._dump_stack, depth))
        self.read_target_memory(self._last_bp_packet.stack.rsp, depth * 8)

    def run(self, pe_path, pdb_path):
        self.set_paths(pe_path, pdb_path)
        try:
            self.pipe_connect(r'\\.\pipe\josxDbg')
            while True:
                self.update()
                self._root.update_idletasks()
                self._root.update()
        except Exception as e:
            print(f'disconnecting : {str(e)}')
        finally:
            self._trace_log_file.close()

    def _dump_stack(self, raw_bytes, at, depth):
        self._print_output(f'\nstack dump from {hex(at)}, {depth} levels:\n')
        offset = 0
        for d in range(depth):
            self._print_output(f'{hex(at + offset)}\t'
                               f'{hex(ctypes.c_uint64.from_buffer_copy(raw_bytes[offset:offset + 8]).value)}\n')
            offset = offset + 8

    def _dump_structure(self, raw_bytes, at, extra_data):
        var_name = extra_data[0]
        var_info = extra_data[1]
        struct_info = extra_data[2]
        phys = self.rva_to_phys(var_info[2].offset, var_info[2].segment - 1)
        self._print_output(f'\n{var_info[0]} {var_name} @ {hex(phys)} (rva {hex(var_info[2].offset)})\n')
        offset = 0
        for field in struct_info:
            # TODO for now...
            if field[2] == 8:
                val = ctypes.c_uint64.from_buffer_copy(raw_bytes[offset:offset + 8])
                self._print_output(f'\t{field[0]}\t{hex(val.value)};\n')
            elif field[2] == 4:
                val = ctypes.c_uint32.from_buffer_copy(raw_bytes[offset:offset + 4])
                self._print_output(f'\t{field[0]}\t{hex(val.value)};\n')
            elif field[2] == 2:
                val = ctypes.c_uint16.from_buffer_copy(raw_bytes[offset:offset + 2])
                self._print_output(f'\t{field[0]}\t{hex(val.value)};\n')
            elif field[2] == 1:
                val = ctypes.c_uint8.from_buffer_copy(raw_bytes[offset:offset + 1])
                self._print_output(f'\t{field[0]}\t{hex(val.value)};\n')
            else:
                self._print_output(f'\t{field[0]}\tUNKNOWN TYPE;\n')
                return
            offset = offset + field[2]

    def _dump_memory_bytes(self, raw_bytes, at, args):
        self._print_output('\n')
        runs = len(raw_bytes) // 16
        i = 0
        width = 1
        steps = 1
        if args is not None:
            width = _convert_input_number(args[2])
            if width > 16:
                raise Exception("dump command unit size > 16 not supported")
            steps = 16//width
        for j in range(runs):
            run = raw_bytes[i:i + 16]
            literal = "".join([chr(b) if 31 < b < 128 else '.' for b in run])
            if width == 1:
                bytes_str = run.hex(' ').lower()
            else:
                # TODO: optimise...
                chunks = []
                for s in range(steps):
                    chunks.append(run[s*width:(s+1)*width].hex().lower())
                bytes_str = " ".join(chunks)
            self._print_output(f'{at:016x} {bytes_str}    {literal}\n')
            i = i + 16
        rem = len(raw_bytes) % 16
        if rem:
            run = raw_bytes[i:i + rem]
            bytes_str = run.hex(' ').lower()
            literal = "".join([chr(b) if 31 < b < 128 else '.' for b in run])
            bytes_str = bytes_str.ljust(3 * 16 - 1, ' ')
            self._print_output(f'{at:016x} {bytes_str}    {literal}\n')

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
                    lookup = self._pdb.lookup_symbol_at_address(call_target)
                    disasm = disasm + ' ==> ' + lookup
        self._print_output(f'{instr.ip:016x} {bytes_str:30} {disasm}\n')

    def _disassemble_bytes_impl(self, raw_bytes, at, _):
        lookup = self._pdb.lookup_symbol_at_address(at)
        self._print_output(f'\n{lookup}:\n')
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
        self._kernel_info = kernel_info_json
        image_info = kernel_info_json['image_info']
        entry_point = image_info['entry_point']
        version_str = str(kernel_info_json['version']['major']) + \
                      '.' + \
                      str(kernel_info_json['version']['minor']) + \
                      '.' + \
                      str(kernel_info_json['version']['patch'])
        self._print_output(f'\nconnected to kernel {version_str}, base is @ {hex(self._image_base)}, '
                           f'entry point @ {hex(entry_point)}\n')
        self._print_output('kernel reports available RAM ' +
                           str(kernel_info_json['system_info']['memory'])
                           + ', and '
                           + str(kernel_info_json['system_info']['processors']) + ' processors\n')
        self._print_output('CPU vendor string: ' + kernel_info_json['system_info']['vendor'] + '\n')
        try:
            hypervisor = kernel_info_json['hypervisor']
            self._print_output('Hypervisor vendor string: ' + hypervisor['id'] + '\n')
        except KeyError:
            pass
        self._print_output('\n')

    def _dump_registers(self, bp_packet):
        self._print_output(
            f'\nrax {bp_packet.stack.rax:016x} rbx {bp_packet.stack.rbx:016x} rcx '
            f'{bp_packet.stack.rcx:016x} rdx {bp_packet.stack.rdx:016x}')
        self._print_output(
            f'\nrsi {bp_packet.stack.rsi:016x} rdi {bp_packet.stack.rdi:016x} rsp '
            f'{bp_packet.stack.rsp:016x} rbp {bp_packet.stack.rbp:016x}')
        self._print_output(
            f'\nr8  {bp_packet.stack.r8:016x} r9  {bp_packet.stack.r9:016x} r10 '
            f'{bp_packet.stack.r10:016x} r11 {bp_packet.stack.r11:016x}')
        self._print_output(
            f'\nr12 {bp_packet.stack.r12:016x} r13 {bp_packet.stack.r13:016x} r14 '
            f'{bp_packet.stack.r14:016x} r15 {bp_packet.stack.r15:016x}')
        self._print_output(
            f'\nrflags {bp_packet.stack.rflags:08x} cs {bp_packet.stack.cs:02x} ss '
            f'{bp_packet.stack.ss:02x}\n')
        if bp_packet.stack.rflags & (1 << 0) != 0:
            self._print_output('CF ')
        if bp_packet.stack.rflags & (1 << 6) != 0:
            self._print_output('ZF ')
        if bp_packet.stack.rflags & (1 << 7) != 0:
            self._print_output('SF ')
        if bp_packet.stack.rflags & (1 << 8) != 0:
            self._print_output('TF ')
        if bp_packet.stack.rflags & (1 << 9) != 0:
            self._print_output('IF ')
        if bp_packet.stack.rflags & (1 << 10) != 0:
            self._print_output('DF ')
        if bp_packet.stack.rflags & (1 << 11) != 0:
            self._print_output('OF ')

        self._print_output(
            f'\ncr0 {bp_packet.cr0:08x} cr3 {bp_packet.cr3:08x} cr4 '
            f'{bp_packet.cr4:08x}\n')
        self._print_output('\n')

    def _on_breakpoint(self):
        try:
            lookup = self._pdb.lookup_symbol_at_address(self._last_bp_packet.stack.rip)
            self._print_output(f'\n>break - code @ {lookup}\n')
            self._clear_stack()

            if self._last_bp_packet.call_stack_size > 0:
                callstack = (ctypes.c_uint64 * self._last_bp_packet.call_stack_size) \
                    .from_buffer_copy(self._last_bp_callstack)
                self._on_print_callstack_entry(f'{hex(self._last_bp_packet.stack.rip)}\t{lookup}\n')
                self.process_callstack(callstack)

            raw_bytes = bytearray(self._last_bp_packet.instruction)
            instr = iced_x86.Decoder(64, raw_bytes, ip=self._last_bp_packet.stack.rip).decode()
            disasm = self._asm_formatter.format(instr)
            bytes_str = raw_bytes[:instr.len].hex().lower()
            self._disassemble_output_instruction(instr, bytes_str, disasm, True)
            # allow input
            self._cli_enable()
        except Exception as e:
            print(str(e))

    def _on_pf(self):
        lookup = self._pdb.lookup_symbol_at_address(self._last_bp_packet.stack.rip)
        error_code = self._last_bp_packet.stack.error_code
        cr2 = self._last_bp_packet.cr2
        p = 'page level protection' if (error_code & (1 << 0)) else 'page not-present'
        wr = 'write' if (error_code & (1 << 1)) else 'read'
        us = 'user mode' if (error_code & (1 << 2)) else 'kernel mode'
        rsvd = 'reserved bit violation' if (error_code & (1 << 3)) else ''
        instr = 'instruction fetch' if (error_code & (1 << 4)) else ''
        flags = ' '.join([p, wr, us, rsvd, instr])
        self._print_output(f'\n>PAGE FAULT - code @ {lookup}\n\t'
                           f'@ {hex(cr2)}: {flags}', 'error')
        # allow input
        self._cli_enable()

    def _on_gpf(self):
        """
        Could be any of:
        * Executing a privileged instruction while CPL > 0.
        * Writing a 1 into any register field that is reserved, must be zero (MBZ).
        * Attempting to execute an SSE instruction specifying an unaligned memory operand.
        * Loading a non-canonical base address into the GDTR or IDTR.
        * Using WRMSR to write a read-only MSR.
        * Any long-mode consistency-check violation.
        """
        lookup = self._pdb.lookup_symbol_at_address(self._last_bp_packet.stack.rip)
        error_code = self._last_bp_packet.stack.error_code
        self._print_output(f'\n>GENERAL PROTECTION FAULT - code @ {hex(self._last_bp_packet.stack.rip)} : {lookup}, '
                           f'error code {hex(error_code)}', 'error')
        self._on_breakpoint()

    def _process_trace_queue_impl(self, trace_queue: queue.Queue):
        lines = []
        while not trace_queue.empty():
            line = trace_queue.get_nowait()
            self._print_trace(f'\n{line}')
            lines.append(line)
        trace_queue.task_done()
        if len(lines) > 0:
            self._trace_log_file.writelines("\n".join(lines))
            self._trace_log_file.write('\n')


if __name__ == '__main__':
    app = DebuggerApp()
    app.run(f'e:/dev/osdev/josx64/build/bootx64.efi', f'e:/dev/osdev/josx64/build/bootx64.pdb')
    app._root.mainloop()
