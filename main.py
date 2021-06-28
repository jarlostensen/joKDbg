"""
This is a sandbox of experimental code to use and refine the DebugCore Debugger module
"""
import time
import pefile

# NOTE: https://stackoverflow.com/questions/21048073/install-python-package-from-github-using-pycharm
import pdbparse
import DebugCore

# disassembler https://pypi.org/project/iced-x86/
import iced_x86
import queue

import tkinter as tk


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
        self._root.title("DebugCore")
        self._root.config(bg="pink")
        # for now
        self._root.resizable(False, False)

        # top
        self._top_pane = tk.Frame(self._root, height=self.__TOP_PANE_HEIGHT, width=self.__PANEL_WIDTH,
                                  bg=self.__DARK_FRAME_BG)
        self._top_pane.pack(fill=tk.BOTH, expand=True, side=tk.TOP)
        self._top_pane.pack_propagate(0)

        # trace
        self.__trace_frame_width = self.__PANEL_WIDTH/3
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

    def _on_target_memory_read(self, packet):
        self._disassemble_bytes_impl(packet, self._last_stack.rip)

    def _on_cli_enter(self, e):
        cmd = self._input.get()
        next_input_state = ''
        self._cli_history.append(cmd)
        if self._state == self._STATE_BREAK:
            if cmd == 'g':
                next_input_state = self.__DEBUGGER_NOT_CONNECTED_MSG
                self.continue_execution()
            elif cmd == 'r':
                self._dump_registers(self._last_stack)
            elif cmd == 'u':
                self.read_target_memory(self._last_stack.rip, 52)
        self._input.set(next_input_state)
        if len(next_input_state) > 0:
            self._cli.configure(state=tk.DISABLED)

    def run(self):
        try:
            self.pipe_connect(r'\\.\pipe\josxDbg')
            while True:
                self.update()
                self._root.update_idletasks()
                self._root.update()
                time.sleep(0.1)
        except Exception as e:
            print("disconnecting")

    def _disassemble_bytes_impl(self, raw_bytes, at):
        decoder = iced_x86.Decoder(64, raw_bytes, ip=at)
        formatter = iced_x86.Formatter(iced_x86.FormatterSyntax.NASM)
        line = 0
        for instr in decoder:
            disasm = formatter.format(instr)
            start_index = instr.ip - at
            bytes_str = raw_bytes[start_index:start_index + instr.len].hex().upper()
            if line == 5 or 'bad' in disasm:
                break
            self._output_window.insert(tk.END, f"\n{instr.ip:016X} {bytes_str:30} {disasm}")
            line = line + 1
        self._output_window.insert(tk.END, f'\n\n')

    def _on_connect_impl(self, kernel_info_json):
        print('>connected: ' + str(kernel_info_json))
        image_info = kernel_info_json['image_info']
        from pdbparse.symlookup import Lookup
        self._pdb_lookup_info = [(r'BOOTX64.PDB', image_info['base'])]

    def _dump_registers(self, stack):
        self._output_window.insert(tk.INSERT,
                                   f'\nrax {stack.rax:016x} rbx {stack.rbx:016x} rcx '
                                   f'{stack.rcx:016x} rdx {stack.rdx:016x}')
        self._output_window.insert(tk.INSERT,
                                   f'\nrsi {stack.rsi:016x} rdi {stack.rdi:016x} rsp '
                                   f'{stack.rsp:016x} rbp {stack.rbp:016x}')
        self._output_window.insert(tk.INSERT,
                                   f'\nr8  {stack.r8:016x} r9  {stack.r9:016x} r10 '
                                   f'{stack.r10:016x} r11 {stack.r11:016x}')
        self._output_window.insert(tk.INSERT,
                                   f'\nr12 {stack.r12:016x} r13 {stack.r13:016x} r14 '
                                   f'{stack.r14:016x} r15 {stack.r15:016x}')
        self._output_window.insert(tk.INSERT,
                                   f'\nrflags {stack.rflags:08x} cs {stack.cs:02x} ss '
                                   f'{stack.ss:02x}\n')
        if stack.rflags & (1 << 0) != 0:
            self._output_window.insert(tk.INSERT, 'CF ')
        if stack.rflags & (1 << 6) != 0:
            self._output_window.insert(tk.INSERT, 'ZF ')
        if stack.rflags & (1 << 7) != 0:
            self._output_window.insert(tk.INSERT, 'SF ')
        if stack.rflags & (1 << 8) != 0:
            self._output_window.insert(tk.INSERT, 'TF ')
        if stack.rflags & (1 << 9) != 0:
            self._output_window.insert(tk.INSERT, 'IF ')
        if stack.rflags & (1 << 10) != 0:
            self._output_window.insert(tk.INSERT, 'DF ')
        if stack.rflags & (1 << 11) != 0:
            self._output_window.insert(tk.INSERT, 'OF ')
        self._output_window.insert(tk.INSERT, '\n')

    def _on_breakpoint(self):
        from pdbparse.symlookup import Lookup
        lobj = Lookup(self._pdb_lookup_info)
        lookup = lobj.lookup(self._last_stack.rip)
        self._output_window.insert(tk.INSERT, f'\n>break - code @ {lookup}')
        self._cli.configure(state=tk.NORMAL)
        self._input.set('')

    def _on_bp_impl(self, at, bp_packet):
        self._output_window.insert(tk.INSERT, f'\n>breakpoint @ {hex(at)}')
        self._dump_bp_info(bp_packet)

    def _on_gpf_impl(self, at, bp_packet):
        self._output_window.insert(tk.INSERT, f'\n>#GPF @ {hex(at)}!!!!')
        self._dump_bp_info(bp_packet)

    def _process_trace_queue_impl(self, trace_queue: queue.Queue):
        while not trace_queue.empty():
            self._trace_window.insert(tk.END, f'\n{trace_queue.get_nowait()}')
        trace_queue.task_done()


if __name__ == '__main__':
    app = DebuggerApp()
    app.run()
    # app._root.mainloop()
