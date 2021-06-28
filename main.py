"""
This is a sandbox of experimental code to use and refine the josKDbg Debugger module
"""
import time
import pefile

# NOTE: https://stackoverflow.com/questions/21048073/install-python-package-from-github-using-pycharm
import pdbparse
import josKDbg

# disassembler https://pypi.org/project/iced-x86/
import iced_x86
import queue

import tkinter as tk


def test_debugger():
    class MyDebugger(josKDbg.Debugger):
        def __init__(self):
            self._pdb_lookup_info = None
            super().__init__()

        def _disassemble_bytes_impl(self, bytes, at):
            decoder = iced_x86.Decoder(64, bytes, ip=at)
            formatter = iced_x86.Formatter(iced_x86.FormatterSyntax.NASM)
            line = 0
            for instr in decoder:
                disasm = formatter.format(instr)
                start_index = instr.ip - at
                bytes_str = bytes[start_index:start_index + instr.len].hex().upper()
                if line == 5 or 'bad' in disasm:
                    break
                print(f"{instr.ip:016X} {bytes_str:30} {disasm}")
                line = line + 1

        def _on_connect_impl(self, kernel_info_json):
            print('>connected: ' + str(kernel_info_json))
            image_info = kernel_info_json['image_info']
            from pdbparse.symlookup import Lookup
            self._pdb_lookup_info = [(r'BOOTX64.PDB', image_info['base'])]

        def _on_breakpoint(self, bp_packet):
            from pdbparse.symlookup import Lookup
            lobj = Lookup(self._pdb_lookup_info)
            lookup = lobj.lookup(bp_packet.stack.rip)
            print(f'\n>break in code @ {lookup}')
            print(
                f'rax {bp_packet.stack.rax:016x} rbx {bp_packet.stack.rbx:016x} rcx {bp_packet.stack.rcx:016x} rdx {bp_packet.stack.rdx:016x}')
            print(
                f'rsi {bp_packet.stack.rsi:016x} rdi {bp_packet.stack.rdi:016x} rsp {bp_packet.stack.rsp:016x} rbp {bp_packet.stack.rbp:016x}')
            print(
                f'r8  {bp_packet.stack.r8:016x} r9  {bp_packet.stack.r9:016x} r10 {bp_packet.stack.r10:016x} r11 {bp_packet.stack.r11:016x}')
            print(
                f'r12 {bp_packet.stack.r12:016x} r13 {bp_packet.stack.r13:016x} r14 {bp_packet.stack.r14:016x} r15 {bp_packet.stack.r15:016x}')
            print(
                f'rflags {bp_packet.stack.rflags:08x} cs {bp_packet.stack.cs:02x} ss {bp_packet.stack.ss:02x}')
            if bp_packet.stack.rflags & (1 << 0) != 0:
                print('CF', end=' ')
            if bp_packet.stack.rflags & (1 << 6) != 0:
                print('ZF', end=' ')
            if bp_packet.stack.rflags & (1 << 7) != 0:
                print('SF', end=' ')
            if bp_packet.stack.rflags & (1 << 8) != 0:
                print('TF', end=' ')
            if bp_packet.stack.rflags & (1 << 9) != 0:
                print('IF', end=' ')
            if bp_packet.stack.rflags & (1 << 10) != 0:
                print('DF', end=' ')
            if bp_packet.stack.rflags & (1 << 11) != 0:
                print('OF', end=' ')
            print()
            print()

        def _on_bp_impl(self, at, bp_packet):
            print()
            print(f'>breakpoint @ {hex(at)}')
            self._dump_bp_info(bp_packet)

        def _on_gpf_impl(self, at, bp_packet):
            print()
            print(f'>#GPF @ {hex(at)}!!!!')
            self._dump_bp_info(bp_packet)

        def _process_trace_queue_impl(self, trace_queue: queue.Queue):
            while not trace_queue.empty():
                print(trace_queue.get_nowait())
            trace_queue.task_done()

    debugger = MyDebugger()
    debugger.pipe_connect(r'\\.\pipe\josxDbg')
    try:
        debugger.main_loop()
    finally:
        print('\n>debugger exiting')


def test_pe_load():
    pe = pefile.PE(r'BOOTX64.EFI')
    for i in pe.DIRECTORY_ENTRY_BASERELOC:
        print(i)


def test_pdb_load():
    try:
        pdb = pdbparse.parse(r'BOOTX64.PDB', fast_load=True)
        pdb.STREAM_DBI.load()
        pdb._update_names()
        pdb.STREAM_GSYM = pdb.STREAM_GSYM.reload()
        if pdb.STREAM_GSYM.size:
            pdb.STREAM_GSYM.load()
        pdb.STREAM_SECT_HDR = pdb.STREAM_SECT_HDR.reload()
        pdb.STREAM_SECT_HDR.load()
        # These are the dicey ones
        pdb.STREAM_OMAP_FROM_SRC = pdb.STREAM_OMAP_FROM_SRC.reload()
        pdb.STREAM_OMAP_FROM_SRC.load()
        pdb.STREAM_SECT_HDR_ORIG = pdb.STREAM_SECT_HDR_ORIG.reload()
        pdb.STREAM_SECT_HDR_ORIG.load()
    except AttributeError as e:
        pass


class DebuggerApp(josKDbg.Debugger):

    __BASE_FONT = ('Consolas', 9)
    __DARK_BG = 'gray20'
    __DARK_FG = 'lightgray'
    __DARK_FRAME_BG = 'gray30'

    __TOP_PANE_HEIGHT = 600
    __BOTTOM_PANE_HEIGHT = 300
    __PANEL_WIDTH = 500 + 728

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

    def _on_cli_enter(self, e):
        if 'g' in self._input.get() and self._state == self._STATE_BREAK:
            self._conn.send_kernel_continue()
            self._input = ''

    def run(self):
        try:
            self.pipe_connect(r'\\.\pipe\josxDbg')
            while True:
                self.update()
                self._root.update_idletasks()
                self._root.update()
                time.sleep(0.1)
        except Exception as e:
            print("disconneting")

    def _disassemble_bytes_impl(self, bytes, at):
        decoder = iced_x86.Decoder(64, bytes, ip=at)
        formatter = iced_x86.Formatter(iced_x86.FormatterSyntax.NASM)
        line = 0
        for instr in decoder:
            disasm = formatter.format(instr)
            start_index = instr.ip - at
            bytes_str = bytes[start_index:start_index + instr.len].hex().upper()
            if line == 5 or 'bad' in disasm:
                break
            self._output_window.insert(tk.END, f"\n{instr.ip:016X} {bytes_str:30} {disasm}")
            line = line + 1

    def _on_connect_impl(self, kernel_info_json):
        print('>connected: ' + str(kernel_info_json))
        image_info = kernel_info_json['image_info']
        from pdbparse.symlookup import Lookup
        self._pdb_lookup_info = [(r'BOOTX64.PDB', image_info['base'])]

    def _on_breakpoint(self, bp_packet):
        from pdbparse.symlookup import Lookup
        lobj = Lookup(self._pdb_lookup_info)
        lookup = lobj.lookup(bp_packet.stack.rip)
        self._output_window.insert(tk.INSERT, f'\n>break in code @ {lookup}')
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
    #app._root.mainloop()

    # test_pdb_load()
    # test_debugger_loop()
    # test_debugger()
