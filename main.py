"""
This is a sandbox of experimental code to use and refine the josKDbg Debugger module
"""

import pefile

# NOTE: https://stackoverflow.com/questions/21048073/install-python-package-from-github-using-pycharm
import pdbparse
import josKDbg

# disassembler https://pypi.org/project/iced-x86/
import iced_x86
import queue


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


if __name__ == '__main__':
    # test_pdb_load()
    # test_debugger_loop()
    test_debugger()

