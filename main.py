import base64
import json
import pefile

# NOTE: https://stackoverflow.com/questions/21048073/install-python-package-from-github-using-pycharm
import pdbparse
import josKDbg

# disassembler https://pypi.org/project/iced-x86/
import iced_x86


class YmlPdbLoader:
    """load and parse a PDB file in YML format created by LLVM"""

    def __init__(self, yml_file_name: str, module_start_phys: int):
        self._yml_file = open(yml_file_name, 'r')
        self._functions = []
        self._sections = {}
        self._lines_sections = []
        self._lines_read_last = 0
        self._module_start_phys = module_start_phys

    def __str__(self):
        return 'yml.pdb module @' + hex(self._module_start_phys)

    def _load_function_information(self):
        line = self._yml_file.readline()
        offset = line.split()
        line = self._yml_file.readline()
        segment_id = line.split()
        line = self._yml_file.readline()
        name = line.split()
        self._lines_read_last = 3
        self._functions.append(dict(name=name[1], offset=int(offset[1]), segment=int(segment_id[1])))

    def _load_section_information(self):
        line = self._yml_file.readline()
        section = line.split()
        line = self._yml_file.readline()
        alignment = line.split()
        line = self._yml_file.readline()
        offset = line.split()
        line = self._yml_file.readline()
        length = line.split()
        line = self._yml_file.readline()
        characteristics = line.split()
        line = self._yml_file.readline()
        name = line.split()
        self._lines_read_last = 5
        self._sections[name[1]] = [int(section[1]), int(length[1]), int(offset[1])]

    def _load_lines_information(self):
        # TODO: read one block completely and return
        pass

    def load(self):
        line = self._yml_file.readline()
        # line number to code offset tables
        section_indent_level = 0
        section = []
        line_num = 1
        while line:
            this_indent_level = len(line) - len(line.lstrip())
            if this_indent_level < section_indent_level:
                section_indent_level = 0
                self._lines_sections.append(section)
            tokens = line.split()
            self._lines_read_last = 1
            if len(tokens) > 1 and tokens[1] == '!Lines':
                section_indent_level = this_indent_level + 1
                section = []
            elif section_indent_level > 0:
                section.append(tokens)
            else:
                if tokens[0] == 'SectionSym:':
                    self._load_section_information()
                    line_num = line_num + self._lines_read_last
                if len(tokens) == 4 and tokens[2] == 'Function':
                    self._load_function_information()
            line = self._yml_file.readline()
            line_num = line_num + self._lines_read_last

        # sort function RVAs
        self._functions.sort(key=lambda entry: entry['offset'])

    def rva_from_phys(self, phys: int, section_name: str):
        section = self._sections[section_name]
        return phys - (section[2] + self._module_start_phys)

    def lookup_function_from_rva(self, rva) -> []:
        # TODO: use bisect or some other pythonic way of searching the sorted object list
        prev_entry = None
        for entry in self._functions:
            if entry['offset'] >= rva:
                return prev_entry
            prev_entry = entry
        return []


class KernelLogAnalyser:
    def __init__(self, kernel_log_name: str):
        self._kernel_log_name = kernel_log_name
        self._kernel_log_file = open(kernel_log_name, 'r')
        self._error_logs = []
        self._load()

    def has_error(self):
        return len(self._error_logs) > 0

    def gp_phys(self):
        if self.has_error():
            for error in self._error_logs:
                if error.find('#GPF'):
                    line_tokens = error.split()
                    return int(line_tokens[-1], 16)
        return 0

    def _load(self):
        line = self._kernel_log_file.readline()
        while line:
            if line.find('error') >= 0:
                self._error_logs.append(line)
            line = self._kernel_log_file.readline()


def test_debugger():
    class MyDebugger(josKDbg.Debugger):
        def __init__(self):
            self._pdb_lookup_info = None
            super().__init__()

        def _disassemble_bytes_impl(self, bytes, at):
            decoder = iced_x86.Decoder(64, bytes, ip=at)
            formatter = iced_x86.Formatter(iced_x86.FormatterSyntax.NASM)
            for instr in decoder:
                disasm = formatter.format(instr)
                start_index = instr.ip - at
                bytes_str = bytes[start_index:start_index + instr.len].hex().upper()
                print(f"{instr.ip:016X} {bytes_str:30} {disasm}")

        def _on_connect_impl(self, kernel_info_json):
            print('>connected: ' + str(kernel_info_json))
            image_info = kernel_info_json['image_info']
            from pdbparse.symlookup import Lookup
            self._pdb_lookup_info = [(r'BOOTX64.PDB', image_info['base'])]

        def _on_bp(self, at, bp_packet):
            print()
            print(f'>breakpoint @ {hex(at)}')
            from pdbparse.symlookup import Lookup
            lobj = Lookup(self._pdb_lookup_info)
            lookup = lobj.lookup(bp_packet.stack.rip)
            print(f'>break in code @ {lookup}')
            print(f'rax {bp_packet.stack.rax:016x} rbx {bp_packet.stack.rbx:016x} rcx {bp_packet.stack.rcx:016x} rdx {bp_packet.stack.rdx:016x}')
            print(
                f'rsi {bp_packet.stack.rsi:016x} rdi {bp_packet.stack.rdi:016x} rsp {bp_packet.stack.rsp:016x} rbp {bp_packet.stack.rbp:016x}')
            print(
                f'r8  {bp_packet.stack.r8:016x} r9 {bp_packet.stack.r9:016x} r10 {bp_packet.stack.r10:016x} r11 {bp_packet.stack.r11:016x}')
            print(
                f'r12 {bp_packet.stack.r12:016x} r13 {bp_packet.stack.r13:016x} r14 {bp_packet.stack.r14:016x} r15 {bp_packet.stack.r15:016x}')
            print()

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

