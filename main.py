import base64
import json
import pefile

# NOTE: https://stackoverflow.com/questions/21048073/install-python-package-from-github-using-pycharm
import pdbparse
import josKDbg

from struct import unpack


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


dbg_pipe_name = r'\\.\pipe\josxDbg'


def test_connection():
    conn = josKDbg.debugger_serial_connection_factory()
    conn.connect(dbg_pipe_name)
    print('>connected: ' + str(conn.kernel_connection_info()))
    image_info = conn.kernel_connection_info()['image_info']
    # print out kernel trace messages until the VM shuts down
    try:
        packet_id, packet_len, packet = conn.read_one_packet_block()
        while True:
            if packet_id == conn.READ_TARGET_MEMORY_RESP:
                pass
            elif packet_id == conn.TRACE:
                payload_as_string = packet.decode("utf-8")
                print(payload_as_string)
            elif packet_id == conn.INT3:
                payload_as_string = packet.decode("utf-8")
                json_packet = json.loads(payload_as_string)
                decodedBytes = base64.b64decode(json_packet['stackframe'])
                stackframe = josKDbg.InterruptStackFrame(decodedBytes)
                print(f'>breakpoint @ {hex(stackframe.cs)}:{hex(stackframe.rip)}')
                from pdbparse.symlookup import Lookup
                lookup_info = [(r'BOOTX64.PDB', image_info['base'])]
                lobj = Lookup(lookup_info)
                # strictly the address of the int3 instruction itself
                lookup = lobj.lookup(stackframe.rip - 1)
                print(lookup)
                # tell the kernel to continue execution
                conn.send_packet(conn.CONTINUE, 0, None)
            # read the next packet
            packet_id, packet_len, packet = conn.read_one_packet_block()
    finally:
        print(">debugger disconnecting")


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
    #test_pdb_load()
    test_connection()
