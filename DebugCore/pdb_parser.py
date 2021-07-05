from typing import Tuple, List, Any
from os import path


def _tpi_type_size(type_name: str) -> int:
    # TODO: LUT, not IF...
    # based on information in pdbparse/tpi.py
    if type_name == 'T_INT1' or \
            type_name == 'T_UINT1' or \
            type_name == 'T_RCHAR':
        return 1
    if type_name.startswith('T_P') or \
            type_name == 'T_SHORT' or \
            type_name == 'T_INT2' or \
            type_name == 'T_UINT2':
        return 2
    if type_name.startswith('T_32') or \
            type_name == 'T_LONG' or \
            type_name == 'T_ULONG' or \
            type_name == 'T_UINT4':
        return 4
    if type_name.startswith('T_64') or \
            type_name == 'T_INT8' or \
            type_name == 'T_UINT8':
        return 8
    raise Exception(f'unsupported type {type_name}')


def _get_type_name(tp):
    # a primitive type does not have a record
    if not "tpi_idx" in dir(tp):
        return str(tp)
    # for structures and unions, just print out the name
    if tp.leaf_type == "LF_UNION" or tp.leaf_type == "LF_STRUCTURE":
        return tp.name
    # a pointer to a known type
    if tp.leaf_type == "LF_POINTER":
        return _get_type_name(tp.utype) + "*"
    # handling 'const', 'volatile', and 'unaligned' modifiers
    if tp.leaf_type == "LF_MODIFIER":
        s = [mod for mod in ['const', 'volatile', 'unaligned'] \
             if tp.modifier[mod]]
        return " ".join(s) + " " + _get_type_name(tp.modified_type)
    # only 1D arrays are supported
    from pdbparse import tpi
    if tp.leaf_type == "LF_ARRAY":
        return _get_type_name(tp.element_type) + \
               "[" + str(int(tp.size / _tpi_type_size(tp.element_type))) + "]"
    return "UNKNOWN"


class DummyOmap(object):

    def remap(self, addr):
        return addr


class PdbParser:
    """
    wraps a number of different pieces of functionality, and some extensions, over
    the pdbparse library.

    see for example https://auscitte.github.io/systems%20blog/Func-Prototypes-With-Pdbparse
    """

    def __init__(self):
        self._pdb = None
        self._symbol_lookup = None
        self._pdb_name = None
        self._pdb_name_base = None
        self._base = 0
        self.addrs = {}
        self._loc_cache = {}
        self.locs = {}
        self.names = {}
        self._struct_cache = {}
        self._var_cache = {}

    def load(self, base: int, name: str):
        import pdbparse
        self._pdb = pdbparse.parse(name, fast_load=True)
        self._pdb.STREAM_DBI.load()
        self._pdb._update_names()
        self._base = base
        self._pdb_name = name
        self._pdb_name_base = ".".join(path.basename(self._pdb_name).split('.')[:-1])

    def _check_load_tpi(self):
        if 'types' in dir(self._pdb.STREAM_TPI):
            return
        self._pdb.STREAM_TPI.load()

    def _check_load_gsym(self):
        if 'globals' in dir(self._pdb.STREAM_GSYM):
            return
        self._pdb.STREAM_GSYM = self._pdb.STREAM_GSYM.reload()
        if self._pdb.STREAM_GSYM.size:
            self._pdb.STREAM_GSYM.load()

    def _check_load_lookup(self):
        if len(self.addrs) > 0:
            return
        # adapted from pdbparse/symlookup.py
        try:
            self._pdb.STREAM_SECT_HDR = self._pdb.STREAM_SECT_HDR.reload()
            self._pdb.STREAM_SECT_HDR.load()
            self._pdb.STREAM_OMAP_FROM_SRC = self._pdb.STREAM_OMAP_FROM_SRC.reload()
            self._pdb.STREAM_OMAP_FROM_SRC.load()
            self._pdb.STREAM_SECT_HDR_ORIG = self._pdb.STREAM_SECT_HDR_ORIG.reload()
            self._pdb.STREAM_SECT_HDR_ORIG.load()
        except AttributeError as e:
            pass
        from operator import itemgetter, attrgetter
        try:
            sects = self._pdb.STREAM_SECT_HDR_ORIG.sections
            omap = self._pdb.STREAM_OMAP_FROM_SRC
        except AttributeError as e:
            # In this case there is no OMAP, so we use the given section
            # headers and use the identity function for omap.remap
            sects = self._pdb.STREAM_SECT_HDR.sections
            omap = DummyOmap()
        self._check_load_gsym()
        gsyms = self._pdb.STREAM_GSYM
        if not hasattr(gsyms, 'globals'):
            gsyms.globals = []

        last_sect = max(sects, key=attrgetter('VirtualAddress'))
        limit = self._base + last_sect.VirtualAddress + last_sect.Misc.VirtualSize

        self.addrs[self._base, limit] = {}
        self.addrs[self._base, limit]['name'] = self._pdb_name_base
        self.addrs[self._base, limit]['addrs'] = []
        for sym in gsyms.globals:
            if not hasattr(sym, 'offset'):
                continue
            off = sym.offset
            try:
                virt_base = sects[sym.segment - 1].VirtualAddress
            except IndexError:
                continue

            mapped = omap.remap(off + virt_base) + self._base
            self.addrs[self._base, limit]['addrs'].append((mapped, sym.name))

        self.addrs[self._base, limit]['addrs'].sort(key=itemgetter(0))
        for base, limit in self.addrs:
            mod = self.addrs[base, limit]['name']
            symbols = self.addrs[base, limit]['addrs']
            self.locs[base, limit] = [a[0] for a in symbols]
            self.names[base, limit] = [a[1] for a in symbols]

    def _lookup(self, loc):
        if loc in self._loc_cache:
            return self._loc_cache[loc]
        self._check_load_lookup()
        from bisect import bisect_right
        for base, limit in self.addrs:
            if base <= loc < limit:
                mod = self.addrs[base, limit]['name']
                symbols = self.addrs[base, limit]['addrs']
                locs = self.locs[base, limit]
                names = self.names[base, limit]
                idx = bisect_right(locs, loc) - 1
                diff = loc - locs[idx]
                if diff:
                    ret = "%s!%s+%#x" % (mod, names[idx], diff)
                else:
                    ret = "%s!%s" % (mod, names[idx])
                self._loc_cache[loc] = ret
                return ret
        return "unknown"

    def get_leaf_type_for_type(self, tname):
        """
        :param tname: name of type
        :return: LF_<type>
        """
        self._check_load_tpi()
        tps = list(filter(lambda t:
                          'name' in self._pdb.STREAM_TPI.types[t]
                          and self._pdb.STREAM_TPI.types[t].name == tname,
                          self._pdb.STREAM_TPI.types))
        if len(tps) == 0:
            raise IndexError(f"{tname} not found in PDB")
        return self._pdb.STREAM_TPI.types[tps[0]].leaf_type

    def get_structure_info(self, sname: str) -> List[Tuple[str, str]]:
        """
        look up and return structure fields:types information, if found
        :param sname: name of structure type
        :return: fields:types
        """
        if sname in self._struct_cache:
            return self._struct_cache[sname]
        self._check_load_tpi()
        tps = list(filter(lambda t:
                          self._pdb.STREAM_TPI.types[t].leaf_type == "LF_STRUCTURE"
                          and self._pdb.STREAM_TPI.types[t].name == sname,
                          self._pdb.STREAM_TPI.types))
        if len(tps) == 0:
            raise IndexError(f"{sname} not found in PDB or not LF_STRUCTURE")
        struct_info = []
        for f in self._pdb.STREAM_TPI.types[tps[0]].fieldlist.substructs:
            struct_info.append((f.name, _get_type_name(f.index)))
        self._struct_cache[sname] = struct_info
        return struct_info

    def get_variable_declaration(self, vname: str) -> Tuple[str, Any]:
        """
        :param vname:
        :return: ()
        """
        if vname in self._var_cache:
            return self._var_cache[vname]
        self._check_load_tpi()
        self._check_load_gsym()
        for s in self._pdb.STREAM_GSYM.globals:
            if "name" in s and s.name == vname:
                if "typind" in s:
                    self._var_cache[vname] = (_get_type_name(self._pdb.STREAM_TPI.types[s.typind]), s)
                    return self._var_cache[vname]
        return None

    def dump_global_symbol_info(self, sname: str):
        print(*[(hex(s.leaf_type), s.name) for s in self._pdb.STREAM_GSYM.globals
                if "name" in dir(s) and sname in s.name], sep="\n")

    def dump_variable_declaration(self, vname):
        s = self.get_variable_declaration(vname)
        if s is not None:
            print(s[0], " ", vname, "; // @ RVA ", hex(s[1].offset), sep="")
        else:
            print(f'{vname} not found')

    def lookup_symbol_at_address(self, address):
        return self._lookup(address)

    def lookup_by_symbol(self, symbol_name) -> Tuple[str, str, int]:
        self._check_load_lookup()
        for base, limit in self.addrs:
            if symbol_name in self.names[base, limit]:
                mod = self.addrs[base, limit]['name']
                locs = self.locs[base, limit]
                names = self.names[base, limit]
                idx = self.names[base, limit].index(symbol_name)
                return mod, names[idx], locs[idx]
        return None
