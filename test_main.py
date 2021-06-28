from TestServer.test_kernel import TestKernel
from time import sleep

#import pefile
#import pdbparse


#def test_pe_load():
#    pe = pefile.PE(r'BOOTX64.EFI')
#    for i in pe.DIRECTORY_ENTRY_BASERELOC:
#        print(i)

#def test_pdb_load():
#    try:
#        pdb = pdbparse.parse(r'BOOTX64.PDB', fast_load=True)
#        pdb.STREAM_DBI.load()
#        pdb._update_names()
#        pdb.STREAM_GSYM = pdb.STREAM_GSYM.reload()
#        if pdb.STREAM_GSYM.size:
#            pdb.STREAM_GSYM.load()
#       pdb.STREAM_SECT_HDR = pdb.STREAM_SECT_HDR.reload()
#        pdb.STREAM_SECT_HDR.load()
#        # These are the dicey ones
#        pdb.STREAM_OMAP_FROM_SRC = pdb.STREAM_OMAP_FROM_SRC.reload()
#        pdb.STREAM_OMAP_FROM_SRC.load()
#        pdb.STREAM_SECT_HDR_ORIG = pdb.STREAM_SECT_HDR_ORIG.reload()
#        pdb.STREAM_SECT_HDR_ORIG.load()
#    except AttributeError as e:
#        pass


if __name__ == '__main__':
    test = TestKernel()
    test.start()
    ticks = 0
    try:
        while True:
            if (ticks & 1) == 0:
                test.trace('tick...')
            else:
                test.trace('tock...')
            ticks = ticks+1
            if ticks == 6:
                print("triggering breakpoint...")
                test.breakpoint()
        sleep(0.5)
    finally:
        pass

