from TestServer.test_kernel import TestKernel
from time import sleep

if __name__ == '__main__':
    test = TestKernel()
    test.start()
    ticks = 0
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
