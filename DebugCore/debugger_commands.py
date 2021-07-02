
CONNECTION_HANDSHAKE = f"josx"
RESP_PACKET_MASK = 0x800
"""
response packets are request packet + mask
"""
CONTINUE = 0
"""
 [->kernel] continue execution
"""
TRACE = 1
"""
[<-kernel] trace message
"""
KERNEL_INFO = 2
"""
[<-kernel] kernel information
"""
BREAKPOINT = 3
"""
[<-kernel] breakpoint hit"""
READ_TARGET_MEMORY = 4
"""
[->kernel]
"""
WRITE_TARGET_MEMORY = 5
"""
[->kernel]
"""
GPF = 6
"""
[<-kernel] general protection fault
"""
GET_TASK_LIST = 7
"""
[->kernel] request active task list
"""
TRACE_STEP = 8
"""
[->kernel] execute next instruction 
"""
TRAVERSE_PAGE_TABLE = 9
"""
[->kernel] traverse and return pagetable entries for address
"""
ASSERT = 10
"""
[<-kernel] assert hit
"""
READ_MSR = 11
"""
[->kernel] read MSR 
"""
UD = 12
"""
[<-kernel] Undefined Instruction exception
"""
UPDATE_BREAKPOINTS = 13
"""
[->kernel] update breakpoints from array
"""
BREAKPOINT_CALLSTACK = 14
"""
a number of 8 byte callstack entries
"""
SINGLE_STEP = 15
"""
execute next instruction and enter subroutines
"""

READ_TARGET_MEMORY_RESP = READ_TARGET_MEMORY + RESP_PACKET_MASK
GET_TASK_LIST_RESP = GET_TASK_LIST + RESP_PACKET_MASK
TRAVERSE_PAGE_TABLE_RESP = TRAVERSE_PAGE_TABLE + RESP_PACKET_MASK
READ_MSR_RESP = READ_MSR + RESP_PACKET_MASK



