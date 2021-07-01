# Creating a kernel debugger from scratch - Part 2

### code
[josx64](https://github.com/jarlostensen/josx64) and [joKDbg](https://github.com/jarlostensen/joKDbg)

## A short recap
In the [first installment](creating_a_kernel_debugger_from_scrach_1.md) of this series I described some of the fundamentals of my little kernel debugger project. There I outlined how a simple framework of kernel code and a debugger written in Python could go a long way towards creating a fully functional, and useful, tool.\
Since then I've made some progress, and in this article I'll go into more depth about breakpoints, stack unwinding, and symbol lookups.

![debugger](assets/debugger_2.png)

## A (slightly) better architecture
I refactored the debugger code quite a lot since the first try, not the least as I get more comfortable with Python and can start thinking about *form* as much as just *function* of the code. The back end now uses a thread to read and write packets to and from the kernel, leaving the UI (based on [tkinter](https://docs.python.org/3/library/tkinter.html) for now) more responsive in addition to separating concerns better.\
Otherwise there is nothing particularly clever about the Python side of the code; the heavy lifting really is done by the modules I use to parse PDBs, PEs, and disassemble instructions. The rest is just book keeping and UI.

## Traps and Faults
Our debugger needs to be in control of traps and faults, so in addition to `int 3` (which we use to "break" into the debugger), the kernel debugger code has to add handlers for 
* debug trap `int 1` which is used for single-stepping code.
* general protection faults (#GP) `int 0xd`.
* page faults (#PF) `int 0xe`.
* unhandled instruction (#UD) faults `int 0x6`

> see Intel® 64 and IA-32 Architectures Software Developer’s Manual section 6.15 for details

Breakpoint handling and trap (single-step) handling is identical as far as the kernel is concerned and it's worth going over the details a bit more here. The code in this section refers to `kernel\debugger.c` in `josx64`.

`int 3` breakpoints are triggered by the instruction itself and `int 1`s are triggered on the next instruction if the trap flag is set and as we enter our interrupt handler the kernel enters into "breakpoint mode" where it waits for further commands from the debugger. It only leaves this mode when it receives a "continue" command. 

When a breakpoint (or the single step trap) is entered the kernel debugger code creates a package containing the interrupt stack frame (which also contains the registers at the point of the interrupt), the instruction `rip` currently points to, and the callstack (see section below).

> I use the [Zydis disassembler](https://zydis.re/) to decode instructions in the kernel. 

For single stepping the handler does exactly the same (it is after all just an automatically triggered breakpoint) and to enable single stepping we simply have to switch on the trap flag (`TF`) in the `rflags` field of the interrupt stack so that it will be switched on after we `iret`, and break out of the debugger loop:

``` c 
case kDebuggerPacket_SingleStep:
{
    // switch on the trap flag so that it will trigger on the next instruction after our iret
    context->rflags |= (1<<8);
    continue_run = true;
}
break;
```

On the debugger side our breakpoint handler unpacks the interrupt stack frame and instruction bytes and displays a bit of information about where we are and what we're looking at:

``` python
# look up where in the code this instruction is from the PDB
lookup = self._pdb_lookup.lookup(self._last_bp_packet.stack.rip)
self._print_output(f'\n>break - code @ {lookup}')

# the kernel has also provided the raw instruction bytes at the breakpoint location
# so we can disassemble and display them
raw_bytes = bytearray(self._last_bp_packet.instruction)
instr = iced_x86.Decoder(64, raw_bytes, ip=self._last_bp_packet.stack.rip).decode()
disasm = self._asm_formatter.format(instr)
self._display_disasm(disasm)
```

> As I mentioned in my first post I use the [iced_x86](https://pypi.org/project/iced-x86/) and [pefile](https://github.com/erocarrera/pefile) Python libraries for disassembly and PDB parsing respectively. 

## Dynamic breakpoints
Settting dynamic breakpoints (i.e. breakpoints that can be controlled programmatically and can be enabled/disabled at will) requires a bit of extra book keeping but is straight forward.\
I have chosen a model where the debugger is the authorative source of breakpoints and the kernel just gets updates whenever breakpoints change. This has it's benefits not the least because it makes management of breakpoints easier on the kernel side.
Whenever breakpoints change (are added, removed, enabled, disabled) the debugger sends the complete list of breakpoints to the kernel which subsequently replaces it's own list with the new list (taking care to uninstall those that are no longer needed.)

For each breakpoint the following information is used by the kernel:
* the address of the breakpoint
* the original instruction byte from that location
* flags (active, inactive)

Recall that a breakpoint [`int 3`](https://www.felixcloutier.com/x86/intn:into:int3:int1) instruction is one byte long (usually) so to inject a breakpoint we simply replace the byte that's there with the instruction byte `0xcc`. 
Once the breakpoint is hit we need to inspect our list of breakpoints to check if it's one that has been set dynamically, (it could also be one that was hard coded into the program by an explicit `int 3` instruction), and if it is we perform a couple of steps:
1. restore the instruction byte from the breakpoint information
2. back up `rip` by one to go back to the start of the restored instruction
3. continue 

Note that in order for the breakpoint to be restored as soon as the original instruction has executed make use of the trap flag (and `int 1`) which we set so that we break back into the debugger immediately after the instruction finishes. At this point we can restore the `0xcc` byte at the breakpoint location again and continue as normal. If we didn't do this then our breakpoint would only ever be hit once and never again.

This ended up being the more involved part of the kernel debugger code simply because of the extra book keeping and state tracking but it's still not complicated. 

As an example, this is all the code needed to set a breakpoint:
``` c
debugger_breakpoint_t new_bp = { 
    ._at = at, 
    ._instr_byte = ((uint8_t*)at)[0], 
    ._active = true 
};
((uint8_t*)at)[0] = 0xcc;
add_breakpoint_to_list(&new_bp);
```

## Stack unwinding
Stack unwinding is a critical piece of functionality for a debugger as it tells us how we got to a particular location.\
However, (Intel/AMD) 64-bit Windows and UEFI applications use the Microsoft `fastcall` calling convention which makes stack unwinding a little bit involved than in 32-bit modes where calling conventions like `stdcall` and `cdecl` pass all arguments on the stack.\
In these modes compilers set up `ebp` to preserve `esp` on entry to a function which gives us the caller's stack frame and lets us quickly find the return address (it's simply the last item pushed on the caller's stack frame at `[ebp+8]`.)

> See for example https://en.wikipedia.org/wiki/X86_calling_conventions 
> and https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-160 for more details

However, the `fastcall` calling convention uses registers `rcx`, `rdx`, `r8`, and `r9` for the first four arguments that fit in a 64-bit word and only uses the stack if it needs more parameters. 
Why this makes stack unwinding a problem is best illustrated with an example:

``` asm
     void  __fastcall  x86_64_rdmsr
             uint              ecx:4          param_1
             uint *            rdx:8          param_2
             uint *            r8:8           param_3
       4989d0       mov        param_3 ,param_2
       4989c9       mov        r9 ,param_1
       b91b000000   mov        param_1 ,0x1b
       0f32         rdmsr
       418901       mov        dword ptr [r9 ],eax
       418910       mov        dword ptr [param_3 ],param_2
       c3           ret
```

In the code above the function `x86_64_rdmsr` uses no stack frame whatsoever, because all the arguments to the function and the return value fits in registers. 
The same example compiled for 32-bit would have had a standard epilog which would have left `ebp` in a known state.
```` asm
    push ebp
    mov ebp, esp
    ...
````
With a standard epilog it is possible to rely on `rbp` being in a known state but using `fastcall` this is not the case so we need another approach. 

The approach I've chosen is brute force but works; simply consider every item on the stack between the current `rsp` and the stack top in order and check if it's the return address of a call.\
I split the work between the kernel and the debugger and in the kernel each 8 byte stack value is checked to see if it points to an exectuable location, i.e it falls inside the `.text` section of the executing image.\
The items on the stack that pass this test are then sent to the debugger where it can be filtered further by looking up the address in the executable to check if it is preceeded by a [`call instruction`](https://www.felixcloutier.com/x86/call). If it is then the location is (most probably) a valid call stack location and can be displayed.

In the kernel the code is simply:
```c
   uint64_t* rsp = current_task->rsp;
   // check every entry on the stack for a valid return address
   // callstack is a vector_t which holds 8-byte entries   
   while(rsp < current_task->stack_top) {
        if ( address_is_inside_text_section(*rsp) ) {
            vector_push_back(&callstack, *rsp);
        }
        ++rsp;
   }
   // the number of elements on the call_stack vector is the depth of the call stack 
   // and we can now send the contents of the vector to the debugger for further analysis (PDB lookup etc.)
```

The debugger loads the PE using [pefile](https://github.com/erocarrera/pefile) and uses it to look up the instruction bytes peceeding each callstack entry it received from the debugger.
If the instruction before is a call we assume it's a part of the callstack and we display it:

``` python
for entry in callstack:
    # calculate the RVA for the entry (which is a physical address) 
    rva = (entry - self._image_base) + (text_section.VirtualAddress - text_section.PointerToRawData)
    # get the image offset
    offset = self._pe.get_offset_from_rva(rva)
    instruction_bytes = self._pe.get_memory_mapped_image()[offset-3:offset]
    # simple but effective; a call instruction can be two or three bytes long
    if instruction_bytes[0] == 0xff or instruction_bytes[1] == 0xff:
        self._display_stack_location(entry)
```

This will single out a call by identifying the previous instruction, like in this example:

``` asm
                        1800027a2 ff  55  00       call       qword ptr [rbp ]  <== previous instruction
    callstack entry ==> 1800027a5 45  31  ed       xor        r13d ,r13d
```

## Next steps
I'm very pleased with the progress so far and my debugger has already helped me find and fix bugs in my kernel code, but the number one feature missing before I'm satisfied with this project (for now) is source code debugging.\
Assembler is great for the code that is actually written in it, but stepping through compiled C code is tedious and even though [Ghidra](https://ghidra-sre.org/) is an excellent companion tool to help analyse the code, I want source and I want symbols.\
This isn't technically hard; the PDB file contains a map between source lines and sections of instructions which can be used to look up into so a source level single-step is simply finding the end of the instruction block corresponding to the current source line (from the PDB) and injecting a normal breakpoint at that location.

As an example, here is a small part of the PDB information in YML format from my kernel project that shows this type of information:
``` yml
- FileName:        'E:\Dev\osdev\josx64\kernel\boot\efi_main.c'
    Lines:
    - Offset:          0
        LineStart:       216
        IsStatement:     false
        EndDelta:        0
    - Offset:          18
        LineStart:       218
        IsStatement:     false
        EndDelta:        0
```

Variables can also be found in the PDB, with their names and type information, which makes it possible to inspect them properly, etc.

Sadly it doesn't appear that [pdbparse](https://github.com/moyix/pdbparse) currently supports reading the streams with this information from the PDB so I'll have to add that myself. This is not an overwhelming task but my vacation is running out so I might not have the time to complete it but, I'll certainly try!

Once I have that working I'll deliver the last installment of this little post series so until then, *happy coding!*
