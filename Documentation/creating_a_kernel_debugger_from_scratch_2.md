# Creating a kernel debugger from scratch - Part 2

## A better architecture
In the first article (LINK) I had a very basic debugger loop running which was able to display information about a breakpoint that was hit in the kernel. 
That was fine as a proof-of-concept, but a more robust solution is required. I won't go in to all the details here but mention that the debugger inner loop has been changed to 
use queues for sending and receiving packets from/to the kernel that are managed by separate threads, which also keeps the debugger UI responsive. 

## Traps and Faults
Our debugger needs to be in control of traps and faults, so in addition to `int 3` (which we use to "break" into the debugger), the kernel debugger code has to add handlers for 
* debug trap `int 1` which we will use for single-stepping code.
* general protection faults (#GP) `int 0xd`.
* page faults (#PF) `int 0xe`.

> see Intel® 64 and IA-32 Architectures Software Developer’s Manual section 6.15 for details

## Stack unwinding
For a debugger stack unwinding is a critical piece of functionality because it tells us how we got to a particular location but in a UEFI application it isn't entirely trivial.  
(Intel/AMD) 64-bit Windows and UEFI applications use the Microsoft `fastcall` calling convention which makes stack unwinding more involved than in 32-bit modes where calling conventions like `stdcall` and `cdecl` pass all arguments on the stack. 
In these modes compilers set up `ebp` to preserve `esp` on entry to a function which gives us the caller's stack frame and lets us quickly find the return address (it's simply the last item pushed on the caller's stack frame.)

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
The same example compiled for 32-bit would have had a standard epilog which would have left `esp` in a known state.
```` asm
    push ebp
    mov ebp, esp
    ...
````
With a standard epilog it is possible to rely on `rbp` being in a known state but using `fastcall` this is not the case so we need another approach. 

The approach I've chosen is brute force but works; simply consider every item on the stack between the current `rsp` and the stack top in order. Each 8 byte value is checked to see if
* it points to exectuable memory (by checking the page table entry for the address).
* there is a [`call instruction`](https://www.felixcloutier.com/x86/call) preceding the address.

Both are simple lookups, one in the page table, the other one to check if a couple of bytes before the address contains a call instruction, which in 64-bit will be one, or two, bytes.\
Because my kernel uses tasks with their own stacks I have access to the top of stack address for each task I'm considering which makes book-ending the search simple.  

The algorithm becomes:
```c
   uint64_t* rsp = current_task->rsp;
   // check every entry on the stack for a valid return address
   while(rsp != current_task->stack_top) {
        if ( paging_is_executable(*rsp) ) {
            uint8_t* code_ptr = *rsp;
            if ( debugger_is_call_instruction_before(code_ptr) ) {
                // code_ptr is another level up in the call stack 
                vector_push_back(call_stack, code_ptr);                
            }
        }
        ++rsp;
   }
   // the number of elements on the call_stack vector is the depth of the call stack 
   // and we can now send the contents of the vector to the debugger for further analysis (PDB lookup etc.)
```

> See for example https://en.wikipedia.org/wiki/X86_calling_conventions 
> and https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-160 for details

## Single stepping

