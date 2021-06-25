# Creating a kernel debugger from scratch - Part I
A while ago I started playing around with kernel development (or "OS development", if you're generous) and because I
primarily work on Windows I wanted to be able to do all the development on that platform.\
However, and perhaps not surprisingly, most hobby OS development happens on Linux and the tools available 
for debugging, running in VMs, etc. on that OS are extensive.\
On windows the situation is different and support is weak for anything other than Windows kernel work.  
As my kernel project source grows and becomes more complex, I reached the limit of what traces and printfs could do and a debugger became increasingly critical. 

So I decided to try to build my own, because "how hard could that be?"

## How to debug a bare metal kernel
To debug a kernel that sits directly on top of the HW we need to provide all the functionality for the debugger to connect, and control, the kernel.
This is everything from establishing the connection to displaying register and memory information, and single stepping through code. 
In essence the kernel and debugger act in a server-client relationship with the debugger remote controlling the kernel over a connection. 
The simplest form of connection is over the serial port, and it is the preferred choice because it is very easy to program and requires no special support from the kernel (as would for example a network connection.)

> see for example this [osdev article on serial ports](https://wiki.osdev.org/Serial_Ports) for more info on how to initialise and use COM ports.

Once we have this connection established we just need a protocol for sending and receiving commands and data between the kernel and debugger and a set of commands and handlers on either side.
In this post I will show you how I've implemented a basic set of commands that can be used as building blocks for a fully functional debugger:
* trace logs
* breakpoint triggering with register information
* read/write target (kernel) memory
* continue execution after breakpoint

## Proof Of Concept
The first version of the debugger will be able to connect to the kernel, get information about the kernel, capture and output trace messages,\
respond to an `int 3` breakpoint triggered from the kernel, and show disassembly of the instructions immediately following the breakpoint.
The debugger will also load the PDB corresponding to the kernel image and use this to show some information about the breakpoint.

For this first version then, I built the following:
* Handlers for a simple serial packet protocol for sending and receiving data between the kernel, and the debugger.\
  Each packet will have an ID and a LENGTH followed by a payload.
  
* A kernel side "wait for debugger" function that waits for a handshake packet from a debugger, and sends information about the kernel back.
* Support in the kernel log trace functions to direct output to the debugger, as packets, when a debugger is connected.
* Support in the kernel `int 3` handler to send information about the breakpoint to the debugger, including: 
    * registers.
    * breakpoint address.
  
* A loop in the kernel waiting for debugger instructions and executing them until a "continue" command is received.    
    
* a loop in the debugger that initiates the handshake, gets information, and processes incoming packets:
    * print trace messages
    * output `int 3` information and look up breakpoint address in the kernel PDB.
    * respond to target memory read messages (more about that later)   

## Tools and languages
The kernel is written in plain C while the debugger is written in Python.
> I have chosen Python for the debugger  because it is quick to iterate and has a lot of functionality easily available (such as PDB and PE handling).

I run the kernel itself in a VM under VirtualBox and direct the `COM1` port to a Windows pipe. This is invisible to the 
kernel and only requires a small amount of Windows specific code on the debugger side.

> I use the `win32pipe` and `win32file` Python modules for the actual pipe connection which provides Python wrappers around the familiar Create/Read/Write file Win32 APIs   

## The protocol
The debugger<->kernel communications protocol is very simple; each packet consists of two 32-bit unsigned integers for packet ID and length:
``` c
typedef struct _debugger_serial_packet {
    uint32_t        _id;
    uint32_t        _length;
} debugger_serial_packet_t;
```
Note that the structure is *packed* to ensure no byte padding (this is not showed above).

The payload of `_length` bytes can be in any format, and I'm using a mix of __JSON__ and raw binary data.    
Supporting JSON data helps in this early stage of development since it's really easy to read and validate and Python has plenty of support for it. 
It requires a little more work on the kernel side to create and parse, but the effort is worth it and once you have the basic functionality in place you have a solid set of tools at your disposal.

To serialise/deserialise packets on the Python side I use `ctypes` which easily lets me use the structure above. In the listing below I've included the helper that does the actual packaging and sending: 
```python
class DebuggerSerialPacket(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('_id', ctypes.c_uint32),
        ('_length', ctypes.c_uint32)
    ]
  
# NOTE: this is a member function of the Debugger class (see below)
def _send_kernel_packet_header(self, packet_id, packet_length):
    """     
    encode as binary and send a C compatible packet to the kernel over our current connection  
    """
    packet = DebuggerSerialPacket()
    packet._id = packet_id
    packet._length = packet_length
    # cast a a pointer to byte array and send as a raw byte array
    # _send_packet_impl is implemented by Debugger class subclass
    self._send_packet_impl(ctypes.cast(ctypes.byref(packet),
                                       ctypes.POINTER(ctypes.c_char * ctypes.sizeof(packet))).contents.raw)
```

## Kernel side
The debugger is initialised once the kernel runtime starts performs a few housekeeping tasks, including registering the `int 3` interrupt handler.
At one point the `debugger_wait_for_connection` function is invoked which sits reading from the serial port until the handshake "josx" message is received. 
When the connection has been established it sends back a JSON payload with version information, and the details of the kernel image needed to resolve addresses later: 

``` c
void debugger_wait_for_connection(peutil_pe_context_t* pe_ctx, uint64_t image_base) {        
    // ========================================================
    // simply sit in a loop (blocking) and wait for the connection to present the correct sequence of bytes
    // NOTE: this is very basic and has no error checking, reconnects, etc.
    static const char kDebugger_Handshake[4] = {'j','o','s','x'};
    serial_wait_for_handshake(kDebugger_Handshake);

    // ========================================================
    // create and send JSON payload back to the debugger
    
    // the json writer will "fwrite" to this buffer through the IO_STREAM handle 
    char json_buffer[1024];
    IO_FILE stream;
    _io_file_from_buffer(&stream, json_buffer, sizeof(json_buffer));

    json_writer_context_t ctx;
    json_initialise_writer(&ctx, &stream);

    // the document below contains information required and/or helpful to the debugger,
    // such as the base address of the loaded PE kernel image (for PDB lookups)
    // and some system stats (number of CPUs, kernel HEAP size)   
    json_write_object_start(&ctx);
        json_write_key(&ctx, "version");
            json_write_object_start(&ctx);
                json_write_key(&ctx, "major");
                json_write_number(&ctx, 0);
                json_write_key(&ctx, "minor");
                json_write_number(&ctx, 1);
                json_write_key(&ctx, "patch");
                json_write_number(&ctx, 0);
            json_write_object_end(&ctx);
        json_write_key(&ctx, "image_info");
            json_write_object_start(&ctx);
                json_write_key(&ctx, "base");
                json_write_number(&ctx, (long long)image_base);
                json_write_key(&ctx, "entry_point");
                json_write_number(&ctx, (long long)peutil_entry_point(pe_ctx));
            json_write_object_end(&ctx);
        json_write_key(&ctx, "system_info");
            json_write_object_start(&ctx);
                json_write_key(&ctx, "processors");
                json_write_number(&ctx, smp_get_processor_count());
                json_write_key(&ctx, "memory");
                json_write_number(&ctx, memory_get_total());
            json_write_object_end(&ctx);
    json_write_object_end(&ctx);

    uint32_t json_size = (uint32_t)ftell(&stream);
    debugger_send_packet(kDebuggerPacket_KernelConnectionInfo, json_buffer, json_size);
}
```
> UEFI kernel binaries are 64-bit Windows Portable Executables and very easy to interpret and parse. 
> I use a small PE utility library I've written to interpret information like the entry point address. 

I have written a *very* lightweight JSON library which uses my own `libc` FILE stream ("IO_FILE"), and in the code above the FILE stream is created on stack which is important; we don't really have (or want to use) memory allocations from a heap at this point.

For reference; this is an example of a typical JSON document returned by the kernel: 
``` json
{
  "version": {
    "major": 0, "minor": 1, "patch": 0
  }, 
  "image_info": {
     "base": 2178084864, "entry_point": 2178092768
  }, 
 "system_info": {
    "processors": 3, "memory": 30740480
  }
}
```

Once the connection has been made the kernel continues as normal and in this first version I simply trigger a breakpoint explicitly via `int 3` to invoke the breakpoint handler. 
This handler in turn packages up the interrupt stack frame for now and sends it back to the debugger before entering into a loop where it awaits further instructions: 
```c
    debugger_packet_bp_t bp_info;
    // the interrupt handler is invoked with a pointer to the 64 bit interrupt stack which is layed out 
    // as described in the Intel® 64 and IA-32 Architectures Software Developer’s Manual
    memcpy(&bp_info._stack, context, sizeof(interrupt_stack_t));
    debugger_send_packet(kDebuggerPacket_Int3, &bp_info, sizeof(bp_info));
    // enter loop waiting for further instructions
    _debugger_loop();
```
The debugger loop function reads the next packet from the serial connection and dispatches it until it gets the "continue execution" command.
In this first version the only other command it handles is the "read from target memory" command which reads and sends back raw bytes from a memory range in the kernel. 
The debugger uses this to request the instruction bytes following the breakpoint address so that it can display a few lines of disassembly.  

## Debugger side

In this first version the debugger connects and then enters a simple loop consuming packets coming from the kernel.\
The VM exposes the COM1 port to a Windows pipe and there is a small amount of boilerplate code associated with this in the debugger which is built using the `win32file` and `win32pipe` modules. 
This is not particularly difficult or sophisticated, so I'm not going to cover that in any detail here.

The beauty writing this in Python becomes clear when you realise that the actual amount of code you have to write for basic functionality is very limited, yet it is already useful. 
I've created a class (`Debugger`) that provides the main loop and delegates to the subclass for things like display. The basic loop is very simple:   
```python
    def main_loop(self):
        last_bp_rip = 0
        # the basic debugger loop
        try:
           # block waiting for a packet header + payload from the kernel  
            packet_id, packet_len, packet = self._conn.read_one_packet_block()
            while True:
               # trace log messages are output as-is 
                if packet_id == self._conn.TRACE:
                    payload_as_string = packet.decode("utf-8")
                    print(payload_as_string)
                # the kernel has triggered a breakpoint (int 3)
                elif packet_id == self._conn.INT3:
                    # this packet contains the interrupt stack etc.  
                    bp_packet = DebuggerBpPacket.from_buffer_copy(packet)
                    last_bp_rip = bp_packet.stack.rip
                    # let subclass display information whichever way it wants 
                    self._on_bp_impl(last_bp_rip, bp_packet)
                    # send back a message to the kernel to read 64 bytes from the instruction following the bp
                    # so that we can display disassembly. Note that the response comes "later"
                    self._conn.send_kernel_read_target_memory(last_bp_rip, 64)
                    # tell the kernel to continue execution
                    self._conn.send_kernel_continue()
                elif packet_id == self._conn.READ_TARGET_MEMORY_RESP:
                    # the response from the earlier request to read kernel memory comes back here and 
                    # we let the subclass process it
                    self._disassemble_bytes_impl(packet, last_bp_rip)
                # (blocking) read the next packet
                packet_id, packet_len, packet = self._conn.read_one_packet_block()
        finally:
            print(">debugger disconnecting")
```
The work required by the subclass for this first version is light and we can use the many modules awailable in the Python ecosystem to help.
As an example; this is the handler for disassembling the instructions after the breakpoint which uses [iced_x86](https://pypi.org/project/iced-x86/) to do the real work:
``` python
    def _disassemble_bytes_impl(self, bytes, at):
        decoder = iced_x86.Decoder(64, bytes, ip=at)
        formatter = iced_x86.Formatter(iced_x86.FormatterSyntax.NASM)
        for instr in decoder:
            disasm = formatter.format(instr)
            start_index = instr.ip - at
            bytes_str = bytes[start_index:start_index + instr.len].hex().upper()
            print(f"{instr.ip:016X} {bytes_str:30} {disasm}")
```

Finally; here is output from an example run of the kernel connecting and triggering a breakpoint: 

```
>connected: 
{'version': 
  {'major': 0, 'minor': 1, 'patch': 0}, 
 'image_info': 
  {'base': 2178084864, 'entry_point': 2178092768}, 
  'system_info': 
   {'processors': 3, 'memory': 30740480}
}
[24:debugger] breakpoint hit at 0x0000000081d31365

>breakpoint @ 0x81d31365
>break in code @ BOOTX64!efi_main+0x485

rax 0000000081d9c4f0 rbx 0000000081d3a5f0 rcx 00000000ffffffff rdx 00000000805de030
rsi 00000000ffffffff rdi 0000000081d4a13c rsp 0000000083237670 rbp 0000000081d39e20
r8  0000000084300000 r9 0000000000000000 r10 ffffffffffd00000 r11 00000000000c0000
r12 0000000082713f18 r13 0000000083237790 r14 0000000081d3bc80 r15 0000000081d39f60

0000000081D31365 48BA5CA6D48100000000           mov rdx,81D4A65Ch
0000000081D3136F 4889F9                         mov rcx,rdi
0000000081D31372 FFD3                           call rbx
0000000081D31374 48B830CBD38100000000           mov rax,81D3CB30h
0000000081D3137E FFD0                           call rax
0000000081D31380 C60425000000002A               mov byte [0],2Ah
0000000081D31388 48C7842480000000FA000000       mov qword [rsp+80h],0FAh
0000000081D31394 48C784248800000008000000       mov qword [rsp+88h],8

[26:debugger] continuing execution

```
As you can see we've got a JSON document with information about the system, version, image base, entry point, etc. followed by a breakpoint hit in the kernel. 
(In this case all I did was to insert a brute force `int 3` instruction in the code).\
On the debugger side you can see parts of the register file at the point of the interrupt, and disassembly of some of the instructions following it.
Lastly the kernel reports that it "continues execution" in response to a command sent from the debugger.

There are a couple of nice pieces of functionality already being demonstrated here: 

1. We can lookup the breakpoint address in the PDB and display basic information about it. 
2. We package machine state (registers) and sent them to the debugger for inspection.
3. The debugger can request to read a block of memory from the kernel which is sent back and disassembled.

It's far from a complete debugger, but the foundations are in place, and you can see how it is now possible to start building more advanced functionality.
The next step is single stepping (pun intended) and dynamically setting breakpoints in the code. This will require a little more work on the kernel side, and some basic user input handling on the debugger side.
That will be the topic of the next post in this series.

Happy Coding.

# Footnotes
This article refers to code in the https://github.com/jarlostensen/joKDbg and https://github.com/jarlostensen/josx64 repos. 
The code in those repos is evolving and should be considered a "Work In Progress"...
