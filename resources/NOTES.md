## Notes

### RCE via Method Described by MalwareTechBlog

General Procedure:

- exploit the use after free condition (duh) of the channel structure for MS_T120 channel
- need to fill the memory previously occupied by the MS_T120 channel structure with our own allocation that will allow us to take control, this is where the heap spray comes into play
- method used in this POC: data sent to one particular channel is never read and is thus never deallocated, thus we can send arbitrary data to this particular channel and it will be allocated on non-paged pool and never deallocated, which is exactly what we need
- next we look for all locations where the channel structures over which we (notionally) have control is used to determine how we can use it to redirect control flow to our code
- in one location, the vtable member of the channel structure is consulted to retrieve a function pointer and this function is later executed: bingo
- situation is made easier by the fact that there is no (hardware) DEP on Windows 7 / Windows Server 2008 R2 targets in non-paged pool kernel memory, so our shellcode and "fake vtable" can actually reside in the same allocation, making the spray simple
- we then spray the pool and insert our chosen address into the fake channel structure over which we have control, high likelihood that our shellcode allocation is hit

Remaining Questions:

- we assume that the vtable of the fake channel structure is consulted and used to make an indirect function call to code that we control, but how do we actually trigger this? is this performed automatically at some point in the protocol so that we actually have control over when this occurs?
