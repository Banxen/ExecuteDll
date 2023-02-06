This tool is designed to assist in dll file execution. Use 32-bit version for 32-bit dll and 64-bit version for 64-bit dll. Exports are handled automatically. 

### Usage:

1. Execute all exports using ExecuteDll.exe 

ExecuteDll.exe mydll.dll

2. Parse and execute the exports using rundll32.exe

ExecuteDll.exe mydll.dll --rundll32

### Cobaltrike beacon dll support:

For 32-bit version of ExecuteDll.exe support is added for dlls where export name contains "ReflectiveLoader". Feel free to tweak.

For 64-bit version of ExecuteDll.exe support is added for dlls where export name contains "ReflectiveLoader" but to execute the reflective loaded dll the "nop" sled has been added which need to be patched at assembly level or in the compiled binary with the following code (Can't find any other way since the Microsoft compiler doesn't support raw assembly for 64-bit):

```
push 4
pop rdx
mov rcx, qword ptr [rsp+0x28] // rsp+0x28 contains the first argument(baseAddres) of main function. Offset to rsp may change based on code compilation so change accordingly.
call rax
```
