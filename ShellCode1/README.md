# ShellCodeInjector
## Shellcode with c/c++

The Shellcode needs to be compiled with specific project settings <br>
to ensure that the code works position independently.<br>

These are:<br>
1. Advanced > Use Debug Libraries: No
2. Advanced > Whole Program Optimization: No Whole Program Optimization
3. C/C++ > General > Debug Information Format: None
4. C/C++ > General > SDL checks: No (/sdl-)
5. C/C++ > Code Generation > Enable C++ Exceptions: No
6. C/C++ > Code Generation > Runtime Library: Multi-threaded (/MT)
7. C/C++ > Code Generation > Security Check: Disable Security Check (/GS-)
8. C/C++ > Language > Conformance mode: No
9. Linker > Input > Additional Dependencies: Empty
10. Linker > Input > Ignore All Default Libraries: Yes (/NODEFAULTLIB)
11. Linker > Debugging > Generate Debug Info: No
12. Linker > Debugging > Generate Map File: Yes (/MAP)
13. Linker > Debugging > SubSystem: Native (/SUBSYSTEM:NATIVE)
14. Linker > Optimization > References: No (/OPT:NOREF)
15. Linker > Advanced > Entry Point: _code
16. Linker > Advanced > No Entry Point: Yes (/NOENTRY)
17. #pragma comment(linker, "/merge:.rdata=.text")

