# syshash

a c implementation for native syscall resolution and execution on windows x64. this is a minimal rewrite of the go library [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall) 

## demo pic
![image](https://github.com/user-attachments/assets/b4f4938e-f024-47ed-87cf-077d59f7f90f)


## overview

syshash provides low-level access to windows nt syscalls by:
- parsing ntdll.dll exports directly from memory
- resolving syscall numbers from function stubs
- executing direct syscalls via inline assembly bypassing ntdll
- executing indirect syscalls through clean ntdll stubs
- restoring hooked ntdll functions from clean filesystem copy
- caching resolved syscalls for performance

## features

### core capabilities
- **syscall resolution**: automatically resolve syscall numbers for any nt* function
- **direct syscalls**: execute syscalls directly via inline assembly bypassing ntdll entirely
- **indirect syscalls**: execute syscalls through clean ntdll stubs to bypass hooks
- **ntdll unhooking**: restore original syscall stubs from clean filesystem copy
- **memory injection**: complete shellcode injection pipeline using only syscalls
- **function enumeration**: dump all ntdll functions (syscalls + regular functions)
- **security bypass patches**: disable amsi, etw, and debug functions via memory patching
- **registry persistence**: establish startup persistence via run key registry entries
- **hash-based obfuscation**: djb2 string hashing to avoid static strings
- **thread-safe caching**: performance optimization with critical section protection

## building

requires mingw-w64 or visual studio with c11 support:

```bash
# using the provided build script
./build.sh

# or manually with gcc
gcc -std=c11 -Wall -Wextra -O2 -m64 -DNDEBUG -s main.c -o syshash.exe -lkernel32 -lntdll -ladvapi32 -static-libgcc -Wl,--strip-all
```

## usage

### basic execution
```bash
# perform all operations automatically
./syshash.exe
```

the program automatically performs the following sequence:

1. **apply critical security patches**: disable amsi scanning and etw logging
2. **unhook ntdll**: restore original syscall functionality from clean filesystem copy
3. **apply debug bypass patches**: disable remote debugging and trace events
4. **establish registry persistence**: add startup entry for current user
5. **inject shellcode**: execute calc.exe shellcode using direct syscalls

### operation details

**amsi/etw patches**:
- patches amsi.dll!AmsiScanBuffer with `xor eax,eax; ret` to bypass amsi scanning
- patches ntdll.dll!EtwEventWrite with `xor eax,eax; ret` to disable etw logging

**ntdll unhooking**:
- reads clean ntdll.dll directly from the filesystem (system32)
- manually maps the pe file sections into memory
- copies the entire clean .text section over the hooked .text section

**debug bypass patches**:
- patches ntdll.dll!DbgUiRemoteBreakin with `ret` to prevent remote debugger attachment
- patches ntdll.dll!NtTraceEvent with `xor eax,eax; ret` to disable trace events
- patches ntdll.dll!NtSystemDebugControl with `xor eax,eax; ret` to disable debug control

**persistence establishment**:
- retrieves current executable path and user sid
- opens registry path `\Registry\User\<SID>\Software\Microsoft\Windows\CurrentVersion\Run`
- creates registry value "windows-internals" pointing to the current executable

## architecture

### modules

- **debug.c**: conditional debug output system
- **obf.c**: string hashing and obfuscation utilities  
- **syscallresolve.c**: core peb parsing and syscall resolution
- **syscall.c**: indirect syscall execution engine
- **unhook.c**: ntdll unhooking via filesystem pe loading and .text section replacement
- **patches.c**: security bypass patches for amsi, etw, debug functions and registry persistence
- **dump.c**: function enumeration and file output
- **main.c**: demonstration and testing harness

### how it works

1. **peb traversal**: access process environment block via gs register
2. **module enumeration**: walk the loader data table to find ntdll.dll
3. **pe parsing**: parse export directory from memory without file access
4. **pattern matching**: identify syscall stubs by bytecode patterns
5. **number extraction**: extract syscall numbers from mov eax instructions
6. **syscall execution**: three methods available: direct via inline assembly, indirect through clean stubs, or normal ntdll calls after unhooking
7. **security patching**: modify function entry points to bypass amsi, etw, and debug mechanisms
8. **unhooking process**: load clean ntdll from filesystem and copy entire .text section to restore original function bytes
9. **persistence establishment**: create registry run keys via ntapi for startup execution

### syscall resolution process

```c
// 1. get ntdll base address
uint32_t ntdll_hash = get_hash("ntdll.dll");
uintptr_t ntdll_base = get_module_base(ntdll_hash);

// 2. resolve function address
uint32_t func_hash = get_hash("NtAllocateVirtualMemory");
uintptr_t func_addr = get_function_address(ntdll_base, func_hash);

// 3. extract syscall number
uint16_t syscall_num = extract_syscall_number(func_addr);

// 4a. execute directly (bypasses ntdll entirely)
uintptr_t args[] = { process, &base, 0, &size, type, protect };
uintptr_t result = external_syscall(syscall_num, args, 6);

// 4b. execute indirectly (calls through clean syscall stub)
uintptr_t result2 = indirect_syscall(syscall_num, args, 6);

// 4c. apply security patches before operations
patch_results_t results = apply_critical_patches();
if (results.successful_count > 0) {
    // amsi and etw bypassed
}

// 4d. or unhook and call ntdll functions normally
unhook_ntdll();
NTSTATUS status = NtAllocateVirtualMemory(process, &base, 0, &size, type, protect);

// 4e. establish persistence
if (create_run_key()) {
    // startup persistence established
}
```

## security considerations

this tool is designed for:
- security research and red team operations
- malware analysis and detection testing
- understanding windows internals
- educational purposes


## technical details

### supported patterns
- standard syscall stub: `4c 8b d1 b8 XX XX 00 00` (mov r10,rcx; mov eax,XXXX)
- alternative patterns: various mov eax locations within function prologue
- hook detection: identifies jmp instructions that indicate userland hooks
- clean stub restoration: overwrites hooked .text section with original bytes from filesystem copy

### limitations
- windows x64 only (uses gs register for peb access)
- requires ntdll.dll to be loaded (standard for all processes)
- syscall numbers are windows version specific
- some heavily hooked environments may require additional evasion

### performance
- first resolution: ~10-50ms (full ntdll parsing)
- cached lookups: ~0.1ms (hash table lookup)
- syscall execution: minimal overhead vs direct calls
- also wayyyy smaller than any go binary could ever dream to be lol

## development

### adding new syscalls
```c
uint16_t syscall_num = get_syscall_number(get_hash("NtNewFunction"));
uintptr_t args[] = { param1, param2, param3 };
uintptr_t result = indirect_syscall(syscall_num, args, 3);
```

### debugging
debug output is automatically enabled during operation to show:
- peb traversal details
- module enumeration and resolution
- patch application status
- unhooking progress
- syscall resolution attempts
- execution traces

## references

- original go implementation: [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall)


## license

this project is provided as-is for educational and authorized security testing purposes only. 
