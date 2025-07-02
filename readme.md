# syshash

a c implementation for native syscall resolution and execution on windows x64. this is a minimal rewrite of the go library [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall) 

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
- **hash-based obfuscation**: djb2 string hashing to avoid static strings
- **thread-safe caching**: performance optimization with critical section protection

## building

requires mingw-w64 or visual studio with c11 support:

```bash
# using the provided build script
./build.sh

# or manually with gcc
gcc -std=c11 -Wall -Wextra -O2 -m64 -DNDEBUG -s main.c -o syshash.exe -lkernel32 -lntdll -static-libgcc
```

## usage

### basic execution
```bash
# run shellcode injection test
./syshash.exe

# enable debug output
./syshash.exe -debug

# dump ntdll functions to files
./syshash.exe -dump

# unhook ntdll and keep process running
./syshash.exe -unhook

# unhook with debug output
./syshash.exe -unhook -debug

## or any combination of the flags :3
```

### dump mode
when run with `-dump`, the program creates two files:
- `ntdll_syscalls.txt` - all nt*/zw* syscall functions with numbers
- `ntdll_all_functions.txt` - complete ntdll export table

example output format:
```
NtAllocateVirtualMemory | 0x12345678 | 24 | 0x7FFE12345678
NtWriteVirtualMemory | 0x87654321 | 58 | 0x7FFE87654321
```

### unhook mode
when run with `-unhook`, the program:
- reads clean ntdll.dll directly from the filesystem (system32)
- manually maps the pe file sections into memory
- copies the entire clean .text section over the hooked .text section
- keeps the process running indefinitely for testing

this restores original syscall functionality for direct calls while maintaining the ability to use indirect syscalls for additional evasion. the process remains active so you can attach debuggers or other tools to verify the unhooking was successful.

## architecture

### modules

- **debug.c**: conditional debug output system
- **obf.c**: string hashing and obfuscation utilities  
- **syscallresolve.c**: core peb parsing and syscall resolution
- **syscall.c**: indirect syscall execution engine
- **unhook.c**: ntdll unhooking via filesystem pe loading and .text section replacement
- **dump.c**: function enumeration and file output
- **main.c**: demonstration and testing harness

### how it works

1. **peb traversal**: access process environment block via gs register
2. **module enumeration**: walk the loader data table to find ntdll.dll
3. **pe parsing**: parse export directory from memory without file access
4. **pattern matching**: identify syscall stubs by bytecode patterns
5. **number extraction**: extract syscall numbers from mov eax instructions
6. **syscall execution**: three methods available - direct via inline assembly, indirect through clean stubs, or normal ntdll calls after unhooking
7. **unhooking process**: load clean ntdll from filesystem and copy entire .text section to restore original function bytes

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

// 4c. or unhook and call ntdll functions normally
unhook_ntdll();
NTSTATUS status = NtAllocateVirtualMemory(process, &base, 0, &size, type, protect);
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
enable debug mode to see:
- peb traversal details
- module enumeration
- export parsing progress
- syscall resolution attempts
- execution traces

## references

- original go implementation: [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall)


## license

this project is provided as-is for educational and authorized security testing purposes only. 
