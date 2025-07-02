#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>
#include <windows.h>
#include "debug.c"

uint32_t get_hash(const char* str);
uintptr_t get_module_base(uint32_t module_hash);

uint64_t do_syscall(int ssn, int nargs, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, 
                    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8, 
                    uint64_t a9, uint64_t a10, uint64_t a11);

uint64_t do_call(void* func_addr, int nargs, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8, 
                 uint64_t a9, uint64_t a10, uint64_t a11);

uint64_t do_indirect_syscall(int ssn, void* syscall_addr, int nargs, uint64_t a0, uint64_t a1, 
                            uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, 
                            uint64_t a7, uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11);

uintptr_t find_clean_syscall_stub(uintptr_t ntdll_base);

uintptr_t external_syscall(uint16_t syscall_number, uintptr_t* args, int arg_count);
uintptr_t direct_call(uintptr_t func_addr, uintptr_t* args, int arg_count);
uintptr_t indirect_syscall(uint16_t syscall_number, uintptr_t* args, int arg_count);

uint64_t do_syscall(int ssn, int nargs, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, 
                    uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8, 
                    uint64_t a9, uint64_t a10, uint64_t a11) {
    uint64_t result;
    
    __asm__ volatile (
        "movq %%rsi, -8(%%rsp)\n\t"
        "movq %%rdi, -16(%%rsp)\n\t"
        
        "movl %1, %%eax\n\t"
        
        "movq %2, %%rcx\n\t"
        
        "movq %3, %%r10\n\t"    
        "movq %4, %%rdx\n\t"    
        "movq %5, %%r8\n\t"     
        "movq %6, %%r9\n\t"     
        
        "subq $4, %%rcx\n\t"   
        "jle 1f\n\t"           
        
        "leaq %7, %%rsi\n\t"   
        "leaq 40(%%rsp), %%rdi\n\t"  
        "rep movsq\n\t"        
        
        "1:\n\t"               
        
        "movq %%r10, %%rcx\n\t"
        
        "syscall\n\t"
        
        "movq -8(%%rsp), %%rsi\n\t"
        "movq -16(%%rsp), %%rdi\n\t"
        
        : "=a" (result)                    
        : "r" (ssn), "r" ((uint64_t)nargs), "r" (a0), "r" (a1), "r" (a2), "r" (a3),
          "m" (a4), "m" (a5), "m" (a6), "m" (a7), "m" (a8), "m" (a9), "m" (a10), "m" (a11)
        : "rcx", "rdx", "r8", "r9", "r10", "rsi", "rdi", "memory"
    );
    
    return result;
}

uint64_t do_call(void* func_addr, int nargs, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                 uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8, 
                 uint64_t a9, uint64_t a10, uint64_t a11) {
    uint64_t result;
    
    __asm__ volatile (
        "movq %1, %%rax\n\t"          
        "subq $48, %%rsp\n\t"         
        
        "movq %3, %%rcx\n\t"          
        "movq %4, %%rdx\n\t"          
        "movq %5, %%r8\n\t"           
        "movq %6, %%r9\n\t"           
        
        "movq %7, 32(%%rsp)\n\t"      
        "movq %8, 40(%%rsp)\n\t"      
        
        "call *%%rax\n\t"
        
        "addq $48, %%rsp\n\t"         
        
        : "=a" (result)                
        : "r" (func_addr), "r" (nargs), "r" (a0), "r" (a1), "r" (a2), "r" (a3), 
          "r" (a4), "r" (a5), "m" (a6), "m" (a7), "m" (a8), "m" (a9), "m" (a10), "m" (a11)
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    
    return result;
}

uint64_t do_indirect_syscall(int ssn, void* syscall_addr, int nargs, uint64_t a0, uint64_t a1, 
                            uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, 
                            uint64_t a7, uint64_t a8, uint64_t a9, uint64_t a10, uint64_t a11) {
    
    (void)nargs; (void)a4; (void)a5; (void)a6; (void)a7; (void)a8; (void)a9; (void)a10; (void)a11;
    
    uint64_t result;
    
    __asm__ volatile (
        "movl %1, %%eax\n\t"          
        "movq %3, %%rcx\n\t"          
        "movq %4, %%rdx\n\t"          
        "movq %5, %%r8\n\t"           
        "movq %6, %%r9\n\t"           
        "callq *%2\n\t"               
        : "=a" (result)                
        : "r" (ssn), "r" (syscall_addr), "r" (a0), "r" (a1), "r" (a2), "r" (a3)
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    
    return result;
}

uintptr_t find_clean_syscall_stub(uintptr_t ntdll_base) {
    if (ntdll_base == 0) {
        return 0;
    }
    
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntdll_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(ntdll_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    
    DWORD export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_dir_rva == 0) {
        return 0;
    }
    
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(ntdll_base + export_dir_rva);
    PDWORD function_names = (PDWORD)(ntdll_base + export_dir->AddressOfNames);
    PDWORD function_addresses = (PDWORD)(ntdll_base + export_dir->AddressOfFunctions);
    PWORD function_ordinals = (PWORD)(ntdll_base + export_dir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        char* function_name = (char*)(ntdll_base + function_names[i]);
        
        if (strncmp(function_name, "Nt", 2) != 0) {
            continue;
        }
        
        WORD ordinal = function_ordinals[i];
        if (ordinal >= export_dir->NumberOfFunctions) {
            continue;
        }
        
        DWORD function_rva = function_addresses[ordinal];
        if (function_rva == 0) {
            continue;
        }
        
        uintptr_t function_addr = ntdll_base + function_rva;
        uint8_t* func_bytes = (uint8_t*)function_addr;
        
        if (func_bytes[0] == 0x4c && func_bytes[1] == 0x8b && func_bytes[2] == 0xd1 &&
            func_bytes[3] == 0xb8 && 
            func_bytes[8] == 0x0f && func_bytes[9] == 0x05) {
            
            return function_addr;
        }
    }
    
    return 0;
}

uintptr_t external_syscall(uint16_t syscall_number, uintptr_t* args, int arg_count) {
    uint64_t padded_args[12] = {0};
    
    for (int i = 0; i < arg_count && i < 12; i++) {
        padded_args[i] = (uint64_t)args[i];
    }
    
    uint64_t result = do_syscall(
        syscall_number, arg_count,
        padded_args[0], padded_args[1], padded_args[2], padded_args[3],
        padded_args[4], padded_args[5], padded_args[6], padded_args[7],
        padded_args[8], padded_args[9], padded_args[10], padded_args[11]
    );
    
    return (uintptr_t)result;
}

uintptr_t direct_call(uintptr_t func_addr, uintptr_t* args, int arg_count) {
    uint64_t padded_args[12] = {0};
    
    for (int i = 0; i < arg_count && i < 12; i++) {
        padded_args[i] = (uint64_t)args[i];
    }
    
    uint64_t result = do_call(
        (void*)func_addr, arg_count,
        padded_args[0], padded_args[1], padded_args[2], padded_args[3],
        padded_args[4], padded_args[5], padded_args[6], padded_args[7],
        padded_args[8], padded_args[9], padded_args[10], padded_args[11]
    );
    
    return (uintptr_t)result;
}

uintptr_t indirect_syscall(uint16_t syscall_number, uintptr_t* args, int arg_count) {
    static uintptr_t cached_syscall_addr = 0;
    
    if (cached_syscall_addr != 0) {
        uint8_t* addr_bytes = (uint8_t*)cached_syscall_addr;
        if (addr_bytes[0] == 0x4c && addr_bytes[1] == 0x8b && addr_bytes[2] == 0xd1) {
            goto use_cached_addr;
        }
        cached_syscall_addr = 0;
    }
    
    uint32_t ntdll_hash = get_hash("ntdll.dll");
    uintptr_t ntdll_base = get_module_base(ntdll_hash);
    
    if (ntdll_base == 0) {
        return external_syscall(syscall_number, args, arg_count);
    }
    
    uintptr_t syscall_addr = find_clean_syscall_stub(ntdll_base);
    
    if (syscall_addr == 0) {
        return external_syscall(syscall_number, args, arg_count);
    }
    
    cached_syscall_addr = syscall_addr;
    
use_cached_addr:
    syscall_addr = cached_syscall_addr;
    
    uint64_t padded_args[12] = {0};
    
    for (int i = 0; i < arg_count && i < 12; i++) {
        padded_args[i] = (uint64_t)args[i];
    }
    
    uint64_t result = do_indirect_syscall(
        syscall_number, (void*)syscall_addr, arg_count,
        padded_args[0], padded_args[1], padded_args[2], padded_args[3],
        padded_args[4], padded_args[5], padded_args[6], padded_args[7],
        padded_args[8], padded_args[9], padded_args[10], padded_args[11]
    );
    
    return (uintptr_t)result;
}

#endif // SYSCALL_H 