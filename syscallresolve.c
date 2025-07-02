#ifndef SYSCALLRESOLVE_H
#define SYSCALLRESOLVE_H


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.c"
#include "obf.c"
#include "hashes.h"

typedef struct _SYSHASH_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} SYSHASH_UNICODE_STRING, *PSYSHASH_UNICODE_STRING;

typedef struct _SYSHASH_LIST_ENTRY {
    struct _SYSHASH_LIST_ENTRY* Flink;
    struct _SYSHASH_LIST_ENTRY* Blink;
} SYSHASH_LIST_ENTRY, *PSYSHASH_LIST_ENTRY;

typedef struct _SYSHASH_LDR_DATA_TABLE_ENTRY {
    SYSHASH_LIST_ENTRY InLoadOrderLinks;
    SYSHASH_LIST_ENTRY InMemoryOrderLinks;
    SYSHASH_LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    SYSHASH_UNICODE_STRING FullDllName;
    SYSHASH_UNICODE_STRING BaseDllName;
} SYSHASH_LDR_DATA_TABLE_ENTRY, *PSYSHASH_LDR_DATA_TABLE_ENTRY;

typedef struct _SYSHASH_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    SYSHASH_LIST_ENTRY InLoadOrderModuleList;
    SYSHASH_LIST_ENTRY InMemoryOrderModuleList;
    SYSHASH_LIST_ENTRY InInitializationOrderModuleList;
} SYSHASH_PEB_LDR_DATA, *PSYSHASH_PEB_LDR_DATA;

typedef struct _SYSHASH_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PSYSHASH_PEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    ULONG CrossProcessFlags;
    PVOID UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
} SYSHASH_PEB, *PSYSHASH_PEB;

typedef struct syscall_cache_entry {
    uint32_t function_hash;
    uint16_t syscall_number;
    uintptr_t function_address;
    struct syscall_cache_entry* next;
} syscall_cache_entry_t;

typedef struct module_cache_entry {
    uint32_t module_hash;
    uintptr_t module_base;
    struct module_cache_entry* next;
} module_cache_entry_t;

static syscall_cache_entry_t* syscall_cache = NULL;
static module_cache_entry_t* module_cache = NULL;

#ifdef _WIN32
static CRITICAL_SECTION syscall_cache_mutex;
static CRITICAL_SECTION module_cache_mutex;
static bool cache_mutex_initialized = false;
static bool module_cache_mutex_initialized = false;
#endif

uintptr_t get_peb(void);
PSYSHASH_PEB get_current_process_peb(void);
uintptr_t get_module_base(uint32_t module_hash);
uintptr_t get_function_address(uintptr_t module_base, uint32_t function_hash);
void list_module_exports(uintptr_t module_base, const char* module_name);
uint16_t get_syscall_number(uint32_t function_hash);
uint16_t get_syscall_and_address(uint32_t function_hash, uintptr_t* syscall_addr);
char* utf16_to_string(PWSTR utf16_str);
uint16_t extract_syscall_number(uintptr_t func_addr);
void init_syscall_cache(void);
void cleanup_syscall_cache(void);

uintptr_t get_peb(void) {
    uintptr_t peb_addr;
    
    __asm__ volatile (
        "movq %%gs:0x60, %0"    
        : "=r" (peb_addr)       
        :                       
        :                       
    );
    
    return peb_addr;
}

PSYSHASH_PEB get_current_process_peb(void) {
    uintptr_t peb_addr = get_peb();
    if (peb_addr == 0) {
        debug_printfln("SYSCALLRESOLVE", "Failed to get PEB address via assembly\n");
        return NULL;
    }
    
    PSYSHASH_PEB peb = (PSYSHASH_PEB)peb_addr;
    
    if (peb == NULL || peb->Ldr == NULL) {
        debug_printfln("SYSCALLRESOLVE", "PEB validation failed\n");
        return NULL;
    }
    
    return peb;
}

char* utf16_to_string(PWSTR utf16_str) {
    if (utf16_str == NULL) {
        return NULL;
    }
    
    int len = 0;
    PWSTR tmp = utf16_str;
    while (*tmp != 0) {
        len++;
        tmp++;
    }
    
    char* ascii_str = malloc(len + 1);
    if (ascii_str == NULL) {
        return NULL;
    }

    for (int i = 0; i < len; i++) {
        ascii_str[i] = (char)(utf16_str[i] & 0xFF);
    }
    ascii_str[len] = '\0';
    
    return ascii_str;
}

uintptr_t get_module_base(uint32_t module_hash) {
    init_syscall_cache();
    
#ifdef _WIN32
    EnterCriticalSection(&module_cache_mutex);
#endif
    
    // Check cache first
    module_cache_entry_t* cached_entry = module_cache;
    while (cached_entry != NULL) {
        if (cached_entry->module_hash == module_hash) {
            uintptr_t cached_base = cached_entry->module_base;
#ifdef _WIN32
            LeaveCriticalSection(&module_cache_mutex);
#endif
            return cached_base;
        }
        cached_entry = cached_entry->next;
    }
    
#ifdef _WIN32
    LeaveCriticalSection(&module_cache_mutex);
#endif
    
    // Not in cache, do expensive PEB walk
    PSYSHASH_PEB peb = get_current_process_peb();
    if (peb == NULL || peb->Ldr == NULL) {
        return 0;
    }
    
    SYSHASH_LIST_ENTRY* entry = &peb->Ldr->InLoadOrderModuleList;
    SYSHASH_LIST_ENTRY* current_entry = entry->Flink;
    
    while (current_entry != entry && current_entry != NULL) {
        PSYSHASH_LDR_DATA_TABLE_ENTRY data_table_entry = 
            (PSYSHASH_LDR_DATA_TABLE_ENTRY)((uintptr_t)current_entry - 
            offsetof(SYSHASH_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks));
        
        char* base_name = utf16_to_string(data_table_entry->BaseDllName.Buffer);
        if (base_name != NULL) {
            uint32_t current_hash = dbj2_hash_str(base_name);
            
            debug_printfln("SYSCALLRESOLVE", "Checking module: %s (hash: 0x%08X)\n", base_name, current_hash);
            
            if (current_hash == module_hash) {
                uintptr_t module_base = (uintptr_t)data_table_entry->DllBase;
                free(base_name);
                debug_printfln("SYSCALLRESOLVE", "Found module base: 0x%p\n", (void*)module_base);
                
                // Cache the result
#ifdef _WIN32
                EnterCriticalSection(&module_cache_mutex);
#endif
                
                module_cache_entry_t* new_entry = malloc(sizeof(module_cache_entry_t));
                if (new_entry != NULL) {
                    new_entry->module_hash = module_hash;
                    new_entry->module_base = module_base;
                    new_entry->next = module_cache;
                    module_cache = new_entry;
                }
                
#ifdef _WIN32
                LeaveCriticalSection(&module_cache_mutex);
#endif
                
                return module_base;
            }
            
            free(base_name);
        }
        
        current_entry = current_entry->Flink;
    }
    
    debug_printfln("SYSCALLRESOLVE", "Module not found for hash: 0x%08X\n", module_hash);
    return 0;
}

uintptr_t get_function_address(uintptr_t module_base, uint32_t function_hash) {
    if (module_base == 0) {
        return 0;
    }
    
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        debug_printfln("SYSCALLRESOLVE", "Invalid DOS signature: 0x%04X\n", dos_header->e_magic);
        return 0;
    }
    
    if (dos_header->e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) || dos_header->e_lfanew > 0x1000) {
        debug_printfln("SYSCALLRESOLVE", "Invalid e_lfanew offset: 0x%X\n", dos_header->e_lfanew);
        return 0;
    }
    
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(module_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        debug_printfln("SYSCALLRESOLVE", "Invalid NT signature: 0x%08X\n", nt_headers->Signature);
        return 0;
    }
    
    if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        debug_printfln("SYSCALLRESOLVE", "Unsupported architecture: 0x%04X\n", nt_headers->FileHeader.Machine);
        return 0;
    }
    
    DWORD export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_dir_size = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    
    if (export_dir_rva == 0 || export_dir_size == 0) {
        debug_printfln("SYSCALLRESOLVE", "No export directory (RVA: 0x%X, Size: 0x%X)\n", export_dir_rva, export_dir_size);
        return 0;
    }
    
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(module_base + export_dir_rva);
    
    if (export_dir->NumberOfFunctions == 0) {
        debug_printfln("SYSCALLRESOLVE", "Export directory has no functions\n");
        return 0;
    }
    
    if (export_dir->AddressOfFunctions == 0) {
        debug_printfln("SYSCALLRESOLVE", "Invalid AddressOfFunctions\n");
        return 0;
    }
    
    PDWORD function_addresses = (PDWORD)(module_base + export_dir->AddressOfFunctions);
    PDWORD function_names = NULL;
    PWORD function_ordinals = NULL;
    
    if (export_dir->NumberOfNames > 0 && export_dir->AddressOfNames != 0 && export_dir->AddressOfNameOrdinals != 0) {
        function_names = (PDWORD)(module_base + export_dir->AddressOfNames);
        function_ordinals = (PWORD)(module_base + export_dir->AddressOfNameOrdinals);
        
        debug_printfln("SYSCALLRESOLVE", "Searching %u named exports for hash 0x%08X\n", export_dir->NumberOfNames, function_hash);
        
        for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
            if (function_names[i] == 0) {
                continue;
            }
            
            char* function_name = (char*)(module_base + function_names[i]);
            
            if (function_name == NULL || function_name[0] == '\0') {
                continue;
            }
            
            uint32_t current_hash = dbj2_hash_str(function_name);
            
            if (current_hash == function_hash) {
                if (i >= export_dir->NumberOfNames) {
                    debug_printfln("SYSCALLRESOLVE", "Invalid ordinal index: %u\n", i);
                    continue;
                }
                
                WORD ordinal = function_ordinals[i];
                
                if (ordinal >= export_dir->NumberOfFunctions) {
                    debug_printfln("SYSCALLRESOLVE", "Ordinal %u out of range (max: %u)\n", ordinal, export_dir->NumberOfFunctions);
                    continue;
                }
                
                DWORD function_rva = function_addresses[ordinal];
                
                if (function_rva >= export_dir_rva && function_rva < export_dir_rva + export_dir_size) {
                    char* forward_name = (char*)(module_base + function_rva);
                    debug_printfln("SYSCALLRESOLVE", "Function %s is forwarded to: %s\n", function_name, forward_name);
                    continue;
                }
                
                if (function_rva == 0) {
                    debug_printfln("SYSCALLRESOLVE", "Function %s has NULL RVA\n", function_name);
                    continue;
                }
                
                uintptr_t function_addr = module_base + function_rva;
                
                debug_printfln("SYSCALLRESOLVE", "Found function: %s at 0x%p (ordinal: %u, RVA: 0x%X)\n", 
                               function_name, (void*)function_addr, ordinal, function_rva);
                return function_addr;
            }
        }
    } else {
        debug_printfln("SYSCALLRESOLVE", "Module has no named exports\n");
    }
    
    debug_printfln("SYSCALLRESOLVE", "Searching %u ordinal-only exports\n", 
                   export_dir->NumberOfFunctions - export_dir->NumberOfNames);
    
    debug_printfln("SYSCALLRESOLVE", "Function not found for hash: 0x%08X\n", function_hash);
    return 0;
}

void list_module_exports(uintptr_t module_base, const char* module_name) {
    if (module_base == 0) {
        return;
    }
    
    debug_printfln("SYSCALLRESOLVE", "=== Listing exports for %s ===\n", module_name);
    
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        debug_printfln("SYSCALLRESOLVE", "Invalid DOS signature\n");
        return;
    }
    
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(module_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        debug_printfln("SYSCALLRESOLVE", "Invalid NT signature\n");
        return;
    }
    
    DWORD export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_dir_rva == 0) {
        debug_printfln("SYSCALLRESOLVE", "No export directory\n");
        return;
    }
    
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(module_base + export_dir_rva);
    PDWORD function_addresses = (PDWORD)(module_base + export_dir->AddressOfFunctions);
    PDWORD function_names = (PDWORD)(module_base + export_dir->AddressOfNames);
    PWORD function_ordinals = (PWORD)(module_base + export_dir->AddressOfNameOrdinals);
    
    (void)function_addresses;
    (void)function_ordinals;
    
    debug_printfln("SYSCALLRESOLVE", "Total functions: %u, Named exports: %u\n", 
                   export_dir->NumberOfFunctions, export_dir->NumberOfNames);
    
    int nt_count = 0;
    for (DWORD i = 0; i < export_dir->NumberOfNames && nt_count < 20; i++) {
        char* function_name = (char*)(module_base + function_names[i]);
        if (strncmp(function_name, "Nt", 2) == 0) {
            uint32_t hash = dbj2_hash_str(function_name);
            debug_printfln("SYSCALLRESOLVE", "  %s (hash: 0x%08X)\n", function_name, hash);
            nt_count++;
        }
    }
    
    if (nt_count >= 20) {
        debug_printfln("SYSCALLRESOLVE", "  ... (showing first 20 Nt* functions)\n");
    }
    
    debug_printfln("SYSCALLRESOLVE", "=== End exports for %s ===\n", module_name);
}

uint16_t extract_syscall_number_with_validation(uintptr_t func_addr, uint32_t function_hash);
uint16_t try_extract_syscall_number(uint8_t* func_bytes, size_t length, uintptr_t func_addr, uint32_t function_hash);
bool validate_syscall_number(uint16_t syscall_number, uint32_t function_hash);
uint16_t try_alternative_extraction_methods(uint8_t* func_bytes, size_t length, uintptr_t func_addr, uint32_t function_hash);
uint16_t guess_syscall_number(uint32_t target_hash);

uint16_t extract_syscall_number(uintptr_t func_addr) {
    if (func_addr == 0) {
        return 0;
    }
    
    return extract_syscall_number_with_validation(func_addr, 0);
}

uint16_t extract_syscall_number_with_validation(uintptr_t func_addr, uint32_t function_hash) {
    if (func_addr == 0) {
        return 0xFFFF;
    }
    
    const size_t max_bytes = 32;
    uint8_t func_bytes[max_bytes];
    
    for (size_t i = 0; i < max_bytes; i++) {
        func_bytes[i] = *((uint8_t*)func_addr + i);
    }
    
    uint16_t syscall_number = try_extract_syscall_number(func_bytes, max_bytes, func_addr, function_hash);
    
    if (syscall_number > 0 && validate_syscall_number(syscall_number, function_hash)) {
        return syscall_number;
    }
    
    syscall_number = try_alternative_extraction_methods(func_bytes, max_bytes, func_addr, function_hash);
    
    if (syscall_number > 0 && validate_syscall_number(syscall_number, function_hash)) {
        return syscall_number;
    }
    
    if (function_hash != 0) {
        debug_printfln("SYSCALLRESOLVE", "Standard extraction failed, attempting to guess syscall for hash 0x%08X\n", function_hash);
        return guess_syscall_number(function_hash);
    }
    
    return 0xFFFF;
}

uint16_t try_extract_syscall_number(uint8_t* func_bytes, size_t length, uintptr_t func_addr, uint32_t function_hash) {
    if (length < 16) {
        return 0xFFFF;
    }
    
    if (length >= 8 &&
        func_bytes[0] == 0x4c && func_bytes[1] == 0x8b && func_bytes[2] == 0xd1 &&
        func_bytes[3] == 0xb8) {
        
        uint16_t syscall_num = func_bytes[4] | (func_bytes[5] << 8);
        if (syscall_num > 0 && syscall_num < 2000) {
            debug_printfln("SYSCALLRESOLVE", "Pattern 1: Found syscall %u for hash 0x%08X\n", syscall_num, function_hash);
            return syscall_num;
        }
    }
    
    if (length >= 8 &&
        func_bytes[0] == 0xb8 &&
        func_bytes[5] == 0x4c && func_bytes[6] == 0x8b && func_bytes[7] == 0xd1) {
        
        uint16_t syscall_num = func_bytes[1] | (func_bytes[2] << 8);
        if (syscall_num > 0 && syscall_num < 2000) {
            debug_printfln("SYSCALLRESOLVE", "Pattern 2: Found syscall %u for hash 0x%08X\n", syscall_num, function_hash);
            return syscall_num;
        }
    }
    
    if (func_bytes[0] == 0xe9 || func_bytes[0] == 0xeb || func_bytes[0] == 0xff) {
        debug_printfln("SYSCALLRESOLVE", "Warning: Function at 0x%p appears to be hooked (starts with JMP: 0x%02X)\n", 
                       (void*)func_addr, func_bytes[0]);
        return 0xFFFF;
    }
    
    return 0xFFFF;
}

bool validate_syscall_number(uint16_t syscall_number, uint32_t function_hash) {
    if (syscall_number == 0 || syscall_number >= 2000) {
        return false;
    }
    
    if (syscall_number < 2) {
        debug_printfln("SYSCALLRESOLVE", "Warning: Unusually low syscall number %u for hash 0x%08X\n", 
                       syscall_number, function_hash);
    }
    
    return true;
}

uint16_t try_alternative_extraction_methods(uint8_t* func_bytes, size_t length, uintptr_t func_addr, uint32_t function_hash) {
    (void)func_addr;
    
    for (size_t i = 0; i < length - 4; i++) {
        if (func_bytes[i] == 0xb8) {
            uint16_t syscall_num = func_bytes[i+1] | (func_bytes[i+2] << 8);
            if (syscall_num > 0 && syscall_num < 2000) {
                debug_printfln("SYSCALLRESOLVE", "Alternative method 1: Found syscall %u at offset %zu for hash 0x%08X\n", 
                               syscall_num, i, function_hash);
                return syscall_num;
            }
        }
    }
    
    for (size_t i = 0; i < length - 1; i++) {
        if (func_bytes[i] == 0x0f && func_bytes[i+1] == 0x05) {
            for (size_t j = i; j >= 4 && j < length; j--) {
                if (func_bytes[j-4] == 0xb8) { // MOV EAX, imm32
                    uint16_t syscall_num = func_bytes[j-3] | (func_bytes[j-2] << 8);
                    if (syscall_num > 0 && syscall_num < 2000) {
                        debug_printfln("SYSCALLRESOLVE", "Backtrack method: Found syscall %u for hash 0x%08X\n", 
                                       syscall_num, function_hash);
                        return syscall_num;
                    }
                }
            }
            break;
        }
    }
    
    int alternative_offsets[] = {8, 12, 16, 20};
    size_t num_offsets = sizeof(alternative_offsets) / sizeof(alternative_offsets[0]);
    
    for (size_t i = 0; i < num_offsets; i++) {
        int offset = alternative_offsets[i];
        if (offset + 1 < (int)length) {
            if (func_bytes[offset] == 0xb8) {
                uint16_t syscall_num = func_bytes[offset+1] | (func_bytes[offset+2] << 8);
                if (syscall_num > 0 && syscall_num < 2000) {
                    debug_printfln("SYSCALLRESOLVE", "Offset method: Found syscall %u at offset %d for hash 0x%08X\n", 
                                   syscall_num, offset, function_hash);
                    return syscall_num;
                }
            }
        }
    }
    
    debug_printfln("SYSCALLRESOLVE", "All extraction methods failed for hash 0x%08X\n", function_hash);
    return 0xFFFF;
}

typedef struct {
    char name[256];
    uint32_t hash;
    uintptr_t address;
    uintptr_t rva;
} export_info_t;

static bool is_clean_syscall(uintptr_t addr, uint16_t* syscall_num) {
    uint8_t* bytes = (uint8_t*)addr;
    
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
        *syscall_num = bytes[4] | (bytes[5] << 8);
        return true;
    }
    return false;
}

static bool is_nt_zw_pair(const char* name1, const char* name2) {
    if (strlen(name1) < 2 || strlen(name2) < 2) {
        return false;
    }
    
    if ((strncmp(name1, "Nt", 2) == 0 && strncmp(name2, "Zw", 2) == 0 && strcmp(name1 + 2, name2 + 2) == 0) ||
        (strncmp(name1, "Zw", 2) == 0 && strncmp(name2, "Nt", 2) == 0 && strcmp(name1 + 2, name2 + 2) == 0)) {
        return true;
    }
    return false;
}

static int compare_exports(const void* a, const void* b) {
    const export_info_t* exp_a = (const export_info_t*)a;
    const export_info_t* exp_b = (const export_info_t*)b;
    if (exp_a->rva < exp_b->rva) return -1;
    if (exp_a->rva > exp_b->rva) return 1;
    return 0;
}

uint16_t guess_syscall_number(uint32_t target_hash) {
    debug_printfln("SYSCALLRESOLVE", "Attempting to guess syscall number for hash 0x%08X\n", target_hash);
    
    uint32_t ntdll_hash = MOD_NTDLL_DLL;
    uintptr_t ntdll_base = get_module_base(ntdll_hash);
    if (ntdll_base == 0) {
        debug_printfln("SYSCALLRESOLVE", "Failed to get ntdll.dll base for syscall guessing\n");
        return 0xFFFF;
    }
    
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntdll_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        debug_printfln("SYSCALLRESOLVE", "Invalid DOS signature in NTDLL\n");
        return 0xFFFF;
    }
    
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(ntdll_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        debug_printfln("SYSCALLRESOLVE", "Invalid PE signature\n");
        return 0xFFFF;
    }
    
    DWORD export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_dir_rva == 0) {
        debug_printfln("SYSCALLRESOLVE", "No export directory found\n");
        return 0xFFFF;
    }
    
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(ntdll_base + export_dir_rva);
    PDWORD function_names = (PDWORD)(ntdll_base + export_dir->AddressOfNames);
    PDWORD function_addresses = (PDWORD)(ntdll_base + export_dir->AddressOfFunctions);
    PWORD function_ordinals = (PWORD)(ntdll_base + export_dir->AddressOfNameOrdinals);
    
    export_info_t* exports = malloc(export_dir->NumberOfNames * sizeof(export_info_t));
    if (!exports) {
        debug_printfln("SYSCALLRESOLVE", "Failed to allocate memory for exports\n");
        return 0xFFFF;
    }
    
    int export_count = 0;
    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        char* function_name = (char*)(ntdll_base + function_names[i]);
        WORD ordinal = function_ordinals[i];
        
        if (ordinal >= export_dir->NumberOfFunctions) {
            continue;
        }
        
        DWORD function_rva = function_addresses[ordinal];
        if (function_rva == 0) {
            continue;
        }
        
        if (strncmp(function_name, "Nt", 2) != 0 && strncmp(function_name, "Zw", 2) != 0) {
            continue;
        }
        
        strncpy(exports[export_count].name, function_name, sizeof(exports[export_count].name) - 1);
        exports[export_count].name[sizeof(exports[export_count].name) - 1] = '\0';
        exports[export_count].hash = get_hash(function_name);
        exports[export_count].address = ntdll_base + function_rva;
        exports[export_count].rva = function_rva;
        export_count++;
    }
    
    qsort(exports, export_count, sizeof(export_info_t), compare_exports);
    
    int target_index = -1;
    for (int i = 0; i < export_count; i++) {
        if (exports[i].hash == target_hash) {
            target_index = i;
            break;
        }
    }
    
    if (target_index == -1) {
        debug_printfln("SYSCALLRESOLVE", "Target function not found for hash 0x%08X\n", target_hash);
        free(exports);
        return 0xFFFF;
    }
    
    debug_printfln("SYSCALLRESOLVE", "Found target function %s at index %d\n", exports[target_index].name, target_index);
    
    for (int offset = -5; offset <= 5; offset++) {
        if (offset == 0) continue;
        
        int pair_idx = target_index + offset;
        if (pair_idx < 0 || pair_idx >= export_count) {
            continue;
        }
        
        if (is_nt_zw_pair(exports[target_index].name, exports[pair_idx].name)) {
            uint16_t syscall_num;
            if (is_clean_syscall(exports[pair_idx].address, &syscall_num)) {
                debug_printfln("SYSCALLRESOLVE", "Found NT/ZW pair %s with syscall %d for target %s\n", 
                    exports[pair_idx].name, syscall_num, exports[target_index].name);
                free(exports);
                return syscall_num;
            }
        }
    }

    uint16_t left_syscall = 0;
    int left_index = -1;
    for (int i = target_index - 1; i >= 0 && i >= target_index - 10; i--) {
        uint16_t syscall_num;
        if (is_clean_syscall(exports[i].address, &syscall_num)) {
            left_syscall = syscall_num;
            left_index = i;
            break;
        }
    }
    
    uint16_t right_syscall = 0;
    int right_index = -1;
    for (int i = target_index + 1; i < export_count && i <= target_index + 10; i++) {
        uint16_t syscall_num;
        if (is_clean_syscall(exports[i].address, &syscall_num)) {
            right_syscall = syscall_num;
            right_index = i;
            break;
        }
    }
    
    if (left_index != -1 && right_index != -1) {
        int position_diff = target_index - left_index;
        int syscall_diff = right_syscall - left_syscall;
        int index_diff = right_index - left_index;
        
        if (index_diff > 0) {
            uint16_t interpolated = left_syscall + (syscall_diff * position_diff) / index_diff;
            debug_printfln("SYSCALLRESOLVE", "Interpolated syscall %d for hash 0x%08X between %s(%d) and %s(%d)\n", 
                interpolated, target_hash, exports[left_index].name, left_syscall, exports[right_index].name, right_syscall);
            free(exports);
            return interpolated;
        }
    }
    
    if (left_index != -1) {
        int offset = target_index - left_index;
        uint16_t guessed = left_syscall + offset;
        debug_printfln("SYSCALLRESOLVE", "Guessed syscall %d for hash 0x%08X using left neighbor %s(%d) + %d\n", 
            guessed, target_hash, exports[left_index].name, left_syscall, offset);
        free(exports);
        return guessed;
    }
    
    if (right_index != -1) {
        int offset = right_index - target_index;
        uint16_t guessed = right_syscall - offset;
        debug_printfln("SYSCALLRESOLVE", "Guessed syscall %d for hash 0x%08X using right neighbor %s(%d) - %d\n", 
            guessed, target_hash, exports[right_index].name, right_syscall, offset);
        free(exports);
        return guessed;
    }
    
    debug_printfln("SYSCALLRESOLVE", "Failed to find clean neighbors for hash 0x%08X\n", target_hash);
    free(exports);
    return 0xFFFF;
}

void init_syscall_cache(void) {
#ifdef _WIN32
    if (!cache_mutex_initialized) {
        InitializeCriticalSection(&syscall_cache_mutex);
        cache_mutex_initialized = true;
    }
    if (!module_cache_mutex_initialized) {
        InitializeCriticalSection(&module_cache_mutex);
        module_cache_mutex_initialized = true;
    }
#endif
}

void cleanup_syscall_cache(void) {
    init_syscall_cache();
    
#ifdef _WIN32
    EnterCriticalSection(&syscall_cache_mutex);
#endif
    
    syscall_cache_entry_t* entry = syscall_cache;
    while (entry != NULL) {
        syscall_cache_entry_t* next = entry->next;
        free(entry);
        entry = next;
    }
    syscall_cache = NULL;
    
#ifdef _WIN32
    LeaveCriticalSection(&syscall_cache_mutex);
    
    EnterCriticalSection(&module_cache_mutex);
#endif
    
    module_cache_entry_t* mod_entry = module_cache;
    while (mod_entry != NULL) {
        module_cache_entry_t* next = mod_entry->next;
        free(mod_entry);
        mod_entry = next;
    }
    module_cache = NULL;
    
#ifdef _WIN32
    LeaveCriticalSection(&module_cache_mutex);
    
    if (cache_mutex_initialized) {
        DeleteCriticalSection(&syscall_cache_mutex);
        cache_mutex_initialized = false;
    }
    if (module_cache_mutex_initialized) {
        DeleteCriticalSection(&module_cache_mutex);
        module_cache_mutex_initialized = false;
    }
#endif
}

uint16_t get_syscall_number(uint32_t function_hash) {
    init_syscall_cache();
    
#ifdef _WIN32
    EnterCriticalSection(&syscall_cache_mutex);
#endif
    
    syscall_cache_entry_t* entry = syscall_cache;
    while (entry != NULL) {
        if (entry->function_hash == function_hash) {
            uint16_t cached_syscall = entry->syscall_number;
#ifdef _WIN32
            LeaveCriticalSection(&syscall_cache_mutex);
#endif
            return cached_syscall;
        }
        entry = entry->next;
    }
    
#ifdef _WIN32
    LeaveCriticalSection(&syscall_cache_mutex);
#endif
    
    uint32_t ntdll_hash = MOD_NTDLL_DLL;
    uintptr_t ntdll_base = get_module_base(ntdll_hash);
    if (ntdll_base == 0) {
        debug_printfln("SYSCALLRESOLVE", "Failed to get ntdll.dll base\n");
        return 0xFFFF;
    }
    
    uintptr_t func_addr = get_function_address(ntdll_base, function_hash);
    if (func_addr == 0) {
        debug_printfln("SYSCALLRESOLVE", "Failed to get function address\n");
        return 0xFFFF;
    }
    
    uint16_t syscall_num = extract_syscall_number_with_validation(func_addr, function_hash);
    if (syscall_num == 0xFFFF) {
        debug_printfln("SYSCALLRESOLVE", "Failed to extract syscall number for hash 0x%08X\n", function_hash);
        return 0xFFFF;
    }
    
#ifdef _WIN32
    EnterCriticalSection(&syscall_cache_mutex);
#endif
    
    syscall_cache_entry_t* new_entry = malloc(sizeof(syscall_cache_entry_t));
    if (new_entry != NULL) {
        new_entry->function_hash = function_hash;
        new_entry->syscall_number = syscall_num;
        new_entry->function_address = func_addr;
        new_entry->next = syscall_cache;
        syscall_cache = new_entry;
    }
    
#ifdef _WIN32
    LeaveCriticalSection(&syscall_cache_mutex);
#endif
    
    return syscall_num;
}

uint16_t get_syscall_and_address(uint32_t function_hash, uintptr_t* syscall_addr) {
    if (syscall_addr == NULL) {
        return 0xFFFF;
    }
    
    init_syscall_cache();
    
#ifdef _WIN32
    EnterCriticalSection(&syscall_cache_mutex);
#endif
    
    syscall_cache_entry_t* entry = syscall_cache;
    while (entry != NULL) {
        if (entry->function_hash == function_hash) {
            uint16_t cached_syscall = entry->syscall_number;
            *syscall_addr = entry->function_address;
#ifdef _WIN32
            LeaveCriticalSection(&syscall_cache_mutex);
#endif
            return cached_syscall;
        }
        entry = entry->next;
    }
    
#ifdef _WIN32
    LeaveCriticalSection(&syscall_cache_mutex);
#endif
    
    uint32_t ntdll_hash = MOD_NTDLL_DLL;
    uintptr_t ntdll_base = get_module_base(ntdll_hash);
    if (ntdll_base == 0) {
        return 0xFFFF;
    }
    
    uintptr_t func_addr = get_function_address(ntdll_base, function_hash);
    if (func_addr == 0) {
        return 0xFFFF;
    }
    
    uint16_t syscall_num = extract_syscall_number_with_validation(func_addr, function_hash);
    if (syscall_num == 0xFFFF) {
        return 0xFFFF;
    }
    
    uint8_t* func_bytes = (uint8_t*)func_addr;
    uintptr_t syscall_instr_addr = 0;
    
    for (int i = 0; i < 32; i++) {
        if (func_bytes[i] == 0x0F && func_bytes[i + 1] == 0x05) {
            syscall_instr_addr = func_addr + i;
            break;
        }
    }
    
    if (syscall_instr_addr == 0) {
        debug_printfln("SYSCALLRESOLVE", "Failed to find syscall instruction\n");
        return 0xFFFF;
    }
    
    *syscall_addr = syscall_instr_addr;
    
#ifdef _WIN32
    EnterCriticalSection(&syscall_cache_mutex);
#endif
    
    syscall_cache_entry_t* new_entry = malloc(sizeof(syscall_cache_entry_t));
    if (new_entry != NULL) {
        new_entry->function_hash = function_hash;
        new_entry->syscall_number = syscall_num;
        new_entry->function_address = syscall_instr_addr;
        new_entry->next = syscall_cache;
        syscall_cache = new_entry;
    }
    
#ifdef _WIN32
    LeaveCriticalSection(&syscall_cache_mutex);
#endif
    
    return syscall_num;
}

#endif // SYSCALLRESOLVE_H 