#ifndef DUMP_H
#define DUMP_H

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
#include "syscallresolve.c"

typedef struct syscall_info {
    char* name;
    uint32_t hash;
    uint16_t syscall_number;
    uintptr_t address;
} syscall_info_t;

typedef struct function_info {
    char* name;
    uint32_t hash;
    uintptr_t address;
    bool is_syscall;
    uint16_t syscall_number;
} function_info_t;

typedef struct syscall_list {
    syscall_info_t* syscalls;
    size_t count;
    size_t capacity;
} syscall_list_t;

typedef struct function_list {
    function_info_t* functions;
    size_t count;
    size_t capacity;
} function_list_t;

typedef struct function_cache_entry {
    char* name;
    function_info_t* info;
    struct function_cache_entry* next;
} function_cache_entry_t;

static function_cache_entry_t* ntdll_function_cache = NULL;
static bool ntdll_cache_initialized = false;

#ifdef _WIN32
static CRITICAL_SECTION ntdll_cache_mutex;
static bool cache_mutex_init = false;
#endif

syscall_list_t* dump_all_syscalls(void);
function_list_t* dump_all_ntdll_functions(void);
function_info_t* find_ntdll_function(const char* function_name);
uintptr_t get_ntdll_function_address(const char* function_name);
void free_syscall_list(syscall_list_t* list);
void free_function_list(function_list_t* list);
void cleanup_ntdll_cache(void);
void init_ntdll_cache_mutex(void);
bool is_syscall_function(const char* name);
bool extract_syscall_info_from_address(uintptr_t func_addr, uint16_t* syscall_number);
bool dump_syscalls_to_file(const char* filename);
bool dump_all_functions_to_file(const char* filename);

void init_ntdll_cache_mutex(void) {
#ifdef _WIN32
    if (!cache_mutex_init) {
        InitializeCriticalSection(&ntdll_cache_mutex);
        cache_mutex_init = true;
    }
#endif
}

bool is_syscall_function(const char* name) {
    if (name == NULL || strlen(name) < 3) {
        return false;
    }
    return (strncmp(name, "Nt", 2) == 0 || strncmp(name, "Zw", 2) == 0);
}

bool extract_syscall_info_from_address(uintptr_t func_addr, uint16_t* syscall_number) {
    if (func_addr == 0 || syscall_number == NULL) {
        return false;
    }
    
    uint8_t first_bytes[16];
    for (int i = 0; i < 16; i++) {
        first_bytes[i] = *((uint8_t*)func_addr + i);
    }
    
    if (first_bytes[0] == 0x4c && first_bytes[1] == 0x8b && 
        first_bytes[2] == 0xd1 && first_bytes[3] == 0xb8) {
        *syscall_number = first_bytes[4] | (first_bytes[5] << 8);
        return *syscall_number > 0;
    }
    
    return false;
}

syscall_list_t* dump_all_syscalls(void) {
    debug_printfln("DUMP", "Starting syscall enumeration...");
    
    uint32_t ntdll_hash = get_hash("ntdll.dll");
    uintptr_t ntdll_base = get_module_base(ntdll_hash);
    if (ntdll_base == 0) {
        debug_printfln("DUMP", "Failed to get ntdll.dll base address");
        return NULL;
    }
    
    debug_printfln("DUMP", "Found ntdll.dll at: 0x%p", (void*)ntdll_base);
    
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntdll_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        debug_printfln("DUMP", "Invalid DOS signature");
        return NULL;
    }
    
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(ntdll_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        debug_printfln("DUMP", "Invalid NT signature");
        return NULL;
    }
    
    DWORD export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_dir_rva == 0) {
        debug_printfln("DUMP", "No export directory");
        return NULL;
    }
    
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(ntdll_base + export_dir_rva);
    PDWORD function_addresses = (PDWORD)(ntdll_base + export_dir->AddressOfFunctions);
    PDWORD function_names = (PDWORD)(ntdll_base + export_dir->AddressOfNames);
    PWORD function_ordinals = (PWORD)(ntdll_base + export_dir->AddressOfNameOrdinals);
    
    debug_printfln("DUMP", "Found %u exports in ntdll.dll", export_dir->NumberOfNames);
    
    syscall_list_t* list = malloc(sizeof(syscall_list_t));
    if (list == NULL) {
        return NULL;
    }
    
    list->capacity = 200;
    list->count = 0;
    list->syscalls = malloc(sizeof(syscall_info_t) * list->capacity);
    if (list->syscalls == NULL) {
        free(list);
        return NULL;
    }
    
    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        char* function_name = (char*)(ntdll_base + function_names[i]);
        
        if (!is_syscall_function(function_name)) {
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
        
        uintptr_t func_addr = ntdll_base + function_rva;
        
        uint16_t syscall_number;
        if (!extract_syscall_info_from_address(func_addr, &syscall_number)) {
            continue;
        }
        
        if (list->count >= list->capacity) {
            list->capacity *= 2;
            syscall_info_t* new_syscalls = realloc(list->syscalls, 
                sizeof(syscall_info_t) * list->capacity);
            if (new_syscalls == NULL) {
                break;
            }
            list->syscalls = new_syscalls;
        }
        
        syscall_info_t* info = &list->syscalls[list->count];
        info->name = malloc(strlen(function_name) + 1);
        if (info->name == NULL) {
            continue;
        }
        strcpy(info->name, function_name);
        info->hash = dbj2_hash_str(function_name);
        info->syscall_number = syscall_number;
        info->address = func_addr;
        
        list->count++;
    }
    
    debug_printfln("DUMP", "Found %zu syscall functions", list->count);
    return list;
}

function_list_t* dump_all_ntdll_functions(void) {
    debug_printfln("DUMP", "Starting ntdll function enumeration...");
    
    uint32_t ntdll_hash = get_hash("ntdll.dll");
    uintptr_t ntdll_base = get_module_base(ntdll_hash);
    if (ntdll_base == 0) {
        debug_printfln("DUMP", "Failed to get ntdll.dll base address");
        return NULL;
    }
    
    debug_printfln("DUMP", "Found ntdll.dll at: 0x%p", (void*)ntdll_base);
    
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)ntdll_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        debug_printfln("DUMP", "Invalid DOS signature");
        return NULL;
    }
    
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(ntdll_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        debug_printfln("DUMP", "Invalid NT signature");
        return NULL;
    }
    
    DWORD export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_dir_rva == 0) {
        debug_printfln("DUMP", "No export directory");
        return NULL;
    }
    
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(ntdll_base + export_dir_rva);
    PDWORD function_addresses = (PDWORD)(ntdll_base + export_dir->AddressOfFunctions);
    PDWORD function_names = (PDWORD)(ntdll_base + export_dir->AddressOfNames);
    PWORD function_ordinals = (PWORD)(ntdll_base + export_dir->AddressOfNameOrdinals);
    
    debug_printfln("DUMP", "Found %u total exports in ntdll.dll", export_dir->NumberOfNames);
    
    function_list_t* list = malloc(sizeof(function_list_t));
    if (list == NULL) {
        return NULL;
    }
    
    list->capacity = export_dir->NumberOfNames;
    list->count = 0;
    list->functions = malloc(sizeof(function_info_t) * list->capacity);
    if (list->functions == NULL) {
        free(list);
        return NULL;
    }
    
    size_t syscall_count = 0;
    
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
        
        uintptr_t func_addr = ntdll_base + function_rva;
        
        bool is_syscall = is_syscall_function(function_name);
        uint16_t syscall_number = 0;
        
        if (is_syscall) {
            if (extract_syscall_info_from_address(func_addr, &syscall_number)) {
                syscall_count++;
            } else {
                is_syscall = false;
            }
        }
        
        function_info_t* info = &list->functions[list->count];
        info->name = malloc(strlen(function_name) + 1);
        if (info->name == NULL) {
            continue;
        }
        strcpy(info->name, function_name);
        info->hash = dbj2_hash_str(function_name);
        info->address = func_addr;
        info->is_syscall = is_syscall;
        info->syscall_number = syscall_number;
        
        list->count++;
    }
    
    debug_printfln("DUMP", "Found %zu total functions (%zu syscalls, %zu regular functions)", 
                   list->count, syscall_count, list->count - syscall_count);
    return list;
}

function_info_t* find_ntdll_function(const char* function_name) {
    if (function_name == NULL) {
        return NULL;
    }
    
    init_ntdll_cache_mutex();
    
#ifdef _WIN32
    EnterCriticalSection(&ntdll_cache_mutex);
#endif
    
    if (ntdll_cache_initialized) {
        function_cache_entry_t* entry = ntdll_function_cache;
        while (entry != NULL) {
            if (strcmp(entry->name, function_name) == 0) {
                function_info_t* result = entry->info;
#ifdef _WIN32
                LeaveCriticalSection(&ntdll_cache_mutex);
#endif
                debug_printfln("DUMP", "Found cached function %s at address 0x%p", 
                               function_name, (void*)result->address);
                return result;
            }
            entry = entry->next;
        }
    }
    
    if (!ntdll_cache_initialized) {
        function_list_t* all_functions = dump_all_ntdll_functions();
        if (all_functions != NULL) {
            for (size_t i = 0; i < all_functions->count; i++) {
                function_cache_entry_t* cache_entry = malloc(sizeof(function_cache_entry_t));
                if (cache_entry == NULL) {
                    continue;
                }
                
                cache_entry->info = malloc(sizeof(function_info_t));
                if (cache_entry->info == NULL) {
                    free(cache_entry);
                    continue;
                }
                
                function_info_t* src = &all_functions->functions[i];
                function_info_t* dst = cache_entry->info;
                
                dst->name = malloc(strlen(src->name) + 1);
                if (dst->name == NULL) {
                    free(cache_entry->info);
                    free(cache_entry);
                    continue;
                }
                strcpy(dst->name, src->name);
                dst->hash = src->hash;
                dst->address = src->address;
                dst->is_syscall = src->is_syscall;
                dst->syscall_number = src->syscall_number;
                
                cache_entry->name = dst->name;
                cache_entry->next = ntdll_function_cache;
                ntdll_function_cache = cache_entry;
            }
            
            free_function_list(all_functions);
            ntdll_cache_initialized = true;
        }
    }
    
    function_cache_entry_t* entry = ntdll_function_cache;
    while (entry != NULL) {
        if (strcmp(entry->name, function_name) == 0) {
            function_info_t* result = entry->info;
#ifdef _WIN32
            LeaveCriticalSection(&ntdll_cache_mutex);
#endif
            debug_printfln("DUMP", "Found function %s at address 0x%p", 
                           function_name, (void*)result->address);
            return result;
        }
        entry = entry->next;
    }
    
#ifdef _WIN32
    LeaveCriticalSection(&ntdll_cache_mutex);
#endif
    
    debug_printfln("DUMP", "Function %s not found in ntdll", function_name);
    return NULL;
}

uintptr_t get_ntdll_function_address(const char* function_name) {
    function_info_t* func_info = find_ntdll_function(function_name);
    if (func_info == NULL) {
        return 0;
    }
    return func_info->address;
}

void free_syscall_list(syscall_list_t* list) {
    if (list == NULL) {
        return;
    }
    
    if (list->syscalls != NULL) {
        for (size_t i = 0; i < list->count; i++) {
            free(list->syscalls[i].name);
        }
        free(list->syscalls);
    }
    
    free(list);
}

void free_function_list(function_list_t* list) {
    if (list == NULL) {
        return;
    }
    
    if (list->functions != NULL) {
        for (size_t i = 0; i < list->count; i++) {
            free(list->functions[i].name);
        }
        free(list->functions);
    }
    
    free(list);
}

void cleanup_ntdll_cache(void) {
    init_ntdll_cache_mutex();
    
#ifdef _WIN32
    EnterCriticalSection(&ntdll_cache_mutex);
#endif
    
    function_cache_entry_t* entry = ntdll_function_cache;
    while (entry != NULL) {
        function_cache_entry_t* next = entry->next;
        
        if (entry->info != NULL) {
            free(entry->info->name);
            free(entry->info);
        }
        free(entry);
        
        entry = next;
    }
    
    ntdll_function_cache = NULL;
    ntdll_cache_initialized = false;
    
#ifdef _WIN32
    LeaveCriticalSection(&ntdll_cache_mutex);
    
    if (cache_mutex_init) {
        DeleteCriticalSection(&ntdll_cache_mutex);
        cache_mutex_init = false;
    }
#endif
}

bool dump_syscalls_to_file(const char* filename) {
    syscall_list_t* syscalls = dump_all_syscalls();
    if (syscalls == NULL) {
        return false;
    }
    
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        debug_printfln("DUMP", "Failed to open file %s for writing", filename);
        free_syscall_list(syscalls);
        return false;
    }
    
    fprintf(file, "# NTDLL syscall functions dump\n");
    fprintf(file, "# generated by syshash\n");
    fprintf(file, "# format: function name | hash | syscall number | address\n");
    fprintf(file, "# total syscalls found: %zu\n\n", syscalls->count);
    
    for (size_t i = 0; i < syscalls->count; i++) {
        fprintf(file, "%s | 0x%08X | %u | 0x%p\n",
                syscalls->syscalls[i].name,
                syscalls->syscalls[i].hash,
                syscalls->syscalls[i].syscall_number,
                (void*)syscalls->syscalls[i].address);
    }
    
    fclose(file);
    free_syscall_list(syscalls);
    
    return true;
}

bool dump_all_functions_to_file(const char* filename) {
    function_list_t* functions = dump_all_ntdll_functions();
    if (functions == NULL) {
        return false;
    }
    
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        debug_printfln("DUMP", "Failed to open file %s for writing", filename);
        free_function_list(functions);
        return false;
    }
    

    size_t syscall_count = 0;
    size_t regular_count = 0;
    for (size_t i = 0; i < functions->count; i++) {
        if (functions->functions[i].is_syscall) {
            syscall_count++;
        } else {
            regular_count++;
        }
    }
    
    fprintf(file, "# ntdll all functions dump\n");
    fprintf(file, "# generated by syshash\n");
    fprintf(file, "# format: function name | hash | is syscall | syscall number | address\n");
    fprintf(file, "# total functions: %zu (syscalls: %zu, regular: %zu)\n\n", 
            functions->count, syscall_count, regular_count);
    
    fprintf(file, "# === syscall functions ===\n");
    for (size_t i = 0; i < functions->count; i++) {
        if (functions->functions[i].is_syscall) {
            fprintf(file, "%s | 0x%08X | YES | %u | 0x%p\n",
                    functions->functions[i].name,
                    functions->functions[i].hash,
                    functions->functions[i].syscall_number,
                    (void*)functions->functions[i].address);
        }
    }
    
    fprintf(file, "\n# === regular functions ===\n");
    for (size_t i = 0; i < functions->count; i++) {
        if (!functions->functions[i].is_syscall) {
            fprintf(file, "%s | 0x%08X | NO | 0 | 0x%p\n",
                    functions->functions[i].name,
                    functions->functions[i].hash,
                    (void*)functions->functions[i].address);
        }
    }
    
    fclose(file);
    free_function_list(functions);
    
    return true;
}

#endif // DUMP_H 