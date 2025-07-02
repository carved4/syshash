#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>

static bool debug_enabled = false;
static bool debug_initialized = false;

void debug_init(void);
void debug_set_mode(bool enabled);
bool debug_is_enabled(void);
void debug_printf(const char* format, ...);
void debug_println(const char* message);
void debug_printfln(const char* prefix, const char* format, ...);

void debug_init(void) {
    if (debug_initialized) {
        return;
    }
    
    const char* debug_vars[] = {
        "WINAPI_DEBUG",
        "SYSCALLRESOLVE_DEBUG", 
        "SYSCALL_DEBUG",
        "DEBUG",
        NULL
    };
    
    for (int i = 0; debug_vars[i] != NULL; i++) {
        const char* debug_value = getenv(debug_vars[i]);
        if (debug_value != NULL) {
            if (strcmp(debug_value, "true") == 0 || strcmp(debug_value, "1") == 0 || 
                strcmp(debug_value, "TRUE") == 0) {
                debug_enabled = true;
                break;
            }
        }
    }
    
    debug_initialized = true;
}

void debug_set_mode(bool enabled) {
    if (!debug_initialized) {
        debug_init();
    }
    debug_enabled = enabled;
}

bool debug_is_enabled(void) {
    if (!debug_initialized) {
        debug_init();
    }
    return debug_enabled;
}

void debug_printf(const char* format, ...) {
    if (!debug_is_enabled()) {
        return;
    }
    
    printf("[DEBUG] ");
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void debug_println(const char* message) {
    if (!debug_is_enabled()) {
        return;
    }
    
    printf("[DEBUG] %s\n", message);
}

void debug_printfln(const char* prefix, const char* format, ...) {
    if (!debug_is_enabled()) {
        return;
    }
    
    printf("[DEBUG %s] ", prefix);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

#endif // DEBUG_H 