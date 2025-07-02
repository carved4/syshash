#ifndef OBF_H
#define OBF_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif
#include "debug.c"


typedef struct hash_cache_entry {
    char* key;
    uint32_t hash;
    struct hash_cache_entry* next;
} hash_cache_entry_t;

typedef struct collision_entry {
    uint32_t hash;
    char* string;
    struct collision_entry* next;
} collision_entry_t;

static hash_cache_entry_t* hash_cache = NULL;
static collision_entry_t* collision_detector = NULL;

#ifdef _WIN32
static CRITICAL_SECTION hash_cache_mutex;
static CRITICAL_SECTION collision_mutex;
static bool mutexes_initialized = false;
#else
static pthread_mutex_t hash_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t collision_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

void obf_init(void);
void obf_cleanup(void);
uint32_t dbj2_hash(const uint8_t* buffer, size_t length);
uint32_t dbj2_hash_str(const char* s);
uint32_t fnv1a_hash(const uint8_t* buffer, size_t length);
uint32_t get_hash(const char* s);
uint32_t get_hash_with_algorithm(const char* s, const char* algorithm);
void clear_hash_cache(void);
void detect_hash_collision(uint32_t hash, const char* new_string);

void obf_init(void) {
#ifdef _WIN32
    if (!mutexes_initialized) {
        InitializeCriticalSection(&hash_cache_mutex);
        InitializeCriticalSection(&collision_mutex);
        mutexes_initialized = true;
    }
#endif
}

void obf_cleanup(void) {
    clear_hash_cache();
    
#ifdef _WIN32
    if (mutexes_initialized) {
        DeleteCriticalSection(&hash_cache_mutex);
        DeleteCriticalSection(&collision_mutex);
        mutexes_initialized = false;
    }
#endif
}

uint32_t dbj2_hash(const uint8_t* buffer, size_t length) {
    uint32_t hash = 5381;
    
    for (size_t i = 0; i < length; i++) {
        uint8_t b = buffer[i];
        if (b == 0) {
            continue;
        }
        
        if (b >= 'a') {
            b -= 0x20;
        }
        
        hash = ((hash << 5) + hash) + (uint32_t)b;
    }
    
    return hash;
}

uint32_t dbj2_hash_str(const char* s) {
    if (s == NULL) {
        return 0;
    }
    return dbj2_hash((const uint8_t*)s, strlen(s));
}

uint32_t fnv1a_hash(const uint8_t* buffer, size_t length) {
    const uint32_t fnv1a_offset = 2166136261U;
    const uint32_t fnv1a_prime = 16777619U;
    
    uint32_t hash = fnv1a_offset;
    
    for (size_t i = 0; i < length; i++) {
        uint8_t b = buffer[i];
        if (b == 0) {
            continue;
        }
        
        if (b >= 'a') {
            b -= 0x20;
        }
        
        hash ^= (uint32_t)b;
        hash *= fnv1a_prime;
    }
    
    return hash;
}

uint32_t get_hash(const char* s) {
    if (s == NULL) {
        return 0;
    }
    
    obf_init();
    
#ifdef _WIN32
    EnterCriticalSection(&hash_cache_mutex);
#else
    pthread_mutex_lock(&hash_cache_mutex);
#endif
    
    hash_cache_entry_t* entry = hash_cache;
    while (entry != NULL) {
        if (strcmp(entry->key, s) == 0) {
            uint32_t cached_hash = entry->hash;
#ifdef _WIN32
            LeaveCriticalSection(&hash_cache_mutex);
#else
            pthread_mutex_unlock(&hash_cache_mutex);
#endif
            return cached_hash;
        }
        entry = entry->next;
    }
    
#ifdef _WIN32
    LeaveCriticalSection(&hash_cache_mutex);
#else
    pthread_mutex_unlock(&hash_cache_mutex);
#endif
    
    uint32_t hash = dbj2_hash_str(s);
    
#ifdef _WIN32
    EnterCriticalSection(&hash_cache_mutex);
#else
    pthread_mutex_lock(&hash_cache_mutex);
#endif
    
    hash_cache_entry_t* new_entry = malloc(sizeof(hash_cache_entry_t));
    if (new_entry != NULL) {
        new_entry->key = malloc(strlen(s) + 1);
        if (new_entry->key != NULL) {
            strcpy(new_entry->key, s);
            new_entry->hash = hash;
            new_entry->next = hash_cache;
            hash_cache = new_entry;
        } else {
            free(new_entry);
        }
    }
    
#ifdef _WIN32
    LeaveCriticalSection(&hash_cache_mutex);
#else
    pthread_mutex_unlock(&hash_cache_mutex);
#endif
    
    detect_hash_collision(hash, s);
    
    return hash;
}

uint32_t get_hash_with_algorithm(const char* s, const char* algorithm) {
    if (s == NULL) {
        return 0;
    }
    
    if (algorithm != NULL && strcmp(algorithm, "fnv1a") == 0) {
        return fnv1a_hash((const uint8_t*)s, strlen(s));
    } else {
        return dbj2_hash_str(s);
    }
}

void detect_hash_collision(uint32_t hash, const char* new_string) {
    obf_init();
    
#ifdef _WIN32
    EnterCriticalSection(&collision_mutex);
#else
    pthread_mutex_lock(&collision_mutex);
#endif
    
    collision_entry_t* entry = collision_detector;
    while (entry != NULL) {
        if (entry->hash == hash) {
            if (strcmp(entry->string, new_string) != 0) {
                debug_printfln("OBF", "Warning: Hash collision detected!\n");
                debug_printfln("OBF", "  Hash: 0x%08X\n", hash);
                debug_printfln("OBF", "  Existing string: %s\n", entry->string);
                debug_printfln("OBF", "  New string: %s\n", new_string);
            }
#ifdef _WIN32
            LeaveCriticalSection(&collision_mutex);
#else
            pthread_mutex_unlock(&collision_mutex);
#endif
            return;
        }
        entry = entry->next;
    }
    
    collision_entry_t* new_entry = malloc(sizeof(collision_entry_t));
    if (new_entry != NULL) {
        new_entry->string = malloc(strlen(new_string) + 1);
        if (new_entry->string != NULL) {
            strcpy(new_entry->string, new_string);
            new_entry->hash = hash;
            new_entry->next = collision_detector;
            collision_detector = new_entry;
        } else {
            free(new_entry);
        }
    }
    
#ifdef _WIN32
    LeaveCriticalSection(&collision_mutex);
#else
    pthread_mutex_unlock(&collision_mutex);
#endif
}

void clear_hash_cache(void) {
    obf_init();
    
#ifdef _WIN32
    EnterCriticalSection(&hash_cache_mutex);
#else
    pthread_mutex_lock(&hash_cache_mutex);
#endif
    
    hash_cache_entry_t* entry = hash_cache;
    while (entry != NULL) {
        hash_cache_entry_t* next = entry->next;
        free(entry->key);
        free(entry);
        entry = next;
    }
    hash_cache = NULL;
    
#ifdef _WIN32
    LeaveCriticalSection(&hash_cache_mutex);
#else
    pthread_mutex_unlock(&hash_cache_mutex);
#endif
    
#ifdef _WIN32
    EnterCriticalSection(&collision_mutex);
#else
    pthread_mutex_lock(&collision_mutex);
#endif
    
    collision_entry_t* col_entry = collision_detector;
    while (col_entry != NULL) {
        collision_entry_t* next = col_entry->next;
        free(col_entry->string);
        free(col_entry);
        col_entry = next;
    }
    collision_detector = NULL;
    
#ifdef _WIN32
    LeaveCriticalSection(&collision_mutex);
#else
    pthread_mutex_unlock(&collision_mutex);
#endif
}

#endif // OBF_H 