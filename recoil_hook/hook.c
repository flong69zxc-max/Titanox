#include "hook.h"

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define HOOK_VA_LIMIT 0x0000FFFFFFFFFFFFULL


static char g_last_error[256];


static uintptr_t strip_fn(const void *p)
{
#if __has_feature(ptrauth_calls)
    uintptr_t raw = (uintptr_t)ptrauth_strip(p, ptrauth_key_function_pointer);
#else
    uintptr_t raw = (uintptr_t)p;
#endif
    return raw & HOOK_VA_LIMIT;
}

static bool hook_region_info(uintptr_t address, vm_prot_t *prot, uintptr_t *start, uintptr_t *end)
{
    if (!address) return false;

    vm_address_t region = (vm_address_t)address;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(
        mach_task_self(),
        &region,
        &size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&info,
        &count,
        &object
    );

    if (object != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object);
    }

    if (kr != KERN_SUCCESS || size == 0) return false;

    if (prot) *prot = info.protection;
    if (start) *start = (uintptr_t)region;
    if (end) *end = (uintptr_t)region + (uintptr_t)size;

    return true;
}

static bool hook_region_maxprot(uintptr_t address, vm_prot_t *outMax)
{
    if (!address) return false;

    vm_address_t region = (vm_address_t)address;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(
        mach_task_self(),
        &region,
        &size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&info,
        &count,
        &object
    );

    if (object != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object);
    }

    if (kr != KERN_SUCCESS || size == 0) return false;

    if (outMax) *outMax = info.max_protection;
    return true;
}

void hook_set_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(g_last_error, sizeof(g_last_error), format, args);
    va_end(args);
}

const char *hook_last_error(void)
{
    return g_last_error;
}

static bool hook_read_bytes(uintptr_t address, void *buffer, size_t length)
{
    if (!address || !buffer || !length) return false;

    vm_size_t got = 0;

    kern_return_t kr = vm_read_overwrite(
        mach_task_self(),
        (vm_address_t)address,
        (vm_size_t)length,
        (vm_address_t)buffer,
        &got
    );

    if (kr != KERN_SUCCESS) return false;

    return got == (vm_size_t)length;
}

static bool hook_page_set(uintptr_t address, size_t length, vm_prot_t requested, bool setMaximum, vm_prot_t *previous)
{
    if (!address || !length) return false;

    vm_prot_t prot = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;

    if (!hook_region_info(address, &prot, &start, &end)) return false;
    if ((address + length) > end) return false;

    if (previous) *previous = prot;

    uintptr_t pageStart = address & ~(uintptr_t)0xFFF;
    uintptr_t pageEnd = (address + length + 0xFFF) & ~(uintptr_t)0xFFF;

    if (pageStart < start) pageStart = start;
    if (pageEnd > end) pageEnd = end;
    if (pageEnd <= pageStart) return false;

    kern_return_t kr = vm_protect(
        mach_task_self(),
        (vm_address_t)pageStart,
        (vm_size_t)(pageEnd - pageStart),
        setMaximum ? TRUE : FALSE,
        requested
    );


    return kr == KERN_SUCCESS;
}



#define HOOK_PTR_ENTRIES 64
#define HOOK_PTR_SLOTS 1024

typedef struct {
    uintptr_t target;
    uintptr_t replacement;
    uintptr_t slots[HOOK_PTR_SLOTS];
    int count;
    bool used;
} hook_ptr_entry_t;

static hook_ptr_entry_t g_ptr_hooks[HOOK_PTR_ENTRIES];

static hook_ptr_entry_t *hook_pointer_find(uintptr_t target);

static uintptr_t hook_image_base_for(uintptr_t address)
{
    uint32_t count = _dyld_image_count();
    if (count > 8192) count = 8192;

    for (uint32_t i = 0; i < count; i++) {
        uintptr_t base = (uintptr_t)_dyld_get_image_header(i);
        if (!base || address < base) continue;

        const struct mach_header_64 *header = (const struct mach_header_64 *)base;

        if (header->magic != MH_MAGIC_64) continue;
        if (header->ncmds == 0 || header->ncmds > 4096) continue;
        if (header->sizeofcmds == 0 || header->sizeofcmds > (4u * 1024u * 1024u)) continue;

        const uint8_t *cursor = (const uint8_t *)(header + 1);
        const uint8_t *limit = cursor + header->sizeofcmds;
        uintptr_t textVmaddr = 0;
        bool haveText = false;

        for (uint32_t c = 0; c < header->ncmds; c++) {
            if (cursor + sizeof(struct load_command) > limit) break;

            const struct load_command *cmd = (const struct load_command *)cursor;

            if (cmd->cmdsize < sizeof(struct load_command)) break;
            if (cursor + cmd->cmdsize > limit) break;

            if (cmd->cmd == LC_SEGMENT_64 && cmd->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
                if (strcmp(seg->segname, "__TEXT") == 0) {
                    textVmaddr = (uintptr_t)seg->vmaddr;
                    haveText = true;
                    break;
                }
            }

            cursor += cmd->cmdsize;
        }

        if (!haveText) continue;

        uintptr_t slide = base - textVmaddr;

        cursor = (const uint8_t *)(header + 1);

        for (uint32_t c = 0; c < header->ncmds; c++) {
            if (cursor + sizeof(struct load_command) > limit) break;

            const struct load_command *cmd = (const struct load_command *)cursor;

            if (cmd->cmdsize < sizeof(struct load_command)) break;
            if (cursor + cmd->cmdsize > limit) break;

            if (cmd->cmd == LC_SEGMENT_64 && cmd->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
                uintptr_t start = (uintptr_t)seg->vmaddr + slide;
                uintptr_t end = start + (uintptr_t)seg->vmsize;

                if (address >= start && address < end) return base;
            }

            cursor += cmd->cmdsize;
        }
    }

    return 0;
}

static bool hook_write_u64(uintptr_t address, uintptr_t value)
{
    vm_prot_t prot = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;

    if (!hook_region_info(address, &prot, &start, &end)) return false;
    if ((address + 8) > end) return false;

    if (prot & VM_PROT_EXECUTE) {
        hook_set_error("data write: refusing executable page at %p", (void *)start);
        return false;
    }

    bool restore = false;
    vm_prot_t savedProt = prot;

    if ((prot & VM_PROT_WRITE) == 0) {
        vm_prot_t maxProt = 0;

        if (!hook_region_maxprot(address, &maxProt)) return false;

        if ((maxProt & VM_PROT_WRITE) == 0) {
            hook_set_error("data write: maxprot at %p has no WRITE", (void *)address);
            return false;
        }

        if (!hook_page_set(address, 8, (vm_prot_t)(maxProt | VM_PROT_READ | VM_PROT_WRITE), TRUE, NULL)) {
            hook_set_error("data write: cannot raise maxprot at %p", (void *)address);
            return false;
        }

        if (!hook_page_set(address, 8, (vm_prot_t)(prot | VM_PROT_READ | VM_PROT_WRITE), FALSE, NULL)) {
            hook_set_error("data write: page %p stays read-only", (void *)address);
            return false;
        }

        restore = true;
    }

    memcpy((void *)address, &value, 8);

    if (restore) {
        hook_page_set(address, 8, savedProt, FALSE, NULL);
    }

    uintptr_t check = 0;

    if (!hook_read_bytes(address, &check, 8)) return false;

    return check == value;
}

static uint64_t g_scan_offsets = 0;
static bool g_seg_layout_logged = false;

typedef struct {
    int mode;
    int key;
    unsigned div;
} hook_slot_fix_t;

static int hook_slot_classify(uintptr_t value, uintptr_t needle, uintptr_t imageBase,
                              uintptr_t slot, hook_slot_fix_t *out)
{
    if (out) {
        out->mode = 0;
        out->key = 0;
        out->div = 0;
    }

    if (!needle) return 0;

    if (value == needle) {
        if (out) out->mode = 1;
        return 1;
    }

    if ((value & HOOK_VA_LIMIT) == needle) {
#if __has_feature(ptrauth_calls)
        unsigned divs[2];
        divs[0] = (unsigned)(slot & 0xFFFFu);
        divs[1] = 0;

        for (int d = 0; d < 2; d++) {
            for (int k = 0; k < 4; k++) {
                void *signedProbe = ptrauth_sign_unauthenticated(
                    (void *)needle, (ptrauth_key)k, (ptrauth_extra_data_t)divs[d]);

                if ((uintptr_t)signedProbe != value) continue;

                if (out) {
                    out->mode = 2;
                    out->key = k;
                    out->div = divs[d];
                }

                return 2;
            }
        }
#else
        (void)slot;
#endif

        return 0;
    }

    if (imageBase && needle > imageBase) {
        uintptr_t offset = needle - imageBase;

        if ((value >> 43) == 0 && (value & 0x7FFFFFFFFFFULL) == offset) {
            if (out) out->mode = 3;
            return 3;
        }
    }

    return 0;
}

static uintptr_t hook_slot_encode(uintptr_t replacement, const hook_slot_fix_t *fix)
{
    if (!fix || fix->mode != 2) return replacement;

#if __has_feature(ptrauth_calls)
    return (uintptr_t)ptrauth_sign_unauthenticated(
        (void *)replacement, (ptrauth_key)fix->key, (ptrauth_extra_data_t)fix->div);
#else
    return replacement;
#endif
}

static int hook_scan_tables_value(uintptr_t imageBase, uintptr_t needle, uintptr_t replacement,
                                  uintptr_t *slots, int capacity, bool dryRun)
{
    if (!imageBase || !needle || !slots || capacity <= 0) return 0;

    g_scan_offsets = 0;

    const struct mach_header_64 *header = (const struct mach_header_64 *)imageBase;

    if (header->magic != MH_MAGIC_64) return 0;
    if (header->ncmds == 0 || header->ncmds > 4096) return 0;
    if (header->sizeofcmds == 0 || header->sizeofcmds > (4u * 1024u * 1024u)) return 0;

    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *limit = cursor + header->sizeofcmds;
    uintptr_t textVmaddr = 0;
    bool haveText = false;
    int segments = 0;

    for (uint32_t c = 0; c < header->ncmds; c++) {
        if (cursor + sizeof(struct load_command) > limit) break;

        const struct load_command *cmd = (const struct load_command *)cursor;

        if (cmd->cmdsize < sizeof(struct load_command)) break;
        if (cursor + cmd->cmdsize > limit) break;

        if (cmd->cmd == LC_SEGMENT_64 && cmd->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                textVmaddr = (uintptr_t)seg->vmaddr;
                haveText = true;
                break;
            }
        }

        cursor += cmd->cmdsize;
    }

    if (!haveText) return 0;

    uintptr_t slide = imageBase - textVmaddr;
    uint8_t buffer[4096];
    int hits = 0;

    cursor = (const uint8_t *)(header + 1);

    for (uint32_t c = 0; c < header->ncmds; c++) {
        if (cursor + sizeof(struct load_command) > limit) break;

        const struct load_command *cmd = (const struct load_command *)cursor;

        if (cmd->cmdsize < sizeof(struct load_command)) break;
        if (cursor + cmd->cmdsize > limit) break;

        if (cmd->cmd != LC_SEGMENT_64 || cmd->cmdsize < sizeof(struct segment_command_64)) {
            cursor += cmd->cmdsize;
            continue;
        }

        const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;

        if (seg->initprot & VM_PROT_EXECUTE) { cursor += cmd->cmdsize; continue; }
        if (((seg->initprot | seg->maxprot) & VM_PROT_WRITE) == 0) { cursor += cmd->cmdsize; continue; }

        uintptr_t start = (uintptr_t)seg->vmaddr + slide;
        uintptr_t end = start + (uintptr_t)seg->vmsize;

        if (!g_seg_layout_logged && segments < 24) {
        }

        segments++;

        for (uintptr_t p = start; (p + 8) <= end; ) {
            size_t want = sizeof(buffer);
            if ((p + want) > end) want = (size_t)(end - p);
            if (want < 8) break;

            if (!hook_read_bytes(p, buffer, want)) { p += 0x1000; continue; }


            for (size_t i = 0; (i + 8) <= want; i += 8) {
                uintptr_t value = 0;
                memcpy(&value, buffer + i, 8);


                uintptr_t slot = p + i;
                hook_slot_fix_t fix;

                int mode = hook_slot_classify(value, needle, imageBase, slot, &fix);

                if (mode == 0) continue;

                if (mode == 3) {
                    g_scan_offsets++;
                    continue;
                }


                if (hits >= capacity) {

                    continue;
                }

                if (dryRun) {
                    slots[hits] = slot;
                    hits++;

                    continue;
                }

                uintptr_t writeValue = hook_slot_encode(replacement, &fix);
                uintptr_t readBack = 0;

                if (!hook_write_u64(slot, writeValue)) continue;

                if (!hook_read_bytes(slot, &readBack, sizeof(readBack)) || readBack != writeValue) {

                    hook_set_error("pointer slot %p did not take: wrote %p read %p",
                                   (void *)slot, (void *)writeValue, (void *)readBack);

                    continue;
                }

                slots[hits] = slot;
                hits++;

            }

            p += want;

            if (want == 0) break;
        }

        cursor += cmd->cmdsize;
    }

    g_seg_layout_logged = true;

    return hits;
}

static int hook_pointer_install(uintptr_t target, uintptr_t replacement)
{
    hook_ptr_entry_t *entry = hook_pointer_find(target);

    if (!entry) {
        for (int i = 0; i < HOOK_PTR_ENTRIES; i++) {
            if (!g_ptr_hooks[i].used) {
                memset(&g_ptr_hooks[i], 0, sizeof(hook_ptr_entry_t));
                g_ptr_hooks[i].used = true;
                g_ptr_hooks[i].target = target;
                entry = &g_ptr_hooks[i];
                break;
            }
        }
    }

    if (!entry) {
        hook_set_error("pointer hook table exhausted (%d)", HOOK_PTR_ENTRIES);
        return 0;
    }

    uintptr_t imageBase = hook_image_base_for(target);

    if (!imageBase) {
        hook_set_error("pointer hook: no image owns %p", (void *)target);
        return 0;
    }

    uintptr_t slots[HOOK_PTR_SLOTS];

    int hits = hook_scan_tables_value(imageBase, target, replacement, slots, HOOK_PTR_SLOTS, false);

    uint64_t offsets = g_scan_offsets;


    if (hits <= 0) {
        if (offsets > 0) {
            hook_set_error("pointer hook: %p not stored as VA, %llu unslid-offset slot(s) found",
                           (void *)target, (unsigned long long)offsets);
        } else {
            hook_set_error("pointer hook: no writable slot references %p", (void *)target);
        }

        return 0;
    }

    for (int i = 0; i < hits && entry->count < HOOK_PTR_SLOTS; i++) {
        entry->slots[entry->count] = slots[i];
        entry->count++;
    }

    entry->replacement = replacement;

    return hits;
}

static hook_ptr_entry_t *hook_pointer_find(uintptr_t target)
{
    for (int i = 0; i < HOOK_PTR_ENTRIES; i++) {
        if (g_ptr_hooks[i].used && g_ptr_hooks[i].target == target) return &g_ptr_hooks[i];
    }

    return NULL;
}

int hook_probe(uintptr_t target)
{
    if (!target) return -1;

    uintptr_t imageBase = hook_image_base_for(target);

    if (!imageBase) return -1;

    uintptr_t slots[HOOK_PTR_SLOTS];

    int hits = hook_scan_tables_value(imageBase, target, 0, slots, HOOK_PTR_SLOTS, true);


    return hits;
}


bool brk_install(void *target, void *replacement)
{
    if (!target || !replacement) {
        hook_set_error("install: null argument target=%p replacement=%p", target, replacement);
        return false;
    }

    uintptr_t addr = strip_fn(target);
    uintptr_t repl = strip_fn(replacement);

    return hook_pointer_install(addr, repl) > 0;
}

bool brk_remove(void *target)
{
    if (!target) return false;

    uintptr_t addr = strip_fn(target);
    hook_ptr_entry_t *ptrEntry = hook_pointer_find(addr);

    if (!ptrEntry) return false;

    bool restored = true;

    for (int x = 0; x < ptrEntry->count; x++) {
        if (!hook_write_u64(ptrEntry->slots[x], ptrEntry->target)) restored = false;
    }

    memset(ptrEntry, 0, sizeof(hook_ptr_entry_t));

    return restored;
}

void *brk_original_ptr(void *target)
{
    if (!target) return NULL;

    uintptr_t addr = strip_fn(target);

    return (void *)addr;
}


