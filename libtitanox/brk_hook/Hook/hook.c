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

#define HOOK_MAX 64
#define HOOK_PATCH_SIZE 16
#define HOOK_TRAMP_SIZE 256
#define HOOK_TRAMP_NEED 48
#define HOOK_SCAN_DRY_LOGS 8
#define HOOK_SCAN_DETAIL_LOGS 32
#define HOOK_NEAR_RANGE (900LL * 1024LL)
#define HOOK_BRANCH_RANGE (120LL * 1024LL * 1024LL)
#define HOOK_VA_LIMIT 0x0000FFFFFFFFFFFFULL

#define HOOK_OP_LDR_X16_8 0x58000050u
#define HOOK_OP_BR_X16 0xD61F0200u
#define HOOK_OP_BLR_X16 0xD63F0200u
#define HOOK_OP_NOP 0xD503201Fu

typedef struct {
    uintptr_t target;
    uintptr_t tramp;
    uintptr_t replacement;
    uint8_t saved[HOOK_PATCH_SIZE];
    uint8_t patch[HOOK_PATCH_SIZE];
    uint64_t hits;
    uint32_t block_bytes;
    bool used;
    bool armed;
    bool near;
    bool from_cave;
} hook_entry_t;

static hook_entry_t g_hooks[HOOK_MAX];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static int g_scan_dry_logged = 0;
static int g_scan_detail_logs = 0;
static const char *g_scan_dry_label = NULL;
static uint64_t g_slot_verify_fails = 0;
static uint64_t g_slot_truncated = 0;
static uint64_t g_ptr_target_cap_hits = 0;
static uint64_t g_total_hits = 0;
static uint64_t g_fail_count = 0;
static kern_return_t g_last_kr = 0;
static bool g_exec_restore_broken = false;
static uint64_t g_install_count = 0;
static bool g_ready = false;
static char g_last_error[256];

static volatile int g_probe_value = 0;

static uintptr_t strip_fn(const void *p)
{
#if __has_feature(ptrauth_calls)
    uintptr_t raw = (uintptr_t)ptrauth_strip(p, ptrauth_key_function_pointer);
#else
    uintptr_t raw = (uintptr_t)p;
#endif
    return raw & HOOK_VA_LIMIT;
}

static void *sign_fn(uintptr_t p)
{
#if __has_feature(ptrauth_calls)
    return ptrauth_sign_unauthenticated((void *)p, ptrauth_key_function_pointer, 0);
#else
    return (void *)p;
#endif
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

bool hook_sign_check(uintptr_t address)
{
    if (!address) return false;

    uintptr_t raw = strip_fn((const void *)address);
    if ((raw & 3) != 0) return false;

    vm_prot_t prot = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;

    if (!hook_region_info(raw, &prot, &start, &end)) return false;
    if (raw < start || raw >= end) return false;

    return (prot & VM_PROT_EXECUTE) ? true : false;
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

static bool hook_image_encryption_state(const struct mach_header_64 *header, uint32_t *outCryptid)
{
    if (!header) return false;
    if (header->magic != MH_MAGIC_64) return false;
    if (header->ncmds == 0 || header->ncmds > 4096) return false;
    if (header->sizeofcmds == 0 || header->sizeofcmds > (4u * 1024u * 1024u)) return false;

    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *limit = cursor + header->sizeofcmds;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > limit) return false;

        const struct load_command *command = (const struct load_command *)cursor;

        if (command->cmdsize < sizeof(struct load_command)) return false;
        if (cursor + command->cmdsize > limit) return false;

        if (command->cmd == LC_ENCRYPTION_INFO_64) {
            if (command->cmdsize < sizeof(struct encryption_info_command_64)) return false;

            const struct encryption_info_command_64 *info =
                (const struct encryption_info_command_64 *)command;

            if (outCryptid) *outCryptid = info->cryptid;
            return true;
        }

        cursor += command->cmdsize;
    }

    return false;
}

bool hook_verify_encryption(void *image)
{
    if (!image) {
        hook_set_error("encryption check: null image");
        return false;
    }

    uint32_t cryptid = 0;
    bool found = hook_image_encryption_state((const struct mach_header_64 *)image, &cryptid);

    if (!found) {
        return true;
    }

    if (cryptid != 0) {
        hook_set_error("encryption check: cryptid=%u, aborting before hook install", cryptid);
        abort();
    }

    return true;
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

    g_last_kr = kr;

    return kr == KERN_SUCCESS;
}

bool hook_code_patch_allowed(void);

static bool hook_page_writable(uintptr_t address, size_t length, vm_prot_t *saved)
{
    vm_prot_t prot = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;

    if (!hook_region_info(address, &prot, &start, &end)) return false;
    if ((address + length) > end) return false;

    if ((prot & VM_PROT_EXECUTE) && !hook_code_patch_allowed()) {
        hook_set_error("write: refusing executable page at %p (code patching disabled)", (void *)start);
        g_fail_count++;
        return false;
    }

    if (saved) *saved = prot;

    vm_prot_t maxProt = 0;

    if (!hook_region_maxprot(address, &maxProt)) {
        hook_set_error("write: cannot read maxprot at %p", (void *)start);
        return false;
    }

    if ((maxProt & VM_PROT_WRITE) == 0) {
        hook_set_error("write: refusing %p, maxprot=%c%c%c has no WRITE",
                       (void *)start,
                       (maxProt & VM_PROT_READ) ? 'r' : '-',
                       (maxProt & VM_PROT_WRITE) ? 'w' : '-',
                       (maxProt & VM_PROT_EXECUTE) ? 'x' : '-');
        g_fail_count++;
        return false;
    }

    if (prot & VM_PROT_WRITE) return true;


    if ((maxProt & (VM_PROT_READ | VM_PROT_WRITE)) != (VM_PROT_READ | VM_PROT_WRITE) ||
        (maxProt & VM_PROT_EXECUTE) != (prot & VM_PROT_EXECUTE)) {
        vm_prot_t raised = (vm_prot_t)(maxProt | VM_PROT_READ | VM_PROT_WRITE |
                                       (prot & VM_PROT_EXECUTE));

        if (!hook_page_set(address, length, raised, TRUE, NULL)) {
            hook_set_error("write: cannot raise maxprot at %p", (void *)start);
            g_fail_count++;
            return false;
        }

    }

    uintptr_t pageStart = address & ~(uintptr_t)0xFFF;
    uintptr_t pageEnd = (address + length + 0xFFF) & ~(uintptr_t)0xFFF;

    if (pageStart < start) pageStart = start;
    if (pageEnd > end) pageEnd = end;

    kern_return_t kr = vm_protect(
        mach_task_self(),
        (vm_address_t)pageStart,
        (vm_size_t)(pageEnd - pageStart),
        FALSE,
        (vm_prot_t)(VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE)
    );

    if (kr == KERN_SUCCESS) return true;


    kr = vm_protect(
        mach_task_self(),
        (vm_address_t)pageStart,
        (vm_size_t)(pageEnd - pageStart),
        FALSE,
        (vm_prot_t)(VM_PROT_READ | VM_PROT_WRITE)
    );

    if (kr != KERN_SUCCESS) {
        hook_set_error("write: rw transition failed at %p kr=%d", (void *)start, kr);
        g_fail_count++;
    }

    return kr == KERN_SUCCESS;
}

static bool hook_page_restore(uintptr_t address, size_t length, vm_prot_t saved)
{
    vm_prot_t target = (vm_prot_t)(saved & ~VM_PROT_WRITE);
    vm_prot_t maxProt = 0;

    if (hook_page_set(address, length, target, FALSE, NULL)) return true;


    if (hook_page_set(address, length, (vm_prot_t)(target | VM_PROT_COPY), FALSE, NULL)) {
        return true;
    }


    hook_region_maxprot(address, &maxProt);


    if (hook_page_set(address, length,
                      (vm_prot_t)(maxProt | VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE),
                      TRUE, NULL) &&
        hook_page_set(address, length, target, FALSE, NULL)) {
        return true;
    }


    hook_set_error("restore: failed at %p kr=%d", (void *)address, (int)g_last_kr);

    return false;
}

static bool hook_page_executable(uintptr_t address, size_t length)
{
    vm_prot_t prot = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;

    if (!hook_region_info(address, &prot, &start, &end)) return false;
    if ((address + length) > end) return false;

    return (prot & VM_PROT_EXECUTE) ? true : false;
}

static bool hook_make_executable(uintptr_t address, size_t length)
{
    if (!address || !length) return false;

    vm_prot_t prot = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;

    if (!hook_region_info(address, &prot, &start, &end)) return false;
    if ((address + length) > end) return false;

    if ((prot & VM_PROT_EXECUTE) == 0) {
        vm_prot_t maxProt = 0;

        if (!hook_region_maxprot(address, &maxProt)) maxProt = prot;

        hook_page_set(start, 1, (vm_prot_t)(maxProt | VM_PROT_READ | VM_PROT_EXECUTE), TRUE, NULL);

        kern_return_t kr = vm_protect(
            mach_task_self(),
            (vm_address_t)start,
            (vm_size_t)(end - start),
            FALSE,
            (vm_prot_t)(VM_PROT_READ | VM_PROT_EXECUTE)
        );

        if (kr != KERN_SUCCESS) {
            hook_set_error("exec: vm_protect RX failed at %p kr=%d errno=%d", (void *)start, kr, errno);
            return false;
        }
    }

    sys_icache_invalidate((void *)address, length);

    vm_prot_t after = 0;
    uintptr_t start2 = 0;
    uintptr_t end2 = 0;

    if (!hook_region_info(address, &after, &start2, &end2)) return false;

    if ((after & VM_PROT_EXECUTE) == 0) {
        hook_set_error("exec: %p still lacks EXECUTE (prot=%d)", (void *)start, (int)after);
        return false;
    }

    if (after & VM_PROT_WRITE) {
    }

    return true;
}

static bool hook_write_bytes(uintptr_t address, const void *data, size_t length)
{
    if (!address || !data || !length) return false;

    vm_prot_t saved = 0;

    if (!hook_page_writable(address, length, &saved)) {
        hook_set_error("write: page not writable at %p len=%zu", (void *)address, length);
        return false;
    }

    memcpy((void *)address, data, length);

    hook_page_restore(address, length, saved);

    sys_icache_invalidate((void *)address, length);

    if ((saved & VM_PROT_EXECUTE) && !hook_page_executable(address, length)) {
        g_exec_restore_broken = true;

        hook_set_error("write: %p lost EXECUTE after restore", (void *)address);
        return false;
    }

    uint8_t verify[HOOK_PATCH_SIZE];

    if (length <= sizeof(verify)) {
        if (!hook_read_bytes(address, verify, length)) {
            hook_set_error("write: readback failed at %p", (void *)address);
            return false;
        }

        if (memcmp(verify, data, length) != 0) {
            hook_set_error("write: readback mismatch at %p", (void *)address);
            return false;
        }
    }

    return true;
}

static int64_t hook_sign_extend(uint64_t value, int bits)
{
    uint64_t shift = (uint64_t)(64 - bits);
    int64_t shifted = (int64_t)(value << shift);
    return shifted >> shift;
}

static void hook_put32(uint8_t *out, int offset, uint32_t word)
{
    memcpy(out + offset, &word, 4);
}

static int hook_emit_movabs(uint8_t *out, uint32_t rd, uint64_t value)
{
    hook_put32(out, 0, 0xD2800000u | ((uint32_t)(value & 0xFFFFu) << 5) | rd);
    hook_put32(out, 4, 0xF2800000u | (1u << 21) | ((uint32_t)((value >> 16) & 0xFFFFu) << 5) | rd);
    hook_put32(out, 8, 0xF2800000u | (2u << 21) | ((uint32_t)((value >> 32) & 0xFFFFu) << 5) | rd);
    hook_put32(out, 12, 0xF2800000u | (3u << 21) | ((uint32_t)((value >> 48) & 0xFFFFu) << 5) | rd);
    return 16;
}

static int hook_emit_abs_jump(uint8_t *out, uintptr_t target, bool link)
{
    hook_put32(out, 0, HOOK_OP_LDR_X16_8);
    hook_put32(out, 4, link ? HOOK_OP_BLR_X16 : HOOK_OP_BR_X16);
    hook_put32(out, 8, (uint32_t)(target & 0xFFFFFFFFu));
    hook_put32(out, 12, (uint32_t)((target >> 32) & 0xFFFFFFFFu));
    return 16;
}

static uint32_t hook_invert_condition(uint32_t insn)
{
    if ((insn & 0xFF000010u) == 0x54000000u) return insn ^ 1u;
    if ((insn & 0x7E000000u) == 0x34000000u) return insn ^ 0x01000000u;
    if ((insn & 0x7E000000u) == 0x36000000u) return insn ^ 0x01000000u;
    return insn;
}

static int hook_emit_abs_cond(uint8_t *out, uint32_t insn, uintptr_t target)
{
    uint32_t inverted = hook_invert_condition(insn);

    if ((insn & 0x7E000000u) == 0x36000000u) {
        inverted = (inverted & 0xFFF8001Fu) | (5u << 5);
    } else {
        inverted = (inverted & 0xFF00001Fu) | (5u << 5);
    }

    hook_put32(out, 0, inverted);
    hook_emit_abs_jump(out + 4, target, false);
    hook_put32(out, 20, HOOK_OP_NOP);

    return 24;
}

static int hook_emit_abs_literal_load(uint8_t *out, uint32_t insn, uintptr_t target)
{
    uint32_t opc = (insn >> 30) & 3u;
    uint32_t rt = insn & 0x1Fu;

    hook_put32(out, 0, 0x18000000u | (opc << 30) | (2u << 5) | rt);
    hook_put32(out, 4, 0x14000000u | 4u);
    hook_put32(out, 8, (uint32_t)(target & 0xFFFFFFFFu));
    hook_put32(out, 12, (uint32_t)((target >> 32) & 0xFFFFFFFFu));

    return 16;
}

static bool hook_reloc_adrp(uint32_t insn, uintptr_t src, uintptr_t dst, uint32_t *out)
{
    int64_t immlo = (int64_t)((insn >> 29) & 3u);
    int64_t immhi = (int64_t)((insn >> 5) & 0x7FFFFu);
    int64_t imm = hook_sign_extend((uint64_t)((immhi << 2) | immlo), 21);

    int64_t srcPage = (int64_t)(src & ~0xFFFULL);
    int64_t dstPage = (int64_t)(dst & ~0xFFFULL);
    int64_t delta = (srcPage + (imm << 12)) - dstPage;

    if ((delta & 0xFFF) != 0) return false;

    int64_t pages = delta >> 12;
    if (pages < -(1LL << 20) || pages >= (1LL << 20)) return false;

    uint32_t lo = (uint32_t)(pages & 3);
    uint32_t hi = (uint32_t)((pages >> 2) & 0x7FFFF);

    *out = (insn & 0x9F00001Fu) | (lo << 29) | (hi << 5);
    return true;
}

static bool hook_reloc_adr(uint32_t insn, uintptr_t src, uintptr_t dst, uint32_t *out)
{
    int64_t immlo = (int64_t)((insn >> 29) & 3u);
    int64_t immhi = (int64_t)((insn >> 5) & 0x7FFFFu);
    int64_t imm = hook_sign_extend((uint64_t)((immhi << 2) | immlo), 21);

    int64_t delta = ((int64_t)src + imm) - (int64_t)dst;

    if (delta < -(1LL << 20) || delta >= (1LL << 20)) return false;

    uint32_t lo = (uint32_t)(delta & 3);
    uint32_t hi = (uint32_t)((delta >> 2) & 0x7FFFF);

    *out = (insn & 0x9F00001Fu) | (lo << 29) | (hi << 5);
    return true;
}

static bool hook_reloc_branch26(uint32_t insn, uintptr_t src, uintptr_t dst, uint32_t *out)
{
    int64_t imm = hook_sign_extend(insn & 0x03FFFFFFu, 26);
    int64_t delta = ((int64_t)src + (imm << 2)) - (int64_t)dst;

    if ((delta & 3) != 0) return false;
    if (delta < -HOOK_BRANCH_RANGE || delta > HOOK_BRANCH_RANGE) return false;

    int64_t words = delta >> 2;
    if (words < -(1LL << 25) || words >= (1LL << 25)) return false;

    *out = (insn & 0xFC000000u) | (uint32_t)(words & 0x03FFFFFFu);
    return true;
}

static bool hook_reloc_branch19(uint32_t insn, uintptr_t src, uintptr_t dst, uint32_t *out)
{
    int64_t imm = hook_sign_extend((insn >> 5) & 0x7FFFFu, 19);
    int64_t delta = ((int64_t)src + (imm << 2)) - (int64_t)dst;

    if ((delta & 3) != 0) return false;
    if (delta < -(1LL << 20) || delta >= (1LL << 20)) return false;

    int64_t words = delta >> 2;
    *out = (insn & 0xFF00001Fu) | ((uint32_t)(words & 0x7FFFFu) << 5);
    return true;
}

static bool hook_reloc_branch14(uint32_t insn, uintptr_t src, uintptr_t dst, uint32_t *out)
{
    int64_t imm = hook_sign_extend((insn >> 5) & 0x3FFFu, 14);
    int64_t delta = ((int64_t)src + (imm << 2)) - (int64_t)dst;

    if ((delta & 3) != 0) return false;
    if (delta < -(1LL << 15) || delta >= (1LL << 15)) return false;

    int64_t words = delta >> 2;
    *out = (insn & 0xFFF8001Fu) | ((uint32_t)(words & 0x3FFFu) << 5);
    return true;
}

static int hook_emit_one(uint32_t insn, uintptr_t src, uintptr_t dst, uint8_t *out)
{
    uint32_t word = insn;
    int64_t imm19 = 0;
    int64_t imm14 = 0;
    int64_t imm26 = 0;

    if ((insn & 0x9F000000u) == 0x90000000u) {
        if (hook_reloc_adrp(insn, src, dst, &word)) {
            hook_put32(out, 0, word);
            hook_put32(out, 4, HOOK_OP_NOP);
            return 8;
        }

        int64_t immlo = (int64_t)((insn >> 29) & 3u);
        int64_t immhi = (int64_t)((insn >> 5) & 0x7FFFFu);
        int64_t imm = hook_sign_extend((uint64_t)((immhi << 2) | immlo), 21);
        uint64_t page = (uint64_t)((int64_t)(src & ~0xFFFULL) + (imm << 12));

        return hook_emit_movabs(out, (uint32_t)(insn & 0x1Fu), page);
    }

    if ((insn & 0x9F000000u) == 0x10000000u) {
        if (hook_reloc_adr(insn, src, dst, &word)) {
            hook_put32(out, 0, word);
            hook_put32(out, 4, HOOK_OP_NOP);
            return 8;
        }

        int64_t immlo = (int64_t)((insn >> 29) & 3u);
        int64_t immhi = (int64_t)((insn >> 5) & 0x7FFFFu);
        int64_t imm = hook_sign_extend((uint64_t)((immhi << 2) | immlo), 21);

        return hook_emit_movabs(out, (uint32_t)(insn & 0x1Fu), (uint64_t)((int64_t)src + imm));
    }

    if ((insn & 0xFC000000u) == 0x14000000u) {
        if (hook_reloc_branch26(insn, src, dst, &word)) {
            hook_put32(out, 0, word);
            hook_put32(out, 4, HOOK_OP_NOP);
            return 8;
        }

        imm26 = hook_sign_extend(insn & 0x03FFFFFFu, 26);
        return hook_emit_abs_jump(out, (uintptr_t)((int64_t)src + (imm26 << 2)), false);
    }

    if ((insn & 0xFC000000u) == 0x94000000u) {
        if (hook_reloc_branch26(insn, src, dst, &word)) {
            hook_put32(out, 0, word);
            hook_put32(out, 4, HOOK_OP_NOP);
            return 8;
        }

        imm26 = hook_sign_extend(insn & 0x03FFFFFFu, 26);
        return hook_emit_abs_jump(out, (uintptr_t)((int64_t)src + (imm26 << 2)), true);
    }

    if ((insn & 0xFF000010u) == 0x54000000u) {
        if (hook_reloc_branch19(insn, src, dst, &word)) {
            hook_put32(out, 0, word);
            hook_put32(out, 4, HOOK_OP_NOP);
            return 8;
        }

        imm19 = hook_sign_extend((insn >> 5) & 0x7FFFFu, 19);
        return hook_emit_abs_cond(out, insn, (uintptr_t)((int64_t)src + (imm19 << 2)));
    }

    if ((insn & 0x7E000000u) == 0x34000000u) {
        if (hook_reloc_branch19(insn, src, dst, &word)) {
            hook_put32(out, 0, word);
            hook_put32(out, 4, HOOK_OP_NOP);
            return 8;
        }

        imm19 = hook_sign_extend((insn >> 5) & 0x7FFFFu, 19);
        return hook_emit_abs_cond(out, insn, (uintptr_t)((int64_t)src + (imm19 << 2)));
    }

    if ((insn & 0x7E000000u) == 0x36000000u) {
        if (hook_reloc_branch14(insn, src, dst, &word)) {
            hook_put32(out, 0, word);
            hook_put32(out, 4, HOOK_OP_NOP);
            return 8;
        }

        imm14 = hook_sign_extend((insn >> 5) & 0x3FFFu, 14);
        return hook_emit_abs_cond(out, insn, (uintptr_t)((int64_t)src + (imm14 << 2)));
    }

    if ((insn & 0x3B000000u) == 0x18000000u) {
        if (hook_reloc_branch19(insn, src, dst, &word)) {
            hook_put32(out, 0, word);
            hook_put32(out, 4, HOOK_OP_NOP);
            return 8;
        }

        imm19 = hook_sign_extend((insn >> 5) & 0x7FFFFu, 19);
        return hook_emit_abs_literal_load(out, insn, (uintptr_t)((int64_t)src + (imm19 << 2)));
    }

    hook_put32(out, 0, insn);
    hook_put32(out, 4, HOOK_OP_NOP);
    return 8;
}

static int hook_emit_block(uintptr_t src, uintptr_t dst, const uint32_t *in, uint8_t *out, int capacity)
{
    int offset = 0;

    for (int i = 0; i < 4; i++) {
        if (offset + 24 > capacity) return -1;

        int written = hook_emit_one(in[i],
                                    src + (uintptr_t)(4 * i),
                                    dst + (uintptr_t)offset,
                                    out + offset);

        if (written <= 0) return -1;
        if (offset + written > capacity) return -1;

        offset += written;
    }

    return offset;
}

static uintptr_t g_cave_cursor = 0;
static uint64_t g_cave_runs = 0;
static uint64_t g_cave_rejected = 0;
static bool g_cave_logged = false;

static bool hook_cave_is_padding(uintptr_t runStart)
{
    uint32_t words[4];
    uintptr_t base = runStart - sizeof(words);

    if (!hook_read_bytes(base, words, sizeof(words))) return false;

    for (int i = 3; i >= 0; i--) {
        uint32_t word = words[i];

        if (word == 0xD503201F) continue;

        if (word == 0xD65F03C0) return true;
        if (word == 0xD65F0FFF) return true;
        if ((word & 0xFFFFFC1Fu) == 0xD65F0000u) return true;
        if ((word & 0xFC000000u) == 0x14000000u) return true;
        if ((word & 0xFFE0001Fu) == 0xD4200000u) return true;

        return false;
    }

    return false;
}

static uintptr_t hook_find_cave_in_region(uintptr_t regionStart, uintptr_t regionEnd,
                                           size_t need, uintptr_t avoid, uintptr_t avoidSize)
{
    if (!regionStart || regionEnd <= regionStart) return 0;
    if ((regionEnd - regionStart) < need) return 0;

    uint8_t buffer[4096];
    uintptr_t cursor = regionStart;

    while ((cursor + need) <= regionEnd) {
        size_t want = sizeof(buffer);
        if ((cursor + want) > regionEnd) want = (size_t)(regionEnd - cursor);

        vm_size_t got = 0;

        kern_return_t kr = vm_read_overwrite(
            mach_task_self(),
            (vm_address_t)cursor,
            (vm_size_t)want,
            (vm_address_t)buffer,
            &got
        );

        if (kr != KERN_SUCCESS || got < 4) {
            cursor = (cursor + 0x1000) & ~0xFFFULL;
            continue;
        }

        size_t run = 0;

        for (size_t i = 0; (i + 4) <= got; i += 4) {
            uint32_t word = 0;
            memcpy(&word, buffer + i, 4);

            if (word != 0 && word != 0xD503201Fu) {
                run = 0;
                continue;
            }

            run += 4;

            if (run < need) continue;

            g_cave_runs++;

            uintptr_t runStart = cursor + i + 4 - run;
            uintptr_t candidate = (runStart + 7) & ~7ULL;

            if ((candidate + need) > (runStart + run)) continue;
            if ((candidate + need) > regionEnd) continue;

            if ((candidate + avoidSize) > avoid && candidate < (avoid + avoidSize)) continue;

            if (!hook_cave_is_padding(runStart)) { g_cave_rejected++; continue; }

            return candidate;
        }

        size_t advance = want;

        if (want > (need + 4)) advance = want - need - 4;
        if (advance < 4) advance = 4;

        cursor += advance;
    }

    return 0;
}

static uintptr_t hook_alloc_from_cave(uintptr_t target, size_t size, bool *near)
{
    vm_prot_t prot = 0;
    uintptr_t regionStart = 0;
    uintptr_t regionEnd = 0;

    if (!hook_region_info(target, &prot, &regionStart, &regionEnd)) return 0;
    if ((prot & VM_PROT_EXECUTE) == 0) return 0;

    vm_prot_t maxProt = 0;

    if (!hook_region_maxprot(target, &maxProt)) return 0;

    if ((maxProt & VM_PROT_WRITE) == 0) {
        return 0;
    }

    uintptr_t floor = regionStart + 0x4000;
    if (floor >= regionEnd) return 0;

    uintptr_t avoid = target & ~0xFFFULL;

    uintptr_t from = g_cave_cursor;
    if (from < floor || (from + size) > regionEnd) from = floor;

    uintptr_t cave = hook_find_cave_in_region(from, regionEnd, size, avoid, 0x1000);

    if (!cave && from != floor) {
        cave = hook_find_cave_in_region(floor, regionEnd, size, avoid, 0x1000);
    }

    if (!cave) {
        if (!g_cave_logged) {
            g_cave_logged = true;

        }

        return 0;
    }

    g_cave_cursor = cave + size;

    if (near) *near = true;


    return cave;
}

static uintptr_t hook_alloc_trampoline(uintptr_t target, size_t size, bool *near, bool *fromCave)
{
    if (near) *near = false;
    if (fromCave) *fromCave = false;

    uintptr_t cave = hook_alloc_from_cave(target, HOOK_TRAMP_NEED, near);

    if (cave) {
        if (fromCave) *fromCave = true;
        return cave;
    }


    void *mapped = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);

    if (mapped != MAP_FAILED) {
        int64_t delta = (int64_t)(uintptr_t)mapped - (int64_t)target;
        if (delta < 0) delta = -delta;
        if (near) *near = (delta <= HOOK_NEAR_RANGE);


        return (uintptr_t)mapped;
    }

    size_t bigger = size * 4;

    mapped = mmap(NULL, bigger, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);

    if (mapped == MAP_FAILED) {
        hook_set_error("trampoline: mmap failed errno=%d size=%zu", errno, bigger);
        return 0;
    }

    return (uintptr_t)mapped;
}

static hook_entry_t *hook_find_locked(uintptr_t target)
{
    for (int i = 0; i < HOOK_MAX; i++) {
        if (g_hooks[i].used && g_hooks[i].target == target) return &g_hooks[i];
    }

    return NULL;
}

static hook_entry_t *hook_claim_locked(uintptr_t target)
{
    for (int i = 0; i < HOOK_MAX; i++) {
        if (!g_hooks[i].used) {
            memset(&g_hooks[i], 0, sizeof(hook_entry_t));
            g_hooks[i].used = true;
            g_hooks[i].target = target;
            return &g_hooks[i];
        }
    }

    return NULL;
}

static void hook_build_patch(uintptr_t replacement, uint8_t *out)
{
    hook_put32(out, 0, HOOK_OP_LDR_X16_8);
    hook_put32(out, 4, HOOK_OP_BR_X16);
    hook_put32(out, 8, (uint32_t)(replacement & 0xFFFFFFFFu));
    hook_put32(out, 12, (uint32_t)((replacement >> 32) & 0xFFFFFFFFu));
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
static uint64_t g_ptr_writes = 0;

static hook_ptr_entry_t *hook_pointer_find(uintptr_t target);

bool hook_code_patch_allowed(void)
{
    const char *flag = getenv("TITANOX_ALLOW_CODE_PATCH");

    if (g_exec_restore_broken) return false;
    if (flag && flag[0] == '0') return false;

    return true;
}

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

static uint64_t g_scan_segments = 0;
static uint64_t g_scan_bytes = 0;
static uint64_t g_scan_values = 0;
static uint64_t g_scan_matches = 0;
static uint64_t g_scan_offsets = 0;
static uint64_t g_scan_slots_used = 0;
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
                                  uintptr_t *slots, int capacity, bool dryRun, const char *label)
{
    if (!imageBase || !needle || !slots || capacity <= 0) return 0;

    g_scan_segments = 0;
    g_scan_bytes = 0;
    g_scan_values = 0;
    g_scan_matches = 0;
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
        g_scan_segments++;

        for (uintptr_t p = start; (p + 8) <= end; ) {
            size_t want = sizeof(buffer);
            if ((p + want) > end) want = (size_t)(end - p);
            if (want < 8) break;

            if (!hook_read_bytes(p, buffer, want)) { p += 0x1000; continue; }

            g_scan_bytes += (uint64_t)want;

            for (size_t i = 0; (i + 8) <= want; i += 8) {
                uintptr_t value = 0;
                memcpy(&value, buffer + i, 8);

                g_scan_values++;

                uintptr_t slot = p + i;
                hook_slot_fix_t fix;

                int mode = hook_slot_classify(value, needle, imageBase, slot, &fix);

                if (mode == 0) continue;

                if (mode == 3) {
                    g_scan_offsets++;
                    continue;
                }

                g_scan_matches++;

                if (hits >= capacity) {
                    g_slot_truncated++;

                    continue;
                }

                if (dryRun) {
                    slots[hits] = slot;
                    hits++;

                    if (label && g_scan_dry_label != label) {
                        g_scan_dry_label = label;
                        g_scan_dry_logged = 0;
                    }

                    if (g_scan_dry_logged < HOOK_SCAN_DRY_LOGS) {
                        g_scan_dry_logged++;

                    }

                    continue;
                }

                uintptr_t writeValue = hook_slot_encode(replacement, &fix);
                uintptr_t readBack = 0;

                if (!hook_write_u64(slot, writeValue)) continue;

                if (!hook_read_bytes(slot, &readBack, sizeof(readBack)) || readBack != writeValue) {
                    g_slot_verify_fails++;

                    hook_set_error("pointer slot %p did not take: wrote %p read %p",
                                   (void *)slot, (void *)writeValue, (void *)readBack);

                    continue;
                }

                slots[hits] = slot;
                hits++;
                g_scan_slots_used++;

                if (g_scan_detail_logs < HOOK_SCAN_DETAIL_LOGS) {
                    g_scan_detail_logs++;

                }
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

    int hits = hook_scan_tables_value(imageBase, target, replacement, slots, HOOK_PTR_SLOTS, false, "addr");

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
    g_ptr_writes += (uint64_t)hits;

    return hits;
}

static hook_ptr_entry_t *hook_pointer_find(uintptr_t target)
{
    for (int i = 0; i < HOOK_PTR_ENTRIES; i++) {
        if (g_ptr_hooks[i].used && g_ptr_hooks[i].target == target) return &g_ptr_hooks[i];
    }

    return NULL;
}

int hook_pointer_count(void)
{
    int total = 0;

    for (int i = 0; i < HOOK_PTR_ENTRIES; i++) {
        if (g_ptr_hooks[i].used) total++;
    }

    return total;
}

int hook_pointer_slots(void)
{
    int total = 0;

    for (int i = 0; i < HOOK_PTR_ENTRIES; i++) {
        if (g_ptr_hooks[i].used) total += g_ptr_hooks[i].count;
    }

    return total;
}

int hook_probe(uintptr_t target)
{
    if (!target) return -1;

    uintptr_t imageBase = hook_image_base_for(target);

    if (!imageBase) return -1;

    uintptr_t slots[HOOK_PTR_SLOTS];

    int hits = hook_scan_tables_value(imageBase, target, 0, slots, HOOK_PTR_SLOTS, true, "probe");


    return hits;
}

static bool hook_code_install(uintptr_t addr, uintptr_t repl);

bool brk_install(void *target, void *replacement)
{
    if (!target || !replacement) {
        hook_set_error("install: null argument target=%p replacement=%p", target, replacement);
        return false;
    }

    uintptr_t addr = strip_fn(target);
    uintptr_t repl = strip_fn(replacement);

    if (hook_code_patch_allowed() && hook_code_install(addr, repl)) return true;


    int hits = hook_pointer_install(addr, repl);

    if (hits > 0) {
        g_install_count++;
        g_ready = true;


        return true;
    }

    g_fail_count++;

    return false;
}

static bool hook_code_install(uintptr_t addr, uintptr_t repl)
{
    if (!addr || !repl) {
        hook_set_error("install: null argument addr=%p replacement=%p", (void *)addr, (void *)repl);
        return false;
    }

    vm_prot_t prot = 0;
    uintptr_t regionStart = 0;
    uintptr_t regionEnd = 0;

    if (!hook_region_info(addr, &prot, &regionStart, &regionEnd)) {
        hook_set_error("install: target %p not mapped", (void *)addr);
        return false;
    }

    if ((addr & 3) != 0) {
        hook_set_error("install: target %p misaligned", (void *)addr);
        return false;
    }

    if ((addr + HOOK_PATCH_SIZE) > regionEnd) {
        hook_set_error("install: target %p too close to region end", (void *)addr);
        return false;
    }

    if ((prot & VM_PROT_EXECUTE) == 0) {
        hook_set_error("install: target %p not executable (prot=%d)", (void *)addr, (int)prot);
        g_fail_count++;
        return false;
    }

    vm_prot_t maxProt = 0;

    if (!hook_region_maxprot(addr, &maxProt)) {
        hook_set_error("install: cannot read maxprot for %p", (void *)addr);
        g_fail_count++;
        return false;
    }

    if ((maxProt & VM_PROT_WRITE) == 0) {
        hook_set_error("install: refusing %p, region maxprot=%c%c%c has no WRITE",
                       (void *)addr,
                       (maxProt & VM_PROT_READ) ? 'r' : '-',
                       (maxProt & VM_PROT_WRITE) ? 'w' : '-',
                       (maxProt & VM_PROT_EXECUTE) ? 'x' : '-');
        g_fail_count++;
        return false;
    }

    if (!hook_sign_check(repl)) {
        hook_set_error("install: replacement %p failed signature check", (void *)repl);
        return false;
    }

    pthread_mutex_lock(&g_lock);

    hook_entry_t *entry = hook_find_locked(addr);

    if (entry && entry->armed) {
        entry->replacement = repl;
        hook_build_patch(repl, entry->patch);

        bool updated = hook_write_bytes(entry->target, entry->patch, HOOK_PATCH_SIZE);
        pthread_mutex_unlock(&g_lock);


        return updated;
    }

    if (!entry) entry = hook_claim_locked(addr);

    if (!entry) {
        pthread_mutex_unlock(&g_lock);
        hook_set_error("install: hook table exhausted (%d)", HOOK_MAX);
        return false;
    }

    uint32_t original[4];

    if (!hook_read_bytes(addr, original, HOOK_PATCH_SIZE)) {
        entry->used = false;
        pthread_mutex_unlock(&g_lock);
        hook_set_error("install: cannot read 16 bytes at %p", (void *)addr);
        return false;
    }

    memcpy(entry->saved, original, HOOK_PATCH_SIZE);

    if (original[0] == HOOK_OP_LDR_X16_8 && original[1] == HOOK_OP_BR_X16) {
        entry->used = false;
        pthread_mutex_unlock(&g_lock);
        hook_set_error("install: %p already carries an inline patch", (void *)addr);
        return false;
    }

    bool near = false;
    bool fromCave = false;
    uintptr_t tramp = hook_alloc_trampoline(addr, HOOK_TRAMP_SIZE, &near, &fromCave);

    if (!tramp) {
        entry->used = false;
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    uint8_t trampoline[HOOK_TRAMP_SIZE];
    memset(trampoline, 0, sizeof(trampoline));

    int blockSize = hook_emit_block(addr, tramp, original, trampoline,
                                    HOOK_TRAMP_SIZE - HOOK_PATCH_SIZE);

    if (blockSize <= 0) {
        vm_deallocate(mach_task_self(), (vm_address_t)tramp, (vm_size_t)HOOK_TRAMP_SIZE);
        entry->used = false;
        pthread_mutex_unlock(&g_lock);
        hook_set_error("install: trampoline emission failed at %p", (void *)addr);
        return false;
    }

    uintptr_t resume = addr + HOOK_PATCH_SIZE;

    hook_put32(trampoline, blockSize + 0, HOOK_OP_LDR_X16_8);
    hook_put32(trampoline, blockSize + 4, HOOK_OP_BR_X16);
    hook_put32(trampoline, blockSize + 8, (uint32_t)(resume & 0xFFFFFFFFu));
    hook_put32(trampoline, blockSize + 12, (uint32_t)((resume >> 32) & 0xFFFFFFFFu));

    size_t trampBytes = (size_t)blockSize + HOOK_PATCH_SIZE;

    if (fromCave) {
        if (!hook_write_bytes(tramp, trampoline, trampBytes)) {
            entry->used = false;
            pthread_mutex_unlock(&g_lock);
            hook_set_error("install: cannot write trampoline into code cave at %p", (void *)tramp);
            return false;
        }

    } else {
        memcpy((void *)tramp, trampoline, trampBytes);


        if (!hook_make_executable(tramp, trampBytes)) {
            vm_deallocate(mach_task_self(), (vm_address_t)tramp, (vm_size_t)HOOK_TRAMP_SIZE);
            entry->used = false;
            pthread_mutex_unlock(&g_lock);
            hook_set_error("install: trampoline at %p is not executable", (void *)tramp);
            return false;
        }

    }

    uint8_t patch[HOOK_PATCH_SIZE];
    hook_build_patch(repl, patch);

    if (!hook_write_bytes(addr, patch, HOOK_PATCH_SIZE)) {
        vm_deallocate(mach_task_self(), (vm_address_t)tramp, (vm_size_t)HOOK_TRAMP_SIZE);
        entry->used = false;
        pthread_mutex_unlock(&g_lock);
        hook_set_error("install: patch write failed at %p", (void *)addr);
        return false;
    }

    entry->tramp = tramp;
    entry->replacement = repl;
    entry->block_bytes = (uint32_t)blockSize;
    entry->near = near;
    entry->from_cave = fromCave;
    memcpy(entry->patch, patch, HOOK_PATCH_SIZE);
    entry->armed = true;

    g_install_count++;
    g_ready = true;

    pthread_mutex_unlock(&g_lock);


    return true;
}

bool brk_observe(void *target)
{
    if (!target) return false;

    uintptr_t addr = strip_fn(target);

    pthread_mutex_lock(&g_lock);
    hook_entry_t *entry = hook_find_locked(addr);
    bool present = (entry != NULL);
    pthread_mutex_unlock(&g_lock);

    return present;
}

bool brk_install_raw_slot(int slot, void *target, void *replacement)
{
    if (slot < 0 || slot >= HOOK_MAX) return false;
    return brk_install(target, replacement);
}

bool brk_remove(void *target)
{
    if (!target) return false;

    uintptr_t addr = strip_fn(target);

    hook_ptr_entry_t *ptrEntry = hook_pointer_find(addr);

    if (ptrEntry) {
        bool restored = true;

        for (int i = 0; i < ptrEntry->count; i++) {
            if (!hook_write_u64(ptrEntry->slots[i], ptrEntry->target)) restored = false;
        }

        int slotCount = ptrEntry->count;
        memset(ptrEntry, 0, sizeof(hook_ptr_entry_t));


        return restored;
    }

    pthread_mutex_lock(&g_lock);

    hook_entry_t *entry = hook_find_locked(addr);

    if (!entry || !entry->armed) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    bool restored = hook_write_bytes(entry->target, entry->saved, HOOK_PATCH_SIZE);

    if (entry->tramp && !entry->from_cave) {
        vm_deallocate(mach_task_self(), (vm_address_t)entry->tramp, (vm_size_t)HOOK_TRAMP_SIZE);
    }

    memset(entry, 0, sizeof(hook_entry_t));

    pthread_mutex_unlock(&g_lock);

    return restored;
}

bool brk_remove_raw(void *target)
{
    return brk_remove(target);
}

uint64_t brk_hits(void *target)
{
    if (!target) return 0;

    uintptr_t addr = strip_fn(target);

    pthread_mutex_lock(&g_lock);
    hook_entry_t *entry = hook_find_locked(addr);
    uint64_t hits = entry ? entry->hits : 0;
    pthread_mutex_unlock(&g_lock);

    return hits;
}

void hook_note_hit(void *target)
{
    if (!target) return;

    uintptr_t addr = strip_fn(target);

    for (int i = 0; i < HOOK_MAX; i++) {
        if (g_hooks[i].used && g_hooks[i].target == addr) {
            g_hooks[i].hits++;
            break;
        }
    }

    g_total_hits++;
}

void *brk_original_ptr(void *target)
{
    if (!target) return NULL;

    uintptr_t addr = strip_fn(target);

    if (hook_pointer_find(addr)) return (void *)addr;

    pthread_mutex_lock(&g_lock);
    hook_entry_t *entry = hook_find_locked(addr);
    uintptr_t tramp = (entry && entry->armed) ? entry->tramp : 0;
    pthread_mutex_unlock(&g_lock);

    if (!tramp) return (void *)addr;

    return (void *)strip_fn((const void *)tramp);
}

void brk_suspend_self(void)
{
    g_probe_value = 1;
}

void brk_resume_self(void)
{
    g_probe_value = 0;
}

int brk_slot_limit(void)
{
    return HOOK_MAX;
}

int brk_live_slot_count(void)
{
    int live = 0;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < HOOK_MAX; i++) {
        if (g_hooks[i].used && g_hooks[i].armed) live++;
    }
    pthread_mutex_unlock(&g_lock);

    return live;
}

int brk_active_count(void)
{
    return brk_live_slot_count();
}

bool brk_calibrate_slots(void)
{
    return brk_slot_limit() > 0;
}

int brk_next_slot(int after)
{
    int result = -1;

    pthread_mutex_lock(&g_lock);

    for (int i = after + 1; i < HOOK_MAX; i++) {
        if (!g_hooks[i].used) {
            result = i;
            break;
        }
    }

    pthread_mutex_unlock(&g_lock);

    return result;
}

static volatile int g_selftest_hits = 0;

typedef int (*hook_selftest_fn)(int);

static volatile hook_selftest_fn g_selftest_call = NULL;

static bool hook_name_marks_host_runtime(const char *name)
{
    if (!name) return false;

    static const char *marks[] = {
        "TweakLoader",
        "LiveContainer",
        "LiveContainerShared",
        "CydiaSubstrate",
        "libellekit",
        "SubstrateLoader",
        NULL
    };

    for (int i = 0; marks[i]; ++i) {
        if (strstr(name, marks[i])) return true;
    }

    return false;
}

bool brk_host_is_livecontainer(void)
{
    uint32_t count = _dyld_image_count();

    if (count > 8192) count = 8192;

    for (uint32_t i = 0; i < count; ++i) {
        if (hook_name_marks_host_runtime(_dyld_get_image_name(i))) return true;
    }

    if (dlsym(RTLD_DEFAULT, "LiveContainerMain") != NULL) return true;

    const char *home = getenv("HOME");

    if (home) {
        char probe[1024];
        snprintf(probe, sizeof(probe), "%s/Documents/Tweaks", home);
        if (access(probe, F_OK) == 0) return true;
    }

    return false;
}

bool brk_arm_function_rva(uintptr_t imageBase, uintptr_t rva, void *replacement, void **outOriginal)
{
    if (!imageBase || !rva || !replacement) return false;

    uintptr_t target = imageBase + rva;

    if (!brk_install((void *)target, replacement)) return false;

    if (outOriginal) *outOriginal = brk_original_ptr((void *)target);

    return true;
}

void brk_teardown(void)
{
    pthread_mutex_lock(&g_lock);

    for (int i = 0; i < HOOK_MAX; i++) {
        if (!g_hooks[i].used) continue;

        if (g_hooks[i].armed) {
            hook_write_bytes(g_hooks[i].target, g_hooks[i].saved, HOOK_PATCH_SIZE);
        }

        if (g_hooks[i].tramp && !g_hooks[i].from_cave) {
            vm_deallocate(mach_task_self(),
                          (vm_address_t)g_hooks[i].tramp,
                          (vm_size_t)HOOK_TRAMP_SIZE);
        }

        memset(&g_hooks[i], 0, sizeof(hook_entry_t));
    }

    g_ready = false;

    pthread_mutex_unlock(&g_lock);

}

bool hook(void *oldArr[], void *newArr[], int count)
{
    if (!oldArr || !newArr || count <= 0) return false;

    bool ok = true;

    for (int i = 0; i < count; i++) {
        if (!oldArr[i] || !newArr[i]) {
            ok = false;
            continue;
        }

        if (!brk_install(oldArr[i], newArr[i])) ok = false;
    }

    return ok;
}

bool unhook(void *oldArr[], int count)
{
    if (!oldArr || count <= 0) return false;

    bool ok = true;

    for (int i = 0; i < count; i++) {
        if (!oldArr[i]) {
            ok = false;
            continue;
        }

        if (!brk_remove(oldArr[i])) ok = false;
    }

    return ok;
}