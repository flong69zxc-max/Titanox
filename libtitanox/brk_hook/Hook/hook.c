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
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define HOOK_MAX 64
#define HOOK_PATCH_SIZE 16
#define HOOK_TRAMP_SIZE 256
#define HOOK_LOG_LIMIT (1024L * 1024L)
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
} hook_entry_t;

static hook_entry_t g_hooks[HOOK_MAX];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

static FILE *g_log = NULL;
static long g_log_bytes = 0;
static uint64_t g_total_hits = 0;
static uint64_t g_fail_count = 0;
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

static FILE *open_log_locked(void)
{
    if (g_log) return g_log;

    const char *home = getenv("HOME");
    char path[1024];

    if (home) {
        snprintf(path, sizeof(path), "%s/Documents/Titanox.log", home);
    } else {
        snprintf(path, sizeof(path), "/tmp/Titanox.log");
    }

    g_log = fopen(path, "a");

    if (g_log) {
        if (fseek(g_log, 0, SEEK_END) == 0) {
            long position = ftell(g_log);
            if (position >= 0) g_log_bytes = position;
        }
    }

    return g_log;
}

FILE *titanox_log_handle(void)
{
    pthread_mutex_lock(&g_log_lock);
    FILE *f = open_log_locked();
    pthread_mutex_unlock(&g_log_lock);
    return f;
}

void brk_diag_log(const char *format, ...)
{
    char buffer[2048];
    va_list args;

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    pthread_mutex_lock(&g_log_lock);

    FILE *f = open_log_locked();
    size_t size = strlen(buffer);

    if (f && g_log_bytes + (long)size + 8 <= HOOK_LOG_LIMIT) {
        int written = fprintf(f, "[hook] %s\n", buffer);
        if (written > 0) g_log_bytes += written;
        fflush(f);
    }

    pthread_mutex_unlock(&g_log_lock);
}

void hook_set_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(g_last_error, sizeof(g_last_error), format, args);
    va_end(args);
    brk_diag_log("%s", g_last_error);
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
        brk_diag_log("encryption check: LC_ENCRYPTION_INFO_64 absent, cryptid treated as 0");
        return true;
    }

    if (cryptid != 0) {
        hook_set_error("encryption check: cryptid=%u, aborting before hook install", cryptid);
        abort();
    }

    brk_diag_log("encryption check: cryptid=0");
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

    kern_return_t kr = vm_protect(
        mach_task_self(),
        (vm_address_t)start,
        (vm_size_t)(end - start),
        setMaximum ? TRUE : FALSE,
        requested
    );

    return kr == KERN_SUCCESS;
}

static bool hook_page_writable(uintptr_t address, size_t length, vm_prot_t *saved)
{
    vm_prot_t prot = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;

    if (!hook_region_info(address, &prot, &start, &end)) return false;
    if ((address + length) > end) return false;

    if (saved) *saved = prot;

    if (prot & VM_PROT_WRITE) return true;

    hook_page_set(start, 1, (vm_prot_t)(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE), TRUE, NULL);

    vm_prot_t writable = (vm_prot_t)(VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);

    kern_return_t kr = vm_protect(
        mach_task_self(),
        (vm_address_t)start,
        (vm_size_t)(end - start),
        FALSE,
        writable
    );

    if (kr == KERN_SUCCESS) return true;

    brk_diag_log("page rw+copy failed kr=%d errno=%d, retrying rw only", kr, errno);

    kr = vm_protect(
        mach_task_self(),
        (vm_address_t)start,
        (vm_size_t)(end - start),
        FALSE,
        (vm_prot_t)(VM_PROT_READ | VM_PROT_WRITE)
    );

    return kr == KERN_SUCCESS;
}

static bool hook_page_restore(uintptr_t address, vm_prot_t saved)
{
    vm_prot_t prot = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;

    if (!hook_region_info(address, &prot, &start, &end)) return false;

    vm_prot_t target = (vm_prot_t)(saved & ~VM_PROT_WRITE);
    if ((saved & VM_PROT_EXECUTE) == 0) target = saved;

    hook_page_set(start, 1, (vm_prot_t)(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE), TRUE, NULL);

    kern_return_t kr = vm_protect(
        mach_task_self(),
        (vm_address_t)start,
        (vm_size_t)(end - start),
        FALSE,
        target
    );

    return kr == KERN_SUCCESS;
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

void hook_log_prot(const char *label, uintptr_t address)
{
    vm_prot_t prot = 0;
    uintptr_t start = 0;
    uintptr_t end = 0;

    if (!hook_region_info(address, &prot, &start, &end)) {
        brk_diag_log("%s %p prot=unmapped", label ? label : "prot", (void *)address);
        return;
    }

    brk_diag_log("%s %p prot=%c%c%c max-ok=%d",
                 label ? label : "prot",
                 (void *)address,
                 (prot & VM_PROT_READ) ? 'r' : '-',
                 (prot & VM_PROT_WRITE) ? 'w' : '-',
                 (prot & VM_PROT_EXECUTE) ? 'x' : '-',
                 (prot & VM_PROT_EXECUTE) ? 1 : 0);
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
        hook_page_set(start, 1, (vm_prot_t)(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE), TRUE, NULL);

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
        brk_diag_log("exec: %p is still writable after RX transition (prot=%d)", (void *)start, (int)after);
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

    hook_page_restore(address, saved);

    sys_icache_invalidate((void *)address, length);

    if ((saved & VM_PROT_EXECUTE) && !hook_page_executable(address, length)) {
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

static uintptr_t hook_alloc_trampoline(uintptr_t target, size_t size, bool *near)
{
    if (near) *near = false;

    void *mapped = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANON, -1, 0);

    if (mapped != MAP_FAILED) {
        int64_t delta = (int64_t)(uintptr_t)mapped - (int64_t)target;
        if (delta < 0) delta = -delta;
        if (near) *near = (delta <= HOOK_NEAR_RANGE);

        brk_diag_log("trampoline mmap ptr=%p delta=%lld",
                     mapped, (long long)((int64_t)(uintptr_t)mapped - (int64_t)target));

        return (uintptr_t)mapped;
    }

    brk_diag_log("trampoline mmap failed errno=%d, fixed sweep", errno);

    uintptr_t page = target & ~0xFFFULL;

    for (int64_t step = 0x10000; step <= (int64_t)HOOK_NEAR_RANGE; step += 0x10000) {
        for (int dir = 0; dir < 2; dir++) {
            vm_address_t candidate =
                dir ? (vm_address_t)(page + (uintptr_t)step)
                    : (vm_address_t)(page - (uintptr_t)step);

            if (candidate < 0x100000000ULL) continue;

            kern_return_t kr = vm_allocate(mach_task_self(), &candidate, size, 0);
            if (kr != KERN_SUCCESS) continue;

            vm_protect(mach_task_self(), candidate, size, FALSE,
                       VM_PROT_READ | VM_PROT_WRITE);

            if (near) *near = true;
            brk_diag_log("trampoline fixed alloc tramp=%p", (void *)candidate);
            return (uintptr_t)candidate;
        }
    }

    size_t bigger = size * 4;

    mapped = mmap(NULL, bigger, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);

    if (mapped == MAP_FAILED) {
        hook_set_error("trampoline: mmap failed errno=%d size=%zu", errno, bigger);
        return 0;
    }

    brk_diag_log("trampoline retry mmap ptr=%p size=%zu", mapped, bigger);
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

bool brk_install(void *target, void *replacement)
{
    if (!target || !replacement) {
        hook_set_error("install: null argument target=%p replacement=%p", target, replacement);
        return false;
    }

    uintptr_t addr = strip_fn(target);
    uintptr_t repl = strip_fn(replacement);

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

        brk_diag_log("install update target=%p replacement=%p status=%d",
                     (void *)addr, (void *)repl, updated ? 1 : 0);

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
    uintptr_t tramp = hook_alloc_trampoline(addr, HOOK_TRAMP_SIZE, &near);

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

    memcpy((void *)tramp, trampoline, trampBytes);

    hook_log_prot("trampoline before RX", tramp);

    if (!hook_make_executable(tramp, trampBytes)) {
        hook_log_prot("trampoline after RX failed", tramp);
        vm_deallocate(mach_task_self(), (vm_address_t)tramp, (vm_size_t)HOOK_TRAMP_SIZE);
        entry->used = false;
        pthread_mutex_unlock(&g_lock);
        hook_set_error("install: trampoline at %p is not executable", (void *)tramp);
        return false;
    }

    hook_log_prot("trampoline after RX", tramp);

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
    memcpy(entry->patch, patch, HOOK_PATCH_SIZE);
    entry->armed = true;

    g_install_count++;
    g_ready = true;

    pthread_mutex_unlock(&g_lock);

    brk_diag_log("install target=%p replacement=%p tramp=%p block=%d near=%d saved=%08x %08x %08x %08x status=1",
                 (void *)addr,
                 (void *)repl,
                 (void *)tramp,
                 blockSize,
                 near ? 1 : 0,
                 original[0], original[1], original[2], original[3]);

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

    pthread_mutex_lock(&g_lock);

    hook_entry_t *entry = hook_find_locked(addr);

    if (!entry || !entry->armed) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    bool restored = hook_write_bytes(entry->target, entry->saved, HOOK_PATCH_SIZE);

    if (entry->tramp) {
        vm_deallocate(mach_task_self(), (vm_address_t)entry->tramp, (vm_size_t)HOOK_TRAMP_SIZE);
    }

    memset(entry, 0, sizeof(hook_entry_t));

    pthread_mutex_unlock(&g_lock);

    brk_diag_log("remove target=%p status=%d", (void *)addr, restored ? 1 : 0);
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

void hook_selftest_probe(void) {}

static volatile int g_selftest_hits = 0;

typedef int (*hook_selftest_fn)(int);

static volatile hook_selftest_fn g_selftest_call = NULL;

static int hook_selftest_replacement(int value)
{
    g_selftest_hits++;
    return value + 1000;
}

bool brk_selftest(void)
{
    g_selftest_hits = 0;

    void *page = mmap(NULL, 0x4000,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);

    if (page == MAP_FAILED) {
        hook_set_error("selftest: mmap failed errno=%d", errno);
        return false;
    }

    uint32_t code[3];
    code[0] = 0x52800020u;
    code[1] = 0x11000400u;
    code[2] = 0xD65F03C0u;

    memcpy(page, code, sizeof(code));

    hook_log_prot("selftest page before RX", (uintptr_t)page);

    if (!hook_make_executable((uintptr_t)page, sizeof(code))) {
        hook_log_prot("selftest page after RX failed", (uintptr_t)page);
        hook_set_error("selftest: generated code cannot be made executable");
        munmap(page, 0x4000);
        return false;
    }

    hook_log_prot("selftest page after RX", (uintptr_t)page);

    g_selftest_call = (hook_selftest_fn)sign_fn((uintptr_t)page);

    int baseline = g_selftest_call(1);

    if (baseline != 2) {
        hook_set_error("selftest: baseline call returned %d", baseline);
        munmap(page, 0x4000);
        g_selftest_call = NULL;
        return false;
    }

    if (!brk_install(page, (void *)hook_selftest_replacement)) {
        munmap(page, 0x4000);
        g_selftest_call = NULL;
        return false;
    }

    int intercepted = g_selftest_call(1);

    hook_selftest_fn original = (hook_selftest_fn)brk_original_ptr(page);
    int viaOriginal = original ? original(1) : -1;

    bool ok = (intercepted == 1001) && (g_selftest_hits == 1) && (viaOriginal == 2);

    if (ok) {
        brk_diag_log("selftest inline patch verified intercepted=%d via_original=%d hits=%d",
                     intercepted, viaOriginal, g_selftest_hits);
    } else {
        hook_set_error("selftest: intercepted=%d hits=%d via_original=%d",
                       intercepted, g_selftest_hits, viaOriginal);
    }

    brk_remove(page);
    munmap(page, 0x4000);
    g_selftest_call = NULL;

    return ok;
}

void *brk_selftest_addr(void)
{
    return (void *)&hook_selftest_probe;
}

void brk_log_state(void)
{
    pthread_mutex_lock(&g_lock);

    int live = 0;

    for (int i = 0; i < HOOK_MAX; i++) {
        if (g_hooks[i].used && g_hooks[i].armed) live++;
    }

    brk_diag_log("state slots=%d live=%d installed=%llu hits=%llu fails=%llu",
                 HOOK_MAX,
                 live,
                 (unsigned long long)g_install_count,
                 (unsigned long long)g_total_hits,
                 (unsigned long long)g_fail_count);

    for (int i = 0; i < HOOK_MAX; i++) {
        if (!g_hooks[i].used) continue;

        brk_diag_log("slot %d target=%p tramp=%p replacement=%p block=%u near=%d armed=%d hits=%llu",
                     i,
                     (void *)g_hooks[i].target,
                     (void *)g_hooks[i].tramp,
                     (void *)g_hooks[i].replacement,
                     g_hooks[i].block_bytes,
                     g_hooks[i].near ? 1 : 0,
                     g_hooks[i].armed ? 1 : 0,
                     (unsigned long long)g_hooks[i].hits);
    }

    pthread_mutex_unlock(&g_lock);
}

int brk_census(uint64_t *outHits, uint64_t *outFails, int *outLive)
{
    if (outHits) *outHits = g_total_hits;
    if (outFails) *outFails = g_fail_count;
    if (outLive) *outLive = brk_live_slot_count();

    return brk_live_slot_count();
}

void brk_trace_exception(const char *label)
{
    brk_diag_log("trace label=%s live=%d hits=%llu",
                 label ? label : "?",
                 brk_live_slot_count(),
                 (unsigned long long)g_total_hits);
}

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

bool brk_chain_active(void)
{
    return false;
}

mach_port_t brk_previous_port(void)
{
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;

    kern_return_t kr = task_get_exception_ports(
        mach_task_self(),
        EXC_MASK_BREAKPOINT,
        masks,
        &count,
        ports,
        behaviors,
        flavors
    );

    if (kr != KERN_SUCCESS) return MACH_PORT_NULL;

    mach_port_t observed = MACH_PORT_NULL;

    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        if (ports[i] != MACH_PORT_NULL) {
            if (observed == MACH_PORT_NULL) observed = ports[i];
            mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }

    return observed;
}

uint64_t brk_chain_counters(uint64_t *fails)
{
    if (fails) *fails = g_fail_count;
    return g_total_hits;
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

        if (g_hooks[i].tramp) {
            vm_deallocate(mach_task_self(),
                          (vm_address_t)g_hooks[i].tramp,
                          (vm_size_t)HOOK_TRAMP_SIZE);
        }

        memset(&g_hooks[i], 0, sizeof(hook_entry_t));
    }

    g_ready = false;

    pthread_mutex_unlock(&g_lock);

    brk_diag_log("teardown complete");
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
