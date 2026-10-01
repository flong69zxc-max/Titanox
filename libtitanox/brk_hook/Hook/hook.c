#include "hook.h"
#include "mach_excServer.h"
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define BRK_MAX_HOOKS 16
#define BRK_BCR_VALUE 0x1e5
#define BRK_SWEEP_US 500000
#define BRK_SLOT_CAP 16
#define BRK_SLOT_DEFAULT 6

typedef struct {
    uintptr_t target;
    uintptr_t replacement;
    bool used;
    int slot;
} brk_entry_t;

static brk_entry_t g_entries[BRK_MAX_HOOKS];
static int g_entry_count = 0;
static mach_port_t g_port = MACH_PORT_NULL;
static mach_port_t g_orig_port = MACH_PORT_NULL;
static int g_slot_limit = BRK_SLOT_DEFAULT;
static bool g_ready = false;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static arm_debug_state64_t g_desired;
static int g_desired_slots = 0;
static volatile int g_sweep_stop = 0;
static bool g_sweep_started = false;
static uint32_t g_live_slots = 0;
static FILE *g_logf = NULL;

FILE *titanox_log_handle(void) {
    if (g_logf) return g_logf;

    const char *home = getenv("HOME");
    char path[1024];
    if (home) {
        snprintf(path, sizeof(path), "%s/Documents/Titanox.log", home);
    } else {
        snprintf(path, sizeof(path), "/tmp/Titanox.log");
    }
    g_logf = fopen(path, "a");
    return g_logf;
}

static void brk_file_log(const char *fmt, ...) {
    FILE *f = titanox_log_handle();
    if (!f) return;
    pthread_mutex_lock(&g_log_lock);
    fprintf(f, "[brk] ");
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fflush(f);
    pthread_mutex_unlock(&g_log_lock);
}

static uintptr_t brk_strip(const void *p) {
    if (p == NULL) return 0;
#if __has_feature(ptrauth_calls)
    return (uintptr_t)ptrauth_strip(p, ptrauth_key_function_pointer);
#else
    return (uintptr_t)p;
#endif
}

static void *brk_sign(uintptr_t raw) {
#if __has_feature(ptrauth_calls)
    return ptrauth_sign_unauthenticated((void *)raw, ptrauth_key_function_pointer, 0);
#else
    return (void *)raw;
#endif
}

static volatile int g_probe_hits;

__attribute__((noinline)) static void brk_probe_target(void) {
    g_probe_hits = 100;
}
__attribute__((noinline)) static void brk_probe_replacement(void) {
    g_probe_hits = 1;
}

void *brk_selftest_addr(void) {
    return (void *)&brk_probe_target;
}

kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t codeCnt) {
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t codeCnt, int *flavor, thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt, thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt) {
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port, exception_type_t exception,
    const mach_exception_data_t code, mach_msg_type_number_t codeCnt,
    int *flavor, const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt, thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt) {

    arm_thread_state64_t *oldSt = (arm_thread_state64_t *)old_state;
    arm_thread_state64_t *newSt = (arm_thread_state64_t *)new_state;

    uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(*oldSt);
    uintptr_t dest = 0;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_entry_count; i++) {
        if (!g_entries[i].used) continue;
        if (g_entries[i].target == pc) {
            dest = g_entries[i].replacement;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);

    if (dest != 0) {
        *newSt = *oldSt;
        *new_stateCnt = old_stateCnt;
        arm_thread_state64_set_pc_fptr(*newSt, brk_sign(dest));
        return KERN_SUCCESS;
    }

    brk_file_log("EXC unmatched pc=%p code0=0x%llx code1=0x%llx\n",
                 (void *)pc,
                 (unsigned long long)(codeCnt > 0 ? code[0] : 0),
                 (unsigned long long)(codeCnt > 1 ? code[1] : 0));

    return KERN_FAILURE;
}

static void *brk_exception_thread(void *arg) {
    (void)arg;
    for (;;) {
        mach_msg_server(mach_exc_server,
                        sizeof(union __RequestUnion__catch_mach_exc_subsystem),
                        g_port, MACH_MSG_OPTION_NONE);
    }
    return NULL;
}

bool brk_install_raw_slot(int slot, void *target, void *replacement);
bool brk_remove_raw(void *target);

bool brk_calibrate_slots(void) {
    uint32_t mask = 0;

    for (int n = 0; n < BRK_SLOT_CAP; n++) {
        if (!brk_install_raw_slot(n, (void *)&brk_probe_target,
                                  (void *)&brk_probe_replacement)) {
            continue;
        }
        g_probe_hits = 0;
        brk_probe_target();
        if (g_probe_hits == 1) {
            mask |= (1u << n);
        }
        brk_remove_raw((void *)&brk_probe_target);
    }

    g_live_slots = mask;
    brk_file_log("calibrate live_slots=0x%08x count=%d\n",
                 mask, __builtin_popcount(mask));
    return mask != 0;
}

int brk_live_slot_count(void) {
    if (g_live_slots == 0) brk_calibrate_slots();
    return __builtin_popcount(g_live_slots);
}

int brk_next_slot(int after) {
    for (int n = after + 1; n < BRK_SLOT_CAP; n++) {
        if (g_live_slots & (1u << n)) return n;
    }
    return -1;
}

int brk_census(uint64_t *bvr_out, int max_slots, int *threads_total) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    int holding[BRK_SLOT_CAP];
    memset(holding, 0, sizeof(holding));

    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS) {
        return -1;
    }

    for (mach_msg_type_number_t i = 0; i < count; i++) {
        arm_debug_state64_t cur;
        mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
        if (thread_get_state(threads[i], ARM_DEBUG_STATE64,
                             (thread_state_t)&cur, &cnt) == KERN_SUCCESS) {
            for (int s = 0; s < max_slots && s < BRK_SLOT_CAP; s++) {
                if ((cur.__bcr[s] & 1u) && cur.__bvr[s] != 0 &&
                    cur.__bvr[s] == bvr_out[s]) {
                    holding[s]++;
                }
            }
        }
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  count * sizeof(thread_act_t));

    if (threads_total) *threads_total = (int)count;
    return 0;
}

void brk_trace_exception(uint64_t exception, uint64_t code0, uint64_t code1,
                         uint64_t pc, int matched_slot) {
    brk_file_log("EXC type=%llu code0=0x%llx code1=0x%llx pc=%p slot=%d\n",
                 (unsigned long long)exception,
                 (unsigned long long)code0,
                 (unsigned long long)code1,
                 (void *)pc, matched_slot);
}

static void brk_build_desired(void) {
    memset(&g_desired, 0, sizeof(g_desired));
    int slot = 0;
    for (int i = 0; i < g_entry_count; i++) {
        if (!g_entries[i].used) continue;
        if (slot >= g_slot_limit) break;
        g_desired.__bvr[slot] = (uint64_t)g_entries[i].target;
        g_desired.__bcr[slot] = (uint32_t)BRK_BCR_VALUE;
        g_entries[i].slot = slot;
        slot++;
    }
    g_desired_slots = slot;
}

static void brk_sync_threads(bool force) {
    arm_debug_state64_t desired;
    int slots;

    pthread_mutex_lock(&g_lock);
    desired = g_desired;
    slots = g_desired_slots;
    pthread_mutex_unlock(&g_lock);

    task_t task = mach_task_self();
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(task, &threads, &count) != KERN_SUCCESS) return;

    for (mach_msg_type_number_t i = 0; i < count; i++) {
        arm_debug_state64_t cur;
        mach_msg_type_number_t cur_cnt = ARM_DEBUG_STATE64_COUNT;
        bool write = force;
        if (thread_get_state(threads[i], ARM_DEBUG_STATE64, (thread_state_t)&cur,
                             &cur_cnt) == KERN_SUCCESS) {
            if (force) {
                bool same = true;
                for (int s = 0; s < slots; s++) {
                    if (cur.__bvr[s] != desired.__bvr[s] || (cur.__bcr[s] & 1u) == 0) {
                        same = false;
                        break;
                    }
                }
                write = !same;
            } else {
                bool virgin = true;
                for (int s = 0; s < slots; s++) {
                    if ((cur.__bcr[s] & 1u) != 0) {
                        virgin = false;
                        break;
                    }
                }
                write = virgin;
            }
        }
        if (write) {
            kern_return_t kr = thread_set_state(threads[i], ARM_DEBUG_STATE64,
                                                (thread_state_t)&desired,
                                                ARM_DEBUG_STATE64_COUNT);
            if (kr != KERN_SUCCESS) {
                brk_file_log("set_state thread=%u kr=%d\n", i, kr);
            }
        }
        mach_port_deallocate(task, threads[i]);
    }
    vm_deallocate(task, (vm_address_t)threads, count * sizeof(thread_act_t));
}

static void brk_publish(void) {
    arm_debug_state64_t desired;

    pthread_mutex_lock(&g_lock);
    brk_build_desired();
    desired = g_desired;
    pthread_mutex_unlock(&g_lock);

    task_set_state(mach_task_self(), ARM_DEBUG_STATE64, (thread_state_t)&desired,
                   ARM_DEBUG_STATE64_COUNT);
    brk_sync_threads(true);
}

static void *brk_sweep_thread(void *arg) {
    (void)arg;
    while (!g_sweep_stop) {
        usleep(BRK_SWEEP_US);
        brk_sync_threads(false);
    }
    return NULL;
}

static bool brk_init(void) {
    if (g_ready) return true;

    size_t sz = sizeof(g_slot_limit);
    int bp = 0;
    if (sysctlbyname("hw.optional.breakpoint", &bp, &sz, NULL, 0) == 0 && bp > 0) {
        g_slot_limit = bp;
    }
    if (g_slot_limit < 1) g_slot_limit = BRK_SLOT_DEFAULT;
    if (g_slot_limit > BRK_SLOT_CAP) g_slot_limit = BRK_SLOT_CAP;

    mach_port_t ports[EXC_TYPES_COUNT];
    exception_mask_t masks[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t port_count = EXC_TYPES_COUNT;
    memset(ports, 0, sizeof(ports));

    if (task_get_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, masks,
                                 &port_count, ports, behaviors,
                                 flavors) == KERN_SUCCESS && port_count > 0) {
        g_orig_port = ports[0];
    }

    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
                           &g_port) != KERN_SUCCESS) {
        brk_file_log("port_allocate_failed\n");
        return false;
    }
    if (mach_port_insert_right(mach_task_self(), g_port, g_port,
                               MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        brk_file_log("port_insert_failed\n");
        return false;
    }
    if (task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, g_port,
                                 EXCEPTION_STATE | MACH_EXCEPTION_CODES,
                                 ARM_THREAD_STATE64) != KERN_SUCCESS) {
        brk_file_log("set_exception_ports_failed\n");
        return false;
    }

    pthread_t th;
    if (pthread_create(&th, NULL, brk_exception_thread, NULL) != 0) {
        brk_file_log("exception_thread_failed\n");
        return false;
    }
    pthread_detach(th);

    g_ready = true;
    brk_file_log("init slot_limit=%d orig_port=%u\n", g_slot_limit, g_orig_port);

    if (!g_sweep_started) {
        g_sweep_started = true;
        pthread_t sweep;
        if (pthread_create(&sweep, NULL, brk_sweep_thread, NULL) == 0) {
            pthread_detach(sweep);
        }
    }
    return true;
}

static bool brk_register(uintptr_t target, uintptr_t replacement) {
    bool ok = false;
    int used = 0;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_entry_count; i++) {
        if (g_entries[i].used) used++;
    }
    for (int i = 0; i < g_entry_count; i++) {
        if (g_entries[i].used && g_entries[i].target == target) {
            g_entries[i].replacement = replacement;
            ok = true;
            break;
        }
    }
    if (!ok && used < g_slot_limit) {
        for (int i = 0; i < g_entry_count; i++) {
            if (!g_entries[i].used) {
                g_entries[i].target = target;
                g_entries[i].replacement = replacement;
                g_entries[i].used = true;
                ok = true;
                break;
            }
        }
        if (!ok && g_entry_count < BRK_MAX_HOOKS) {
            g_entries[g_entry_count].target = target;
            g_entries[g_entry_count].replacement = replacement;
            g_entries[g_entry_count].used = true;
            g_entry_count++;
            ok = true;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return ok;
}

bool brk_install(void *target, void *replacement) {
    if (target == NULL || replacement == NULL) return false;
    if (!brk_init()) return false;

    uintptr_t t = brk_strip(target);
    uintptr_t r = brk_strip(replacement);
    if (t == 0 || r == 0) return false;
    if (!brk_register(t, r)) {
        brk_file_log("install_rejected t=%p slot_limit=%d\n", (void *)t, g_slot_limit);
        return false;
    }

    brk_publish();
    brk_file_log("installed t=%p r=%p\n", (void *)t, (void *)r);
    return true;
}

bool brk_remove(void *target) {
    if (target == NULL) return false;

    uintptr_t t = brk_strip(target);
    bool found = false;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_entry_count; i++) {
        if (g_entries[i].used && g_entries[i].target == t) {
            g_entries[i].used = false;
            g_entries[i].target = 0;
            g_entries[i].replacement = 0;
            found = true;
        }
    }
    pthread_mutex_unlock(&g_lock);

    if (found) {
        brk_publish();
        brk_file_log("removed t=%p\n", (void *)t);
    }
    return found;
}

bool brk_install_raw_slot(int slot, void *target, void *replacement) {
    (void)replacement;
    if (slot < 0 || slot >= BRK_SLOT_CAP) return false;
    if (!g_ready) brk_init();
    if (!g_ready) return false;

    task_t task = mach_task_self();
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(task, &threads, &count) != KERN_SUCCESS) return false;

    for (mach_msg_type_number_t i = 0; i < count; i++) {
        arm_debug_state64_t cur;
        mach_msg_type_number_t cur_cnt = ARM_DEBUG_STATE64_COUNT;
        if (thread_get_state(threads[i], ARM_DEBUG_STATE64,
                             (thread_state_t)&cur, &cur_cnt) == KERN_SUCCESS) {
            cur.__bvr[slot] = (uint64_t)target;
            cur.__bcr[slot] = (uint32_t)BRK_BCR_VALUE;
            thread_set_state(threads[i], ARM_DEBUG_STATE64,
                             (thread_state_t)&cur, ARM_DEBUG_STATE64_COUNT);
        }
        mach_port_deallocate(task, threads[i]);
    }
    vm_deallocate(task, (vm_address_t)threads, count * sizeof(thread_act_t));
    return true;
}

bool brk_remove_raw(void *target) {
    if (target == NULL) return false;
    uintptr_t t = (uintptr_t)target;

    task_t task = mach_task_self();
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(task, &threads, &count) != KERN_SUCCESS) return false;

    for (mach_msg_type_number_t i = 0; i < count; i++) {
        arm_debug_state64_t cur;
        mach_msg_type_number_t cur_cnt = ARM_DEBUG_STATE64_COUNT;
        if (thread_get_state(threads[i], ARM_DEBUG_STATE64,
                             (thread_state_t)&cur, &cur_cnt) == KERN_SUCCESS) {
            bool changed = false;
            for (int s = 0; s < BRK_SLOT_CAP; s++) {
                if (cur.__bvr[s] == (uint64_t)t) {
                    cur.__bvr[s] = 0;
                    cur.__bcr[s] = 0;
                    changed = true;
                }
            }
            if (changed) {
                thread_set_state(threads[i], ARM_DEBUG_STATE64,
                                 (thread_state_t)&cur, ARM_DEBUG_STATE64_COUNT);
            }
        }
        mach_port_deallocate(task, threads[i]);
    }
    vm_deallocate(task, (vm_address_t)threads, count * sizeof(thread_act_t));
    return true;
}

bool brk_arm_function_rva(uintptr_t image_base, uint64_t rva, void *replacement) {
    uintptr_t target = image_base + rva;
    if ((target & 3u) != 0) {
        brk_file_log("reject unaligned rva=0x%llx\n", (unsigned long long)rva);
        return false;
    }
    return brk_install((void *)target, replacement);
}

bool hook(void *oldArr[], void *newArr[], int count) {
    if (oldArr == NULL || newArr == NULL || count <= 0) return false;
    int done = 0;
    for (int i = 0; i < count; i++) {
        if (brk_install(oldArr[i], newArr[i])) done++;
    }
    return done == count;
}

bool unhook(void *oldArr[], int count) {
    if (oldArr == NULL || count <= 0) return false;
    int done = 0;
    for (int i = 0; i < count; i++) {
        if (brk_remove(oldArr[i])) done++;
    }
    return done == count;
}

void *brk_original_ptr(void *target) {
    if (target == NULL) return NULL;
    return brk_sign(brk_strip(target));
}

void brk_suspend_self(void) {
    arm_debug_state64_t empty;
    memset(&empty, 0, sizeof(empty));
    thread_t self = mach_thread_self();
    thread_set_state(self, ARM_DEBUG_STATE64, (thread_state_t)&empty,
                     ARM_DEBUG_STATE64_COUNT);
    mach_port_deallocate(mach_task_self(), self);
}

void brk_resume_self(void) {
    arm_debug_state64_t desired;
    pthread_mutex_lock(&g_lock);
    desired = g_desired;
    pthread_mutex_unlock(&g_lock);
    thread_t self = mach_thread_self();
    thread_set_state(self, ARM_DEBUG_STATE64, (thread_state_t)&desired,
                     ARM_DEBUG_STATE64_COUNT);
    mach_port_deallocate(mach_task_self(), self);
}

int brk_active_count(void) {
    int used = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_entry_count; i++) {
        if (g_entries[i].used) used++;
    }
    pthread_mutex_unlock(&g_lock);
    return used;
}

int brk_slot_limit(void) {
    if (!g_ready) brk_init();
    return g_slot_limit;
}

void brk_log_state(void) {
    brk_file_log("state active=%d limit=%d live=0x%x\n",
                 brk_active_count(), g_slot_limit, g_live_slots);
}

static volatile int g_selftest_hits = 0;

__attribute__((noinline)) static void brk_selftest_target(void) {
    g_selftest_hits = 100;
}

__attribute__((noinline)) static void brk_selftest_probe(void) {
    g_selftest_hits = 1;
}

bool brk_selftest(void) {
    if (!brk_init()) return false;

    void *target = (void *)&brk_selftest_target;
    void *probe = (void *)&brk_selftest_probe;
    if (!brk_install(target, probe)) {
        brk_file_log("selftest_install_failed\n");
        return false;
    }

    g_selftest_hits = 0;
    brk_selftest_target();
    int hits = g_selftest_hits;
    brk_remove(target);
    brk_file_log("selftest hits=%d\n", hits);
    return hits == 1;
}