#include "hook.h"
#include "mach_excServer.h"
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <os/log.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
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
} brk_entry_t;

static brk_entry_t g_entries[BRK_MAX_HOOKS];
static int g_entry_count = 0;
static mach_port_t g_port = MACH_PORT_NULL;
static mach_port_t g_orig_port = MACH_PORT_NULL;
static int g_slot_limit = BRK_SLOT_DEFAULT;
static bool g_ready = false;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static arm_debug_state64_t g_desired;
static int g_desired_slots = 0;
static volatile int g_sweep_stop = 0;
static bool g_sweep_started = false;

static os_log_t brk_channel(void) {
    static os_log_t ch = NULL;
    if (ch == NULL) {
        ch = os_log_create("com.titanox.brk", "hook");
    }
    return ch;
}

static void brk_log(const char *tag, uint64_t a, uint64_t b) {
    os_log_with_type(brk_channel(), OS_LOG_TYPE_DEFAULT,
                     "[titanox] %{public}s a=%{public}llu b=%{public}llu",
                     tag, (unsigned long long)a, (unsigned long long)b);
}

static uintptr_t brk_strip(const void *p) {
    if (p == NULL) {
        return 0;
    }
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

kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t codeCnt) {
    brk_log("exc_raise_identity", (uint64_t)exception, (uint64_t)codeCnt);
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t codeCnt, int *flavor, thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt, thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt) {
    brk_log("exc_raise_state_identity", (uint64_t)exception, (uint64_t)codeCnt);
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port, exception_type_t exception,
    const mach_exception_data_t code, mach_msg_type_number_t codeCnt,
    int *flavor, const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt, thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt) {

    arm_thread_state64_t *old_st = (arm_thread_state64_t *)old_state;
    arm_thread_state64_t *new_st = (arm_thread_state64_t *)new_state;

    uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(*old_st);
    uintptr_t dest = 0;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_entry_count; i++) {
        if (!g_entries[i].used) {
            continue;
        }
        if (g_entries[i].target == pc) {
            dest = g_entries[i].replacement;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);

    if (dest != 0) {
        *new_st = *old_st;
        *new_stateCnt = old_stateCnt;
        arm_thread_state64_set_pc_fptr(*new_st, brk_sign(dest));
        return KERN_SUCCESS;
    }

    if (g_orig_port != MACH_PORT_NULL) {
        return mach_msg_server(mach_exc_server,
                               sizeof(union __RequestUnion__catch_mach_exc_subsystem),
                               g_orig_port, MACH_MSG_OPTION_NONE);
    }

    brk_log("unhandled_breakpoint", (uint64_t)pc, (uint64_t)exception);
    return KERN_FAILURE;
}

static void *brk_exception_thread(void *arg) {
    for (;;) {
        mach_msg_server(mach_exc_server,
                        sizeof(union __RequestUnion__catch_mach_exc_subsystem),
                        g_port, MACH_MSG_OPTION_NONE);
    }
    return NULL;
}

static void brk_build_desired(void) {
    memset(&g_desired, 0, sizeof(g_desired));
    int slot = 0;
    for (int i = 0; i < g_entry_count; i++) {
        if (!g_entries[i].used) {
            continue;
        }
        if (slot >= g_slot_limit) {
            break;
        }
        g_desired.__bvr[slot] = (uint64_t)g_entries[i].target;
        g_desired.__bcr[slot] = (uint32_t)BRK_BCR_VALUE;
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
    if (task_threads(task, &threads, &count) != KERN_SUCCESS) {
        brk_log("task_threads_failed", 0, 0);
        return;
    }

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
            thread_set_state(threads[i], ARM_DEBUG_STATE64, (thread_state_t)&desired,
                             ARM_DEBUG_STATE64_COUNT);
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
    while (!g_sweep_stop) {
        usleep(BRK_SWEEP_US);
        brk_sync_threads(false);
    }
    return NULL;
}

static bool brk_init(void) {
    if (g_ready) {
        return true;
    }

    size_t sz = sizeof(g_slot_limit);
    int bp = 0;
    if (sysctlbyname("hw.optional.breakpoint", &bp, &sz, NULL, 0) == 0 && bp > 0) {
        g_slot_limit = bp;
    }
    if (g_slot_limit < 1) {
        g_slot_limit = BRK_SLOT_DEFAULT;
    }
    if (g_slot_limit > BRK_SLOT_CAP) {
        g_slot_limit = BRK_SLOT_CAP;
    }

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
        brk_log("port_allocate_failed", 0, 0);
        return false;
    }
    if (mach_port_insert_right(mach_task_self(), g_port, g_port,
                               MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        brk_log("port_insert_failed", 0, 0);
        return false;
    }
    if (task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, g_port,
                                 EXCEPTION_STATE | MACH_EXCEPTION_CODES,
                                 ARM_THREAD_STATE64) != KERN_SUCCESS) {
        brk_log("set_exception_ports_failed", 0, 0);
        return false;
    }

    pthread_t th;
    if (pthread_create(&th, NULL, brk_exception_thread, NULL) != 0) {
        brk_log("exception_thread_failed", 0, 0);
        return false;
    }
    pthread_detach(th);

    g_ready = true;
    brk_log("init", (uint64_t)g_slot_limit, (uint64_t)g_orig_port);

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
        if (g_entries[i].used) {
            used++;
        }
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
    if (target == NULL || replacement == NULL) {
        return false;
    }
    if (!brk_init()) {
        return false;
    }

    uintptr_t t = brk_strip(target);
    uintptr_t r = brk_strip(replacement);
    if (t == 0 || r == 0) {
        return false;
    }
    if (!brk_register(t, r)) {
        brk_log("install_rejected", t, (uint64_t)g_slot_limit);
        return false;
    }

    brk_publish();
    brk_log("installed", t, r);
    return true;
}

bool brk_remove(void *target) {
    if (target == NULL) {
        return false;
    }

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
        brk_log("removed", t, 0);
    }
    return found;
}

bool hook(void *old[], void *new[], int count) {
    if (old == NULL || new == NULL || count <= 0) {
        return false;
    }
    int done = 0;
    for (int i = 0; i < count; i++) {
        if (brk_install(old[i], new[i])) {
            done++;
        }
    }
    return done == count;
}

bool unhook(void *old[], int count) {
    if (old == NULL || count <= 0) {
        return false;
    }
    int done = 0;
    for (int i = 0; i < count; i++) {
        if (brk_remove(old[i])) {
            done++;
        }
    }
    return done == count;
}

void *brk_original_ptr(void *target) {
    if (target == NULL) {
        return NULL;
    }
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
        if (g_entries[i].used) {
            used++;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return used;
}

int brk_slot_limit(void) {
    if (!g_ready) {
        brk_init();
    }
    return g_slot_limit;
}

void brk_log_state(void) {
    brk_log("state_active", (uint64_t)brk_active_count(), (uint64_t)g_slot_limit);
}

static volatile int g_selftest_hits = 0;

__attribute__((noinline)) static void brk_selftest_target(void) {
    g_selftest_hits = 100;
}

__attribute__((noinline)) static void brk_selftest_probe(void) {
    g_selftest_hits = 1;
}

bool brk_selftest(void) {
    if (!brk_init()) {
        return false;
    }

    void *target = (void *)&brk_selftest_target;
    void *probe = (void *)&brk_selftest_probe;
    if (!brk_install(target, probe)) {
        brk_log("selftest_install_failed", 0, 0);
        return false;
    }

    g_selftest_hits = 0;
    brk_selftest_target();
    int hits = g_selftest_hits;
    brk_remove(target);
    brk_log("selftest", (uint64_t)hits, 0);
    return hits == 1;
}
