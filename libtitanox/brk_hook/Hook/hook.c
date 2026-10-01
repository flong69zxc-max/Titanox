#include "hook.h"
#include "mach_excServer.h"

#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

#define BRK_MAX 16
#define BRK_BCR 0x1e5ULL
#define BRK_VERIFY_MASK 0x1e1ULL
#define BRK_LOG_LIMIT (1024L * 1024L)
#define BRK_POLL_US 100000
#define BRK_PAUSED_MAX 64

typedef struct {
    uintptr_t target;
    uintptr_t replacement;
    uint64_t hits;
    bool used;
    bool armed;
    bool observe;
} brk_entry_t;

static brk_entry_t g_entries[BRK_MAX];
static uintptr_t g_owned_target[BRK_MAX];
static mach_port_t g_paused[BRK_PAUSED_MAX];

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static mach_port_t g_port = MACH_PORT_NULL;
static mach_port_t g_server_thread = MACH_PORT_NULL;
static mach_port_t g_sweep_thread = MACH_PORT_NULL;

static int g_physical_limit = 6;
static uint32_t g_live_mask = 0;
static bool g_ready = false;

static FILE *g_log = NULL;
static long g_log_bytes = 0;
static __thread unsigned g_pause_depth = 0;
static __thread mach_port_t g_pause_port = MACH_PORT_NULL;

static volatile int g_probe_value = 0;

static uintptr_t strip_pointer(const void *p)
{
#if __has_feature(ptrauth_calls)
    return (uintptr_t)ptrauth_strip(
        p,
        ptrauth_key_function_pointer
    );
#else
    return (uintptr_t)p;
#endif
}

static void *sign_pointer(uintptr_t p)
{
#if __has_feature(ptrauth_calls)
    return ptrauth_sign_unauthenticated(
        (void *)p,
        ptrauth_key_function_pointer,
        0
    );
#else
    return (void *)p;
#endif
}

static FILE *open_log_locked(void)
{
    if (g_log) return g_log;

    const char *home = getenv("HOME");
    char path[1024];

    if (home) {
        snprintf(
            path,
            sizeof(path),
            "%s/Documents/Titanox.log",
            home
        );
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

    if (f && g_log_bytes + (long)size + 7 <= BRK_LOG_LIMIT) {
        int written = fprintf(f, "[brk] %s\n", buffer);
        if (written > 0) g_log_bytes += written;
        fflush(f);
    }

    pthread_mutex_unlock(&g_log_lock);
}

static int task_port_status(void)
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

    if (kr != KERN_SUCCESS) return -1;

    int owned = 0;

    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        if (ports[i] == g_port &&
            (masks[i] & EXC_MASK_BREAKPOINT) &&
            behaviors[i] ==
                (exception_behavior_t)(EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES) &&
            flavors[i] == ARM_THREAD_STATE64) {
            owned = 1;
        }

        if (ports[i] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }

    return owned;
}

static int thread_port_status(mach_port_t thread)
{
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;

    kern_return_t kr = thread_get_exception_ports(
        thread,
        EXC_MASK_BREAKPOINT,
        masks,
        &count,
        ports,
        behaviors,
        flavors
    );

    if (kr != KERN_SUCCESS) return -1;

    int present = 0;

    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        if (ports[i] != MACH_PORT_NULL) {
            present = 1;
            mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }

    return present;
}

static bool is_paused_locked(mach_port_t thread)
{
    for (int i = 0; i < BRK_PAUSED_MAX; ++i) {
        if (g_paused[i] == thread) return true;
    }

    return false;
}

static bool merge_thread_locked(
    mach_port_t thread,
    bool allowArming)
{
    arm_debug_state64_t current;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;

    kern_return_t kr = thread_get_state(
        thread,
        ARM_DEBUG_STATE64,
        (thread_state_t)&current,
        &count
    );

    if (kr != KERN_SUCCESS || count != ARM_DEBUG_STATE64_COUNT) {
        return false;
    }

    arm_debug_state64_t next = current;
    bool changed = false;
    bool ok = true;

    for (int slot = 0; slot < BRK_MAX; ++slot) {
        if (!g_owned_target[slot]) continue;

        bool desired = allowArming &&
            g_entries[slot].used &&
            g_entries[slot].armed;

        bool enabled = (current.__bcr[slot] & 1ULL) != 0;
        uintptr_t present = (uintptr_t)current.__bvr[slot];

        bool ownValue =
            present == g_owned_target[slot] ||
            present == g_entries[slot].target;

        if (desired && enabled && !ownValue) {
            ok = false;
            continue;
        }

        if (desired) {
            next.__bvr[slot] = g_entries[slot].target;
            next.__bcr[slot] = BRK_BCR;
        } else if (ownValue) {
            next.__bvr[slot] = 0;
            next.__bcr[slot] = 0;
        } else {
            continue;
        }

        if (next.__bvr[slot] != current.__bvr[slot] ||
            ((next.__bcr[slot] ^ current.__bcr[slot]) &
                BRK_VERIFY_MASK)) {
            changed = true;
        }
    }

    if (!changed) return ok;

    kr = thread_set_state(
        thread,
        ARM_DEBUG_STATE64,
        (thread_state_t)&next,
        ARM_DEBUG_STATE64_COUNT
    );

    if (kr != KERN_SUCCESS) {
        return false;
    }

    arm_debug_state64_t readback;
    count = ARM_DEBUG_STATE64_COUNT;

    kr = thread_get_state(
        thread,
        ARM_DEBUG_STATE64,
        (thread_state_t)&readback,
        &count
    );

    if (kr != KERN_SUCCESS || count != ARM_DEBUG_STATE64_COUNT) {
        return false;
    }

    for (int slot = 0; slot < BRK_MAX; ++slot) {
        if (!g_owned_target[slot]) continue;

        bool desired = allowArming &&
            g_entries[slot].used &&
            g_entries[slot].armed;

        uintptr_t before = (uintptr_t)current.__bvr[slot];

        bool ownValue =
            before == g_owned_target[slot] ||
            before == g_entries[slot].target;

        if (!desired && !ownValue) continue;

        uint64_t wantedBVR =
            desired ? g_entries[slot].target : 0;

        uint64_t wantedBCR =
            desired ? BRK_BCR & BRK_VERIFY_MASK : 0;

        if (readback.__bvr[slot] != wantedBVR ||
            (readback.__bcr[slot] & BRK_VERIFY_MASK) != wantedBCR) {
            ok = false;
        }
    }

    return ok;
}

static bool sync_locked(void)
{
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;

    kern_return_t kr = task_threads(
        mach_task_self(),
        &threads,
        &count
    );

    if (kr != KERN_SUCCESS) return false;

    bool portOwned = task_port_status() == 1;
    bool ok = portOwned;

    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        bool service =
            threads[i] == g_server_thread ||
            threads[i] == g_sweep_thread;

        int threadPort = service ? 0 : thread_port_status(threads[i]);

        bool allow =
            portOwned &&
            !service &&
            threadPort == 0 &&
            !is_paused_locked(threads[i]);

        if (!service && threadPort != 0) {
            ok = false;
        }

        if (!merge_thread_locked(threads[i], allow)) ok = false;

        mach_port_deallocate(mach_task_self(), threads[i]);
    }

    vm_deallocate(
        mach_task_self(),
        (vm_address_t)threads,
        count * sizeof(thread_act_t)
    );

    return ok;
}

static void *exception_loop(void *arg)
{
    for (;;) {
        kern_return_t kr = mach_msg_server(
            mach_exc_server,
            sizeof(union __RequestUnion__catch_mach_exc_subsystem),
            g_port,
            MACH_MSG_OPTION_NONE
        );

        if (kr != KERN_SUCCESS) {
            usleep(10000);
        }
    }

    return NULL;
}

static void *sweep_loop(void *arg)
{
    for (;;) {
        usleep(BRK_POLL_US);

        pthread_mutex_lock(&g_lock);
        sync_locked();
        pthread_mutex_unlock(&g_lock);
    }

    return NULL;
}

static void init_once(void)
{
    int limit = 0;
    size_t size = sizeof(limit);

    if (sysctlbyname(
            "hw.optional.breakpoint",
            &limit,
            &size,
            NULL,
            0) == 0 && limit > 0) {
        g_physical_limit = limit;
    }

    if (g_physical_limit > BRK_MAX) g_physical_limit = BRK_MAX;
    if (g_physical_limit < 1) g_physical_limit = 1;

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

    if (kr != KERN_SUCCESS) {
        brk_diag_log("initial_exception_query_failed kr=%d", kr);
        return;
    }

    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        if (ports[i] != MACH_PORT_NULL) {
            brk_diag_log(
                "existing_task_exception_port port=%u behavior=%d flavor=%d",
                ports[i],
                behaviors[i],
                flavors[i]
            );

            mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }

    kr = mach_port_allocate(
        mach_task_self(),
        MACH_PORT_RIGHT_RECEIVE,
        &g_port
    );

    if (kr != KERN_SUCCESS) return;

    kr = mach_port_insert_right(
        mach_task_self(),
        g_port,
        g_port,
        MACH_MSG_TYPE_MAKE_SEND
    );

    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), g_port);
        g_port = MACH_PORT_NULL;
        return;
    }

    pthread_t server;

    if (pthread_create(&server, NULL, exception_loop, NULL) != 0) {
        mach_port_deallocate(mach_task_self(), g_port);
        g_port = MACH_PORT_NULL;
        return;
    }

    g_server_thread = pthread_mach_thread_np(server);
    pthread_detach(server);

    kr = task_set_exception_ports(
        mach_task_self(),
        EXC_MASK_BREAKPOINT,
        g_port,
        EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
        ARM_THREAD_STATE64
    );

    if (kr != KERN_SUCCESS) {
        brk_diag_log("set_exception_ports_failed kr=%d", kr);
        return;
    }

    g_live_mask = (1U << g_physical_limit) - 1U;
    g_ready = true;

    pthread_t sweep;

    if (pthread_create(&sweep, NULL, sweep_loop, NULL) == 0) {
        pthread_mutex_lock(&g_lock);
        g_sweep_thread = pthread_mach_thread_np(sweep);
        pthread_mutex_unlock(&g_lock);
        pthread_detach(sweep);
    }

    brk_diag_log(
        "init physical_limit=%d behavior=state_identity poll_us=%d",
        g_physical_limit,
        BRK_POLL_US
    );
}

static bool initialize(void)
{
    pthread_once(&g_once, init_once);
    return g_ready;
}

static bool register_slot(
    int requestedSlot,
    void *target,
    void *replacement,
    bool observe)
{
    if (!target || (!observe && !replacement)) return false;
    if (!initialize()) return false;

    uintptr_t t = strip_pointer(target);
    uintptr_t r = observe ? 0 : strip_pointer(replacement);

    if (!t || (t & 3U) || (!observe && (!r || (r & 3U)))) {
        return false;
    }

    pthread_mutex_lock(&g_lock);

    int slot = -1;

    for (int i = 0; i < BRK_MAX; ++i) {
        if (g_entries[i].used && g_entries[i].target == t) {
            slot = i;
            break;
        }
    }

    if (slot < 0 && requestedSlot >= 0) {
        if (requestedSlot < g_physical_limit &&
            !g_entries[requestedSlot].used) {
            slot = requestedSlot;
        }
    }

    if (slot < 0 && requestedSlot < 0) {
        for (int i = 0; i < g_physical_limit; ++i) {
            if ((g_live_mask & (1U << i)) && !g_entries[i].used) {
                slot = i;
                break;
            }
        }
    }

    if (slot < 0 ||
        (requestedSlot >= 0 && slot != requestedSlot)) {
        pthread_mutex_unlock(&g_lock);
        brk_diag_log("install_rejected target=%p", (void *)t);
        return false;
    }

    brk_entry_t previous = g_entries[slot];
    uintptr_t previousOwned = g_owned_target[slot];

    if (previousOwned && previousOwned != t) {
        g_entries[slot].armed = false;
        sync_locked();
    }

    g_entries[slot] = (brk_entry_t){
        .target = t,
        .replacement = r,
        .hits = 0,
        .used = true,
        .armed = true,
        .observe = observe
    };

    g_owned_target[slot] = t;

    bool ok = sync_locked();

    if (!ok) {
        g_entries[slot].armed = false;
        sync_locked();
        g_entries[slot] = previous;
        g_owned_target[slot] = previousOwned;
        sync_locked();
    }

    pthread_mutex_unlock(&g_lock);

    brk_diag_log(
        "install target=%p slot=%d mode=%s verified=%d",
        (void *)t,
        slot,
        observe ? "first_hit" : "replacement",
        ok
    );

    return ok;
}

kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt)
{
    mach_port_deallocate(mach_task_self(), thread);
    mach_port_deallocate(mach_task_self(), task);
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
    kern_return_t result = KERN_FAILURE;
    int matched = -1;

    if (exception != EXC_BREAKPOINT ||
        *flavor != ARM_THREAD_STATE64 ||
        old_stateCnt != ARM_THREAD_STATE64_COUNT ||
        *new_stateCnt < ARM_THREAD_STATE64_COUNT) {
        goto finish;
    }

    arm_thread_state64_t old;
    memcpy(&old, old_state, sizeof(old));
    uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(old);

    pthread_mutex_lock(&g_lock);

    for (int i = 0; i < BRK_MAX; ++i) {
        if (g_entries[i].used && g_entries[i].target == pc) {
            matched = i;
            break;
        }
    }

    if (matched >= 0) {
        brk_entry_t *entry = &g_entries[matched];
        arm_thread_state64_t next = old;

        entry->hits++;

        if (entry->observe) {
            entry->armed = false;
            sync_locked();

            if (merge_thread_locked(thread, false)) {
                memcpy(new_state, &next, sizeof(next));
                *new_stateCnt = ARM_THREAD_STATE64_COUNT;
                result = KERN_SUCCESS;
            }
        } else if (entry->armed) {
            arm_thread_state64_set_pc_fptr(
                next,
                sign_pointer(entry->replacement)
            );

            memcpy(new_state, &next, sizeof(next));
            *new_stateCnt = ARM_THREAD_STATE64_COUNT;
            result = KERN_SUCCESS;
        }
    }

    pthread_mutex_unlock(&g_lock);

finish:
    mach_port_deallocate(mach_task_self(), thread);
    mach_port_deallocate(mach_task_self(), task);

    return result;
}

bool brk_install(void *target, void *replacement)
{
    return register_slot(-1, target, replacement, false);
}

bool brk_observe(void *target)
{
    return register_slot(-1, target, NULL, true);
}

bool brk_install_raw_slot(int slot, void *target, void *replacement)
{
    return register_slot(slot, target, replacement, false);
}

bool brk_remove(void *target)
{
    if (!target || !initialize()) return false;

    uintptr_t t = strip_pointer(target);
    bool found = false;

    pthread_mutex_lock(&g_lock);

    for (int i = 0; i < BRK_MAX; ++i) {
        if (g_entries[i].used && g_entries[i].target == t) {
            g_entries[i].armed = false;
            g_entries[i].used = false;
            found = true;
        }
    }

    bool synced = sync_locked();

    pthread_mutex_unlock(&g_lock);

    brk_diag_log(
        "remove target=%p found=%d synced=%d",
        (void *)t,
        found,
        synced
    );

    return found && synced;
}

bool brk_remove_raw(void *target)
{
    return brk_remove(target);
}

uint64_t brk_hits(void *target)
{
    uintptr_t t = strip_pointer(target);
    uint64_t hits = 0;

    pthread_mutex_lock(&g_lock);

    for (int i = 0; i < BRK_MAX; ++i) {
        if (g_entries[i].used && g_entries[i].target == t) {
            hits = g_entries[i].hits;
            break;
        }
    }

    pthread_mutex_unlock(&g_lock);
    return hits;
}

__attribute__((noinline))
static void probe_target(void)
{
    g_probe_value = 100;
}

__attribute__((noinline))
static void probe_replacement(void)
{
    g_probe_value = 1;
}

void *brk_selftest_addr(void)
{
    return (void *)&probe_target;
}

bool brk_calibrate_slots(void)
{
    if (!initialize() || brk_active_count() != 0) return false;

    uint32_t mask = 0;

    for (int slot = 0; slot < g_physical_limit; ++slot) {
        g_probe_value = 0;

        bool installed = brk_install_raw_slot(
            slot,
            (void *)&probe_target,
            (void *)&probe_replacement
        );

        if (installed) {
            probe_target();

            if (g_probe_value == 1) mask |= 1U << slot;

            brk_remove((void *)&probe_target);
        }

        brk_diag_log(
            "calibration slot=%d installed=%d value=%d",
            slot,
            installed,
            g_probe_value
        );
    }

    pthread_mutex_lock(&g_lock);
    g_live_mask = mask;
    pthread_mutex_unlock(&g_lock);

    brk_diag_log(
        "calibration live_mask=0x%x live_count=%d",
        mask,
        __builtin_popcount(mask)
    );

    return mask != 0;
}

bool brk_selftest(void)
{
    if (!brk_install(
            (void *)&probe_target,
            (void *)&probe_replacement)) return false;

    g_probe_value = 0;
    probe_target();

    int value = g_probe_value;
    bool removed = brk_remove((void *)&probe_target);

    brk_diag_log(
        "selftest value=%d removed=%d",
        value,
        removed
    );

    return value == 1 && removed;
}

int brk_live_slot_count(void)
{
    if (!initialize()) return 0;

    pthread_mutex_lock(&g_lock);
    int count = __builtin_popcount(g_live_mask);
    pthread_mutex_unlock(&g_lock);

    return count;
}

int brk_slot_limit(void)
{
    return brk_live_slot_count();
}

int brk_next_slot(int after)
{
    if (!initialize()) return -1;
    if (after < -1) after = -1;
    if (after >= BRK_MAX - 1) return -1;

    pthread_mutex_lock(&g_lock);

    int result = -1;

    for (int i = after + 1; i < g_physical_limit; ++i) {
        if (g_live_mask & (1U << i)) {
            result = i;
            break;
        }
    }

    pthread_mutex_unlock(&g_lock);
    return result;
}

int brk_active_count(void)
{
    pthread_mutex_lock(&g_lock);

    int count = 0;

    for (int i = 0; i < BRK_MAX; ++i) {
        if (g_entries[i].used) count++;
    }

    pthread_mutex_unlock(&g_lock);
    return count;
}

void *brk_original_ptr(void *target)
{
    return target ? sign_pointer(strip_pointer(target)) : NULL;
}

void brk_suspend_self(void)
{
    if (!initialize()) return;
    if (g_pause_depth++) return;

    mach_port_t self = mach_thread_self();

    pthread_mutex_lock(&g_lock);

    int selected = -1;

    for (int i = 0; i < BRK_PAUSED_MAX; ++i) {
        if (g_paused[i] == MACH_PORT_NULL) {
            selected = i;
            break;
        }
    }

    if (selected >= 0) {
        g_paused[selected] = self;
        g_pause_port = self;
        merge_thread_locked(self, false);
    }

    pthread_mutex_unlock(&g_lock);

    if (selected < 0) {
        g_pause_depth = 0;
        mach_port_deallocate(mach_task_self(), self);
    }
}

void brk_resume_self(void)
{
    if (!g_pause_depth || --g_pause_depth) return;

    pthread_mutex_lock(&g_lock);

    for (int i = 0; i < BRK_PAUSED_MAX; ++i) {
        if (g_paused[i] == g_pause_port) {
            g_paused[i] = MACH_PORT_NULL;
            break;
        }
    }

    sync_locked();

    pthread_mutex_unlock(&g_lock);

    if (g_pause_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), g_pause_port);
        g_pause_port = MACH_PORT_NULL;
    }
}

void brk_log_state(void)
{
    if (!initialize()) {
        brk_diag_log("state initialization_failed");
        return;
    }

    pthread_mutex_lock(&g_lock);

    for (int slot = 0; slot < BRK_MAX; ++slot) {
        if (!g_entries[slot].used) continue;

        brk_diag_log(
            "entry slot=%d target=%p replacement=%p armed=%d observe=%d hits=%llu",
            slot,
            (void *)g_entries[slot].target,
            (void *)g_entries[slot].replacement,
            g_entries[slot].armed,
            g_entries[slot].observe,
            (unsigned long long)g_entries[slot].hits
        );
    }

    brk_diag_log(
        "state task_port_owned=%d",
        task_port_status()
    );

    pthread_mutex_unlock(&g_lock);
}

int brk_census(
    uint64_t *expected_bvr,
    int max_slots,
    int *threads_total)
{
    if (!expected_bvr || max_slots < 1) return -1;
    if (max_slots > BRK_MAX) max_slots = BRK_MAX;

    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;

    kern_return_t kr = task_threads(
        mach_task_self(),
        &threads,
        &count
    );

    if (kr != KERN_SUCCESS) return -1;

    int matchedThreads = 0;

    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        arm_debug_state64_t debug;
        mach_msg_type_number_t words = ARM_DEBUG_STATE64_COUNT;

        kr = thread_get_state(
            threads[i],
            ARM_DEBUG_STATE64,
            (thread_state_t)&debug,
            &words
        );

        bool matched = kr == KERN_SUCCESS;

        if (matched) {
            for (int slot = 0; slot < max_slots; ++slot) {
                if (!expected_bvr[slot]) continue;

                bool same =
                    debug.__bvr[slot] == expected_bvr[slot] &&
                    (debug.__bcr[slot] & BRK_VERIFY_MASK) ==
                        (BRK_BCR & BRK_VERIFY_MASK);

                if (!same) matched = false;
            }
        }

        if (matched) matchedThreads++;

        mach_port_deallocate(mach_task_self(), threads[i]);
    }

    vm_deallocate(
        mach_task_self(),
        (vm_address_t)threads,
        count * sizeof(thread_act_t)
    );

    if (threads_total) *threads_total = (int)count;

    return matchedThreads;
}

void brk_trace_exception(
    uint64_t exception,
    uint64_t code0,
    uint64_t code1,
    uint64_t pc,
    int matched_slot)
{
    brk_diag_log(
        "trace type=%llu code0=0x%llx code1=0x%llx pc=%p slot=%d",
        (unsigned long long)exception,
        (unsigned long long)code0,
        (unsigned long long)code1,
        (void *)(uintptr_t)pc,
        matched_slot
    );
}

bool brk_arm_function_rva(
    uintptr_t image_base,
    uint64_t rva,
    void *replacement)
{
    if (!rva || rva > UINTPTR_MAX - image_base) return false;

    return brk_install(
        (void *)(image_base + (uintptr_t)rva),
        replacement
    );
}

bool hook(void *oldArr[], void *newArr[], int count)
{
    if (!oldArr || !newArr || count < 1) return false;

    int installed = 0;

    for (; installed < count; ++installed) {
        if (!brk_install(oldArr[installed], newArr[installed])) break;
    }

    if (installed == count) return true;

    for (int i = 0; i < installed; ++i) brk_remove(oldArr[i]);

    return false;
}

bool unhook(void *oldArr[], int count)
{
    if (!oldArr || count < 1) return false;

    bool ok = true;

    for (int i = 0; i < count; ++i) {
        if (!brk_remove(oldArr[i])) ok = false;
    }

    return ok;
}