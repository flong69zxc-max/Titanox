#include "hook.h"
#include "mach_excServer.h"
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <mach-o/dyld_images.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

__thread int g_in_hook = 0;

extern void OXLogC(const char *tag, uint64_t a, uint64_t b);

kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t codeCnt) {
    OXLogC("EXC_RAISE_UNHANDLED", (uint64_t)exception, (uint64_t)codeCnt);
    abort();
}

kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code,
    mach_msg_type_number_t codeCnt, int *flavor,
    thread_state_t old_state, mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state, mach_msg_type_number_t *new_stateCnt) {
    OXLogC("EXC_RAISE_STATE_IDENTITY_UNHANDLED", (uint64_t)exception, (uint64_t)codeCnt);
    abort();
}

mach_port_t server;
static mach_port_t orig_handler_port = MACH_PORT_NULL;

struct hook { uintptr_t old; uintptr_t new; };
static struct hook hooks[16];
static int active_hooks = 0;
static arm_debug_state64_t g_debug_state = {};
static int g_debug_slots = 0;
static volatile int g_exc_count = 0;
static volatile int g_apply_count = 0;
static volatile int g_stop_timer = 0;

kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port, exception_type_t exception,
    const mach_exception_data_t code, mach_msg_type_number_t codeCnt,
    int *flavor, const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt, thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt) {

    arm_thread_state64_t *old = (arm_thread_state64_t *)old_state;
    arm_thread_state64_t *new = (arm_thread_state64_t *)new_state;

    uintptr_t pc_raw = (uintptr_t)arm_thread_state64_get_pc(*old);
    uintptr_t pc_fptr = (uintptr_t)arm_thread_state64_get_pc_fptr(*old);
    g_exc_count++;

    if (g_in_hook) {
        *new = *old;
        *new_stateCnt = old_stateCnt;
        arm_thread_state64_set_pc_fptr(*new, (void *)(uintptr_t)(pc_raw + 4));
        return KERN_SUCCESS;
    }

    OXLogC("EXC_RAW", (uint64_t)pc_raw, (uint64_t)g_exc_count);
    OXLogC("EXC_FPTR", (uint64_t)pc_fptr, (uint64_t)exception);

    for (int i = 0; i < active_hooks; ++i) {
        if (hooks[i].old == pc_raw) {
            OXLogC("EXC_MATCH_RAW", (uint64_t)pc_raw, (uint64_t)i);
        }
        if (hooks[i].old == pc_fptr) {
            OXLogC("EXC_MATCH_FPTR", (uint64_t)pc_fptr, (uint64_t)i);
        }
    }

    for (int i = 0; i < active_hooks; ++i) {
        uintptr_t target = hooks[i].old;
        if (target == pc_raw || target == pc_fptr) {
            OXLogC("EXC_DISPATCH", (uint64_t)target, (uint64_t)hooks[i].new);
            *new = *old;
            *new_stateCnt = old_stateCnt;
            arm_thread_state64_set_pc_fptr(*new, (void *)(uintptr_t)hooks[i].new);
            return KERN_SUCCESS;
        }
    }

    if (orig_handler_port != MACH_PORT_NULL) {
        return mach_msg_server(mach_exc_server,
                               sizeof(union __RequestUnion__catch_mach_exc_subsystem),
                               orig_handler_port, MACH_MSG_OPTION_NONE);
    }
    return KERN_FAILURE;
}

void *exception_handler(void *unused) {
    OXLogC("EXC_THREAD_STARTED", 0, 0);
    while (1) {
        mach_msg_server(mach_exc_server,
                        sizeof(union __RequestUnion__catch_mach_exc_subsystem),
                        server, MACH_MSG_OPTION_NONE);
    }
    return NULL;
}

static void read_back_debug_state(void) {
    arm_debug_state64_t back = {};
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(mach_thread_self(), ARM_DEBUG_STATE64,
                                         (thread_state_t)&back, &cnt);
    OXLogC("READBACK_KR", (uint64_t)kr, (uint64_t)cnt);
    for (int i = 0; i < 6; i++) {
        OXLogC("READBACK_SLOT", (uint64_t)back.__bvr[i], (uint64_t)back.__bcr[i]);
    }
}

static void dump_debug_state(const char *tag) {
    for (int i = 0; i < 6; i++) {
        OXLogC(tag, (uint64_t)g_debug_state.__bvr[i], (uint64_t)g_debug_state.__bcr[i]);
    }
}

static void apply_debug_state_to_all_threads(const char *why) {
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t tkr = task_threads(mach_task_self(), &threads, &thread_count);
    if (tkr != KERN_SUCCESS) {
        OXLogC("TASK_THREADS_FAIL", (uint64_t)tkr, 0);
        return;
    }
    int fail = 0, ok = 0;
    kern_return_t last_err = 0;
    for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
        kern_return_t kr = thread_set_state(threads[i], ARM_DEBUG_STATE64,
                                             (thread_state_t)&g_debug_state,
                                             ARM_DEBUG_STATE64_COUNT);
        if (kr == KERN_SUCCESS) ok++;
        else { fail++; last_err = kr; }
    }
    for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  thread_count * sizeof(*threads));

    g_apply_count++;
    if (g_apply_count <= 5 || (g_apply_count % 25) == 0) {
        OXLogC(why, (uint64_t)ok, (uint64_t)fail);
        if (fail) OXLogC("APPLY_LAST_ERR", (uint64_t)last_err, 0);
    }
}

static void *reapply_timer_thread(void *arg) {
    while (!g_stop_timer) {
        usleep(500 * 1000);
        apply_debug_state_to_all_threads("APPLY_TIMER");
    }
    return NULL;
}

static void start_reapply_timer(void) {
    static pthread_t t;
    static int started = 0;
    if (started) return;
    pthread_create(&t, NULL, reapply_timer_thread, NULL);
    started = 1;
    OXLogC("TIMER_STARTED", 0, 0);
}

static void verify_brk_instruction(uintptr_t addr) {
    uint32_t w = 0;
    vm_size_t outSize = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)addr, 4,
                                         (vm_address_t)&w, &outSize);
    OXLogC("VERIFY_BRK", (uint64_t)kr, (uint64_t)w);
}

bool hook(void *old[], void *new[], int count) {
    static bool initialized = false;
    static int breakpoints = 6;

    if (!initialized) {
        size_t size = sizeof(breakpoints);
        int r = sysctlbyname("hw.optional.breakpoint", &breakpoints, &size, NULL, 0);
        OXLogC("SYSCTL_BP", (uint64_t)breakpoints, (uint64_t)r);

        mach_port_t current_ports[EXC_TYPES_COUNT];
        mach_msg_type_number_t port_count = EXC_TYPES_COUNT;
        exception_mask_t masks[EXC_TYPES_COUNT];
        exception_behavior_t behaviors[EXC_TYPES_COUNT];
        thread_state_flavor_t flavors[EXC_TYPES_COUNT];

        kern_return_t kr0 = task_get_exception_ports(mach_task_self(),
                                                     EXC_MASK_BREAKPOINT,
                                                     masks, &port_count,
                                                     current_ports,
                                                     behaviors, flavors);
        OXLogC("GET_EXC_PORTS", (uint64_t)kr0, (uint64_t)port_count);
        if (kr0 == KERN_SUCCESS && port_count > 0) {
            orig_handler_port = current_ports[0];
            OXLogC("EXC_PORT_SAVED", (uint64_t)orig_handler_port,
                   (uint64_t)behaviors[0]);
        }

        kern_return_t kr1 = mach_port_allocate(mach_task_self(),
                                                MACH_PORT_RIGHT_RECEIVE, &server);
        OXLogC("PORT_ALLOC", (uint64_t)kr1, (uint64_t)server);

        kern_return_t kr2 = mach_port_insert_right(mach_task_self(), server, server,
                                                    MACH_MSG_TYPE_MAKE_SEND);
        OXLogC("PORT_INSERT", (uint64_t)kr2, 0);

        kern_return_t kr3 = task_set_exception_ports(mach_task_self(),
                                EXC_MASK_BREAKPOINT, server,
                                EXCEPTION_STATE | MACH_EXCEPTION_CODES,
                                ARM_THREAD_STATE64);
        OXLogC("SET_EXC_PORT", (uint64_t)kr3, 0);

        pthread_t thread;
        int pr = pthread_create(&thread, NULL, exception_handler, NULL);
        OXLogC("PTHREAD_CREATE", (uint64_t)pr, (uint64_t)thread);

        start_reapply_timer();
        initialized = true;
        OXLogC("HOOK_INIT_DONE", 0, 0);
    }

    if (g_debug_slots + count > breakpoints) {
        OXLogC("NO_SLOTS", (uint64_t)g_debug_slots, (uint64_t)count);
        return false;
    }

    for (int i = 0; i < count; i++) {
        int slot = g_debug_slots;
        uintptr_t target = (uintptr_t)old[i];
        uintptr_t dest = (uintptr_t)new[i];

        g_debug_state.__bvr[slot] = target;
        g_debug_state.__bcr[slot] = 0x1e5;

        hooks[active_hooks].old = target;
        hooks[active_hooks].new = dest;
        g_debug_slots++;
        active_hooks++;

        OXLogC("REGISTER_HOOK", (uint64_t)slot, target);
        verify_brk_instruction(target);
    }

    kern_return_t tkr = task_set_state(mach_task_self(), ARM_DEBUG_STATE64,
                                       (thread_state_t)&g_debug_state,
                                       ARM_DEBUG_STATE64_COUNT);
    OXLogC("TASK_SET_STATE", (uint64_t)tkr, (uint64_t)g_debug_slots);

    dump_debug_state("DUMP_BVR_BCR");

    apply_debug_state_to_all_threads("APPLY_INSTALL");

    read_back_debug_state();
    return true;
}

bool unhook(void *old[], int count) {
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < active_hooks; j++) {
            if (hooks[j].old == (uintptr_t)old[i]) {
                hooks[j] = hooks[active_hooks - 1];
                active_hooks--;
                break;
            }
        }
    }
    memset(&g_debug_state, 0, sizeof(g_debug_state));
    g_debug_slots = 0;
    for (int i = 0; i < active_hooks && i < 16; i++) {
        g_debug_state.__bvr[i] = hooks[i].old;
        g_debug_state.__bcr[i] = 0x1e5;
        g_debug_slots++;
    }
    task_set_state(mach_task_self(), ARM_DEBUG_STATE64,
                   (thread_state_t)&g_debug_state, ARM_DEBUG_STATE64_COUNT);
    apply_debug_state_to_all_threads("APPLY_UNHOOK");
    return true;
}