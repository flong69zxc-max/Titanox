#include <mach/mach.h>
#include <mach/vm_types.h>
#include <mach/arm/thread_status.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

extern bool brk_install(void *target, void *replacement);
extern bool brk_remove(void *target);

#define BRK_BCR_VALUE 0x1e5
#define BRK_SLOT_CAP  16

extern FILE *titanox_log_handle(void);
static void brk_file_log(const char *fmt, ...);

static volatile int g_probe_hits;

__attribute__((noinline)) static void brk_probe_target(void)
{
	g_probe_hits = 100;
}
__attribute__((noinline)) static void brk_probe_replacement(void)
{
	g_probe_hits = 1;
}

extern void *brk_selftest_addr(void);
extern bool  brk_install_raw_slot(int slot, void *target, void *replacement);
extern bool  brk_remove_raw(void *target);

static uint32_t g_live_slots;

bool brk_calibrate_slots(void)
{
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

int brk_live_slot_count(void)
{
	if (g_live_slots == 0) {
		brk_calibrate_slots();
	}
	return __builtin_popcount(g_live_slots);
}

int brk_next_slot(int after)
{
	for (int n = after + 1; n < BRK_SLOT_CAP; n++) {
		if (g_live_slots & (1u << n)) {
			return n;
		}
	}
	return -1;
}

int brk_census(uint64_t *bvr_out, int max_slots, int *threads_total)
{
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

	if (threads_total) {
		*threads_total = (int)count;
	}
	return 0;
}

void brk_trace_exception(uint64_t exception, uint64_t code0, uint64_t code1,
                         uint64_t pc, int matched_slot)
{
	brk_file_log("EXC type=%llu code0=0x%llx code1=0x%llx pc=%p slot=%d\n",
	             (unsigned long long)exception,
	             (unsigned long long)code0,
	             (unsigned long long)code1,
	             (void *)pc, matched_slot);
}

static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

static void brk_file_log(const char *fmt, ...)
{
	FILE *f = titanox_log_handle();
	if (!f) {
		return;
	}
	pthread_mutex_lock(&g_log_lock);
	fprintf(f, "[brk] ");
	va_list ap;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fflush(f);
	pthread_mutex_unlock(&g_log_lock);
}

bool brk_arm_function_rva(uintptr_t image_base, uint64_t rva, void *replacement)
{
	uintptr_t target = image_base + rva;
	if ((target & 3u) != 0) {
		brk_file_log("reject unaligned rva=0x%llx addr=%p\n",
		             (unsigned long long)rva, (void *)target);
		return false;
	}
	return brk_install((void *)target, replacement);
}