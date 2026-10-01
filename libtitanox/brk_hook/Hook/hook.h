#ifndef TITANOX_BRK_HOOK_H
#define TITANOX_BRK_HOOK_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

bool hook(void *oldArr[], void *newArr[], int count);
bool unhook(void *oldArr[], int count);

bool brk_install(void *target, void *replacement);
bool brk_remove(void *target);
bool brk_observe(void *target);
uint64_t brk_hits(void *target);

void *brk_original_ptr(void *target);
void brk_suspend_self(void);
void brk_resume_self(void);

int brk_active_count(void);
int brk_slot_limit(void);
bool brk_selftest(void);
void brk_log_state(void);

bool brk_calibrate_slots(void);
int brk_live_slot_count(void);
int brk_next_slot(int after);

int brk_census(
    uint64_t *expected_bvr,
    int max_slots,
    int *threads_total
);

void brk_trace_exception(
    uint64_t exception,
    uint64_t code0,
    uint64_t code1,
    uint64_t pc,
    int matched_slot
);

bool brk_arm_function_rva(
    uintptr_t image_base,
    uint64_t rva,
    void *replacement
);

bool brk_install_raw_slot(
    int slot,
    void *target,
    void *replacement
);

bool brk_remove_raw(void *target);
void *brk_selftest_addr(void);

FILE *titanox_log_handle(void);
void brk_diag_log(const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif