#ifndef TITANOX_HOOK_H
#define TITANOX_HOOK_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <mach/mach.h>

#ifdef __cplusplus
extern "C" {
#endif

FILE *titanox_log_handle(void);

void brk_diag_log(const char *format, ...);

void hook_set_error(const char *format, ...);

const char *hook_last_error(void);

bool hook_sign_check(uintptr_t address);

void hook_log_prot(const char *label, uintptr_t address);

bool hook_verify_encryption(void *image);

bool brk_install(void *target, void *replacement);

bool brk_observe(void *target);

bool brk_install_raw_slot(int slot, void *target, void *replacement);

bool brk_remove(void *target);

bool brk_remove_raw(void *target);

uint64_t brk_hits(void *target);

void hook_note_hit(void *target);

void *brk_original_ptr(void *target);

void brk_suspend_self(void);

void brk_resume_self(void);

int brk_slot_limit(void);

int brk_live_slot_count(void);

int brk_active_count(void);

bool brk_calibrate_slots(void);

int brk_next_slot(int after);

bool brk_selftest(void);

bool brk_selftest_at(uintptr_t hint);

void *brk_selftest_addr(void);

void hook_selftest_probe(void);

void brk_log_state(void);

int brk_census(uint64_t *outHits, uint64_t *outFails, int *outLive);

void brk_trace_exception(const char *label);

bool brk_host_is_livecontainer(void);

bool brk_chain_active(void);

mach_port_t brk_previous_port(void);

uint64_t brk_chain_counters(uint64_t *fails);

bool brk_arm_function_rva(uintptr_t imageBase, uintptr_t rva, void *replacement, void **outOriginal);

void brk_teardown(void);

bool hook(void *oldArr[], void *newArr[], int count);

bool unhook(void *oldArr[], int count);

#ifdef __cplusplus
}
#endif

#endif
