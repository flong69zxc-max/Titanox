#ifndef RECOIL_HOOK_H
#define RECOIL_HOOK_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <mach/mach.h>

#ifdef __cplusplus
extern "C" {
#endif



void hook_set_error(const char *format, ...);

const char *hook_last_error(void);

bool hook_sign_check(uintptr_t address);


bool hook_verify_encryption(void *image);

bool hook_code_patch_allowed(void);

int hook_pointer_count(void);

int hook_pointer_slots(void);

int hook_probe(uintptr_t target);

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









bool brk_host_is_livecontainer(void);




bool brk_arm_function_rva(uintptr_t imageBase, uintptr_t rva, void *replacement, void **outOriginal);

void brk_teardown(void);

bool hook(void *oldArr[], void *newArr[], int count);

bool unhook(void *oldArr[], int count);

#ifdef __cplusplus
}
#endif

#endif

