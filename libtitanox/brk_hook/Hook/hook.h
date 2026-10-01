#ifndef TITANOX_BRK_HOOK_H
#define TITANOX_BRK_HOOK_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool hook(void *oldArr[], void *newArr[], int count);
bool unhook(void *oldArr[], int count);

bool brk_install(void *target, void *replacement);
bool brk_remove(void *target);
void *brk_original_ptr(void *target);
void brk_suspend_self(void);
void brk_resume_self(void);
int brk_active_count(void);
int brk_slot_limit(void);
bool brk_selftest(void);
void brk_log_state(void);

#ifdef __cplusplus
}
#endif

#endif