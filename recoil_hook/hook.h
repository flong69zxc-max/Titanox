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

int hook_probe(uintptr_t target);

bool brk_install(void *target, void *replacement);

bool brk_remove(void *target);

void *brk_original_ptr(void *target);

#ifdef __cplusplus
}
#endif

#endif
