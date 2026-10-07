#ifndef RECOIL_HOOK_H
#define RECOIL_HOOK_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <mach/mach.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RCL_HOOK_MAX 64
#define RCL_HOOK_SLOTS_MAX 32

typedef struct {
    uintptr_t rva;
    void *replacement;
    int control;
} rcl_hook_t;

int rcl_hooks_install(uintptr_t imageBase, const rcl_hook_t *hooks, int count, void **originals);
int rcl_hooks_uninstall(void);
uintptr_t rcl_hook_image_base(uintptr_t address);

void hook_set_error(const char *format, ...);
const char *hook_last_error(void);

#ifdef __cplusplus
}
#endif

#endif
