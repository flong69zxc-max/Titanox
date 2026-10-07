#ifndef RECOIL_OBJC_H
#define RECOIL_OBJC_H

#include <stdint.h>
#include <objc/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*rcl_objc_body_t)(void);

int rcl_objc_arm(uintptr_t imageBase, const char *clsName, const char *selName, rcl_objc_body_t body);

#ifdef __cplusplus
}
#endif

#endif
