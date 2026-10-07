#pragma once

#include "hook.h"

class HookWrapper {
public:
    static bool callHook(void *origArray[], void *hookArray[], int count) {
        return hook(origArray, hookArray, count);
    }

    static bool callUnHook(void *origArray[], int count) {
        return unhook(origArray, count);
    }

    static bool install(void *target, void *replacement) {
        return brk_install(target, replacement);
    }

    static bool remove(void *target) {
        return brk_remove(target);
    }

    static void *originalPointer(void *target) {
        return brk_original_ptr(target);
    }

    static void suspendSelf(void) {
        brk_suspend_self();
    }

    static void resumeSelf(void) {
        brk_resume_self();
    }
};
