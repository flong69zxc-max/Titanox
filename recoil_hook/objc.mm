#include "objc.h"
#include "hook.h"

#include <stddef.h>
#include <stdlib.h>

#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

#define RCL_OBJC_HOOK_MAX 32
#define RCL_OBJC_WANTED_MAX 4

typedef struct {
    __unsafe_unretained Class cls;
    __unsafe_unretained Class wanted[RCL_OBJC_WANTED_MAX];
    int wantedCount;
    SEL sel;
    IMP original;
    IMP replacement;
    const char *selName;
    const char *signature;
    int hits;
    int used;
    rcl_objc_body_t body;
} rcl_objc_hook_t;

static rcl_objc_hook_t g_objc_hooks[RCL_OBJC_HOOK_MAX];

static uintptr_t rcl_objc_strip_imp(IMP imp) {
#if defined(__has_feature)
#if __has_feature(ptrauth_calls)
    return (uintptr_t)ptrauth_strip((void *)imp, ptrauth_key_function_pointer);
#endif
#endif
    return (uintptr_t)imp;
}

static const char *rcl_objc_skip_compound(const char *p) {
    char open = *p;
    char close = (open == '{') ? '}' : ((open == '(') ? ')' : ']');
    int depth = 0;

    while (*p) {
        if (*p == open) {
            depth++;
        } else if (*p == close) {
            depth--;
            if (depth == 0) {
                p++;
                break;
            }
        }

        p++;
    }

    return p;
}

static int rcl_objc_arg_types(const char *types, char *out, size_t capacity) {
    if (!types || !out || capacity < 8) return -1;

    size_t used = 0;
    const char *p = types;

    while (*p && (used + 1) < capacity) {
        while (*p >= '0' && *p <= '9') p++;
        if (!*p) break;

        char c = *p;

        if (c == 'r' || c == 'n' || c == 'N' || c == 'o' || c == 'O' || c == 'R' || c == 'V') {
            p++;
            continue;
        }

        if (c == '^') {
            p++;
            if (*p == '{' || *p == '(' || *p == '[') p = rcl_objc_skip_compound(p);
            out[used++] = '^';
            continue;
        }

        if (c == '{' || c == '(' || c == '[') {
            p = rcl_objc_skip_compound(p);
            out[used++] = 'X';
            continue;
        }

        out[used++] = c;
        p++;
    }

    out[used] = 0;

    return (int)used;
}

static int rcl_objc_class_owns(Class cls, SEL sel) {
    if (!cls || !sel) return 0;

    unsigned count = 0;
    Method *list = class_copyMethodList(cls, &count);

    if (!list) return 0;

    int found = 0;

    for (unsigned i = 0; i < count; i++) {
        if (method_getName(list[i]) == sel) {
            found = 1;
            break;
        }
    }

    free(list);

    return found;
}

static Class rcl_objc_owner(Class cls, SEL sel) {
    if (!cls || !sel) return Nil;

    for (Class c = cls; c; c = class_getSuperclass(c)) {
        if (rcl_objc_class_owns(c, sel)) return c;
    }

    return Nil;
}

static rcl_objc_hook_t *rcl_objc_find(id self, SEL _cmd) {
    Class start = object_getClass(self);

    if (!start) return NULL;

    rcl_objc_hook_t *bySelector = NULL;
    int bySelectorCount = 0;

    for (int i = 0; i < RCL_OBJC_HOOK_MAX; i++) {
        rcl_objc_hook_t *hook = &g_objc_hooks[i];

        if (!hook->used || hook->sel != _cmd) continue;

        bySelector = hook;
        bySelectorCount++;

        for (Class c = start; c; c = class_getSuperclass(c)) {
            if (c == hook->cls) return hook;
        }
    }

    if (bySelectorCount == 1) return bySelector;

    return NULL;
}

static int rcl_objc_targets(id self, rcl_objc_hook_t *hook) {
    if (!hook || hook->wantedCount <= 0) return 0;

    Class start = object_getClass(self);

    if (!start) return 0;

    for (int i = 0; i < hook->wantedCount; i++) {
        Class wanted = hook->wanted[i];

        if (!wanted) continue;

        for (Class c = start; c; c = class_getSuperclass(c)) {
            if (c == wanted) return 1;
        }
    }

    return 0;
}

static void rcl_objc_rep_a(id self, SEL _cmd) {
    rcl_objc_hook_t *hook = rcl_objc_find(self, _cmd);

    if (hook) hook->hits++;

    if (hook && hook->body && rcl_objc_targets(self, hook)) hook->body();

    if (hook && hook->original) {
        reinterpret_cast<void (*)(id, SEL)>(hook->original)(self, _cmd);
    }
}

static void rcl_objc_rep_b(id self, SEL _cmd, id a1) {
    rcl_objc_hook_t *hook = rcl_objc_find(self, _cmd);

    if (hook && hook->original) {
        reinterpret_cast<void (*)(id, SEL, id)>(hook->original)(self, _cmd, a1);
    }
}

static void rcl_objc_rep1b(id self, SEL _cmd, BOOL a1) {
    rcl_objc_hook_t *hook = rcl_objc_find(self, _cmd);

    if (hook && hook->original) {
        reinterpret_cast<void (*)(id, SEL, BOOL)>(hook->original)(self, _cmd, a1);
    }
}

static void rcl_objc_rep_c(id self, SEL _cmd, id a1, id a2) {
    rcl_objc_hook_t *hook = rcl_objc_find(self, _cmd);

    if (hook && hook->original) {
        reinterpret_cast<void (*)(id, SEL, id, id)>(hook->original)(self, _cmd, a1, a2);
    }
}

int rcl_objc_arm(uintptr_t imageBase, const char *clsName, const char *selName, rcl_objc_body_t body) {
    if (!imageBase || !clsName || !selName || !body) return 0;

    Class wanted = objc_getClass(clsName);

    if (!wanted) return 0;
    if (rcl_hook_image_base((uintptr_t)wanted) != imageBase) return 0;

    SEL sel = sel_registerName(selName);

    Class owner = rcl_objc_owner(wanted, sel);

    if (!owner) return 0;
    if (rcl_hook_image_base((uintptr_t)owner) != imageBase) return 0;

    Method method = class_getInstanceMethod(owner, sel);

    if (!method) return 0;
    if (!sel_isEqual(method_getName(method), sel)) return 0;

    const char *types = method_getTypeEncoding(method);

    if (!types) return 0;

    char args[10];
    int argc = rcl_objc_arg_types(types, args, sizeof(args));

    if (argc < 3) return 0;
    if (args[0] != 'v') return 0;

    IMP replacement = NULL;

    if (argc == 3) {
        replacement = reinterpret_cast<IMP>(rcl_objc_rep_a);
    } else if (argc == 4 && args[3] == '@') {
        replacement = reinterpret_cast<IMP>(rcl_objc_rep_b);
    } else if (argc == 4 && args[3] == 'B') {
        replacement = reinterpret_cast<IMP>(rcl_objc_rep1b);
    } else if (argc == 5 && args[3] == '@' && args[4] == '@') {
        replacement = reinterpret_cast<IMP>(rcl_objc_rep_c);
    } else {
        return 0;
    }

    for (int i = 0; i < RCL_OBJC_HOOK_MAX; i++) {
        if (!g_objc_hooks[i].used) continue;
        if (g_objc_hooks[i].cls != owner || g_objc_hooks[i].sel != sel) continue;

        return 0;
    }

    for (int i = 0; i < RCL_OBJC_HOOK_MAX; i++) {
        if (g_objc_hooks[i].used) continue;

        IMP previous = method_setImplementation(method, replacement);

        if (!previous) return 0;

        if (rcl_objc_strip_imp(previous) == rcl_objc_strip_imp(replacement)) {
            method_setImplementation(method, previous);
            return 0;
        }

        g_objc_hooks[i].used = 1;
        g_objc_hooks[i].cls = owner;
        g_objc_hooks[i].sel = sel;
        g_objc_hooks[i].original = previous;
        g_objc_hooks[i].replacement = replacement;
        g_objc_hooks[i].selName = selName;
        g_objc_hooks[i].signature = types;
        g_objc_hooks[i].hits = 0;
        g_objc_hooks[i].body = body;

        g_objc_hooks[i].wanted[0] = owner;
        g_objc_hooks[i].wantedCount = 1;

        return 1;
    }

    return 0;
}
