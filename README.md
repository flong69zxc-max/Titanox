# Titanox

Hooking library for jailed iOS. This copy has a reworked breakpoint hook.

## What is in here

Breakpoint hooks use hardware breakpoints (BRP registers) plus a Mach exception
port. Nothing is written into the target code, so this works on the `__TEXT` of a
signed binary. Six concurrent hooks, and a hook can call the original.

Also in the box: inline hook and patch (binary rewrite, needs re-signing), symbol
hooks via fishhook, ObjC swizzling, vtable hooks via MemX.

## Breakpoint hook

```cpp
#include "brk_hook/Hook/hook_wrapper.hpp"

static void (*orig_tick)(void *, float) = nullptr;

static void tick(void *self, float dt) {
    brk_suspend_self();
    if (orig_tick) orig_tick(self, dt);
    brk_resume_self();
}

void install(uintptr_t target) {
    orig_tick = (void (*)(void *, float))brk_original_ptr((void *)target);
    brk_install((void *)target, (void *)&tick);
}
```

`suspend_self` / `resume_self` only touch the calling thread. That is the whole
trick behind calling the original: with the breakpoints off for that thread, the
original address is an ordinary function again.

ObjC side:

```objc
[TitanoxHook addBreakpointAtAddress:target withHook:(void *)&tick];
[TitanoxHook breakpointSelfTest];
```

## Self test

`brk_selftest()` arms a breakpoint on a function, calls it, and checks whether the
replacement actually ran. On a jailed iOS 26/27 app that is the only honest way to
find out whether the mechanism is alive on the device. Call it once at startup and
look for `selftest` in `com.titanox.brk`.

## Build

```
cd libtitanox
make package
```

## Notes

- Breakpoint state lives in the BRP registers and is per thread. Threads created
  after install inherit it from the task; a 500 ms sweep picks up the rest.
- Six slots is the hardware limit. `brk_slot_limit()` reports what the device gives.
- Each breakpoint hook costs one exception round trip per call. Fine at 60 Hz, not
  fine inside a tight loop.
- Breakpoints that are not ours are forwarded to whatever handler was registered
  before us (debugger, crash reporter).
- On arm64e the addresses are PAC-stripped before they are written into DBGBVR, and
  `brk_original_ptr()` hands back a signed function pointer.

## Credits

rage for Titanox. Euclid Jan G. and Saagar Jha for the breakpoint hook. ElleKit for
the idea, LiveContainer for a shipped example of the same trick on iOS 26+.
