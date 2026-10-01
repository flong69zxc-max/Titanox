#import "libtitanox.h"
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#import "../fishhook/fishhook.h"
#include "../brk_hook/Hook/hook_wrapper.hpp"
#import "../MemX/MemX.hpp"
#import "../MemX/VMTWrapper.h"
#import "../vm_funcs/vm.hpp"

extern "C" {
bool brk_chain_active(void);
bool brk_host_is_livecontainer(void);
mach_port_t brk_previous_port(void);
uint64_t brk_chain_counters(uint64_t *fails);
void brk_teardown(void);
}

static const char *TitanoxProtectedSymbols[] = {
    "_dyld_get_image_header",
    "_dyld_get_image_name",
    "_dyld_get_image_vmaddr_slide",
    "_dyld_image_count",
    "_dlopen",
    "_dlsym",
    "dyld_get_image_header",
    "dyld_get_image_name",
    "dyld_get_image_vmaddr_slide",
    "dyld_image_count",
    "dlopen",
    "dlsym",
    NULL
};

static BOOL TitanoxSymbolIsProtected(const char *symbol) {
    if (!symbol) return YES;

    const char *name = symbol;
    if (name[0] == '_') name++;

    for (int i = 0; TitanoxProtectedSymbols[i]; i++) {
        if (strcmp(symbol, TitanoxProtectedSymbols[i]) == 0) return YES;
        if (strcmp(name, TitanoxProtectedSymbols[i]) == 0) return YES;
    }

    return NO;
}

static BOOL TitanoxHostIsLiveContainer(void) {
    static int cached = -1;
    if (cached >= 0) return cached ? YES : NO;

    int found = 0;

    uint32_t count = _dyld_image_count();
    if (count > 8192) count = 8192;

    for (uint32_t i = 0; i < count && !found; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, "TweakLoader")) found = 1;
        else if (strstr(name, "LiveContainer")) found = 1;
        else if (strstr(name, "LiveContainerShared")) found = 1;
        else if (strstr(name, "CydiaSubstrate")) found = 1;
        else if (strstr(name, "libellekit")) found = 1;
    }

    if (!found) {
        NSString *identifier = [NSBundle mainBundle].bundleIdentifier;
        if (identifier &&
            [identifier rangeOfString:@"livecontainer"
                              options:NSCaseInsensitiveSearch].location != NSNotFound) {
            found = 1;
        }
    }

    if (!found && dlsym(RTLD_DEFAULT, "LiveContainerMain") != NULL) found = 1;

    cached = found;
    return found ? YES : NO;
}

static BOOL TitanoxHeaderIsValid(const struct mach_header *header) {
    if (!header) return NO;
    if (header->magic != MH_MAGIC_64 && header->magic != MH_MAGIC) return NO;
    if (header->ncmds == 0 || header->ncmds > 4096) return NO;
    return YES;
}

@implementation TitanoxHook : NSObject

#pragma mark - logging to TITANOX_LOGS.txt

+ (void)log:(NSString *)format, ... {
    va_list args;
    va_start(args, format);
    THLog(format, args);
    va_end(args);
}

+ (BOOL)isProtectedSymbol:(const char *)symbol {
    return TitanoxSymbolIsProtected(symbol);
}

+ (BOOL)isHostLiveContainer {
    return TitanoxHostIsLiveContainer();
}

#pragma mark - Base Address and VM Address Slide

uint64_t GetBaseAddress(const char* libName) {
    if (!libName) return 0;

    uint32_t count = _dyld_image_count();
    if (count > 8192) count = 8192;

    for (uint32_t i = 0; i < count; ++i) {
        const char* DyldName = _dyld_get_image_name(i);
        if (!DyldName) continue;
        if (strstr(DyldName, libName)) {
            const struct mach_header *header = _dyld_get_image_header(i);
            if (!TitanoxHeaderIsValid(header)) continue;
            return (uint64_t)header;
        }
    }
    return 0;
}

intptr_t GetVmAddrSlide(const char* libName) {
    if (!libName) return 0;

    uint32_t count = _dyld_image_count();
    if (count > 8192) count = 8192;

    for (uint32_t i = 0; i < count; ++i) {
        const char* DyldName = _dyld_get_image_name(i);
        if (!DyldName) continue;
        if (strstr(DyldName, libName)) {
            const struct mach_header *header = _dyld_get_image_header(i);
            if (!TitanoxHeaderIsValid(header)) continue;
            return _dyld_get_image_vmaddr_slide(i);
        }
    }
    return 0;
}

#pragma mark - Breakpoint hook

+ (BOOL)addBreakpointAtAddress:(void *)original withHook:(void *)hook {
    if (!original || !hook) {
        THLog(@"[ERROR] addBreakpointAtAddress: invalid params. original=%p, hook=%p", original, hook);
        return NO;
    }
    if (TitanoxHostIsLiveContainer()) {
        THLog(@"[BRK] host=livecontainer previous_port=%u chained=%d",
              (unsigned)brk_previous_port(), brk_chain_active() ? 1 : 0);
    }
    if (!HookWrapper::install(original, hook)) {
        THLog(@"[ERROR] brk_install failed for %p (slots %d/%d)", original, brk_active_count(), brk_slot_limit());
        return NO;
    }
    THLog(@"[BRK] hooked %p -> %p (%d/%d slots)", original, hook, brk_active_count(), brk_slot_limit());
    return YES;
}

#pragma mark - remove breakpoint (orig supported)

+ (BOOL)removeBreakpointAtAddress:(void *)original {
    if (!original) {
        THLog(@"[ERROR] removeBreakpointAtAddress: invalid param");
        return NO;
    }
    if (!HookWrapper::remove(original)) {
        THLog(@"[ERROR] no breakpoint at %p", original);
        return NO;
    }
    THLog(@"[BRK] unhooked %p (%d/%d slots)", original, brk_active_count(), brk_slot_limit());
    return YES;
}

+ (void *)originalPointerForBreakpoint:(void *)original {
    return original ? HookWrapper::originalPointer(original) : NULL;
}

+ (void)suspendBreakpoints {
    HookWrapper::suspendSelf();
}

+ (void)resumeBreakpoints {
    HookWrapper::resumeSelf();
}

+ (BOOL)breakpointSelfTest {
    return HookWrapper::selfTest() ? YES : NO;
}

+ (int)breakpointSlotLimit {
    return brk_slot_limit();
}

+ (void)releaseHostExceptionPort {
    brk_teardown();
}

+ (NSString *)findExecInBundle:(NSString *)libName {
    if (!libName || libName.length == 0) return nil;

    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSString *mainBundlePath = [[NSBundle mainBundle] bundlePath];
    if (!mainBundlePath) return nil;

    NSDirectoryEnumerator *enumerator = [fileManager enumeratorAtPath:mainBundlePath];
    if (!enumerator) return nil;

    for (NSString *filePath in enumerator) {
        if (!filePath) continue;
        if ([filePath.lastPathComponent isEqualToString:libName]) {
            return [mainBundlePath stringByAppendingPathComponent:filePath];
        }
    }

    return nil;
}

+ (uintptr_t)MemXgetImageBase:(NSString *)imageName {
    return MemX::GetImageBase([imageName UTF8String]);
}

+ (BOOL)MemXisValidPointer:(uintptr_t)address {
    return MemX::IsValidPointer(address);
}

+ (BOOL)MemXreadMemory:(uintptr_t)address buffer:(void *)buffer length:(size_t)len {
    if (!buffer) return NO;
    return MemX::_read(address, buffer, len);
}

+ (NSString *)MemXreadString:(uintptr_t)address maxLength:(size_t)maxLen {
    std::string value = MemX::ReadString((void *)address, maxLen);
    if (value.empty()) return nil;
    if (value == "Invalid Pointer!!") return nil;
    return [NSString stringWithUTF8String:value.c_str()];
}

+ (void)MemXwriteMemory:(uintptr_t)address value:(NSNumber *)value type:(NSString *)type {
    if (!value || !type) {
        THLog(@"[MemX] Invalid write request");
        return;
    }

    static NSDictionary<NSString *, NSNumber *> *typeMap;
    if (!typeMap) {
        typeMap = @{
            @"int"       : @0,
            @"long"      : @1,
            @"uintptr_t" : @2,
            @"uint32_t"  : @3,
            @"uint64_t"  : @4,
            @"uint8_t"   : @5
        };
    }

    switch (typeMap[type].intValue) {
        case 0: MemX::Write<int>(address, [value intValue]); break;
        case 1: MemX::Write<long>(address, [value longValue]); break;
        case 2: MemX::Write<uintptr_t>(address, (uintptr_t)[value unsignedLongLongValue]); break;
        case 3: MemX::Write<uint32_t>(address, [value unsignedIntValue]); break;
        case 4: MemX::Write<uint64_t>(address, [value unsignedLongLongValue]); break;
        case 5: MemX::Write<uint8_t>(address, [value unsignedCharValue]); break;
        default: THLog(@"[MemX] Unknown type: %@", type); break;
    }
}

+ (void)ClearAddrRanges {
    MemX::ClearAddrRange();
}

#pragma mark - MemX Virtual Function hooking stuff

+ (void *)vmthookCreateWithNewFunction:(void *)newFunc index:(int32_t)index {
    if (!newFunc) {
        THLog(@"[ERROR] vmthookCreateWithNewFunction: ERROR - newFunc is NULL");
        return NULL;
    }
    if (index < 0) {
        THLog(@"[ERROR] vmthookCreateWithNewFunction: ERROR - index (%d) is negative", index);
        return NULL;
    }
    THLog(@"[...] vmthookCreateWithNewFunction: Creating hook with newFunc=%p, index=%d", newFunc, index);
    void *makehook = VMTHook_Create(newFunc, index);
    if (!makehook) {
        THLog(@"[ERROR] vmthookCreateWithNewFunction: Failed to create hook");
    } else {
        THLog(@"[Success] vmthookCreateWithNewFunction: Hook created at %p", makehook);
    }
    return makehook;
}

+ (void)vmthookSwap:(void *)hook instance:(void *)instance {
    if (!hook) {
        THLog(@"[ERROR] vmthookSwap: ERROR - hook pointer is NULL");
        return;
    }
    if (!instance) {
        THLog(@"[ERROR] vmthookSwap: ERROR - instance pointer is NULL");
        return;
    }
    if (!MemX::IsValidPointer((uintptr_t)instance)) {
        THLog(@"[ERROR] vmthookSwap: instance %p is not inside a known image", instance);
        return;
    }
    THLog(@"[...] vmthookSwap: Swapping hook %p on instance %p", hook, instance);
    VMTHook_Swap(hook, instance);
    THLog(@"[Success] vmthookSwap: Swap complete");
}

+ (void)vmthookReset:(void *)hook instance:(void *)instance {
    if (!hook) {
        THLog(@"[ERROR] vmthookReset: ERROR - hook pointer is NULL");
        return;
    }
    if (!instance) {
        THLog(@"[ERROR] vmthookReset: ERROR - instance pointer is NULL");
        return;
    }
    if (!MemX::IsValidPointer((uintptr_t)instance)) {
        THLog(@"[ERROR] vmthookReset: instance %p is not inside a known image", instance);
        return;
    }
    THLog(@"[...] vmthookReset: Resetting hook %p on instance %p", hook, instance);
    VMTHook_Reset(hook, instance);
    THLog(@"[Success] vmthookReset: Reset complete");
}

+ (void)vmthookDestroy:(void *)hook {
    if (!hook) {
        THLog(@"[ERROR] vmthookDestroy: ERROR - hook pointer is NULL");
        return;
    }
    THLog(@"[...] vmthookDestroy: Destroying hook %p", hook);
    VMTHook_Destroy(hook);
    THLog(@"[Success] vmthookDestroy: Destroy complete");
}

+ (void *)vmtinvokerCreateWithInstance:(void *)instance index:(int32_t)index {
    if (!instance) {
        THLog(@"[ERROR] vmtinvokerCreateWithInstance: ERROR - instance pointer is NULL");
        return NULL;
    }
    if (index < 0) {
        THLog(@"[ERROR] vmtinvokerCreateWithInstance: ERROR - index (%d) is negative", index);
        return NULL;
    }
    if (!MemX::IsValidPointer((uintptr_t)instance)) {
        THLog(@"[ERROR] vmtinvokerCreateWithInstance: instance %p is not inside a known image", instance);
        return NULL;
    }
    THLog(@"[...] vmtinvokerCreateWithInstance: Creating invoker for instance %p, index %d", instance, index);
    void *callhookidk = VMTInvoker_Create(instance, index);
    if (!callhookidk) {
        THLog(@"[ERROR] vmtinvokerCreateWithInstance: Failed to create invoker");
    } else {
        THLog(@"[Success] vmtinvokerCreateWithInstance: Invoker created at %p", callhookidk);
    }
    return callhookidk;
}

+ (void)vmtinvokerDestroy:(void *)invoker {
    if (!invoker) {
        THLog(@"[ERROR] vmtinvokerDestroy: ERROR - invoker pointer is NULL");
        return;
    }
    THLog(@"[...] vmtinvokerDestroy: Destroying invoker %p", invoker);
    VMTInvoker_Destroy(invoker);
    THLog(@"[Success] vmtinvokerDestroy: Destroy complete");
}

#pragma mark - Static Inline Patch

- (instancetype)initWithMachOName:(NSString *)machoName {
    self = [super init];
    if (self) {
        if (!machoName || [machoName length] == 0) {
            return nil;
        }
        self->_machoName = machoName;
        std::string nameStr([machoName UTF8String]);
        _hooker = std::make_unique<SIH::MachOHooker>(nameStr);
        if (!_hooker) {
            return nil;
        }
    }
    return self;
}

- (NSString *)applyPatchAtVaddr:(uint64_t)vaddr patchBytes:(NSString *)patchHex {
    if (!_hooker) return @"<hooker not initialized>";
    if (!patchHex || [patchHex length] == 0) return @"<invalid patch>";
    std::string hexStr([patchHex UTF8String]);
    auto result = _hooker->apply_patch(vaddr, hexStr);
    if (result.has_value()) {
        return [NSString stringWithUTF8String:result->c_str()];
    }
    return @"<no result>";
}

- (void *)hookFunctionAtVaddr:(uint64_t)vaddr withReplacement:(void *)replacement {
    if (!_hooker || !replacement) return NULL;
    if (vaddr == 0) return NULL;
    return _hooker->hook_function(vaddr, replacement);
}

- (BOOL)activatePatchAtVaddr:(uint64_t)vaddr patchBytes:(NSString *)patchHex {
    if (!_hooker) return NO;
    if (!patchHex || [patchHex length] == 0) return NO;
    std::string hexStr([patchHex UTF8String]);
    return _hooker->activate_patch(vaddr, hexStr);
}

- (BOOL)deactivatePatchAtVaddr:(uint64_t)vaddr patchBytes:(NSString *)patchHex {
    if (!_hooker) return NO;
    if (!patchHex || [patchHex length] == 0) return NO;
    std::string hexStr([patchHex UTF8String]);
    return _hooker->deactivate_patch(vaddr, hexStr);
}

#pragma mark - Static Function Hooking

+ (void)hookStaticFunction:(const char *)symbol
         withReplacement:(void *)replacement
           inLibrary:(const char *)libName
        outOldFunction:(void **)oldFunction {

    if (!symbol || symbol[0] == 0 || !replacement) {
        THLog(@"[ERROR] hookStaticFunction: invalid arguments");
        return;
    }

    if (TitanoxSymbolIsProtected(symbol)) {
        THLog(@"[ERROR] hookStaticFunction: refusing to rebind protected symbol %s", symbol);
        return;
    }

    NSString *libNameString = [NSString stringWithUTF8String:libName];
    NSString *libPath = [self findExecInBundle:libNameString];

    if (!libPath) {
        THLog(@"[ERROR] library not found in bundle: %s", libName);
        return;
    }

    void *handle = dlopen([libPath UTF8String], RTLD_NOW | RTLD_NOLOAD);

    if (!handle) {
        THLog(@"Failed to open library: %s", libName);
        return;
    }

    void *symAddr = dlsym(handle, symbol);
    if (!symAddr) {
        THLog(@"Failed to resolve symbol %s before hooking", symbol);
        dlclose(handle);
        return;
    }

    if ([self isFunctionHooked:symbol withOriginal:symAddr inLibrary:libName]) {
        THLog(@"Warning: Function %s is already hooked.", symbol);
        dlclose(handle);
        return;
    }

    struct rebinding rebind;
    rebind.name = symbol;
    rebind.replacement = replacement;
    rebind.replaced = oldFunction;

    int result = rebind_symbols((struct rebinding[]){rebind}, 1);
    if (result != 0) {
        THLog(@"Failed to hook %s with error %d", symbol, result);
    } else {
        THLog(@"Successfully hooked %s", symbol);
    }
    dlclose(handle);
}

#pragma mark - Method Swizzling

+ (void)swizzleMethod:(SEL)originalSelector
          withMethod:(SEL)swizzledSelector
            inClass:(Class)targetClass {

    if (!originalSelector || !swizzledSelector || !targetClass) {
        THLog(@"[ERROR] swizzleMethod: invalid arguments");
        return;
    }

    Method originalMethod = class_getInstanceMethod(targetClass, originalSelector);
    Method swizzledMethod = class_getInstanceMethod(targetClass, swizzledSelector);

    if (!originalMethod || !swizzledMethod) {
        THLog(@"[ERROR] swizzleMethod: method not found on class");
        return;
    }

    BOOL didAddMethod = class_addMethod(targetClass,
                                        originalSelector,
                                        method_getImplementation(swizzledMethod),
                                        method_getTypeEncoding(swizzledMethod));

    if (didAddMethod) {
        class_replaceMethod(targetClass,
                            swizzledSelector,
                            method_getImplementation(originalMethod),
                            method_getTypeEncoding(originalMethod));
    } else {
        method_exchangeImplementations(originalMethod, swizzledMethod);
    }
}

#pragma mark - Method Overriding

+ (void)overrideMethodInClass:(Class)targetClass
                     selector:(SEL)selector
              withNewFunction:(IMP)newFunction
            oldFunctionPointer:(IMP *)oldFunctionPointer {

    if (!targetClass || !selector || !newFunction) {
        THLog(@"[ERROR] overrideMethodInClass: invalid arguments");
        return;
    }

    Method method = class_getInstanceMethod(targetClass, selector);

    if (!method) {
        THLog(@"[ERROR] overrideMethodInClass: method not found");
        return;
    }

    if (oldFunctionPointer) {
        *oldFunctionPointer = method_getImplementation(method);
    }

    method_setImplementation(method, newFunction);
}

#pragma mark - Memory Patching

+ (BOOL)readMemoryAt:(mach_vm_address_t)address buffer:(void *)buffer size:(mach_vm_size_t)size {
    if (!buffer || size == 0) return NO;
    return vm_read_custom(address, buffer, size);
}

+ (BOOL)writeMemoryAt:(mach_vm_address_t)address data:(const void *)data size:(mach_vm_size_t)size {
    if (!data || size == 0) return NO;
    return vm_write_custom(address, data, size);
}

+ (void *)allocateMemoryWithSize:(mach_vm_size_t)size flags:(int)flags {
    if (size == 0) return NULL;
    return vm_allocate_custom(size, flags);
}

+ (BOOL)deallocateMemoryAt:(mach_vm_address_t)address size:(mach_vm_size_t)size {
    if (address == 0 || size == 0) return NO;
    return vm_deallocate_custom(address, size);
}

+ (kern_return_t)protectMemoryAt:(mach_vm_address_t)address size:(mach_vm_size_t)size setMax:(BOOL)setMax protection:(vm_prot_t)newProt {
    if (address == 0 || size == 0) return KERN_INVALID_ARGUMENT;
    return vm_protect_custom(address, size, setMax, newProt);
}

+ (void)patchMemoryAtAddress:(void *)address
                   withPatch:(uint8_t*)patch
                       size:(size_t)size {

    if (!address || !patch || size == 0) {
        THLog(@"Invalid patch request.");
        return;
    }

    if (![self isSafeToPatchMemoryAtAddress:address length:size]) {
        THLog(@"Memory patching aborted: unsafe memory region at %p", address);
        return;
    }

    bool res = THPatchMem::PatchMemory(address, patch, size);

    if (res) {
        THLog(@"Memory patch succeeded at address %p", address);
    } else {
        THLog(@"Memory patch failed at address %p", address);
    }
}

#pragma mark - isHooked

+ (BOOL)isFunctionHooked:(const char *)symbol
           withOriginal:(void *)original
             inLibrary:(const char *)libName {

    if (!symbol || !original) return YES;

    Dl_info info;
    if (dladdr(original, &info)) {
        if (!info.dli_sname) return YES;

        NSString *libNameString = [NSString stringWithUTF8String:libName];
        NSString *libPath = [self findExecInBundle:libNameString];

        if (strcmp(info.dli_sname, symbol) == 0 &&
            (!libName || (libPath && info.dli_fname &&
             [libPath isEqualToString:[NSString stringWithUTF8String:info.dli_fname]]))) {
            return NO;
        }
    }
    return YES;
}

#pragma mark - Bool Hooking

+ (void)hookBoolByName:(const char *)symbol
             inLibrary:(const char *)libName {

    if (!symbol || symbol[0] == 0) {
        THLog(@"[ERROR] hookBoolByName: invalid symbol");
        return;
    }

    if (TitanoxSymbolIsProtected(symbol)) {
        THLog(@"[ERROR] hookBoolByName: refusing to touch protected symbol %s", symbol);
        return;
    }

    NSString *libNameString = [NSString stringWithUTF8String:libName];
    NSString *libPath = [self findExecInBundle:libNameString];

    if (!libPath) {
        THLog(@"[ERROR] library not found in bundle: %s", libName);
        return;
    }

    void *handle = dlopen([libPath UTF8String], RTLD_NOW | RTLD_NOLOAD);
    if (!handle) {
        THLog(@"Failed to open library: %s", libName);
        return;
    }

    bool *boolAddress = (bool *)dlsym(handle, symbol);
    if (!boolAddress) {
        THLog(@"Failed to find symbol: %s", symbol);
        dlclose(handle);
        return;
    }

    if (![self isSafeToPatchMemoryAtAddress:boolAddress length:sizeof(bool)]) {
        THLog(@"Memory patching aborted: unsafe memory region.");
        dlclose(handle);
        return;
    }

    *boolAddress = !*boolAddress;
    THLog(@"Successfully toggled bool %s in library %s to %d", symbol, libName, *boolAddress);

    dlclose(handle);
}

#pragma mark - Safety Checks

+ (BOOL)isSafeToPatchMemoryAtAddress:(void *)address
                              length:(size_t)length {

    if (!address || length == 0) {
        THLog(@"Error: Invalid memory address or length.");
        return NO;
    }

    vm_address_t regionStart = (vm_address_t)address;
    vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t objectName = MACH_PORT_NULL;

    if (vm_region_64(mach_task_self(), &regionStart, &regionSize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &infoCount, &objectName) != KERN_SUCCESS) {
        THLog(@"Error: Failed to get memory region info.");
        return NO;
    }

    if (objectName != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), objectName);
    }

    if (regionSize == 0) return NO;
    if ((uintptr_t)regionStart + (uintptr_t)regionSize < (uintptr_t)address + length) {
        THLog(@"Error: requested patch crosses the region boundary.");
        return NO;
    }

    if (info.protection & VM_PROT_EXECUTE) {
        THLog(@"Error: refusing to patch executable memory.");
        return NO;
    }

    return (info.protection & VM_PROT_WRITE) ? YES : NO;
}

#pragma mark - B.A & VM.ADDR.SLIDE

+ (uint64_t)getBaseAddressOfLibrary:(const char *)libName {
    return GetBaseAddress(libName);
}

+ (intptr_t)getVmAddrSlideOfLibrary:(const char *)libName {
    return GetVmAddrSlide(libName);
}

@end
