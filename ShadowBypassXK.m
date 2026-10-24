// language: Objective-C++, file: ShadowBypassXK.mm, target: iOS arm64/arm64e jailed
// Build: xcrun -sdk iphoneos clang++ -std=gnu++17 -arch arm64e -arch arm64 \
//        -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//        -miphoneos-version-min=13.0 -fobjc-arc -O2 -dynamiclib \
//        -Wl,-undefined,dynamic_lookup \
//        -I deps/Titanox/libtitanox \
//        -I deps/Titanox/libtitanox/libtitanox \
//        -L deps/Titanox -ltitanox \
//        -framework Foundation -framework UIKit -framework Security \
//        -o ShadowBypassXK.dylib ShadowBypassXK.mm
//
// Titanox header MUST stay at deps/Titanox/libtitanox/libtitanox/libtitanox.h
// because its #imports are relative to that directory.

#import <Foundation/Foundation.h>
#import "libtitanox.h"
#include <mach-o/dyld.h>
#include <ptrauth.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <dlfcn.h>

// ============================================================
// GOT HOOKS (exported symbols — unlimited, safe)
// ============================================================

static int (*orig_kill)(pid_t, int) = NULL;
static int hk_kill(pid_t pid, int sig) {
    if (pid == getpid() && (sig == SIGKILL || sig == SIGSTOP || sig == SIGABRT))
        return 0;
    return orig_kill ? orig_kill(pid, sig) : -1;
}

static int (*orig_sysctl)(int*, u_int, void*, size_t*, void*, size_t) = NULL;
static int hk_sysctl(int *n, u_int nl, void *o, size_t *ol, void *nw, size_t nw2) {
    int rc = orig_sysctl ? orig_sysctl(n, nl, o, ol, nw, nw2) : -1;
    if (rc == 0 && n && nl >= 4 && o &&
        n[0] == CTL_KERN && n[1] == KERN_PROC &&
        n[2] == KERN_PROC_PID && n[3] == getpid()) {
        struct kinfo_proc *kp = (struct kinfo_proc*)o;
        if (kp) kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return rc;
}

static int (*orig_ptrace)(int, pid_t, caddr_t, int) = NULL;
static int hk_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    if (req == 31) return 0; // PT_DENY_ATTACH
    return orig_ptrace ? orig_ptrace(req, pid, addr, data) : -1;
}

static int (*orig_GetReportData)(void*, unsigned int*) = NULL;
static int hk_GetReportData(void *o, unsigned int *l) {
    if (o) memset(o, 0, l ? *l : 0);
    if (l) *l = 0;
    return 0;
}
static int (*orig_GetReportData2)(void*, unsigned int*) = NULL;
static int hk_GetReportData2(void *o, unsigned int *l) {
    if (o) memset(o, 0, l ? *l : 0);
    if (l) *l = 0;
    return 0;
}
static int (*orig_OnRecvSignature)(const char*, unsigned int) = NULL;
static int hk_OnRecvSignature(const char *s, unsigned int l) { (void)s; (void)l; return 0; }
static int (*orig_OnRecvData)(const char*, unsigned int) = NULL;
static int hk_OnRecvData(const char *d, unsigned int l) { (void)d; (void)l; return 0; }
static int (*orig_DelReportData)(void) = NULL;
static int hk_DelReportData(void) { return 0; }

// ============================================================
// INTERNAL HOOKS
// ============================================================

// 0x10C24 — dynamic resolver. Use the static-inline-hook API because it
// returns a trampoline we can call (BRK does not).
typedef void *(*resolver_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t);
static resolver_fn_t orig_resolver = NULL;

static void *hk_resolver(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    void *resolved = orig_resolver ? orig_resolver(a0, a1, a2, a3) : NULL;
    // Only swap the anti-debug primitives; leave everything else intact so
    // the game's own open/read/connect calls keep working.
    if (resolved == (void*)dlsym(RTLD_DEFAULT, "kill"))   return (void*)&hk_kill;
    if (resolved == (void*)dlsym(RTLD_DEFAULT, "ptrace")) return (void*)&hk_ptrace;
    if (resolved == (void*)dlsym(RTLD_DEFAULT, "sysctl")) return (void*)&hk_sysctl;
    return resolved;
}

// 0x4C18 / 0x2ED6C / 0x33794 / 0x3358C — return success/no-threat.
static uint64_t repl_prot_flags(void)      { return 0; }
static uint64_t repl_ct_init(void)         { return 0; }
static uint64_t repl_proxy_detect(void)    { return 0; }
static uint64_t repl_screen_capture(void)  { return 0; }

// 0x33D6C — intentionally NOT hooked (device fingerprint needed for binding).

// ============================================================
// INSTALLATION
// ============================================================

static uint64_t g_anogs_base = 0;
static int g_brk_used = 0;

static void install_got_hooks() {
    [TitanoxHook hookStaticFunction:"_kill"
                    withReplacement:(void*)&hk_kill
                          inLibrary:"libSystem.B.dylib"
                     outOldFunction:(void**)&orig_kill];
    [TitanoxHook hookStaticFunction:"_sysctl"
                    withReplacement:(void*)&hk_sysctl
                          inLibrary:"libSystem.B.dylib"
                     outOldFunction:(void**)&orig_sysctl];
    [TitanoxHook hookStaticFunction:"_ptrace"
                    withReplacement:(void*)&hk_ptrace
                          inLibrary:"libSystem.B.dylib"
                     outOldFunction:(void**)&orig_ptrace];

    [TitanoxHook hookStaticFunction:"_AnoSDKGetReportData"
                    withReplacement:(void*)&hk_GetReportData
                          inLibrary:"anogs"
                     outOldFunction:(void**)&orig_GetReportData];
    [TitanoxHook hookStaticFunction:"_AnoSDKGetReportData2"
                    withReplacement:(void*)&hk_GetReportData2
                          inLibrary:"anogs"
                     outOldFunction:(void**)&orig_GetReportData2];
    [TitanoxHook hookStaticFunction:"_AnoSDKOnRecvSignature"
                    withReplacement:(void*)&hk_OnRecvSignature
                          inLibrary:"anogs"
                     outOldFunction:(void**)&orig_OnRecvSignature];
    [TitanoxHook hookStaticFunction:"_AnoSDKOnRecvData"
                    withReplacement:(void*)&hk_OnRecvData
                          inLibrary:"anogs"
                     outOldFunction:(void**)&orig_OnRecvData];
    [TitanoxHook hookStaticFunction:"_AnoSDKDelReportData"
                    withReplacement:(void*)&hk_DelReportData
                          inLibrary:"anogs"
                     outOldFunction:(void**)&orig_DelReportData];

    NSLog(@"[XK] GOT: kill=%p sysctl=%p ptrace=%p AnoSDK=%p",
          (void*)orig_kill, (void*)orig_sysctl, (void*)orig_ptrace,
          (void*)orig_GetReportData);
}

static void install_brk(uintptr_t vaddr, void *repl, const char *name) {
    uintptr_t addr = g_anogs_base + vaddr;
    if ([TitanoxHook addBreakpointAtAddress:(void*)addr withHook:repl]) {
        NSLog(@"[XK] BRK OK  %s @ 0x%lx", name, addr);
        g_brk_used++;
    } else {
        NSLog(@"[XK] BRK FAILED  %s @ 0x%lx", name, addr);
    }
}

static void install_internal_hooks() {
    // 0x10C24 via static-inline-hook (needs a trampoline to call the original).
    // If inline hooking the resolver destabilises the game, comment this block
    // and rely on GOT hooks alone — the resolver will still return real kill/
    // ptrace pointers, but those already point at our GOT hooks, so the effect
    // is the same without touching __TEXT.
    TitanoxHook *hooker = [[TitanoxHook alloc] initWithMachOName:@"anogs"];
    if (hooker) {
        void *tramp = [hooker hookFunctionAtVaddr:(g_anogs_base + 0x10C24)
                                 withReplacement:(void*)&hk_resolver];
        if (tramp) {
            orig_resolver = (resolver_fn_t)tramp;
            NSLog(@"[XK] resolver inline-hooked, tramp=%p", tramp);
        } else {
            NSLog(@"[XK] resolver inline hook failed — relying on GOT only");
        }
    }

    // BRK hooks (max 6). Four here, leaving two spare.
    install_brk(0x4C18,  (void*)&repl_prot_flags,     "prot_flags");
    install_brk(0x2ED6C, (void*)&repl_ct_init,        "ct_init");
    install_brk(0x33794, (void*)&repl_proxy_detect,   "proxy_detect");
    install_brk(0x3358C, (void*)&repl_screen_capture, "screen_capture");

    // 0x33D6C — NOT hooked on purpose. Disabling the fingerprint breaks
    // account binding and fires an integrity alert on the server side.
    NSLog(@"[XK] BRK slots used: %d / 6", g_brk_used);
}

// ============================================================
// ENTRY
// ============================================================

__attribute__((constructor))
static void xk_entry() {
    @autoreleasepool {
        g_anogs_base = [TitanoxHook getBaseAddressOfLibrary:"anogs"];
        if (!g_anogs_base) {
            NSLog(@"[XK] anogs not loaded yet");
            return;
        }
        NSLog(@"[XK] anogs base = 0x%llx", g_anogs_base);

        install_got_hooks();
        install_internal_hooks();

        NSLog(@"[XK] done");
    }
}
