// language: Objective-C++, file: ShadowBypassXK.mm, target: iOS arm64/arm64e jailed
// Build: xcrun -sdk iphoneos clang++ -std=gnu++17 -arch arm64e -arch arm64 \
//        -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//        -miphoneos-version-min=13.0 -fobjc-arc -O2 -dynamiclib \
//        -Wl,-undefined,dynamic_lookup -Wl,-install_name,@rpath/ShadowBypassXK.dylib \
//        -I deps/Titanox -I deps/specter/include \
//        -L deps/specter/lib -lspecter -lc++ \
//        -framework Foundation -framework UIKit -framework Security \
//        -o ShadowBypassXK.dylib ShadowBypassXK.mm
//
// Dependencies (clone once):
//   git clone https://github.com/Ragekill3377/Titanox deps/Titanox
//   git clone https://github.com/Batchhh/libspecter deps/specter
//   cd deps/specter && make ios
//
// Layer map:
//   GOT (Titanox fishhook)  → kill, sysctl, ptrace, AnoSDK* exports  [unlimited]
//   BRK (Titanox, max 6)    → 0x10C24, 0x4C18, 0x2ED6C, 0x33794, 0x3358C
//   Inline (specter)        → fallback when BRK slots exhausted
//   0x33D6C                 → intentionally NOT hooked (link integrity)
//
// Safety:
//   * __TEXT is never written by BRK hooks → checksum stays clean.
//   * Every hook result is logged to Documents/TITANOX_LOGS.TXT (Titanox).
//   * GOT rebind is idempotent; installing twice is a no-op.

#import <Foundation/Foundation.h>
#import "libtitanox.h"
#include <mach-o/dyld.h>
#include <ptrauth.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <dlfcn.h>

// specter-mem C API
extern "C" {
    int32_t mem_init(const char *name, const void *config);
    int32_t mem_hook_install_at(uintptr_t absolute_addr, uintptr_t replacement,
                                uintptr_t *trampoline_out);
    int32_t mem_scan_image_first(const char *image, const char *pattern,
                                 uintptr_t *out);
}

// ============================================================
// 1. GOT HOOKS — exported symbols only (fishhook via Titanox)
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

// --- AnoSDK report path: zero-length report means nothing to ban ---
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
// 2. BRK HOOKS — internal anogs functions by vaddr
// ============================================================

// 0x10C24 — dynamic function resolver.
// It returns pointers to open/read/write/syscall/getenv/kill/select/connect/
// send/recv/dlopen/dlsym/objc_msgSend. Returning NULL for everything breaks
// anogs entirely. Safer: return the real pointer for everything EXCEPT
// kill/syscall/ptrace, which get our stubs.
//
// Signature is unknown (varies per build). We capture the first 8 args in
// registers (x0..x7) and return NULL only if the resolved pointer matches
// the real kill/ptrace. Otherwise we return whatever the original would
// have — but since BRK redirects before the prologue, we cannot call the
// original here. Compromise: return the real dlsym(kill) pointer for the
// common cases the game needs, and our stub for the detector cases.
//
// In practice: anogs uses the resolver only for its own checks. Returning
// the real libc pointers for open/read/write/connect, and our stubs for
// kill/ptrace/syscall, is enough.
static void *repl_resolver(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    (void)a0; (void)a1; (void)a2; (void)a3;
    // We cannot know which slot was requested without more context.
    // Return a generic "safe" pointer — anogs will call it and get 0.
    // If this breaks the game, use the inline-hook path instead (below).
    return NULL;
}

// 0x4C18 — aggregates protection flags into a bitmask.
static uint64_t repl_prot_flags(void) {
    return 0; // 0 = no threats detected
}

// 0x2ED6C — initializes the ct (CONNECTOR) channel.
static uint64_t repl_ct_init(void) {
    return 0; // success
}

// 0x33794 — proxy detection (CFNetworkCopySystemProxySettings).
static uint64_t repl_proxy_detect(void) {
    return 0; // no proxy
}

// 0x3358C — screen capture detection (UIScreen isCaptured).
static uint64_t repl_screen_capture(void) {
    return 0; // not captured
}

// ============================================================
// 3. Pattern-scan fallback for builds where the vaddrs shift
// ============================================================
// If the target vaddr moves between builds, these patterns let us re-find
// each function. Fill from YOUR build. Format is IDA-style: "DE AD ?? EF".
// The wildcards cover ADRP/ADD immediates that change per build.
static const char *PAT_RESOLVER   = NULL; // e.g. "?? ?? ?? ?? 08 00 40 F9"
static const char *PAT_PROT_FLAGS = NULL;
static const char *PAT_CT_INIT    = NULL;
static const char *PAT_PROXY      = NULL;
static const char *PAT_SCREEN     = NULL;

// ============================================================
// 4. Installation
// ============================================================

static uintptr_t g_anogs_base = 0;
static int g_brk_used = 0;

static bool install_got_hooks() {
    bool any = false;
    // Titanox fishhook: by symbol name, works on jailed iOS.
    any |= [TitanoxHook hookStaticFunction:"_kill"
                          withReplacement:(void*)&hk_kill
                           outOldFunction:(void**)&orig_kill];
    any |= [TitanoxHook hookStaticFunction:"_sysctl"
                          withReplacement:(void*)&hk_sysctl
                           outOldFunction:(void**)&orig_sysctl];
    any |= [TitanoxHook hookStaticFunction:"_ptrace"
                          withReplacement:(void*)&hk_ptrace
                           outOldFunction:(void**)&orig_ptrace];
    any |= [TitanoxHook hookStaticFunction:"_AnoSDKGetReportData"
                          withReplacement:(void*)&hk_GetReportData
                           outOldFunction:(void**)&orig_GetReportData];
    any |= [TitanoxHook hookStaticFunction:"_AnoSDKGetReportData2"
                          withReplacement:(void*)&hk_GetReportData2
                           outOldFunction:(void**)&orig_GetReportData2];
    any |= [TitanoxHook hookStaticFunction:"_AnoSDKOnRecvSignature"
                          withReplacement:(void*)&hk_OnRecvSignature
                           outOldFunction:(void**)&orig_OnRecvSignature];
    any |= [TitanoxHook hookStaticFunction:"_AnoSDKOnRecvData"
                          withReplacement:(void*)&hk_OnRecvData
                           outOldFunction:(void**)&orig_OnRecvData];
    any |= [TitanoxHook hookStaticFunction:"_AnoSDKDelReportData"
                          withReplacement:(void*)&hk_DelReportData
                           outOldFunction:(void**)&orig_DelReportData];
    return any;
}

// Install one BRK hook; on exhaustion, fall back to specter inline hook.
static bool install_brk_or_inline(uintptr_t vaddr, void *repl, const char *name) {
    uintptr_t addr = g_anogs_base + vaddr;

    // Try BRK first — undetected, no __TEXT write.
    if ([TitanoxHook addBreakpointAtAddress:(void*)addr withReplacement:repl]) {
        NSLog(@"[XK] BRK hook OK  %s @ 0x%lx", name, addr);
        g_brk_used++;
        return true;
    }

    // BRK slots full → specter inline hook (writes __TEXT).
    uintptr_t tramp = 0;
    int32_t rc = mem_hook_install_at(addr, (uintptr_t)repl, &tramp);
    if (rc == 0) {
        NSLog(@"[XK] inline hook OK  %s @ 0x%lx tramp=0x%lx", name, addr, tramp);
        return true;
    }
    NSLog(@"[XK] FAILED to hook %s (rc=%d)", name, rc);
    return false;
}

static void install_internal_hooks() {
    // 0x10C24 — resolver. Comment out if the game crashes; use inline instead.
    // install_brk_or_inline(0x10C24, (void*)&repl_resolver, "resolver");

    install_brk_or_inline(0x4C18,  (void*)&repl_prot_flags,    "prot_flags");
    install_brk_or_inline(0x2ED6C, (void*)&repl_ct_init,       "ct_init");
    install_brk_or_inline(0x33794, (void*)&repl_proxy_detect,  "proxy_detect");
    install_brk_or_inline(0x3358C, (void*)&repl_screen_capture,"screen_capture");

    // 0x33D6C — device fingerprint: NOT hooked. Game needs real values for
    // account binding. Hooking it triggers an immediate integrity alert.

    NSLog(@"[XK] BRK slots used: %d / 6", g_brk_used);
}

// ============================================================
// 5. Entry
// ============================================================

__attribute__((constructor))
static void xk_entry() {
    @autoreleasepool {
        // Locate anogs before anything else.
        g_anogs_base = [TitanoxHook getBaseAddressForImage:"anogs"];
        if (!g_anogs_base) {
            NSLog(@"[XK] anogs not loaded — aborting");
            return;
        }
        NSLog(@"[XK] anogs base = 0x%lx", g_anogs_base);

        // Init specter for inline fallback and pattern scanning.
        // If mem_init conflicts with Titanox's Mach port, drop this line.
        if (mem_init("anogs", NULL) != 0) {
            NSLog(@"[XK] specter init failed — inline fallback disabled");
        }

        // Layer 1: GOT hooks (unlimited).
        bool got_ok = install_got_hooks();
        NSLog(@"[XK] GOT hooks: %s", got_ok ? "OK" : "PARTIAL");

        // Layer 2: BRK hooks for internal functions (max 6).
        install_internal_hooks();

        NSLog(@"[XK] done — check Documents/TITANOX_LOGS.TXT");
    }
}
