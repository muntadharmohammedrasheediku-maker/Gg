// language: Objective-C++, file: ShadowBypassXK.mm, target: iOS arm64/arm64e jailed
// SAFE mode: GOT rebind only. No __TEXT modification, no hardware breakpoints.
// This cannot crash the game. BRK hooks are behind a compile-time switch.

#import <Foundation/Foundation.h>
#import "libtitanox.h"

#include <sys/sysctl.h>
#include <sys/types.h>
#include <mach-o/dyld.h>
#include <ptrauth.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <dlfcn.h>

#ifndef CTL_KERN
#define CTL_KERN 1
#endif
#ifndef KERN_PROC
#define KERN_PROC 14
#endif
#ifndef KERN_PROC_PID
#define KERN_PROC_PID 1
#endif
#ifndef P_TRACED
#define P_TRACED 0x00000800
#endif

// =====================================================================
// SAFETY SWITCH
// 0 = GOT only (safe, use this first)
// 1 = GOT + BRK hooks (only after verifying every vaddr in your build)
// =====================================================================
#define ENABLE_BRK_HOOKS 0
#define ENABLE_RESOLVER_INLINE 0

// ================== GOT hooks ==================
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
    if (req == 31) return 0;
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

// ================== BRK replacements (unused unless enabled) ==================
static uint64_t repl_prot_flags(void)      { return 0; }
static uint64_t repl_ct_init(void)         { return 0; }
static uint64_t repl_proxy_detect(void)    { return 0; }
static uint64_t repl_screen_capture(void)  { return 0; }

typedef void *(*resolver_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t);
static resolver_fn_t orig_resolver = NULL;
static void *hk_resolver(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    void *resolved = orig_resolver ? orig_resolver(a0, a1, a2, a3) : NULL;
    if (resolved == (void*)dlsym(RTLD_DEFAULT, "kill"))   return (void*)&hk_kill;
    if (resolved == (void*)dlsym(RTLD_DEFAULT, "ptrace")) return (void*)&hk_ptrace;
    if (resolved == (void*)dlsym(RTLD_DEFAULT, "sysctl")) return (void*)&hk_sysctl;
    return resolved;
}

// ================== installers ==================
static uint64_t g_anogs_base = 0;

static void install_got_hooks() {
    NSLog(@"[XK] enter install_got_hooks");
    [TitanoxHook hookStaticFunction:"_kill"
                    withReplacement:(void*)&hk_kill
                          inLibrary:"libSystem.B.dylib"
                     outOldFunction:(void**)&orig_kill];
    NSLog(@"[XK] kill done, orig=%p", (void*)orig_kill);

    [TitanoxHook hookStaticFunction:"_sysctl"
                    withReplacement:(void*)&hk_sysctl
                          inLibrary:"libSystem.B.dylib"
                     outOldFunction:(void**)&orig_sysctl];
    NSLog(@"[XK] sysctl done, orig=%p", (void*)orig_sysctl);

    [TitanoxHook hookStaticFunction:"_ptrace"
                    withReplacement:(void*)&hk_ptrace
                          inLibrary:"libSystem.B.dylib"
                     outOldFunction:(void**)&orig_ptrace];
    NSLog(@"[XK] ptrace done, orig=%p", (void*)orig_ptrace);

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

    NSLog(@"[XK] AnoSDK hooks: GetRep=%p GetRep2=%p RecvSig=%p RecvData=%p DelRep=%p",
          (void*)orig_GetReportData, (void*)orig_GetReportData2,
          (void*)orig_OnRecvSignature, (void*)orig_OnRecvData,
          (void*)orig_DelReportData);
}

#if ENABLE_BRK_HOOKS
// Verify target reads as a function prologue before arming a breakpoint.
static bool looks_like_prologue(uintptr_t addr) {
    uint32_t inst = 0;
    if (memcpy(&inst, (void*)addr, 4) != &inst) return false;
    // STP x29,x30,[sp,#-N]!  (standard prologue)
    if ((inst & 0xFFC07FFFu) == 0xA9807BFDu) return true;
    // PACIASP (arm64e leaf)
    if (inst == 0xD503233Fu) return true;
    // SUB sp, sp, #N
    if ((inst & 0xFFC003FFu) == 0xD10003FFu) return true;
    // MOV x29, sp
    if (inst == 0x910003FDu) return true;
    return false;
}

static void install_brk(uintptr_t vaddr, void *repl, const char *name) {
    uintptr_t addr = g_anogs_base + vaddr;
    if (!looks_like_prologue(addr)) {
        NSLog(@"[XK] SKIP %s @ 0x%lx (not a prologue)", name, addr);
        return;
    }
    if ([TitanoxHook addBreakpointAtAddress:(void*)addr withHook:repl]) {
        NSLog(@"[XK] BRK OK %s @ 0x%lx", name, addr);
    } else {
        NSLog(@"[XK] BRK FAILED %s @ 0x%lx", name, addr);
    }
}
#endif

__attribute__((constructor))
static void xk_entry() {
    @autoreleasepool {
        NSLog(@"[XK] === entry ===");

        g_anogs_base = [TitanoxHook getBaseAddressOfLibrary:"anogs"];
        if (!g_anogs_base) {
            NSLog(@"[XK] anogs not loaded — abort");
            return;
        }
        NSLog(@"[XK] anogs base = 0x%llx", g_anogs_base);

        install_got_hooks();
        NSLog(@"[XK] GOT complete");

#if ENABLE_RESOLVER_INLINE
        TitanoxHook *hooker = [[TitanoxHook alloc] initWithMachOName:@"anogs"];
        if (hooker) {
            void *tramp = [hooker hookFunctionAtVaddr:(g_anogs_base + 0x10C24)
                                     withReplacement:(void*)&hk_resolver];
            orig_resolver = (resolver_fn_t)tramp;
            NSLog(@"[XK] resolver tramp=%p", tramp);
        }
#endif

#if ENABLE_BRK_HOOKS
        install_brk(0x4C18,  (void*)&repl_prot_flags,     "prot_flags");
        install_brk(0x2ED6C, (void*)&repl_ct_init,        "ct_init");
        install_brk(0x33794, (void*)&repl_proxy_detect,   "proxy_detect");
        install_brk(0x3358C, (void*)&repl_screen_capture, "screen_capture");
#endif

        NSLog(@"[XK] === done ===");
    }
}
