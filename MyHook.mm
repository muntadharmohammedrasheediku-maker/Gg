// MyHook.mm
// هوك شامل للحمايات على iOS — arm64 / arm64e (PAC-aware)
// نسخة no-jailbreak آمنة: تأجيل التثبيت حتى نهاية dyld

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <ptrauth.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <unistd.h>
#import <fcntl.h>
#import <sys/stat.h>
#import <dirent.h>
#import <string.h>
#import <stdarg.h>
#import <stdlib.h>
#import <stdio.h>
#import <signal.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>

// ============================================================
// بدائل غير متوفرة في iOS SDK
// ============================================================

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
#ifndef PT_TRACE_ME
#define PT_TRACE_ME 0
#endif
#ifndef CTL_KERN
#define CTL_KERN 1
#endif
#ifndef KERN_PROC
#define KERN_PROC 14
#endif
#ifndef KERN_PROC_PID
#define KERN_PROC_PID 1
#endif
#ifndef KERN_PROCARGS2
#define KERN_PROCARGS2 49
#endif

extern int ptrace(int request, pid_t pid, caddr_t addr, int data);
extern int fstatat(int fd, const char *path, struct stat *buf, int flag);

#include "Dobby.h"

// ============================================================
// 0. أدوات مساعدة
// ============================================================

static uintptr_t get_image_slide(const char *name) {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, name))
            return (uintptr_t)_dyld_get_image_vmaddr_slide(i);
    }
    return 0;
}

static uintptr_t get_image_base(const char *name) {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, name))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

static void *addr_from_vmaddr(const char *image, uintptr_t vmaddr) {
    uintptr_t slide = get_image_slide(image);
    return slide ? (void *)(slide + vmaddr) : NULL;
}

static void *addr_from_symbol(const char *sym) {
    void *h = dlopen(NULL, RTLD_NOW);
    return h ? dlsym(h, sym) : NULL;
}

// ============================================================
// 1. دعم PAC (arm64e)
// ============================================================

#if __arm64e__
static inline void *strip_pac(void *p) {
    return __builtin_ptrauth_strip(p, ptrauth_key_asia);
}
#else
#define strip_pac(p) (p)
#endif

// ============================================================
// 2. قوائم سوداء
// ============================================================

static const char *g_jb_paths[] = {
    "/Applications/Cydia.app", "/Applications/Sileo.app",
    "/Applications/Zebra.app", "/Applications/Installer.app",
    "/Applications/blackra1n.app", "/Applications/FakeCarrier.app",
    "/Applications/SBSettings.app", "/Applications/WinterBoard.app",
    "/Applications/IntelliScreen.app",
    "/Library/MobileSubstrate", "/usr/lib/libsubstrate.dylib",
    "/usr/lib/libsubstitute.dylib", "/usr/lib/substitute-inserter.dylib",
    "/etc/apt", "/etc/apt/sources.list", "/etc/apt/apt.conf.d",
    "/private/etc/apt", "/private/etc/ssh/sshd_config",
    "/var/lib/apt", "/var/lib/cydia", "/var/cache/apt",
    "/var/lib/dpkg/status", "/private/var/lib/dpkg/status",
    "/private/var/lib/apt", "/private/var/lib/cydia",
    "/private/var/stash", "/private/var/tmp/cydia.log",
    "/bin/bash", "/bin/sh", "/usr/bin/ssh", "/usr/sbin/sshd",
    "/usr/libexec/sftp-server", "/usr/libexec/cydia",
    "cydia://", "sileo://", "zbra://", "filza://", "undecimus://",
    "/var/jb", "/var/jb/usr", "/var/jb/Library",
    "/private/preboot/",
    "frida", "Frida", "gadget", "libfrida",
    "libhooker", "Substrate", "MobileSubstrate",
    NULL
};

static BOOL kw_match(const char *hay, const char **list) {
    if (!hay) return NO;
    for (int i = 0; list[i]; i++)
        if (strstr(hay, list[i])) return YES;
    return NO;
}

static BOOL is_jb_path(const char *p) {
    return kw_match(p, g_jb_paths);
}

// ============================================================
// 3. تجاوز كشف الجيلبريك — File I/O Layer
// ============================================================

static int (*orig_open)(const char *, int, ...) = NULL;
static int (*orig_openat)(int, const char *, int, ...) = NULL;
static int (*orig_access)(const char *, int) = NULL;
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int (*orig_fstatat)(int, const char *, struct stat *, int) = NULL;
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static DIR *(*orig_opendir)(const char *) = NULL;

static int hook_open(const char *p, int f, ...) {
    if (is_jb_path(p)) { errno = ENOENT; return -1; }
    mode_t m = 0;
    if (f & O_CREAT) {
        va_list ap; va_start(ap, f);
        m = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (!orig_open) { errno = ENOSYS; return -1; }
    return orig_open(p, f, m);
}
static int hook_openat(int fd, const char *p, int f, ...) {
    if (is_jb_path(p)) { errno = ENOENT; return -1; }
    mode_t m = 0;
    if (f & O_CREAT) {
        va_list ap; va_start(ap, f);
        m = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (!orig_openat) { errno = ENOSYS; return -1; }
    return orig_openat(fd, p, f, m);
}
static int hook_access(const char *p, int m) {
    if (is_jb_path(p)) { errno = ENOENT; return -1; }
    return orig_access ? orig_access(p, m) : -1;
}
static int hook_stat(const char *p, struct stat *s) {
    if (is_jb_path(p)) { errno = ENOENT; return -1; }
    return orig_stat ? orig_stat(p, s) : -1;
}
static int hook_lstat(const char *p, struct stat *s) {
    if (is_jb_path(p)) { errno = ENOENT; return -1; }
    return orig_lstat ? orig_lstat(p, s) : -1;
}
static int hook_fstatat(int fd, const char *p, struct stat *s, int f) {
    if (is_jb_path(p)) { errno = ENOENT; return -1; }
    return orig_fstatat ? orig_fstatat(fd, p, s, f) : -1;
}
static FILE *hook_fopen(const char *p, const char *m) {
    if (is_jb_path(p)) { errno = ENOENT; return NULL; }
    return orig_fopen ? orig_fopen(p, m) : NULL;
}
static DIR *hook_opendir(const char *p) {
    if (is_jb_path(p)) { errno = ENOENT; return NULL; }
    return orig_opendir ? orig_opendir(p) : NULL;
}

// ============================================================
// 4. تجاوز كشف المُحقّق
// ============================================================

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;
static int (*orig_ptrace)(int, pid_t, caddr_t, int) = NULL;

static int hook_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                       void *newp, size_t newlen) {
    if (!orig_sysctl) { errno = ENOSYS; return -1; }
    if (name && namelen >= 4 &&
        name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        int r = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
        if (r == 0 && oldp && oldlenp && *oldlenp >= sizeof(struct kinfo_proc)) {
            struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
            kp->kp_proc.p_flag &= ~P_TRACED;
            kp->kp_proc.p_flag |=  P_LP64;
            kp->kp_proc.p_oppid = 0;
        }
        return r;
    }
    if (name && namelen >= 3 && name[0] == CTL_KERN && name[1] == KERN_PROCARGS2) {
        if (oldp && oldlenp) memset(oldp, 0, *oldlenp);
        return 0;
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int hook_sysctlbyname(const char *n, void *o, size_t *ol, void *ni, size_t nl) {
    if (!orig_sysctlbyname) { errno = ENOSYS; return -1; }
    if (!n) return orig_sysctlbyname(n, o, ol, ni, nl);

    if (strcmp(n, "kern.proc.pid") == 0 || strcmp(n, "kern.procargs2") == 0) {
        if (o && ol) memset(o, 0, *ol);
        return 0;
    }
    if (strcmp(n, "kern.hv_vmm_present") == 0) {
        int zero = 0;
        if (o && ol && *ol >= sizeof(int)) {
            memcpy(o, &zero, sizeof(int));
            *ol = sizeof(int);
        }
        return 0;
    }
    return orig_sysctlbyname(n, o, ol, ni, nl);
}

static int hook_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    if (req == PT_DENY_ATTACH) return 0;
    return orig_ptrace ? orig_ptrace(req, pid, addr, data) : 0;
}

// ============================================================
// 5. Anti-Cheat SDK (AnoSDK / ACE)
// ============================================================

static int  (*orig_AnoSDKInit)(void *) = NULL;
static int   hook_AnoSDKInit(void *cfg) { return 0; }

static int  (*orig_AnoSDKIoctl)(int, void *, int) = NULL;
static int   hook_AnoSDKIoctl(int cmd, void *p, int n) { return 0; }

static int  (*orig_AnoSDKIoctlOld)(int, void *, int) = NULL;
static int   hook_AnoSDKIoctlOld(int cmd, void *p, int n) { return 0; }

static int  (*orig_AnoSDKGetReportData)(void *, int) = NULL;
static int   hook_AnoSDKGetReportData(void *p, int n) { return 0; }

static int  (*orig_AnoSDKGetReportData2)(void *, int, void *) = NULL;
static int   hook_AnoSDKGetReportData2(void *p, int n, void *o) { return 0; }

static int  (*orig_AnoSDKDelReportData)(void *) = NULL;
static int   hook_AnoSDKDelReportData(void *p) { return 0; }

static int  (*orig_AnoSDKSetUserInfo)(void *) = NULL;
static int   hook_AnoSDKSetUserInfo(void *u) { return 0; }

static void (*orig_AnoSDKOnPause)(void) = NULL;
static void  hook_AnoSDKOnPause(void) {}
static void (*orig_AnoSDKOnResume)(void) = NULL;
static void  hook_AnoSDKOnResume(void) {}

static int  (*orig_AnoSDKOnRecvData)(void *, int) = NULL;
static int   hook_AnoSDKOnRecvData(void *p, int n) { return 0; }

static int  (*orig_AnoSDKOnRecvSignature)(void *, int) = NULL;
static int   hook_AnoSDKOnRecvSignature(void *p, int n) { return 0; }

static int  (*orig_CheckSymbolSource)(void *) = NULL;
static int   hook_CheckSymbolSource(void *p) { return 0; }

// ============================================================
// 6. Crash Reporting (UQM / CrashSight / QAPM / TDM)
// ============================================================

// UQM
static void (*orig_UQM_SetUserValue)(void *, void *, void *) = NULL;
static void  hook_UQM_SetUserValue(void *a, void *b, void *c) {}

static void (*orig_UQM_SetCrashObserver)(void *) = NULL;
static void  hook_UQM_SetCrashObserver(void *p) {}

static int  (*orig_UQM_ReportException)(void) = NULL;
static int   hook_UQM_ReportException(void) { return 0; }

static void (*orig_UQM_SetCrashLogObserver)(void *) = NULL;
static void  hook_UQM_SetCrashLogObserver(void *p) {}

static void (*orig_UQM_ConfigTimeout)(int) = NULL;
static void  hook_UQM_ConfigTimeout(int t) {}

static int  (*orig_UQM_Init)(void *, bool, bool, void *) = NULL;
static int   hook_UQM_Init(void *p, bool a, bool b, void *c) { return 0; }

static void (*orig_UQM_LogInfo)(int, void *, void *) = NULL;
static void  hook_UQM_LogInfo(int i, void *a, void *b) {}

static void (*orig_UQM_SetAppId)(void *) = NULL;
static void  hook_UQM_SetAppId(void *p) {}

static void (*orig_UQM_SetUserId)(void *) = NULL;
static void  hook_UQM_SetUserId(void *p) {}

// CrashSight
static int  (*orig_CS_ReportStuck)(void) = NULL;
static int   hook_CS_ReportStuck(void) { return 0; }

static void (*orig_CS_TestOomCrash)(void) = NULL;
static void  hook_CS_TestOomCrash(void) {}

static void (*orig_CS_ReportLogInfo)(const char *, const char *) = NULL;
static void  hook_CS_ReportLogInfo(const char *a, const char *b) {}

static int  (*orig_CS_GetCrashThreadId)(void) = NULL;
static int   hook_CS_GetCrashThreadId(void) { return 0; }

static bool (*orig_CS_IsLastSessionCrash)(void) = NULL;
static bool  hook_CS_IsLastSessionCrash(void) { return false; }

static void (*orig_CS_SetUploadThreadNum)(int) = NULL;
static void  hook_CS_SetUploadThreadNum(int n) {}

static void (*orig_CS_ConfigCrashReporter)(int) = NULL;
static void  hook_CS_ConfigCrashReporter(int n) {}

static int  (*orig_CS_ReportExceptionJson)(void) = NULL;
static int   hook_CS_ReportExceptionJson(void) { return 0; }

static void (*orig_CS_SetCatchMultiSignal)(bool) = NULL;
static void  hook_CS_SetCatchMultiSignal(bool b) {}

static int  (*orig_CS_GetLastSessionUserId)(void *, int) = NULL;
static int   hook_CS_GetLastSessionUserId(void *p, int n) { return 0; }

// QAPM
static void (*orig_QAPM_Report)(void) = NULL;
static void  hook_QAPM_Report(void) {}

static void (*orig_QAPM_SenceCustomPref)(void) = NULL;
static void  hook_QAPM_SenceCustomPref(void) {}

static void (*orig_QAPM_SenceEI)(void) = NULL;
static void  hook_QAPM_SenceEI(void) {}

static void (*orig_QAPM_SencePI)(void) = NULL;
static void  hook_QAPM_SencePI(void) {}

// TDM
static const char *(*orig_TdmEventNameEi)(void) = NULL;
static const char *hook_TdmEventNameEi(void) { return NULL; }

static const char *(*orig_TdmEventNamePi)(void) = NULL;
static const char *hook_TdmEventNamePi(void) { return NULL; }

// ============================================================
// 7. تعطيل كشف تسجيل الشاشة
// ============================================================

static BOOL (*orig_isCaptured)(id, SEL) = NULL;
static BOOL hook_isCaptured(id self, SEL _cmd) { return NO; }

// ============================================================
// 8. تعطيل DNS الخبيث
// ============================================================

static void (*orig_WGGetHostByNameAsyncWithTag)(const char *, int, void *) = NULL;
static void hook_WGGetHostByNameAsyncWithTag(const char *h, int t, void *cb) {
    // نحجب الاستعلام بالكامل
}

// ============================================================
// 9. مساعد التثبيت
// ============================================================

static void hook_export(const char *name, void *repl, void **orig) {
    void *addr = addr_from_symbol(name);
    if (!addr) {
        *orig = NULL;
        return;
    }
    void *clean = strip_pac(addr);
    int r = DobbyHook(clean, repl, orig);
    if (r != 0) {
        *orig = NULL;
    }
}

static void hook_objc_method(const char *cls, const char *sel,
                             void *repl, void **orig) {
    Class c = objc_getClass(cls);
    if (!c) return;
    Method m = class_getInstanceMethod(c, sel_registerName(sel));
    if (!m) return;
    if (orig) *orig = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)repl);
}

// ============================================================
// 10. تثبيت الهوكات (يُستدعى متأخراً بعد انتهاء dyld)
// ============================================================

static void do_install_hooks(void) {
    // ---------- 1) كشف المُحقّق ----------
    hook_export("ptrace",       (void *)hook_ptrace,       (void **)&orig_ptrace);
    hook_export("sysctl",       (void *)hook_sysctl,       (void **)&orig_sysctl);
    hook_export("sysctlbyname", (void *)hook_sysctlbyname, (void **)&orig_sysctlbyname);

    // ---------- 2) Anti-Cheat SDK ----------
    hook_export("AnoSDKInit",            (void *)hook_AnoSDKInit,            (void **)&orig_AnoSDKInit);
    hook_export("AnoSDKIoctl",           (void *)hook_AnoSDKIoctl,           (void **)&orig_AnoSDKIoctl);
    hook_export("AnoSDKIoctlOld",        (void *)hook_AnoSDKIoctlOld,        (void **)&orig_AnoSDKIoctlOld);
    hook_export("AnoSDKGetReportData",   (void *)hook_AnoSDKGetReportData,   (void **)&orig_AnoSDKGetReportData);
    hook_export("AnoSDKGetReportData2",  (void *)hook_AnoSDKGetReportData2,  (void **)&orig_AnoSDKGetReportData2);
    hook_export("AnoSDKDelReportData",   (void *)hook_AnoSDKDelReportData,   (void **)&orig_AnoSDKDelReportData);
    hook_export("AnoSDKSetUserInfo",     (void *)hook_AnoSDKSetUserInfo,     (void **)&orig_AnoSDKSetUserInfo);
    hook_export("AnoSDKOnPause",         (void *)hook_AnoSDKOnPause,         (void **)&orig_AnoSDKOnPause);
    hook_export("AnoSDKOnResume",        (void *)hook_AnoSDKOnResume,        (void **)&orig_AnoSDKOnResume);
    hook_export("AnoSDKOnRecvData",      (void *)hook_AnoSDKOnRecvData,      (void **)&orig_AnoSDKOnRecvData);
    hook_export("AnoSDKOnRecvSignature", (void *)hook_AnoSDKOnRecvSignature, (void **)&orig_AnoSDKOnRecvSignature);
    hook_export("CheckSymbolSource",     (void *)hook_CheckSymbolSource,     (void **)&orig_CheckSymbolSource);

    // ---------- 3) UQM ----------
    hook_export("_ZN3UQM8UQMCrash12SetUserValueERKNS_9UQMStringES3_",
                (void *)hook_UQM_SetUserValue, (void **)&orig_UQM_SetUserValue);
    hook_export("_ZN3UQM8UQMCrash16SetCrashObserverEPNS_16UQMCrashObserverE",
                (void *)hook_UQM_SetCrashObserver, (void **)&orig_UQM_SetCrashObserver);
    hook_export("_ZN3UQM8UQMCrash18ReportExceptionPRVEiRKNS_9UQMStringES3_S3_RKNS_9UQMVectorINS_9UQMKVPairELj16EEES3_bi",
                (void *)hook_UQM_ReportException, (void **)&orig_UQM_ReportException);
    hook_export("_ZN3UQM8UQMCrash19SetCrashLogObserverEPNS_19UQMCrashLogObserverE",
                (void *)hook_UQM_SetCrashLogObserver, (void **)&orig_UQM_SetCrashLogObserver);
    hook_export("_ZN3UQM8UQMCrash24ConfigCrashHandleTimeoutEi",
                (void *)hook_UQM_ConfigTimeout, (void **)&orig_UQM_ConfigTimeout);
    hook_export("_ZN3UQM8UQMCrash4InitERKNS_9UQMStringEbbS3_",
                (void *)hook_UQM_Init, (void **)&orig_UQM_Init);
    hook_export("_ZN3UQM8UQMCrash7LogInfoEiRKNS_9UQMStringES3_",
                (void *)hook_UQM_LogInfo, (void **)&orig_UQM_LogInfo);
    hook_export("_ZN3UQM8UQMCrash8SetAppIdERKNS_9UQMStringE",
                (void *)hook_UQM_SetAppId, (void **)&orig_UQM_SetAppId);
    hook_export("_ZN3UQM8UQMCrash9SetUserIdERKNS_9UQMStringE",
                (void *)hook_UQM_SetUserId, (void **)&orig_UQM_SetUserId);

    // ---------- 4) CrashSight ----------
    hook_export("_ZN6GCloud10CrashSight21CrashSightMobileAgent11ReportStuckEiilPKcS3_S3_iS3_",
                (void *)hook_CS_ReportStuck, (void **)&orig_CS_ReportStuck);
    hook_export("_ZN6GCloud10CrashSight21CrashSightMobileAgent12TestOomCrashEv",
                (void *)hook_CS_TestOomCrash, (void **)&orig_CS_TestOomCrash);
    hook_export("_ZN6GCloud10CrashSight21CrashSightMobileAgent13ReportLogInfoEPKcS3_",
                (void *)hook_CS_ReportLogInfo, (void **)&orig_CS_ReportLogInfo);
    hook_export("_ZN6GCloud10CrashSight21CrashSightMobileAgent16GetCrashThreadIdEv",
                (void *)hook_CS_GetCrashThreadId, (void **)&orig_CS_GetCrashThreadId);
    hook_export("_ZN6GCloud10CrashSight21CrashSightMobileAgent18IsLastSessionCrashEv",
                (void *)hook_CS_IsLastSessionCrash, (void **)&orig_CS_IsLastSessionCrash);
    hook_export("_ZN6GCloud10CrashSight21CrashSightMobileAgent18SetUploadThreadNumEi",
                (void *)hook_CS_SetUploadThreadNum, (void **)&orig_CS_SetUploadThreadNum);
    hook_export("_ZN6GCloud10CrashSight21CrashSightMobileAgent19ConfigCrashReporterEi",
                (void *)hook_CS_ConfigCrashReporter, (void **)&orig_CS_ConfigCrashReporter);
    hook_export("_ZN6GCloud10CrashSight21CrashSightMobileAgent19ReportExceptionJsonEiPKcS3_S3_S3_iS3_",
                (void *)hook_CS_ReportExceptionJson, (void **)&orig_CS_ReportExceptionJson);
    hook_export("_ZN6GCloud10CrashSight21CrashSightMobileAgent19SetCatchMultiSignalEb",
                (void *)hook_CS_SetCatchMultiSignal, (void **)&orig_CS_SetCatchMultiSignal);
    hook_export("_ZN6GCloud10CrashSight21CrashSightMobileAgent20GetLastSessionUserIdEPvi",
                (void *)hook_CS_GetLastSessionUserId, (void **)&orig_CS_GetLastSessionUserId);

    // ---------- 5) QAPM / TDM ----------
    hook_export("QAPMReport",                (void *)hook_QAPM_Report,          (void **)&orig_QAPM_Report);
    hook_export("QAPMReportSenceCustomPref", (void *)hook_QAPM_SenceCustomPref, (void **)&orig_QAPM_SenceCustomPref);
    hook_export("QAPMReportSenceEI",         (void *)hook_QAPM_SenceEI,         (void **)&orig_QAPM_SenceEI);
    hook_export("QAPMReportSencePI",         (void *)hook_QAPM_SencePI,         (void **)&orig_QAPM_SencePI);
    hook_export("TdmEventNameEi",            (void *)hook_TdmEventNameEi,       (void **)&orig_TdmEventNameEi);
    hook_export("TdmEventNamePi",            (void *)hook_TdmEventNamePi,       (void **)&orig_TdmEventNamePi);

    // ---------- 6) DNS ----------
    hook_export("WGGetHostByNameAsyncWithTag",
                (void *)hook_WGGetHostByNameAsyncWithTag,
                (void **)&orig_WGGetHostByNameAsyncWithTag);

    // ---------- 7) File I/O (JB) ----------
    hook_export("open",    (void *)hook_open,    (void **)&orig_open);
    hook_export("openat",  (void *)hook_openat,  (void **)&orig_openat);
    hook_export("access",  (void *)hook_access,  (void **)&orig_access);
    hook_export("stat",    (void *)hook_stat,    (void **)&orig_stat);
    hook_export("lstat",   (void *)hook_lstat,   (void **)&orig_lstat);
    hook_export("fstatat", (void *)hook_fstatat, (void **)&orig_fstatat);
    hook_export("fopen",   (void *)hook_fopen,   (void **)&orig_fopen);
    hook_export("opendir", (void *)hook_opendir, (void **)&orig_opendir);

    // ---------- 8) ObjC ----------
    hook_objc_method("UIScreen", "isCaptured",
                     (void *)hook_isCaptured, (void **)&orig_isCaptured);
}

// ============================================================
// 11. نقطة الدخول — آمنة no-jailbreak
// ============================================================

static void schedule_install(void) {
    // ننتظر حتى انتهاء تحميل dyld ثم نُثبّت
    dispatch_async(dispatch_get_main_queue(), ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            do_install_hooks();
        });
    });
}

__attribute__((constructor))
static void init_hooks(void) {
    // لا نلمس أي شيء هنا — فقط نجدول
    schedule_install();
}
