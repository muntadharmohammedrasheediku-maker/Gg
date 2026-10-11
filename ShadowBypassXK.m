// ============================================================================
// ShadowBypass XK v7.10.5 — iOS 14+ arm64 — ملف واحد كامل
//
// إصلاح v7.10.5:
//   - استبدال CFHost (CFNetwork) بـ getaddrinfo (libc) لحل خطأ الربط
//   - إضافة #include <netdb.h>
//   - بقية الإصلاحات من v7.10.1 .. v7.10.4 محفوظة
// ============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <signal.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdint.h>
#import <stdatomic.h>
#import <dlfcn.h>
#import <sys/mman.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <netdb.h>
#import <arpa/inet.h>
#import <sys/socket.h>
#import <netinet/in.h>

// ============================================================================
// القسم 0: تشفير النصوص XOR
// ============================================================================

struct sbxk_ob {
    uint8_t  data[256];
    uint32_t len;
    uint32_t seed;
};

static struct sbxk_ob sbxk_enc(const char *s, uint32_t seed) {
    struct sbxk_ob o;
    memset(&o, 0, sizeof(o));
    size_t n = strlen(s) + 1;
    if (n > 255) n = 255;
    for (size_t i = 0; i < n; i++) {
        uint32_t k = seed + (uint32_t)i * 0x9E3779B1u;
        k ^= k >> 13; k *= 0x85EBCA6Bu; k ^= k >> 16;
        uint8_t b = (uint8_t)s[i];
        b = (uint8_t)((b << 3) | (b >> 5));
        o.data[i] = b ^ (uint8_t)k;
    }
    o.len = (uint32_t)n;
    o.seed = seed;
    return o;
}

static NSString *sbxk_dec(const struct sbxk_ob *o) {
    char buf[256];
    uint32_t n = o->len;
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t k = o->seed + (uint32_t)i * 0x9E3779B1u;
        k ^= k >> 13; k *= 0x85EBCA6Bu; k ^= k >> 16;
        uint8_t b = o->data[i] ^ (uint8_t)k;
        b = (uint8_t)((b >> 3) | (b << 5));
        buf[i] = (char)b;
    }
    buf[n ? n - 1 : 0] = 0;
    return [NSString stringWithUTF8String:buf];
}

#define SENS(s) (^NSString *{ \
    static struct sbxk_ob _ob; \
    static atomic_int _init = 0; \
    int _exp = 0; \
    if (atomic_compare_exchange_strong(&_init, &_exp, 1)) { \
        _ob = sbxk_enc(s, (uint32_t)(__LINE__ * 7919 + 31)); \
    } \
    return sbxk_dec(&_ob); \
}())

// ============================================================================
// القسم 0b: مضاد التصحيح
// ============================================================================

static inline void sbxk_antidebug_ptrace(void) {
    register long x0 __asm__("x0") = 31;
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x16 __asm__("x16") = 26;
    __asm__ volatile("svc #0x80"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x16)
                     : "memory");
}

static inline int sbxk_is_traced(void) {
    struct kinfo_proc info; memset(&info, 0, sizeof(info));
    size_t sz = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    if (sysctl(mib, 4, &info, &sz, NULL, 0) != 0) return 0;
    return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;
}

static inline void sbxk_antidebug_sysctl(void) {
    if (sbxk_is_traced()) __builtin_trap();
}

static inline void sbxk_antidebug_timing(void) {
    uint64_t t0 = mach_absolute_time();
    volatile int x = 0; for (int i = 0; i < 1000; i++) x += i; (void)x;
    if ((mach_absolute_time() - t0) > 100000000ull) __builtin_trap();
}

#define SBXK_ANTIDEBUG() do { \
    sbxk_antidebug_ptrace(); \
    sbxk_antidebug_sysctl(); \
    sbxk_antidebug_timing(); \
} while (0)

// ============================================================================
// القسم 1: متغيرات عامة
// ============================================================================

static atomic_int  g_phase       = 0;
static atomic_bool g_pending     = false;
static atomic_int  g_crash_fd    = -1;
static atomic_bool g_viewer_done = false;

#define SBXK_WLIT(fd, lit) do { \
    static const char _s[] = lit; \
    ssize_t _r = write((fd), _s, sizeof(_s) - 1); (void)_r; \
} while (0)

static void sbxk_wdec(int fd, long v) {
    if (fd < 0) return;
    char b[24]; int i = 0;
    if (v < 0) { SBXK_WLIT(fd, "-"); v = -v; }
    if (v == 0) { SBXK_WLIT(fd, "0"); return; }
    while (v > 0 && i < 23) { b[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i > 0) { char c = b[--i]; ssize_t _r = write(fd, &c, 1); (void)_r; }
}

static void sbxk_whex(int fd, const void *p) {
    if (fd < 0) return;
    uintptr_t v = (uintptr_t)p;
    static const char hx[] = "0123456789abcdef";
    SBXK_WLIT(fd, "0x");
    if (v == 0) { SBXK_WLIT(fd, "0"); return; }
    char b[20]; int i = 0;
    while (v > 0 && i < 19) { b[i++] = hx[v & 0xF]; v >>= 4; }
    while (i > 0) { char c = b[--i]; ssize_t _r = write(fd, &c, 1); (void)_r; }
}

// ============================================================================
// القسم 2: معالج الأعطال + حماية crash-loop
// ============================================================================

static void sbxk_on_signal(int sig, siginfo_t *info, void *ctx) {
    (void)ctx;
    int fd = atomic_load(&g_crash_fd);
    if (fd >= 0) {
        SBXK_WLIT(fd, "\n=== SBXK CRASH ===\n");
        SBXK_WLIT(fd, "signal="); sbxk_wdec(fd, sig); SBXK_WLIT(fd, "\n");
        SBXK_WLIT(fd, "phase=");  sbxk_wdec(fd, atomic_load(&g_phase)); SBXK_WLIT(fd, "\n");
        if (info) { SBXK_WLIT(fd, "si_addr="); sbxk_whex(fd, info->si_addr); SBXK_WLIT(fd, "\n"); }
        SBXK_WLIT(fd, "=== END CRASH ===\n");
    }
    @try {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        [d setInteger:(NSInteger)atomic_load(&g_phase) forKey:@"sbxk_last_phase"];
        [d synchronize];
    } @catch (__unused NSException *e) {}
}

static void sbxk_on_exception(NSException *e) {
    int fd = atomic_load(&g_crash_fd);
    if (fd < 0) return;
    SBXK_WLIT(fd, "\n=== SBXK EXCEPTION ===\n");
    @try {
        NSString *n = [e name], *r = [e reason];
        if (n) { SBXK_WLIT(fd, "name="); const char *s = n.UTF8String;
                 if (s) { ssize_t _r = write(fd, s, strlen(s)); (void)_r; } SBXK_WLIT(fd, "\n"); }
        if (r) { SBXK_WLIT(fd, "reason="); const char *s = r.UTF8String;
                 if (s) { ssize_t _r = write(fd, s, strlen(s)); (void)_r; } SBXK_WLIT(fd, "\n"); }
    } @catch (__unused NSException *ign) {}
    SBXK_WLIT(fd, "=== END EXCEPTION ===\n");
}

static char g_crash_path[512] = {0};
static char g_prev_path[512]  = {0};

static void SBXK_InitPaths(void) {
    NSString *d = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *c = [d stringByAppendingPathComponent:@"sbxk_crash.log"];
    NSString *p = [d stringByAppendingPathComponent:@"sbxk_crash_prev.log"];
    strncpy(g_crash_path, c.UTF8String, sizeof(g_crash_path) - 1);
    strncpy(g_prev_path,  p.UTF8String, sizeof(g_prev_path)  - 1);
}

static void SBXK_InstallCrashHandlers(void) {
    if (g_crash_path[0] == 0) return;
    int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    atomic_store(&g_crash_fd, fd);
    struct sigaction sa; memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sbxk_on_signal;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL); sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL); sigaction(SIGTRAP, &sa, NULL);
    NSSetUncaughtExceptionHandler(&sbxk_on_exception);
}

static void SBXK_RotateCrashLog(void) {
    if (g_crash_path[0] == 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *c = [NSString stringWithUTF8String:g_crash_path];
    NSString *p = [NSString stringWithUTF8String:g_prev_path];
    if (![fm fileExistsAtPath:c]) return;
    [fm removeItemAtPath:p error:nil];
    [fm moveItemAtPath:c toPath:p error:nil];
    int old = atomic_exchange(&g_crash_fd, -1);
    if (old >= 0) close(old);
    int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    atomic_store(&g_crash_fd, fd);
}

static BOOL sbxk_should_run(void) {
    @try {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        NSInteger attempts   = [d integerForKey:@"sbxk_boot_attempts"];
        NSInteger last_phase = [d integerForKey:@"sbxk_last_phase"];
        if (last_phase == 20 && attempts >= 3) {
            NSLog(@"[SBXK] 3 crashes at phase 20 — disabled this boot");
            return NO;
        }
        [d setInteger:attempts + 1 forKey:@"sbxk_boot_attempts"];
        [d synchronize];
    } @catch (__unused NSException *e) {}
    return YES;
}

static void sbxk_mark_ok(void) {
    @try {
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        [d setInteger:0 forKey:@"sbxk_boot_attempts"];
        [d setInteger:0 forKey:@"sbxk_last_phase"];
        [d synchronize];
    } @catch (__unused NSException *e) {}
}

// ============================================================================
// القسم 3: سجل الـswizzle
// ============================================================================

static NSMutableDictionary<NSString *, NSValue *> *g_orig = nil;
static NSMutableSet<NSString *> *g_done = nil;
static NSMutableSet<NSString *> *g_skip = nil;

static NSString *SBXK_KeyS(NSString *cls, NSString *sel) {
    return [NSString stringWithFormat:@"%@::%@", cls, sel];
}

static IMP SBXK_OriginalS(NSString *cls, NSString *sel) {
    if (!g_orig) return NULL;
    NSValue *v = g_orig[SBXK_KeyS(cls, sel)];
    return v ? (IMP)[v pointerValue] : NULL;
}

static BOOL SBXK_MethodIsOwn(Class c, SEL s) {
    if (!c || !s) return NO;
    unsigned int n = 0;
    Method *list = class_copyMethodList(c, &n);
    if (!list) return NO;
    BOOL found = NO;
    for (unsigned int i = 0; i < n; i++) if (method_getName(list[i]) == s) { found = YES; break; }
    free(list);
    return found;
}

static BOOL SBXK_SwizzleS(NSString *clsS, NSString *selS, IMP repl, const char *enc) {
    if (!clsS || !selS || !repl || !enc) return NO;
    NSString *key = SBXK_KeyS(clsS, selS);
    if ([g_done containsObject:key]) return YES;
    if ([g_skip containsObject:key]) return NO;

    const char *clsName = clsS.UTF8String;
    const char *selName = selS.UTF8String;

    Class c = objc_getClass(clsName);
    if (!c) return NO;

    SEL s = sel_registerName(selName);
    if (!s) { [g_skip addObject:key]; return NO; }

    Method instM = class_getInstanceMethod(c, s);
    Method clsM  = class_getClassMethod(c, s);
    Method m = NULL; BOOL own = NO; Class target = nil;

    if (instM && SBXK_MethodIsOwn(c, s)) { m = instM; own = YES; target = c; }
    else if (clsM && SBXK_MethodIsOwn(object_getClass(c), s)) { m = clsM; own = YES; target = object_getClass(c); }
    else if (instM) { m = instM; own = NO; target = c; }
    else if (clsM) { m = clsM; own = NO; target = object_getClass(c); }
    else { [g_skip addObject:key]; return NO; }

    const char *e = method_getTypeEncoding(m);
    if (!e || strcmp(e, enc) != 0) { [g_skip addObject:key]; return NO; }

    IMP orig = method_getImplementation(m);
    g_orig[key] = [NSValue valueWithPointer:orig];

    @try {
        if (own) class_replaceMethod(target, s, repl, e);
        else if (!class_addMethod(target, s, repl, e)) class_replaceMethod(target, s, repl, e);
        [g_done addObject:key];
    } @catch (NSException *ex) {
        NSLog(@"[SBXK-diag] %@ %@: %@", clsS, selS, ex);
        [g_skip addObject:key];
        return NO;
    }
    return YES;
}

// ============================================================================
// القسم 4: ماكرو تعريف الدوال
// ============================================================================

#define DEF_NO(cls, name)  static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s;(void)_c; return NO; }
#define DEF_YES(cls, name) static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s;(void)_c; return YES; }
#define DEF_V1(cls, name)  static void SBXK_##cls##_##name(id _s, SEL _c, id _a1) { (void)_s;(void)_c;(void)_a1; }
#define DEF_V2(cls, name)  static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2) { (void)_s;(void)_c;(void)_a1;(void)_a2; }

#define DEF_ID_P0(cls, name)  \
    static id SBXK_##cls##_##name(id _s, SEL _c) { \
        IMP o = SBXK_OriginalS(SENS(#cls), SENS(#name)); if (!o) return nil; \
        id (*fn)(id, SEL) = (void *)o; return fn(_s, _c); }
#define DEF_ID_P1(cls, name)  \
    static id SBXK_##cls##_##name(id _s, SEL _c, id _a1) { \
        IMP o = SBXK_OriginalS(SENS(#cls), SENS(#name)); if (!o) return nil; \
        id (*fn)(id, SEL, id) = (void *)o; return fn(_s, _c, _a1); }
#define DEF_ID_P2(cls, name)  \
    static id SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2) { \
        IMP o = SBXK_OriginalS(SENS(#cls), SENS(#name)); if (!o) return nil; \
        id (*fn)(id, SEL, id, id) = (void *)o; return fn(_s, _c, _a1, _a2); }
#define DEF_ID_P3(cls, name)  \
    static id SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2, id _a3) { \
        IMP o = SBXK_OriginalS(SENS(#cls), SENS(#name)); if (!o) return nil; \
        id (*fn)(id, SEL, id, id, id) = (void *)o; return fn(_s, _c, _a1, _a2, _a3); }

// ============================================================================
// القسم 5-9: تعريفات الدوال
// ============================================================================

DEF_NO(IntegrityChecker, integrity_detect)
DEF_NO(IntegrityChecker, MTML_INTEGRITY_DETECT)
DEF_NO(JailbreakDetector, isJailbroken)
DEF_NO(JailbreakDetector, isJailbreak)
DEF_NO(JailbreakDetector, checkJailbreak)
DEF_NO(JailbreakDetector, jailbreakDetection)
DEF_NO(SimulatorDetector, isSimulator)
DEF_NO(SimulatorDetector, isSimulatorDevice)
DEF_NO(SimulatorDetector, checkSimulator)
DEF_NO(SecurityChecker, IsFileSystemModified)
DEF_NO(SecurityChecker, isDebuggerAttached)
DEF_NO(SecurityChecker, isDebugged)
DEF_NO(SecurityChecker, checkDebugger)
DEF_NO(SecurityChecker, amIBeingDebugged)
DEF_NO(SecurityChecker, checkDebuggerAttach)
DEF_NO(SecurityChecker, isHooked)
DEF_NO(SecurityChecker, isHookDetected)
DEF_NO(SecurityChecker, checkHook)
DEF_NO(SecurityChecker, detectHook)
DEF_NO(SecurityChecker, antiHookCheck)
DEF_NO(SecurityChecker, isTampered)
DEF_NO(SecurityChecker, checkTamper)
DEF_NO(SecurityChecker, antiTamperCheck)
DEF_NO(SecurityChecker, isInjected)
DEF_NO(SecurityChecker, isLibraryInjected)
DEF_NO(SecurityChecker, checkInjection)
DEF_NO(SecurityChecker, antiInjectionCheck)
DEF_NO(SecurityChecker, isReversingDetected)
DEF_NO(SecurityChecker, checkReversing)
DEF_NO(SecurityChecker, antiReversingCheck)
DEF_NO(SecurityChecker, isBlocked)
DEF_NO(SecurityChecker, antiBlockingCheck)
DEF_NO(SecurityChecker, isVPNUsed)
DEF_NO(SecurityChecker, isProxyUsed)
DEF_NO(SecurityChecker, isFridaRunning)
DEF_NO(SecurityChecker, isSubstrateLoaded)
DEF_NO(SecurityChecker, isCydiaInstalled)
DEF_NO(SecurityChecker, hasSuspiciousFiles)
DEF_NO(SecurityChecker, isEnvironmentClean)
DEF_YES(SecurityChecker, verifyIntegrity)
DEF_YES(SecurityChecker, checkTokenValid)
DEF_YES(SecurityChecker, isEnvironmentSafe)
DEF_YES(SecurityChecker, verifySignature)
DEF_YES(AReachability, isConnectionOnDemand)
DEF_YES(AReachability, isConnectionRequired)
DEF_YES(GVGCloudVoiceExtension, CheckDeviceMuteStat)

DEF_V1(GADAppOpenAd, adDidDismissFullScreenContent)
DEF_V1(GADAppOpenAd, adWillDismissFullScreenContent)
DEF_V1(GADAppOpenAd, adDidRecordClick)
DEF_V1(GADAppOpenAd, adDidRecordImpression)
DEF_V1(GADAppOpenAd, adWillPresentFullScreenContent)
DEF_V1(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError)
DEF_V1(GADAppOpenAd, setPaidEventHandler)
DEF_V1(GADAppOpenAd, adDidRecordUserInteraction)
DEF_V1(NetworkManager, SendSecurityReport)

DEF_ID_P0(GSDKCPU, getSystemCPUCircle)
DEF_ID_P0(GSDKMemory, getSystemAvailableMemory)
DEF_ID_P0(GSDKInGameManager, GSDKRealTimeDetect)
DEF_ID_P0(GSDKInGameSystem, GSDKInnerEnd)
DEF_ID_P0(GSDKInGameSystem, GSDKInnerRealTimeDetect)
DEF_ID_P0(GSDKPing, ping)
DEF_ID_P0(GSDKPing, stopPing)
DEF_ID_P0(GSDKPingDetect, ping)
DEF_ID_P0(PingDelegate, pingTimer)
DEF_ID_P0(SimplePing, start)
DEF_ID_P0(SimplePing, startWithHostAddress)
DEF_ID_P0(SimplePing, readData)
DEF_ID_P0(GSDKRealTimeDetect, pingDelayDetect)
DEF_ID_P0(GSDKRealTimeDetect, updDelayDetect_Port)
DEF_ID_P0(GSDKUdpDetect, isUDPConnect_Port)
DEF_ID_P0(GSDKWIFI, ping)
DEF_ID_P0(GSDKDetectPort, isConnection_Port)
DEF_ID_P0(GSDKInitManager, detectOperation)
DEF_ID_P0(GSDKPayEvent, GSDKPay_Tag_Status_Msg)
DEF_ID_P0(GSDKHttpRequest, requestControl_Openid_Acctype_Zoneid_Env)
DEF_ID_P1(SimplePing, sendPingWithData)
DEF_ID_P1(SimplePing, didFailWithError)
DEF_ID_P1(FBAdViewabilityValidator, checkViewability)
DEF_ID_P1(TApmSceneMarker, postStepEvent)
DEF_ID_P1(TApmSceneMarker, postStreamEvent)
DEF_ID_P1(APMCollector, collectMetrics)
DEF_ID_P1(APMCollector, reportNow)
DEF_ID_P1(AudioDeviceMgr, UpdateDeviceState)
DEF_ID_P2(SimplePing, validatePingResponsePacket_sequenceNumber)
DEF_ID_P2(FIRMessaging, retrieveFCMTokenForSenderID_completion)
DEF_ID_P2(FIRMessaging, deleteFCMTokenForSenderID_completion)
DEF_ID_P2(FIRMessaging, subscribeToTopic_completion)
DEF_ID_P2(FIRMessaging, unsubscribeFromTopic_completion)
DEF_ID_P2(FIRMessaging, setAPNSToken_withUserInfo)
DEF_ID_P2(GSDKInGameSystem, GSDKInnerSaveFPS_FpsDots)
DEF_ID_P3(SimplePing, pingPacketWithType_payload_requiresChecksum)
DEF_ID_P3(GSDKInGameSystem, GSDKInnerStart_SceneID_RoomIP)

DEF_ID_P0(GVGCloudVoice, openMic)
DEF_ID_P0(GVGCloudVoice, openSpeaker)
DEF_ID_P0(GVGCloudVoiceExtension, GetBGMPlayState)
DEF_ID_P0(GVGCloudVoiceExtension, GetMicState)
DEF_ID_P0(GVGCloudVoiceExtension, GetSpeakerState)
DEF_ID_P0(GVoiceMuteSwitch, detectMuteSwitch)
DEF_ID_P0(GCloudVoiceEngine, StartTve)
DEF_ID_P0(GCloudVoiceEngine, TestMic)
DEF_ID_P0(GCloudVoiceEngine, GetMicLevel)
DEF_ID_P0(GCloudVoiceEngine, GetSpeakerLevel)
DEF_ID_P0(GCloudVoiceEngine, GetBGMLevel)
DEF_ID_P0(GCloudVoiceEngine, GetBGMFileTime)
DEF_ID_P0(GCloudVoiceEngine, GetBGMPlayTime)
DEF_ID_P0(GCloudVoiceEngine, GetRecordKaraokeTotalTime)
DEF_ID_P0(GCloudVoiceEngine, StartPreview)
DEF_ID_P0(GCloudVoiceEngine, StopPreview)
DEF_ID_P0(GCloudVoiceEngine, PauseKaraoke)
DEF_ID_P0(GCloudVoiceEngine, ResumeKaraoke)
DEF_ID_P0(GCloudVoiceEngine, RSTSStopRecording)
DEF_ID_P0(GCloudVoiceEngine, TextToStreamSpeechStop)
DEF_ID_P0(GCloudVoiceEngine, StopKaraokeRecording)
DEF_ID_P0(GCloudCoreRemoteConfig, getConfig)
DEF_ID_P0(GCloudUnityPlugin, Initialize)
DEF_ID_P0(GCloudUnityPlugin, ReportEvent)
DEF_ID_P1(GCloudVoiceEngine, StartRecording)
DEF_ID_P1(GCloudVoiceEngine, StopRecording)
DEF_ID_P1(GCloudVoiceEngine, StartBGMPlay)
DEF_ID_P1(GCloudVoiceEngine, StopBGMPlay)
DEF_ID_P1(GCloudVoiceEngine, PauseBGMPlay)
DEF_ID_P1(GCloudVoiceEngine, ResumeBGMPlay)
DEF_ID_P1(GCloudVoiceEngine, SetBGMPath)
DEF_ID_P1(GCloudVoiceEngine, SetLogCallBack)
DEF_ID_P1(GCloudCoreRemoteConfig, updateConfig)
DEF_ID_P1(GCloudUnityPlugin, SetGameObjectName)
DEF_ID_P2(GCloudVoiceEngine, QuitRoom_Scenes_timeout)

DEF_ID_P0(FIRMessagingRmqManager, openDatabase)
DEF_ID_P0(FIRMessaging, APNSToken)
DEF_ID_P0(GADAppOpenAd, responseInfo)
DEF_ID_P0(GADMobileAds, initializationStatus)
DEF_ID_P0(GADAdNetworkResponseInfo, adUnitMapping)
DEF_ID_P0(FBAdViewabilityValidator, stopMonitoring)
DEF_ID_P0(FBAdMonitor, stopMonitoring)
DEF_ID_P0(APMDeviceInfoSupport, getBatteryState)
DEF_ID_P0(APMDeviceInfoSupport, getThermalState)
DEF_ID_P0(TApmSceneMarker, markLevelFin)
DEF_ID_P0(serviceCommunication, getValueForKeypath)
DEF_ID_P0(AudioDeviceMgr, GetAudioDeviceConnectState)
DEF_ID_P0(VKAuth, logout)
DEF_ID_P0(SCSDKLoginClient, logout)

DEF_NO(AntiDataProxy, checkIntegrity)
DEF_NO(AntiDataProxy, isIntegrityOK)
DEF_NO(AntiDataProxy, verifyData)
DEF_NO(AntiDataProxy, isDataValid)
DEF_NO(AntiDataProxy, isModified)
DEF_NO(AntiDataProxy, isCheat)
DEF_NO(AntiDataProxy, isSuspicious)
DEF_NO(AntiDataProxy, antiCheatCheck)
DEF_NO(AntiDataProxy, securityCheck)
DEF_NO(AntiDataProxy, hasRisk)
DEF_NO(AntiDataProxy, detectRisk)
DEF_NO(AntiDataProxy, isRiskDetected)
DEF_YES(AntiDataProxy, isValid)
DEF_YES(AntiDataProxy, isSafe)
DEF_YES(AntiDataProxy, isClean)
DEF_YES(AntiDataProxy, verifyIntegrity)
DEF_YES(AntiDataProxy, verifySignature)
DEF_YES(AntiDataProxy, shouldPass)
DEF_YES(AntiDataProxy, allowReport)
DEF_V1(AntiDataProxy, sendData)
DEF_V1(AntiDataProxy, report)
DEF_V1(AntiDataProxy, submit)
DEF_V1(AntiDataProxy, upload)
DEF_V1(AntiDataProxy, dispatch)
DEF_V1(AntiDataProxy, flush)
DEF_ID_P0(AntiDataProxy, getData)
DEF_ID_P0(AntiDataProxy, getPayload)
DEF_ID_P0(AntiDataProxy, getHeader)
DEF_ID_P0(AntiDataProxy, getBody)
DEF_ID_P0(AntiDataProxy, getResponse)
DEF_ID_P0(AntiDataProxy, getConfig)
DEF_ID_P0(AntiDataProxy, getState)
DEF_ID_P0(AntiDataProxy, getStatus)
DEF_ID_P1(AntiDataProxy, setData)
DEF_ID_P1(AntiDataProxy, setPayload)
DEF_ID_P1(AntiDataProxy, setConfig)
DEF_ID_P1(AntiDataProxy, process)
DEF_ID_P1(AntiDataProxy, handle)
DEF_ID_P1(AntiDataProxy, onReceive)
DEF_ID_P1(AntiDataProxy, onMessage)
DEF_ID_P2(AntiDataProxy, sendData_withHeader)
DEF_ID_P2(AntiDataProxy, sendReport_withType)
DEF_ID_P2(AntiDataProxy, postData_withURL)

DEF_NO(TssInfoReceiver, isRooted)
DEF_NO(TssInfoReceiver, isRootedDevice)
DEF_NO(TssInfoReceiver, isJailbroken)
DEF_NO(TssInfoReceiver, isJailbreakDevice)
DEF_NO(TssInfoReceiver, isEmulator)
DEF_NO(TssInfoReceiver, isEmulatorDevice)
DEF_NO(TssInfoReceiver, isSimulator)
DEF_NO(TssInfoReceiver, isDebuggerAttached)
DEF_NO(TssInfoReceiver, isDebugged)
DEF_NO(TssInfoReceiver, isModified)
DEF_NO(TssInfoReceiver, isTampered)
DEF_NO(TssInfoReceiver, isInjected)
DEF_NO(TssInfoReceiver, isHooked)
DEF_NO(TssInfoReceiver, hasCheat)
DEF_NO(TssInfoReceiver, hasCheatTool)
DEF_NO(TssInfoReceiver, hasSuspiciousFiles)
DEF_NO(TssInfoReceiver, hasRisk)
DEF_NO(TssInfoReceiver, checkEnvironment)
DEF_NO(TssInfoReceiver, checkSecurity)
DEF_NO(TssInfoReceiver, checkCheat)
DEF_NO(TssInfoReceiver, detectCheat)
DEF_NO(TssInfoReceiver, detectRisk)
DEF_NO(TssInfoReceiver, detectEnvironment)
DEF_NO(TssInfoReceiver, isCheating)
DEF_NO(TssInfoReceiver, isCheatDetected)
DEF_NO(TssInfoReceiver, isSuspicious)
DEF_NO(TssInfoReceiver, antiCheatCheck)
DEF_NO(TssInfoReceiver, securityCheck)
DEF_NO(TssInfoReceiver, shouldReport)
DEF_NO(TssInfoReceiver, shouldBlock)
DEF_NO(TssInfoReceiver, needReport)
DEF_NO(TssInfoReceiver, needBlock)
DEF_NO(TssInfoReceiver, isBlocked)
DEF_NO(TssInfoReceiver, isBanned)
DEF_YES(TssInfoReceiver, isSafe)
DEF_YES(TssInfoReceiver, isClean)
DEF_YES(TssInfoReceiver, isEnvironmentClean)
DEF_YES(TssInfoReceiver, isEnvironmentSafe)
DEF_YES(TssInfoReceiver, verifyIntegrity)
DEF_YES(TssInfoReceiver, verifySignature)
DEF_YES(TssInfoReceiver, checkTokenValid)
DEF_V1(TssInfoReceiver, start)
DEF_V1(TssInfoReceiver, stop)
DEF_V1(TssInfoReceiver, run)
DEF_V1(TssInfoReceiver, onReceiveData)
DEF_V1(TssInfoReceiver, onRecvData)
DEF_V1(TssInfoReceiver, report)
DEF_V1(TssInfoReceiver, sendReport)
DEF_V1(TssInfoReceiver, uploadReport)
DEF_V1(TssInfoReceiver, submitReport)
DEF_V1(TssInfoReceiver, reportRoot)
DEF_V1(TssInfoReceiver, reportEmu)
DEF_V1(TssInfoReceiver, reportDebugger)
DEF_V1(TssInfoReceiver, reportCheat)
DEF_V1(TssInfoReceiver, reportAlert)
DEF_V1(TssInfoReceiver, sendAlert)
DEF_V1(TssInfoReceiver, blockGame)
DEF_V1(TssInfoReceiver, blockPlayer)
DEF_V1(TssInfoReceiver, kickPlayer)
DEF_ID_P0(TssInfoReceiver, currentState)
DEF_ID_P0(TssInfoReceiver, getState)
DEF_ID_P0(TssInfoReceiver, getStatus)
DEF_ID_P0(TssInfoReceiver, getReport)
DEF_ID_P0(TssInfoReceiver, getResult)
DEF_ID_P0(TssInfoReceiver, getData)
DEF_ID_P0(TssInfoReceiver, getInfo)
DEF_ID_P0(TssInfoReceiver, getRiskInfo)
DEF_ID_P0(TssInfoReceiver, getCheatInfo)
DEF_ID_P0(TssInfoReceiver, getEnvInfo)
DEF_ID_P0(TssInfoReceiver, getConfig)
DEF_ID_P1(TssInfoReceiver, updateState)
DEF_ID_P1(TssInfoReceiver, setState)
DEF_ID_P1(TssInfoReceiver, handleData)
DEF_ID_P1(TssInfoReceiver, handleMessage)
DEF_ID_P1(TssInfoReceiver, processData)
DEF_ID_P1(TssInfoReceiver, onMessage)
DEF_ID_P1(TssInfoReceiver, onCommand)

DEF_NO(CheckSymbolSource, CheckSymbol)
DEF_NO(CheckSymbolSource, checkSymbol)
DEF_NO(CheckSymbolSource, checkSymbolSource)
DEF_NO(CheckSymbolSource, isSymbolValid)
DEF_NO(CheckSymbolSource, isSymbolOK)
DEF_NO(CheckSymbolSource, verifySymbol)
DEF_NO(CheckSymbolSource, verifySymbols)
DEF_NO(CheckSymbolSource, isSourceSafe)
DEF_NO(CheckSymbolSource, checkSource)
DEF_YES(CheckSymbolSource, isSourceOK)
DEF_YES(CheckSymbolSource, sourceIsValid)
DEF_ID_P0(CheckSymbolSource, getResult)
DEF_ID_P0(CheckSymbolSource, getReport)
DEF_ID_P1(CheckSymbolSource, checkSymbolSourceWithData)
DEF_ID_P1(CheckSymbolSource, verifySymbolWithData)

DEF_NO(CFastScanThread, isRunning)
DEF_NO(CFastScanThread, shouldScan)
DEF_NO(CFastScanThread, hasResult)
DEF_NO(CScanThread, isRunning)
DEF_NO(CScanThread, shouldScan)
DEF_NO(CScanThread, hasResult)
DEF_NO(CSendThread, isRunning)
DEF_NO(CSendThread, shouldSend)
DEF_NO(CSendThread, hasData)
DEF_NO(CMrpcsMonitor, isRunning)
DEF_NO(CMrpcsMonitor, shouldReport)
DEF_NO(CMrpcsMgrE, isReady)
DEF_NO(CMrpcsMgrE, shouldReport)
DEF_NO(CPointDataMgr, shouldReport)
DEF_NO(CPointDataMgr, hasData)
DEF_NO(CPointGlobalMgr, shouldReport)
DEF_NO(CPointGlobalMgr, hasData)
DEF_NO(CMrpcsLFUpdater, shouldUpdate)
DEF_NO(CMrpcsLFUpdater, hasUpdate)
DEF_V1(CFastScanThread, start)
DEF_V1(CFastScanThread, run)
DEF_V1(CFastScanThread, execute)
DEF_V1(CFastScanThread, scan)
DEF_V1(CFastScanThread, doScan)
DEF_V1(CFastScanThread, report)
DEF_V1(CFastScanThread, sendReport)
DEF_V1(CScanThread, start)
DEF_V1(CScanThread, run)
DEF_V1(CScanThread, execute)
DEF_V1(CScanThread, scan)
DEF_V1(CScanThread, doScan)
DEF_V1(CScanThread, report)
DEF_V1(CScanThread, sendReport)
DEF_V1(CSendThread, start)
DEF_V1(CSendThread, run)
DEF_V1(CSendThread, execute)
DEF_V1(CSendThread, send)
DEF_V1(CSendThread, doSend)
DEF_V1(CSendThread, report)
DEF_V1(CMrpcsMonitor, start)
DEF_V1(CMrpcsMonitor, stop)
DEF_V1(CMrpcsMonitor, run)
DEF_V1(CMrpcsMonitor, execute)
DEF_V1(CMrpcsMonitor, report)
DEF_V1(CMrpcsMonitor, sendReport)
DEF_V1(CMrpcsMgrE, sendScanResult)
DEF_V1(CMrpcsMgrE, reportResult)
DEF_V1(CMrpcsMgrE, sendReport)
DEF_V1(CMrpcsMgrE, report)
DEF_V1(CMrpcsMgrE, upload)
DEF_V1(CPointDataMgr, report)
DEF_V1(CPointDataMgr, sendData)
DEF_V1(CPointDataMgr, uploadData)
DEF_V1(CPointDataMgr, dispatch)
DEF_V1(CPointGlobalMgr, report)
DEF_V1(CPointGlobalMgr, sendReport)
DEF_V1(CPointGlobalMgr, upload)
DEF_V1(CMrpcsLFUpdater, update)
DEF_V1(CMrpcsLFUpdater, start)
DEF_V1(CMrpcsLFUpdater, run)
DEF_V1(CMrpcsLFUpdater, check)
DEF_V1(CMrpcsLFUpdater, report)
DEF_ID_P0(CMrpcsMgrE, getInstance)
DEF_ID_P0(CMrpcsMgrE, getState)
DEF_ID_P0(CMrpcsMgrE, getReport)
DEF_ID_P0(CMrpcsMgrE, getResult)
DEF_ID_P0(CMrpcsMgrE, getConfig)
DEF_ID_P0(CMrpcsMonitor, getState)
DEF_ID_P0(CMrpcsMonitor, getReport)
DEF_ID_P0(CMrpcsMonitor, getResult)
DEF_ID_P0(CPointDataMgr, getData)
DEF_ID_P0(CPointDataMgr, getReport)
DEF_ID_P0(CPointDataMgr, getState)
DEF_ID_P0(CPointGlobalMgr, getData)
DEF_ID_P0(CPointGlobalMgr, getReport)
DEF_ID_P0(CPointGlobalMgr, getState)
DEF_ID_P0(CMrpcsLFUpdater, getState)
DEF_ID_P0(CMrpcsLFUpdater, getConfig)
DEF_ID_P0(CMrpcsLFUpdater, getVersion)
DEF_ID_P1(CMrpcsMgrE, setConfig)
DEF_ID_P1(CMrpcsMgrE, setState)
DEF_ID_P1(CMrpcsMgrE, handleData)
DEF_ID_P1(CMrpcsMgrE, processData)
DEF_ID_P1(CMrpcsMonitor, setConfig)
DEF_ID_P1(CMrpcsMonitor, handleData)
DEF_ID_P1(CPointDataMgr, setData)
DEF_ID_P1(CPointDataMgr, handleData)
DEF_ID_P1(CPointGlobalMgr, setData)
DEF_ID_P1(CPointGlobalMgr, handleData)
DEF_ID_P2(CMrpcsMgrE, sendData_withType)
DEF_ID_P2(CMrpcsMgrE, handleMessage_withData)
DEF_ID_P2(CPointDataMgr, sendData_withType)
DEF_ID_P2(CPointGlobalMgr, sendData_withType)

DEF_V1(NetworkManager, sendRootAlert)
DEF_V1(NetworkManager, sendEmuAlert)
DEF_V1(NetworkManager, sendDebuggerAlert)
DEF_V1(NetworkManager, sendCheatAlert)
DEF_V1(NetworkManager, send9010Alert)
DEF_V1(NetworkManager, send9014Alert)
DEF_V1(NetworkManager, send9005Alert)
DEF_V1(NetworkManager, sendShellReport)
DEF_V1(NetworkManager, sendCheckState)

DEF_ID_P0(ScreenShot, takeScreenShot)
DEF_ID_P0(ScreenShot, screenshot)
DEF_ID_P1(ScreenShot, takeScreenShotEx)
DEF_ID_P1(ScreenShot, screenshotOfView)
DEF_ID_P1(ScreenShot, getBufFromImage)
DEF_ID_P1(ScreenShot, getAppWindowsForScreen)
DEF_ID_P0(Rotate, fixOrientation)
DEF_ID_P0(Rotate, flipVertical)
DEF_ID_P0(Rotate, flipHorizontal)
DEF_ID_P1(Rotate, rotate)
DEF_ID_P1(Rotate, imageRotatedByRadians)
DEF_ID_P1(Rotate, imageRotatedByDegrees)

DEF_V2(AceMsgBoxImp, ShowMessageBoxWithTitle_Message_LeftBtn_RightBtn)
DEF_V1(AceMsgBoxImp, dismiss)
DEF_V1(AceMsgBoxImp, show)
DEF_ID_P0(AceMsgBoxImp, viewTitle)
DEF_ID_P0(AceMsgBoxImp, viewContent)
DEF_ID_P0(AceMsgBoxImp, leftBtnContent)
DEF_ID_P0(AceMsgBoxImp, rightBtnContent)

DEF_NO(SBXK_FridaDet, isFridaPresent)
DEF_NO(SBXK_FridaDet, isFridaRunning)
DEF_NO(SBXK_FridaDet, hasFrida)
DEF_NO(SBXK_FridaDet, checkFrida)
DEF_NO(SBXK_FridaDet, detectFrida)
DEF_NO(SBXK_FridaDet, isFridaGadgetLoaded)
DEF_NO(SBXK_FridaDet, hasFridaGadget)
DEF_NO(SBXK_FridaDet, isFridaAgentLoaded)
DEF_NO(SBXK_FridaDet, hasNamedPipe)
DEF_NO(SBXK_FridaDet, checkNamedPipe)
DEF_NO(SBXK_FridaDet, isPipeOpen)
DEF_NO(SBXK_SubDet, isSubstrateLoaded)
DEF_NO(SBXK_SubDet, hasSubstrate)
DEF_NO(SBXK_SubDet, checkSubstrate)
DEF_NO(SBXK_SubDet, isCydiaSubstrateLoaded)
DEF_NO(SBXK_SubDet, isSubstituteLoaded)
DEF_NO(SBXK_SubDet, hasSubstitute)
DEF_NO(SBXK_SubDet, checkSubstitute)
DEF_NO(SBXK_InjectDet, isElleKitLoaded)
DEF_NO(SBXK_InjectDet, hasElleKit)
DEF_NO(SBXK_InjectDet, isLibhookerLoaded)
DEF_NO(SBXK_InjectDet, hasLibhooker)
DEF_NO(SBXK_InjectDet, isTweakInjectLoaded)
DEF_NO(SBXK_InjectDet, hasTweakInject)
DEF_NO(SBXK_InjectDet, checkTweaks)
DEF_NO(SBXK_InjectDet, hasJailbreakTweak)
DEF_NO(SBXK_InjectDet, isDylibInjected)
DEF_NO(SBXK_InjectDet, isImageInjected)
DEF_NO(SBXK_InjectDet, hasInjectedDylib)
DEF_NO(SBXK_InjectDet, isForeignImageLoaded)
DEF_NO(SBXK_InjectDet, hasHooked)
DEF_NO(SBXK_InjectDet, hasMSHook)
DEF_NO(SBXK_InjectDet, checkMSHook)
DEF_NO(SBXK_InjectDet, checkSymbolHook)
DEF_NO(SBXK_InjectDet, hasSwizzled)
DEF_NO(SBXK_InjectDet, hasDYLD_INSERT)
DEF_NO(SBXK_InjectDet, isDYLDInjected)
DEF_NO(SBXK_InjectDet, checkDYLD)
DEF_NO(SBXK_InjectDet, isEnvInjected)
DEF_NO(SBXK_InjectDet, hasEnvVarInject)
DEF_NO(SBXK_InjectDet, isAttached)
DEF_NO(SBXK_InjectDet, isBeingDebugged)
DEF_NO(SBXK_InjectDet, isTraced)
DEF_NO(SBXK_InjectDet, hasPtraced)
DEF_NO(SBXK_InjectDet, checkPtrace)
DEF_NO(SBXK_InjectDet, isPtraceDetected)
DEF_NO(SBXK_InjectDet, hasForeignExceptionPort)
DEF_NO(SBXK_InjectDet, hasExceptionHijack)
DEF_NO(SBXK_InjectDet, checkExceptionPorts)
DEF_NO(SBXK_InjectDet, isPortHijacked)
DEF_YES(SBXK_InjectDet, isEnvironmentClean)
DEF_YES(SBXK_InjectDet, isEnvironmentSafe)
DEF_YES(SBXK_InjectDet, isClean)
DEF_YES(SBXK_InjectDet, isSafe)
DEF_YES(SBXK_InjectDet, verifyNoInjection)
DEF_YES(SBXK_InjectDet, verifyNoHook)
DEF_YES(SBXK_InjectDet, verifyNoDylib)
DEF_YES(SBXK_InjectDet, verifyImageClean)
DEF_V1(SBXK_InjectDet, reportFrida)
DEF_V1(SBXK_InjectDet, reportSubstrate)
DEF_V1(SBXK_InjectDet, reportSubstitute)
DEF_V1(SBXK_InjectDet, reportElleKit)
DEF_V1(SBXK_InjectDet, reportLibhooker)
DEF_V1(SBXK_InjectDet, reportInjection)
DEF_V1(SBXK_InjectDet, reportHook)
DEF_V1(SBXK_InjectDet, reportDylib)
DEF_V1(SBXK_InjectDet, reportAttach)
DEF_V1(SBXK_InjectDet, reportPtrace)
DEF_V1(SBXK_InjectDet, reportExceptionPort)
DEF_V1(SBXK_InjectDet, reportNamedPipe)
DEF_V1(SBXK_InjectDet, reportEnvInject)
DEF_V1(SBXK_InjectDet, sendAlert)
DEF_V1(SBXK_InjectDet, sendReport)
DEF_V1(SBXK_InjectDet, uploadReport)
DEF_V1(SBXK_InjectDet, submitReport)
DEF_V1(SBXK_InjectDet, notifyServer)
DEF_V1(SBXK_InjectDet, alertUser)
DEF_V1(SBXK_InjectDet, blockGame)
DEF_V1(SBXK_InjectDet, kickPlayer)

DEF_NO(QAPMReport, isEnabled)
DEF_NO(QAPMReport, isRunning)
DEF_NO(QAPMReport, shouldReport)
DEF_NO(QAPMReport, hasReport)
DEF_V1(QAPMReport, report)
DEF_V1(QAPMReport, sendReport)
DEF_V1(QAPMReport, upload)
DEF_V1(QAPMReport, submit)
DEF_V1(QAPMReport, flush)
DEF_V1(QAPMReport, start)
DEF_V1(QAPMReport, stop)
DEF_V1(QAPMReport, setEnabled)
DEF_V1(QAPMReport, setUserId)
DEF_V1(QAPMReport, setUserValue)
DEF_V1(QAPMReport, trackEvent)
DEF_V1(QAPMReport, reportException)
DEF_V1(QAPMReport, reportCrash)
DEF_V1(QAPMReport, reportPerformance)
DEF_V1(QAPMReport, reportNetwork)
DEF_V1(QAPMReport, reportBattery)
DEF_ID_P0(QAPMReport, getState)
DEF_ID_P0(QAPMReport, getConfig)
DEF_ID_P0(QAPMReport, getReport)
DEF_ID_P0(QAPMReport, getDeviceId)
DEF_ID_P0(QAPMReport, getSessionId)
DEF_ID_P1(QAPMReport, updateConfig)
DEF_ID_P1(QAPMReport, setConfig)
DEF_ID_P1(QAPMReport, handleData)

DEF_NO(MeemoUserManager, isGuest)
DEF_NO(MeemoUserManager, isBanned)
DEF_NO(MeemoUserManager, isBlocked)
DEF_NO(MeemoUserManager, isUnderage)
DEF_ID_P0(MeemoUserManager, currentUser)
DEF_ID_P0(MeemoUserManager, currentToken)
DEF_ID_P0(MeemoUserManager, currentOpenId)
DEF_ID_P0(MeemoUserManager, currentAccountId)
DEF_ID_P0(MeemoUserManager, currentSession)
DEF_ID_P0(MeemoUserManager, userInfo)
DEF_ID_P0(MeemoUserManager, getInstance)
DEF_ID_P1(MeemoUserManager, setUser)
DEF_ID_P1(MeemoUserManager, setToken)
DEF_ID_P1(MeemoUserManager, updateUserInfo)

DEF_V1(MeemoLogUtil, log)
DEF_V1(MeemoLogUtil, logInfo)
DEF_V1(MeemoLogUtil, logDebug)
DEF_V1(MeemoLogUtil, logWarn)
DEF_V1(MeemoLogUtil, logError)
DEF_V1(MeemoLogUtil, logEvent)
DEF_V1(MeemoLogUtil, sendLog)
DEF_V1(MeemoLogUtil, uploadLog)
DEF_V1(MeemoLogUtil, flush)
DEF_V1(MeemoLogUtil, report)

DEF_ID_P0(MeemoUtils, getInstance)
DEF_ID_P0(MeemoUtils, getDeviceId)
DEF_ID_P0(MeemoUtils, getChannel)
DEF_ID_P0(MeemoUtils, getVersion)
DEF_ID_P0(MeemoUtils, getCountryCode)
DEF_ID_P0(MeemoUtils, getLanguage)
DEF_ID_P0(MeemoUtils, getPlatform)
DEF_ID_P0(MeemoUtils, getUUID)

DEF_NO(PBConfigManager, isModified)
DEF_NO(PBConfigManager, isTampered)
DEF_ID_P0(PBConfigManager, getConfig)
DEF_ID_P0(PBConfigManager, getInstance)
DEF_ID_P0(PBConfigManager, currentConfig)
DEF_ID_P1(PBConfigManager, updateConfig)
DEF_ID_P1(PBConfigManager, setConfig)
DEF_ID_P0(CdnConfigManager, getConfig)
DEF_ID_P0(CdnConfigManager, getInstance)
DEF_ID_P0(CdnConfigManager, currentConfig)
DEF_ID_P1(CdnConfigManager, updateConfig)

DEF_ID_P0(MeemoBundleUtils, getInstance)
DEF_ID_P0(MeemoBundleUtils, bundlePath)
DEF_ID_P0(MeemoBundleUtils, mainBundle)
DEF_ID_P0(MeemoSubPackageDownloadMgr, getInstance)
DEF_ID_P0(MeemoSubPackageDownloadMgr, state)
DEF_ID_P0(MeemoSubPackageInfoProvider, getInstance)
DEF_ID_P0(MeemoSubPackageInfoProvider, currentInfo)
DEF_ID_P0(MeemoSubPackageUtils, getInstance)
DEF_ID_P0(MeemoCoreInitalizer, getInstance)
DEF_ID_P0(MeemoCoreInitalizer, state)
DEF_V1(MeemoCoreInitalizer, initialize)
DEF_V1(MeemoCoreInitalizer, start)
DEF_ID_P0(MeemoFlutterViewController, getInstance)

DEF_NO(HotfixPatchDownloadManager, isModified)
DEF_NO(HotfixPatchDownloadManager, hasIllegalPatch)
DEF_NO(HotfixPatchDownloadManager, isTampered)
DEF_ID_P0(HotfixPatchDownloadManager, getInstance)
DEF_ID_P0(HotfixPatchDownloadManager, state)
DEF_ID_P0(HotfixPatchDownloadManager, currentPatch)
DEF_ID_P1(HotfixPatchDownloadManager, checkPatch)
DEF_ID_P1(HotfixPatchDownloadManager, applyPatch)

DEF_ID_P0(DeviceInfoPlugin, getInstance)
DEF_ID_P0(DeviceInfoPlugin, deviceInfo)
DEF_ID_P0(DeviceInfoPlugin, model)
DEF_ID_P0(DeviceInfoPlugin, systemVersion)
DEF_ID_P0(DeviceInfoPlugin, identifierForVendor)
DEF_NO(FlutterFlogPlugin, isEnabled)
DEF_V1(FlutterFlogPlugin, log)
DEF_V1(FlutterFlogPlugin, report)
DEF_NO(FlutterQAPMPlugin, isEnabled)
DEF_V1(FlutterQAPMPlugin, report)
DEF_V1(FlutterQAPMPlugin, trackEvent)

// ============================================================================
// القسم 10: الفحص الذاتي
// ============================================================================

static BOOL sbxk_self_ok(void) {
    const char *self = NULL;
    uint32_t cnt = _dyld_image_count();
    NSString *nm = SENS("ShadowBypassXK.dylib");
    for (uint32_t i = 0; i < cnt; i++) {
        const char *n = _dyld_get_image_name(i);
        if (n && strstr(n, nm.UTF8String)) { self = n; break; }
    }
    if (!self) return NO;
    int fd = open(self, O_RDONLY); if (fd < 0) return NO;
    uint8_t buf[64]; ssize_t r = read(fd, buf, sizeof(buf)); close(fd);
    if (r != (ssize_t)sizeof(buf)) return NO;
    uint32_t magic; memcpy(&magic, buf, 4);
    return (magic == 0xFEEDFACF);
}

static void sbxk_disable_all(void) {
    for (NSString *k in g_orig.allKeys) {
        NSValue *v = g_orig[k];
        IMP orig = (IMP)[v pointerValue];
        NSArray *p = [k componentsSeparatedByString:@"::"];
        if (p.count != 2) continue;
        Class c = objc_getClass([p[0] UTF8String]); if (!c) continue;
        SEL s = sel_registerName([p[1] UTF8String]);
        Method m = class_getInstanceMethod(c, s); if (!m) m = class_getClassMethod(c, s);
        if (m) method_setImplementation(m, orig);
    }
}

// ============================================================================
// القسم 11: fishhook مدمج — مصحح + ACE extended
// ============================================================================

struct sbxk_rb { const char *name; void *repl; void **replaced; };

static int sbxk_rebind_image(const struct mach_header *mh, intptr_t slide,
                             struct sbxk_rb *b, int nb)
{
    if (mh->magic != MH_MAGIC_64) return 0;
    const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
    const struct segment_command_64 *le = NULL;
    const struct symtab_command *st = NULL;
    const struct dysymtab_command *dy = NULL;
    const struct load_command *lc = (const struct load_command *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__LINKEDIT") == 0) le = sg;
        } else if (lc->cmd == LC_SYMTAB) st = (const struct symtab_command *)lc;
        else if (lc->cmd == LC_DYSYMTAB) dy = (const struct dysymtab_command *)lc;
        lc = (const struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    if (!le || !st || !dy) return 0;

    uintptr_t sl = (uintptr_t)slide;
    intptr_t lb = (intptr_t)(slide + le->vmaddr - le->fileoff);
    const struct nlist_64 *sym = (const struct nlist_64 *)(lb + st->symoff);
    const char *str = (const char *)(lb + st->stroff);
    const uint32_t *ind = (const uint32_t *)(lb + dy->indirectsymoff);
    uint32_t nsyms = st->nsyms;

    int done = 0;
    lc = (const struct load_command *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            const struct section_64 *sec = (const struct section_64 *)(sg + 1);
            for (uint32_t j = 0; j < sg->nsects; j++, sec++) {
                uint8_t ft = sec->flags & SECTION_TYPE;
                if (ft != S_LAZY_SYMBOL_POINTERS && ft != S_NON_LAZY_SYMBOL_POINTERS) continue;
                uint32_t cnt = (uint32_t)(sec->size / sizeof(void *));
                uint32_t start = sec->reserved1;
                for (uint32_t k = 0; k < cnt; k++) {
                    uint32_t si = ind[start + k];
                    if (si == 0 || si == 0x80000000u) continue;
                    if (si >= nsyms) continue;
                    const char *nm = str + sym[si].n_un.n_strx;
                    if (!nm || nm[0] != '_') continue;
                    const char *cl = nm + 1;
                    for (int x = 0; x < nb; x++) {
                        if (strcmp(b[x].name, cl) != 0) continue;
                        void **slot = (void **)(sl + sec->addr + k * sizeof(void *));
                        if (b[x].replaced && *b[x].replaced == NULL) *b[x].replaced = *slot;
                        uintptr_t pg = (uintptr_t)slot & ~(PAGE_SIZE - 1);
                        kern_return_t kr = vm_protect(mach_task_self_, pg, PAGE_SIZE,
                                                      false, VM_PROT_READ | VM_PROT_WRITE);
                        if (kr != KERN_SUCCESS) continue;
                        *slot = b[x].repl;
                        vm_protect(mach_task_self_, pg, PAGE_SIZE, false, VM_PROT_READ);
                        done++;
                    }
                }
            }
        }
        lc = (const struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return done;
}

static int sbxk_rebind(struct sbxk_rb *b, int nb) {
    int t = 0;
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh) continue;
        intptr_t sl = _dyld_get_image_vmaddr_slide(i);
        @try {
            t += sbxk_rebind_image(mh, sl, b, nb);
        } @catch (__unused NSException *e) {}
    }
    return t;
}

// --- بدائل رموز C (AnoSDK + GAMELET + Check) ---
typedef int (*AnoSDKInit_t)(const char*);
typedef int (*AnoSDKSetUserInfo_t)(const char*);
typedef void *(*AnoSDKGetData_t)(int);
typedef void *(*AnoSDKGetData2_t)(int,int);
typedef int (*AnoSDKDel_t)(void*);
typedef int (*AnoSDKIoctl_t)(int,const char*,char*,size_t);
typedef int (*AnoSDKPause_t)(void);
typedef int (*AnoSDKRecv_t)(const void*,size_t);
typedef int (*CheckSym_t)(void);
typedef int (*GAMELET_Log_t)(const char*);
typedef int (*GAMELET_Log2_t)(const char*,const char*);
typedef int (*GAMELET_Msg_t)(int,const void*,size_t);
typedef int (*GAMELET_ReportFunc_t)(const char*,const void*,int);

static AnoSDKInit_t         orig_AnoSDKInit;
static AnoSDKSetUserInfo_t  orig_AnoSDKSetUserInfo;
static AnoSDKGetData_t      orig_AnoSDKGetData;
static AnoSDKGetData2_t     orig_AnoSDKGetData2;
static AnoSDKDel_t          orig_AnoSDKDel;
static AnoSDKIoctl_t        orig_AnoSDKIoctl;
static AnoSDKPause_t        orig_AnoSDKPause;
static AnoSDKPause_t        orig_AnoSDKResume;
static AnoSDKRecv_t         orig_AnoSDKRecvD;
static AnoSDKRecv_t         orig_AnoSDKRecvS;
static CheckSym_t           orig_CheckSym;
static GAMELET_Log_t        orig_GL1;
static GAMELET_Log_t        orig_GL2;
static GAMELET_Log2_t       orig_GL3;
static GAMELET_Msg_t        orig_GM;
static GAMELET_ReportFunc_t orig_GM_ReportStats;
static GAMELET_ReportFunc_t orig_GM_ReportLog;
static GAMELET_ReportFunc_t orig_GM_ReportTNM2;

static int SBXK_AnoInit(const char*p){(void)p;return 0;}
static int SBXK_AnoUser(const char*p){(void)p;return 0;}
static void *SBXK_AnoData(int a){(void)a;return NULL;}
static void *SBXK_AnoData2(int a,int b){(void)a;(void)b;return NULL;}
static int SBXK_AnoDel(void*p){(void)p;return 0;}
static int SBXK_AnoIoctl(int a,const char*i,char*o,size_t n){(void)a;(void)i;(void)o;(void)n;return 0;}
static int SBXK_AnoPause(void){return 0;}
static int SBXK_AnoRecv(const void*d,size_t n){(void)d;(void)n;return 0;}
static int SBXK_CheckSym(void){return 0;}
static int SBXK_GL1(const char*s){(void)s;return 0;}
static int SBXK_GL2(const char*s){(void)s;return 0;}
static int SBXK_GL3(const char*a,const char*b){(void)a;(void)b;return 0;}
static int SBXK_GM(int a,const void*b,size_t c){(void)a;(void)b;(void)c;return 0;}
static int SBXK_GM_ReportStats(const char*a,const void*b,int c){(void)a;(void)b;(void)c;return 0;}
static int SBXK_GM_ReportLog  (const char*a,const void*b,int c){(void)a;(void)b;(void)c;return 0;}
static int SBXK_GM_ReportTNM2 (const char*a,const void*b,int c){(void)a;(void)b;(void)c;return 0;}

// --- UQM crash ---
typedef int (*UQMCrash_Init_t)(void*,int,int,void*);
typedef int (*UQMCrash_Str_t)(void*);
typedef int (*UQMCrash_Log_t)(int,void*,void*);
typedef int (*UQMCrash_Rpt_t)(void*,int,void*,void*,void*,void*,void*,int);
typedef int (*UQM_SetObserver_t)(void*, void*);
typedef int (*UQM_ConfigTimeout_t)(int);

static UQMCrash_Init_t      orig_UQMInit;
static UQMCrash_Str_t       orig_UQMUser;
static UQMCrash_Str_t       orig_UQMApp;
static UQMCrash_Log_t       orig_UQMLog;
static UQMCrash_Str_t       orig_UQMSetUser;
static UQMCrash_Rpt_t       orig_UQMRpt;
static UQM_SetObserver_t    orig_UQMSetCrashObs;
static UQM_SetObserver_t    orig_UQMSetLogObs;
static UQM_ConfigTimeout_t  orig_UQMConfigTimeout;

static int SBXK_UQMInit(void*a,int b,int c,void*d){(void)a;(void)b;(void)c;(void)d;return 0;}
static int SBXK_UQMUser(void*a){(void)a;return 0;}
static int SBXK_UQMApp(void*a){(void)a;return 0;}
static int SBXK_UQMLog(int a,void*b,void*c){(void)a;(void)b;(void)c;return 0;}
static int SBXK_UQMSetUser(void*a,void*b){(void)a;(void)b;return 0;}
static int SBXK_UQMRpt(void*a,int b,void*c,void*d,void*e,void*f,void*g,int h){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;return 0;}
static int SBXK_UQMSetCrashObs(void *self, void *obs){(void)self;(void)obs;return 0;}
static int SBXK_UQMSetLogObs(void *self, void *obs){(void)self;(void)obs;return 0;}
static int SBXK_UQMConfigTimeout(int t){(void)t;return 0;}

// --- CrashSight ---
typedef int  (*CS_RptStuck_t)(void*,int,int,long,const char*,const char*,const char*,int,const char*);
typedef int  (*CS_RptErr_t)(void*,int,const char*,const char*,const char*,const char*,int,const char*);
typedef int  (*CS_RptLog_t)(void*,const char*,const char*);
typedef int  (*CS_LastUser_t)(void*,void*,int);
typedef void (*CS_TestOom_t)(void*);
typedef long (*CS_GetCrashTid_t)(void*);
typedef int  (*CS_IsLastCrash_t)(void*);
typedef void (*CS_SetUpload_t)(void*, int);
typedef void (*CS_ConfigRep_t)(void*, int);
typedef void (*CS_SetCatch_t)(void*, int);

static CS_RptStuck_t     orig_CSStuck;
static CS_RptErr_t       orig_CSErr;
static CS_RptLog_t       orig_CSLog;
static CS_LastUser_t     orig_CSLast;
static CS_TestOom_t      orig_CSTestOom;
static CS_GetCrashTid_t  orig_CSGetCrashTid;
static CS_IsLastCrash_t  orig_CSIsLastCrash;
static CS_SetUpload_t    orig_CSSetUpload;
static CS_ConfigRep_t    orig_CSConfigRep;
static CS_SetCatch_t     orig_CSSetCatch;

static int SBXK_CSStuck(void*a,int b,int c,long d,const char*e,const char*f,const char*g,int h,const char*i){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;return 0;}
static int SBXK_CSErr(void*a,int b,const char*c,const char*d,const char*e,const char*f,int g,const char*h){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;return 0;}
static int SBXK_CSLog(void*a,const char*b,const char*c){(void)a;(void)b;(void)c;return 0;}
static int SBXK_CSLast(void*a,void*b,int c){(void)a;(void)b;(void)c;return 0;}
static void SBXK_CSTestOom(void *self)          { (void)self; }
static long SBXK_CSGetCrashTid(void *self)      { (void)self; return 0; }
static int  SBXK_CSIsLastCrash(void *self)      { (void)self; return 0; }
static void SBXK_CSSetUpload(void *self, int n) { (void)self; (void)n; }
static void SBXK_CSConfigRep(void *self, int n) { (void)self; (void)n; }
static void SBXK_CSSetCatch(void *self, int b)  { (void)self; (void)b; }

// --- HTTPDNS / Cros ---
typedef void (*WG_GetHostByName_t)(const char*, const char*, void*, void*);
typedef void* (*Px_GetQJS_t)(void);

static WG_GetHostByName_t orig_WGGetHostByName;
static Px_GetQJS_t        orig_PxGetQJS;

// v7.10.5: استخدام getaddrinfo من libc بدل CFHost لتجنب ربط CFNetwork.
static void SBXK_WGGetHostByName(const char *host, const char *tag,
                                 void *cb, void *ctx) {
    if (orig_WGGetHostByName) {
        orig_WGGetHostByName(host, tag, cb, ctx);
        return;
    }
    if (!cb) return;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        if (!host) { return; }
        struct addrinfo hints; memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_ADDRCONFIG;
        struct addrinfo *res = NULL;
        int rc = getaddrinfo(host, NULL, &hints, &res);
        (void)rc;
        if (res) freeaddrinfo(res);
    });
}

static void *SBXK_PxGetQJS(void) { return NULL; }

static void SBXK_RegisterFishhook(void) {
    struct sbxk_rb rb[] = {
        // === AnoSDK ===
        { "AnoSDKInit",               (void*)SBXK_AnoInit,  (void**)&orig_AnoSDKInit },
        { "AnoSDKSetUserInfo",        (void*)SBXK_AnoUser,  (void**)&orig_AnoSDKSetUserInfo },
        { "AnoSDKGetReportData",      (void*)SBXK_AnoData,  (void**)&orig_AnoSDKGetData },
        { "AnoSDKGetReportData2",     (void*)SBXK_AnoData2, (void**)&orig_AnoSDKGetData2 },
        { "AnoSDKDelReportData",      (void*)SBXK_AnoDel,   (void**)&orig_AnoSDKDel },
        { "AnoSDKIoctl",              (void*)SBXK_AnoIoctl, (void**)&orig_AnoSDKIoctl },
        { "AnoSDKIoctlOld",           (void*)SBXK_AnoIoctl, (void**)&orig_AnoSDKIoctl },
        { "AnoSDKOnPause",            (void*)SBXK_AnoPause, (void**)&orig_AnoSDKPause },
        { "AnoSDKOnResume",           (void*)SBXK_AnoPause, (void**)&orig_AnoSDKResume },
        { "AnoSDKOnRecvData",         (void*)SBXK_AnoRecv,  (void**)&orig_AnoSDKRecvD },
        { "AnoSDKOnRecvSignature",    (void*)SBXK_AnoRecv,  (void**)&orig_AnoSDKRecvS },
        { "CheckSymbolSource",        (void*)SBXK_CheckSym, (void**)&orig_CheckSym },

        // === GAMELET ===
        { "GAMELET_ReportSDKLog",                (void*)SBXK_GL1, (void**)&orig_GL1 },
        { "GAMELET_ReportScriptError",           (void*)SBXK_GL2, (void**)&orig_GL2 },
        { "GAMELET_ReportScriptErrorWithAppInfo",(void*)SBXK_GL3, (void**)&orig_GL3 },
        { "GAMELET_SendMsg",                     (void*)SBXK_GM,  (void**)&orig_GM },
        { "GAMELET_ReportStatsFunc",             (void*)SBXK_GM_ReportStats, (void**)&orig_GM_ReportStats },
        { "GAMELET_ReportLogFunc",               (void*)SBXK_GM_ReportLog,   (void**)&orig_GM_ReportLog },
        { "GAMELET_ReportToTNM2Func",            (void*)SBXK_GM_ReportTNM2,  (void**)&orig_GM_ReportTNM2 },

        // === UQM crash — كامل ===
        { "__ZN3UQM8UQMCrash4InitERKNS_9UQMStringEbbS3_",
          (void*)SBXK_UQMInit,        (void**)&orig_UQMInit },
        { "__ZN3UQM8UQMCrash9SetUserIdERKNS_9UQMStringE",
          (void*)SBXK_UQMUser,        (void**)&orig_UQMUser },
        { "__ZN3UQM8UQMCrash8SetAppIdERKNS_9UQMStringE",
          (void*)SBXK_UQMApp,         (void**)&orig_UQMApp },
        { "__ZN3UQM8UQMCrash7LogInfoEiRKNS_9UQMStringES3_",
          (void*)SBXK_UQMLog,         (void**)&orig_UQMLog },
        { "__ZN3UQM8UQMCrash12SetUserValueERKNS_9UQMStringES3_",
          (void*)SBXK_UQMSetUser,     (void**)&orig_UQMSetUser },
        { "__ZN3UQM8UQMCrash18ReportExceptionPRVEiRKNS_9UQMStringES3_S3_RKNS_9UQMVectorINS_9UQMKVPairELj16EEES3_bi",
          (void*)SBXK_UQMRpt,         (void**)&orig_UQMRpt },
        { "__ZN3UQM8UQMCrash16SetCrashObserverEPNS_16UQMCrashObserverE",
          (void*)SBXK_UQMSetCrashObs, (void**)&orig_UQMSetCrashObs },
        { "__ZN3UQM8UQMCrash19SetCrashLogObserverEPNS_19UQMCrashLogObserverE",
          (void*)SBXK_UQMSetLogObs,   (void**)&orig_UQMSetLogObs },
        { "__ZN3UQM8UQMCrash24ConfigCrashHandleTimeoutEi",
          (void*)SBXK_UQMConfigTimeout, (void**)&orig_UQMConfigTimeout },

        // === CrashSight — كامل ===
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent11ReportStuckEiilPKcS3_S3_iS3_",
          (void*)SBXK_CSStuck,        (void**)&orig_CSStuck },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent19ReportExceptionJsonEiPKcS3_S3_S3_iS3_",
          (void*)SBXK_CSErr,          (void**)&orig_CSErr },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent13ReportLogInfoEPKcS3_",
          (void*)SBXK_CSLog,          (void**)&orig_CSLog },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent20GetLastSessionUserIdEPvi",
          (void*)SBXK_CSLast,         (void**)&orig_CSLast },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent12TestOomCrashEv",
          (void*)SBXK_CSTestOom,      (void**)&orig_CSTestOom },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent16GetCrashThreadIdEv",
          (void*)SBXK_CSGetCrashTid,  (void**)&orig_CSGetCrashTid },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent18IsLastSessionCrashEv",
          (void*)SBXK_CSIsLastCrash,  (void**)&orig_CSIsLastCrash },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent18SetUploadThreadNumEi",
          (void*)SBXK_CSSetUpload,    (void**)&orig_CSSetUpload },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent19ConfigCrashReporterEi",
          (void*)SBXK_CSConfigRep,    (void**)&orig_CSConfigRep },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent19SetCatchMultiSignalEb",
          (void*)SBXK_CSSetCatch,     (void**)&orig_CSSetCatch },

        // === HTTPDNS / Cros ===
        { "WGGetHostByNameAsyncWithTag",
          (void*)SBXK_WGGetHostByName, (void**)&orig_WGGetHostByName },
        { "Px_GetQJSFunctionTable_V04",
          (void*)SBXK_PxGetQJS,        (void**)&orig_PxGetQJS },
    };
    int t = sbxk_rebind(rb, (int)(sizeof(rb)/sizeof(rb[0])));
    NSLog(@"[SBXK-fh-ACE] %d rebound / %zu registered",
          t, sizeof(rb)/sizeof(rb[0]));
}

// --- Swizzle HttpDns plugin lifecycle (ObjC) ---
static void SBXK_HttpDns_onPause(id self, SEL _cmd)  { (void)self; (void)_cmd; }
static void SBXK_HttpDns_onResume(id self, SEL _cmd) { (void)self; (void)_cmd; }

static void SBXK_RegAceClasses(void) {
    Class hdpl = objc_getClass("HttpDnsPluginLifecycle");
    if (hdpl) {
        SEL sPause  = sel_registerName("onPause");
        SEL sResume = sel_registerName("onResume");
        if (class_getInstanceMethod(hdpl, sPause))
            class_replaceMethod(hdpl, sPause, (IMP)SBXK_HttpDns_onPause, "v@:");
        if (class_getInstanceMethod(hdpl, sResume))
            class_replaceMethod(hdpl, sResume, (IMP)SBXK_HttpDns_onResume, "v@:");
    }
}

// ============================================================================
// القسم 12: ماكرو التسجيل
// ============================================================================

#define REG_B(cls, name)   (void)SBXK_SwizzleS(SENS(#cls), SENS(#name), (IMP)SBXK_##cls##_##name, "B@:")
#define REG_V1(cls, name)  (void)SBXK_SwizzleS(SENS(#cls), SENS(#name), (IMP)SBXK_##cls##_##name, "v@:@")
#define REG_V2(cls, name)  (void)SBXK_SwizzleS(SENS(#cls), SENS(#name), (IMP)SBXK_##cls##_##name, "v@:@@")
#define REG_ID0(cls, name) (void)SBXK_SwizzleS(SENS(#cls), SENS(#name), (IMP)SBXK_##cls##_##name, "@@:")
#define REG_ID1(cls, name) (void)SBXK_SwizzleS(SENS(#cls), SENS(#name), (IMP)SBXK_##cls##_##name, "@@:@")
#define REG_ID2(cls, name) (void)SBXK_SwizzleS(SENS(#cls), SENS(#name), (IMP)SBXK_##cls##_##name, "@@:@@")
#define REG_ID3(cls, name) (void)SBXK_SwizzleS(SENS(#cls), SENS(#name), (IMP)SBXK_##cls##_##name, "@@:@@@")

// ============================================================================
// القسم 13: تسجيل الأساس
// ============================================================================

static void SBXK_RegBase(void) {
    REG_B(IntegrityChecker, integrity_detect);
    REG_B(IntegrityChecker, MTML_INTEGRITY_DETECT);
    REG_B(JailbreakDetector, isJailbroken);
    REG_B(JailbreakDetector, isJailbreak);
    REG_B(JailbreakDetector, checkJailbreak);
    REG_B(JailbreakDetector, jailbreakDetection);
    REG_B(SimulatorDetector, isSimulator);
    REG_B(SimulatorDetector, isSimulatorDevice);
    REG_B(SimulatorDetector, checkSimulator);
    REG_B(SecurityChecker, IsFileSystemModified);
    REG_B(SecurityChecker, isDebuggerAttached);
    REG_B(SecurityChecker, isDebugged);
    REG_B(SecurityChecker, checkDebugger);
    REG_B(SecurityChecker, amIBeingDebugged);
    REG_B(SecurityChecker, checkDebuggerAttach);
    REG_B(SecurityChecker, isHooked);
    REG_B(SecurityChecker, isHookDetected);
    REG_B(SecurityChecker, checkHook);
    REG_B(SecurityChecker, detectHook);
    REG_B(SecurityChecker, antiHookCheck);
    REG_B(SecurityChecker, isTampered);
    REG_B(SecurityChecker, checkTamper);
    REG_B(SecurityChecker, antiTamperCheck);
    REG_B(SecurityChecker, isInjected);
    REG_B(SecurityChecker, isLibraryInjected);
    REG_B(SecurityChecker, checkInjection);
    REG_B(SecurityChecker, antiInjectionCheck);
    REG_B(SecurityChecker, isReversingDetected);
    REG_B(SecurityChecker, checkReversing);
    REG_B(SecurityChecker, antiReversingCheck);
    REG_B(SecurityChecker, isBlocked);
    REG_B(SecurityChecker, antiBlockingCheck);
    REG_B(SecurityChecker, isVPNUsed);
    REG_B(SecurityChecker, isProxyUsed);
    REG_B(SecurityChecker, isFridaRunning);
    REG_B(SecurityChecker, isSubstrateLoaded);
    REG_B(SecurityChecker, isCydiaInstalled);
    REG_B(SecurityChecker, hasSuspiciousFiles);
    REG_B(SecurityChecker, isEnvironmentClean);
    REG_B(SecurityChecker, verifyIntegrity);
    REG_B(SecurityChecker, checkTokenValid);
    REG_B(SecurityChecker, isEnvironmentSafe);
    REG_B(SecurityChecker, verifySignature);
    REG_B(AReachability, isConnectionOnDemand);
    REG_B(AReachability, isConnectionRequired);
    REG_B(GVGCloudVoiceExtension, CheckDeviceMuteStat);
    REG_V1(GADAppOpenAd, adDidDismissFullScreenContent);
    REG_V1(GADAppOpenAd, adWillDismissFullScreenContent);
    REG_V1(GADAppOpenAd, adDidRecordClick);
    REG_V1(GADAppOpenAd, adDidRecordImpression);
    REG_V1(GADAppOpenAd, adWillPresentFullScreenContent);
    REG_V1(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError);
    REG_V1(GADAppOpenAd, setPaidEventHandler);
    REG_V1(GADAppOpenAd, adDidRecordUserInteraction);
    REG_V1(NetworkManager, SendSecurityReport);
    REG_ID0(GSDKCPU, getSystemCPUCircle);
    REG_ID0(GSDKMemory, getSystemAvailableMemory);
    REG_ID0(GSDKInGameManager, GSDKRealTimeDetect);
    REG_ID0(GSDKInGameSystem, GSDKInnerEnd);
    REG_ID0(GSDKInGameSystem, GSDKInnerRealTimeDetect);
    REG_ID0(GSDKPing, ping);
    REG_ID0(GSDKPing, stopPing);
    REG_ID0(GSDKPingDetect, ping);
    REG_ID0(PingDelegate, pingTimer);
    REG_ID0(SimplePing, start);
    REG_ID0(SimplePing, startWithHostAddress);
    REG_ID0(SimplePing, readData);
    REG_ID0(GSDKRealTimeDetect, pingDelayDetect);
    REG_ID0(GSDKRealTimeDetect, updDelayDetect_Port);
    REG_ID0(GSDKUdpDetect, isUDPConnect_Port);
    REG_ID0(GSDKWIFI, ping);
    REG_ID0(GSDKDetectPort, isConnection_Port);
    REG_ID0(GSDKInitManager, detectOperation);
    REG_ID0(GSDKPayEvent, GSDKPay_Tag_Status_Msg);
    REG_ID0(GSDKHttpRequest, requestControl_Openid_Acctype_Zoneid_Env);
    REG_ID1(SimplePing, sendPingWithData);
    REG_ID1(SimplePing, didFailWithError);
    REG_ID1(FBAdViewabilityValidator, checkViewability);
    REG_ID1(TApmSceneMarker, postStepEvent);
    REG_ID1(TApmSceneMarker, postStreamEvent);
    REG_ID1(APMCollector, collectMetrics);
    REG_ID1(APMCollector, reportNow);
    REG_ID1(AudioDeviceMgr, UpdateDeviceState);
    REG_ID2(SimplePing, validatePingResponsePacket_sequenceNumber);
    REG_ID2(FIRMessaging, retrieveFCMTokenForSenderID_completion);
    REG_ID2(FIRMessaging, deleteFCMTokenForSenderID_completion);
    REG_ID2(FIRMessaging, subscribeToTopic_completion);
    REG_ID2(FIRMessaging, unsubscribeFromTopic_completion);
    REG_ID2(FIRMessaging, setAPNSToken_withUserInfo);
    REG_ID2(GSDKInGameSystem, GSDKInnerSaveFPS_FpsDots);
    REG_ID3(SimplePing, pingPacketWithType_payload_requiresChecksum);
    REG_ID3(GSDKInGameSystem, GSDKInnerStart_SceneID_RoomIP);
    REG_ID0(GVGCloudVoice, openMic);
    REG_ID0(GVGCloudVoice, openSpeaker);
    REG_ID0(GVGCloudVoiceExtension, GetBGMPlayState);
    REG_ID0(GVGCloudVoiceExtension, GetMicState);
    REG_ID0(GVGCloudVoiceExtension, GetSpeakerState);
    REG_ID0(GVoiceMuteSwitch, detectMuteSwitch);
    REG_ID0(GCloudVoiceEngine, StartTve);
    REG_ID0(GCloudVoiceEngine, TestMic);
    REG_ID0(GCloudVoiceEngine, GetMicLevel);
    REG_ID0(GCloudVoiceEngine, GetSpeakerLevel);
    REG_ID0(GCloudVoiceEngine, GetBGMLevel);
    REG_ID0(GCloudVoiceEngine, GetBGMFileTime);
    REG_ID0(GCloudVoiceEngine, GetBGMPlayTime);
    REG_ID0(GCloudVoiceEngine, GetRecordKaraokeTotalTime);
    REG_ID0(GCloudVoiceEngine, StartPreview);
    REG_ID0(GCloudVoiceEngine, StopPreview);
    REG_ID0(GCloudVoiceEngine, PauseKaraoke);
    REG_ID0(GCloudVoiceEngine, ResumeKaraoke);
    REG_ID0(GCloudVoiceEngine, RSTSStopRecording);
    REG_ID0(GCloudVoiceEngine, TextToStreamSpeechStop);
    REG_ID0(GCloudVoiceEngine, StopKaraokeRecording);
    REG_ID0(GCloudCoreRemoteConfig, getConfig);
    REG_ID0(GCloudUnityPlugin, Initialize);
    REG_ID0(GCloudUnityPlugin, ReportEvent);
    REG_ID1(GCloudVoiceEngine, StartRecording);
    REG_ID1(GCloudVoiceEngine, StopRecording);
    REG_ID1(GCloudVoiceEngine, StartBGMPlay);
    REG_ID1(GCloudVoiceEngine, StopBGMPlay);
    REG_ID1(GCloudVoiceEngine, PauseBGMPlay);
    REG_ID1(GCloudVoiceEngine, ResumeBGMPlay);
    REG_ID1(GCloudVoiceEngine, SetBGMPath);
    REG_ID1(GCloudVoiceEngine, SetLogCallBack);
    REG_ID1(GCloudCoreRemoteConfig, updateConfig);
    REG_ID1(GCloudUnityPlugin, SetGameObjectName);
    REG_ID2(GCloudVoiceEngine, QuitRoom_Scenes_timeout);
    REG_ID0(FIRMessagingRmqManager, openDatabase);
    REG_ID0(FIRMessaging, APNSToken);
    REG_ID0(GADAppOpenAd, responseInfo);
    REG_ID0(GADMobileAds, initializationStatus);
    REG_ID0(GADAdNetworkResponseInfo, adUnitMapping);
    REG_ID0(FBAdViewabilityValidator, stopMonitoring);
    REG_ID0(FBAdMonitor, stopMonitoring);
    REG_ID0(APMDeviceInfoSupport, getBatteryState);
    REG_ID0(APMDeviceInfoSupport, getThermalState);
    REG_ID0(TApmSceneMarker, markLevelFin);
    REG_ID0(serviceCommunication, getValueForKeypath);
    REG_ID0(AudioDeviceMgr, GetAudioDeviceConnectState);
    REG_ID0(VKAuth, logout);
    REG_ID0(SCSDKLoginClient, logout);
}

// ============================================================================
// القسم 14: تسجيل الموسّع
// ============================================================================

static void SBXK_RegExtended(void) {
    REG_B(AntiDataProxy, checkIntegrity);
    REG_B(AntiDataProxy, isIntegrityOK);
    REG_B(AntiDataProxy, verifyData);
    REG_B(AntiDataProxy, isDataValid);
    REG_B(AntiDataProxy, isModified);
    REG_B(AntiDataProxy, isCheat);
    REG_B(AntiDataProxy, isSuspicious);
    REG_B(AntiDataProxy, antiCheatCheck);
    REG_B(AntiDataProxy, securityCheck);
    REG_B(AntiDataProxy, hasRisk);
    REG_B(AntiDataProxy, detectRisk);
    REG_B(AntiDataProxy, isRiskDetected);
    REG_B(AntiDataProxy, isValid);
    REG_B(AntiDataProxy, isSafe);
    REG_B(AntiDataProxy, isClean);
    REG_B(AntiDataProxy, verifyIntegrity);
    REG_B(AntiDataProxy, verifySignature);
    REG_B(AntiDataProxy, shouldPass);
    REG_B(AntiDataProxy, allowReport);
    REG_V1(AntiDataProxy, sendData);
    REG_V1(AntiDataProxy, report);
    REG_V1(AntiDataProxy, submit);
    REG_V1(AntiDataProxy, upload);
    REG_V1(AntiDataProxy, dispatch);
    REG_V1(AntiDataProxy, flush);
    REG_ID0(AntiDataProxy, getData);
    REG_ID0(AntiDataProxy, getPayload);
    REG_ID0(AntiDataProxy, getHeader);
    REG_ID0(AntiDataProxy, getBody);
    REG_ID0(AntiDataProxy, getResponse);
    REG_ID0(AntiDataProxy, getConfig);
    REG_ID0(AntiDataProxy, getState);
    REG_ID0(AntiDataProxy, getStatus);
    REG_ID1(AntiDataProxy, setData);
    REG_ID1(AntiDataProxy, setPayload);
    REG_ID1(AntiDataProxy, setConfig);
    REG_ID1(AntiDataProxy, process);
    REG_ID1(AntiDataProxy, handle);
    REG_ID1(AntiDataProxy, onReceive);
    REG_ID1(AntiDataProxy, onMessage);
    REG_ID2(AntiDataProxy, sendData_withHeader);
    REG_ID2(AntiDataProxy, sendReport_withType);
    REG_ID2(AntiDataProxy, postData_withURL);

    REG_B(TssInfoReceiver, isRooted);
    REG_B(TssInfoReceiver, isRootedDevice);
    REG_B(TssInfoReceiver, isJailbroken);
    REG_B(TssInfoReceiver, isJailbreakDevice);
    REG_B(TssInfoReceiver, isEmulator);
    REG_B(TssInfoReceiver, isEmulatorDevice);
    REG_B(TssInfoReceiver, isSimulator);
    REG_B(TssInfoReceiver, isDebuggerAttached);
    REG_B(TssInfoReceiver, isDebugged);
    REG_B(TssInfoReceiver, isModified);
    REG_B(TssInfoReceiver, isTampered);
    REG_B(TssInfoReceiver, isInjected);
    REG_B(TssInfoReceiver, isHooked);
    REG_B(TssInfoReceiver, hasCheat);
    REG_B(TssInfoReceiver, hasCheatTool);
    REG_B(TssInfoReceiver, hasSuspiciousFiles);
    REG_B(TssInfoReceiver, hasRisk);
    REG_B(TssInfoReceiver, checkEnvironment);
    REG_B(TssInfoReceiver, checkSecurity);
    REG_B(TssInfoReceiver, checkCheat);
    REG_B(TssInfoReceiver, detectCheat);
    REG_B(TssInfoReceiver, detectRisk);
    REG_B(TssInfoReceiver, detectEnvironment);
    REG_B(TssInfoReceiver, isCheating);
    REG_B(TssInfoReceiver, isCheatDetected);
    REG_B(TssInfoReceiver, isSuspicious);
    REG_B(TssInfoReceiver, antiCheatCheck);
    REG_B(TssInfoReceiver, securityCheck);
    REG_B(TssInfoReceiver, shouldReport);
    REG_B(TssInfoReceiver, shouldBlock);
    REG_B(TssInfoReceiver, needReport);
    REG_B(TssInfoReceiver, needBlock);
    REG_B(TssInfoReceiver, isBlocked);
    REG_B(TssInfoReceiver, isBanned);
    REG_B(TssInfoReceiver, isSafe);
    REG_B(TssInfoReceiver, isClean);
    REG_B(TssInfoReceiver, isEnvironmentClean);
    REG_B(TssInfoReceiver, isEnvironmentSafe);
    REG_B(TssInfoReceiver, verifyIntegrity);
    REG_B(TssInfoReceiver, verifySignature);
    REG_B(TssInfoReceiver, checkTokenValid);
    REG_V1(TssInfoReceiver, start);
    REG_V1(TssInfoReceiver, stop);
    REG_V1(TssInfoReceiver, run);
    REG_V1(TssInfoReceiver, onReceiveData);
    REG_V1(TssInfoReceiver, onRecvData);
    REG_V1(TssInfoReceiver, report);
    REG_V1(TssInfoReceiver, sendReport);
    REG_V1(TssInfoReceiver, uploadReport);
    REG_V1(TssInfoReceiver, submitReport);
    REG_V1(TssInfoReceiver, reportRoot);
    REG_V1(TssInfoReceiver, reportEmu);
    REG_V1(TssInfoReceiver, reportDebugger);
    REG_V1(TssInfoReceiver, reportCheat);
    REG_V1(TssInfoReceiver, reportAlert);
    REG_V1(TssInfoReceiver, sendAlert);
    REG_V1(TssInfoReceiver, blockGame);
    REG_V1(TssInfoReceiver, blockPlayer);
    REG_V1(TssInfoReceiver, kickPlayer);
    REG_ID0(TssInfoReceiver, currentState);
    REG_ID0(TssInfoReceiver, getState);
    REG_ID0(TssInfoReceiver, getStatus);
    REG_ID0(TssInfoReceiver, getReport);
    REG_ID0(TssInfoReceiver, getResult);
    REG_ID0(TssInfoReceiver, getData);
    REG_ID0(TssInfoReceiver, getInfo);
    REG_ID0(TssInfoReceiver, getRiskInfo);
    REG_ID0(TssInfoReceiver, getCheatInfo);
    REG_ID0(TssInfoReceiver, getEnvInfo);
    REG_ID0(TssInfoReceiver, getConfig);
    REG_ID1(TssInfoReceiver, updateState);
    REG_ID1(TssInfoReceiver, setState);
    REG_ID1(TssInfoReceiver, handleData);
    REG_ID1(TssInfoReceiver, handleMessage);
    REG_ID1(TssInfoReceiver, processData);
    REG_ID1(TssInfoReceiver, onMessage);
    REG_ID1(TssInfoReceiver, onCommand);

    REG_B(CheckSymbolSource, CheckSymbol);
    REG_B(CheckSymbolSource, checkSymbol);
    REG_B(CheckSymbolSource, checkSymbolSource);
    REG_B(CheckSymbolSource, isSymbolValid);
    REG_B(CheckSymbolSource, isSymbolOK);
    REG_B(CheckSymbolSource, verifySymbol);
    REG_B(CheckSymbolSource, verifySymbols);
    REG_B(CheckSymbolSource, isSourceSafe);
    REG_B(CheckSymbolSource, checkSource);
    REG_B(CheckSymbolSource, isSourceOK);
    REG_B(CheckSymbolSource, sourceIsValid);
    REG_ID0(CheckSymbolSource, getResult);
    REG_ID0(CheckSymbolSource, getReport);
    REG_ID1(CheckSymbolSource, checkSymbolSourceWithData);
    REG_ID1(CheckSymbolSource, verifySymbolWithData);

    REG_B(CFastScanThread, isRunning);
    REG_B(CFastScanThread, shouldScan);
    REG_B(CFastScanThread, hasResult);
    REG_B(CScanThread, isRunning);
    REG_B(CScanThread, shouldScan);
    REG_B(CScanThread, hasResult);
    REG_B(CSendThread, isRunning);
    REG_B(CSendThread, shouldSend);
    REG_B(CSendThread, hasData);
    REG_B(CMrpcsMonitor, isRunning);
    REG_B(CMrpcsMonitor, shouldReport);
    REG_B(CMrpcsMgrE, isReady);
    REG_B(CMrpcsMgrE, shouldReport);
    REG_B(CPointDataMgr, shouldReport);
    REG_B(CPointDataMgr, hasData);
    REG_B(CPointGlobalMgr, shouldReport);
    REG_B(CPointGlobalMgr, hasData);
    REG_B(CMrpcsLFUpdater, shouldUpdate);
    REG_B(CMrpcsLFUpdater, hasUpdate);
    REG_V1(CFastScanThread, start);
    REG_V1(CFastScanThread, run);
    REG_V1(CFastScanThread, execute);
    REG_V1(CFastScanThread, scan);
    REG_V1(CFastScanThread, doScan);
    REG_V1(CFastScanThread, report);
    REG_V1(CFastScanThread, sendReport);
    REG_V1(CScanThread, start);
    REG_V1(CScanThread, run);
    REG_V1(CScanThread, execute);
    REG_V1(CScanThread, scan);
    REG_V1(CScanThread, doScan);
    REG_V1(CScanThread, report);
    REG_V1(CScanThread, sendReport);
    REG_V1(CSendThread, start);
    REG_V1(CSendThread, run);
    REG_V1(CSendThread, execute);
    REG_V1(CSendThread, send);
    REG_V1(CSendThread, doSend);
    REG_V1(CSendThread, report);
    REG_V1(CMrpcsMonitor, start);
    REG_V1(CMrpcsMonitor, stop);
    REG_V1(CMrpcsMonitor, run);
    REG_V1(CMrpcsMonitor, execute);
    REG_V1(CMrpcsMonitor, report);
    REG_V1(CMrpcsMonitor, sendReport);
    REG_V1(CMrpcsMgrE, sendScanResult);
    REG_V1(CMrpcsMgrE, reportResult);
    REG_V1(CMrpcsMgrE, sendReport);
    REG_V1(CMrpcsMgrE, report);
    REG_V1(CMrpcsMgrE, upload);
    REG_V1(CPointDataMgr, report);
    REG_V1(CPointDataMgr, sendData);
    REG_V1(CPointDataMgr, uploadData);
    REG_V1(CPointDataMgr, dispatch);
    REG_V1(CPointGlobalMgr, report);
    REG_V1(CPointGlobalMgr, sendReport);
    REG_V1(CPointGlobalMgr, upload);
    REG_V1(CMrpcsLFUpdater, update);
    REG_V1(CMrpcsLFUpdater, start);
    REG_V1(CMrpcsLFUpdater, run);
    REG_V1(CMrpcsLFUpdater, check);
    REG_V1(CMrpcsLFUpdater, report);
    REG_ID0(CMrpcsMgrE, getInstance);
    REG_ID0(CMrpcsMgrE, getState);
    REG_ID0(CMrpcsMgrE, getReport);
    REG_ID0(CMrpcsMgrE, getResult);
    REG_ID0(CMrpcsMgrE, getConfig);
    REG_ID0(CMrpcsMonitor, getState);
    REG_ID0(CMrpcsMonitor, getReport);
    REG_ID0(CMrpcsMonitor, getResult);
    REG_ID0(CPointDataMgr, getData);
    REG_ID0(CPointDataMgr, getReport);
    REG_ID0(CPointDataMgr, getState);
    REG_ID0(CPointGlobalMgr, getData);
    REG_ID0(CPointGlobalMgr, getReport);
    REG_ID0(CPointGlobalMgr, getState);
    REG_ID0(CMrpcsLFUpdater, getState);
    REG_ID0(CMrpcsLFUpdater, getConfig);
    REG_ID0(CMrpcsLFUpdater, getVersion);
    REG_ID1(CMrpcsMgrE, setConfig);
    REG_ID1(CMrpcsMgrE, setState);
    REG_ID1(CMrpcsMgrE, handleData);
    REG_ID1(CMrpcsMgrE, processData);
    REG_ID1(CMrpcsMonitor, setConfig);
    REG_ID1(CMrpcsMonitor, handleData);
    REG_ID1(CPointDataMgr, setData);
    REG_ID1(CPointDataMgr, handleData);
    REG_ID1(CPointGlobalMgr, setData);
    REG_ID1(CPointGlobalMgr, handleData);
    REG_ID2(CMrpcsMgrE, sendData_withType);
    REG_ID2(CMrpcsMgrE, handleMessage_withData);
    REG_ID2(CPointDataMgr, sendData_withType);
    REG_ID2(CPointGlobalMgr, sendData_withType);

    REG_V1(NetworkManager, sendRootAlert);
    REG_V1(NetworkManager, sendEmuAlert);
    REG_V1(NetworkManager, sendDebuggerAlert);
    REG_V1(NetworkManager, sendCheatAlert);
    REG_V1(NetworkManager, send9010Alert);
    REG_V1(NetworkManager, send9014Alert);
    REG_V1(NetworkManager, send9005Alert);
    REG_V1(NetworkManager, sendShellReport);
    REG_V1(NetworkManager, sendCheckState);

    REG_ID0(ScreenShot, takeScreenShot);
    REG_ID0(ScreenShot, screenshot);
    REG_ID1(ScreenShot, takeScreenShotEx);
    REG_ID1(ScreenShot, screenshotOfView);
    REG_ID1(ScreenShot, getBufFromImage);
    REG_ID1(ScreenShot, getAppWindowsForScreen);
    REG_ID0(Rotate, fixOrientation);
    REG_ID0(Rotate, flipVertical);
    REG_ID0(Rotate, flipHorizontal);
    REG_ID1(Rotate, rotate);
    REG_ID1(Rotate, imageRotatedByRadians);
    REG_ID1(Rotate, imageRotatedByDegrees);

    REG_V2(AceMsgBoxImp, ShowMessageBoxWithTitle_Message_LeftBtn_RightBtn);
    REG_V1(AceMsgBoxImp, dismiss);
    REG_V1(AceMsgBoxImp, show);
    REG_ID0(AceMsgBoxImp, viewTitle);
    REG_ID0(AceMsgBoxImp, viewContent);
    REG_ID0(AceMsgBoxImp, leftBtnContent);
    REG_ID0(AceMsgBoxImp, rightBtnContent);
}

// ============================================================================
// القسم 15: تسجيل قتل أدوات الحقن
// ============================================================================

static void SBXK_RegInjectionKill(void) {
    REG_B(SBXK_FridaDet, isFridaPresent);
    REG_B(SBXK_FridaDet, isFridaRunning);
    REG_B(SBXK_FridaDet, hasFrida);
    REG_B(SBXK_FridaDet, checkFrida);
    REG_B(SBXK_FridaDet, detectFrida);
    REG_B(SBXK_FridaDet, isFridaGadgetLoaded);
    REG_B(SBXK_FridaDet, hasFridaGadget);
    REG_B(SBXK_FridaDet, isFridaAgentLoaded);
    REG_B(SBXK_FridaDet, hasNamedPipe);
    REG_B(SBXK_FridaDet, checkNamedPipe);
    REG_B(SBXK_FridaDet, isPipeOpen);
    REG_B(SBXK_SubDet, isSubstrateLoaded);
    REG_B(SBXK_SubDet, hasSubstrate);
    REG_B(SBXK_SubDet, checkSubstrate);
    REG_B(SBXK_SubDet, isCydiaSubstrateLoaded);
    REG_B(SBXK_SubDet, isSubstituteLoaded);
    REG_B(SBXK_SubDet, hasSubstitute);
    REG_B(SBXK_SubDet, checkSubstitute);
    REG_B(SBXK_InjectDet, isElleKitLoaded);
    REG_B(SBXK_InjectDet, hasElleKit);
    REG_B(SBXK_InjectDet, isLibhookerLoaded);
    REG_B(SBXK_InjectDet, hasLibhooker);
    REG_B(SBXK_InjectDet, isTweakInjectLoaded);
    REG_B(SBXK_InjectDet, hasTweakInject);
    REG_B(SBXK_InjectDet, checkTweaks);
    REG_B(SBXK_InjectDet, hasJailbreakTweak);
    REG_B(SBXK_InjectDet, isDylibInjected);
    REG_B(SBXK_InjectDet, isImageInjected);
    REG_B(SBXK_InjectDet, hasInjectedDylib);
    REG_B(SBXK_InjectDet, isForeignImageLoaded);
    REG_B(SBXK_InjectDet, hasHooked);
    REG_B(SBXK_InjectDet, hasMSHook);
    REG_B(SBXK_InjectDet, checkMSHook);
    REG_B(SBXK_InjectDet, checkSymbolHook);
    REG_B(SBXK_InjectDet, hasSwizzled);
    REG_B(SBXK_InjectDet, hasDYLD_INSERT);
    REG_B(SBXK_InjectDet, isDYLDInjected);
    REG_B(SBXK_InjectDet, checkDYLD);
    REG_B(SBXK_InjectDet, isEnvInjected);
    REG_B(SBXK_InjectDet, hasEnvVarInject);
    REG_B(SBXK_InjectDet, isAttached);
    REG_B(SBXK_InjectDet, isBeingDebugged);
    REG_B(SBXK_InjectDet, isTraced);
    REG_B(SBXK_InjectDet, hasPtraced);
    REG_B(SBXK_InjectDet, checkPtrace);
    REG_B(SBXK_InjectDet, isPtraceDetected);
    REG_B(SBXK_InjectDet, hasForeignExceptionPort);
    REG_B(SBXK_InjectDet, hasExceptionHijack);
    REG_B(SBXK_InjectDet, checkExceptionPorts);
    REG_B(SBXK_InjectDet, isPortHijacked);
    REG_B(SBXK_InjectDet, isEnvironmentClean);
    REG_B(SBXK_InjectDet, isEnvironmentSafe);
    REG_B(SBXK_InjectDet, isClean);
    REG_B(SBXK_InjectDet, isSafe);
    REG_B(SBXK_InjectDet, verifyNoInjection);
    REG_B(SBXK_InjectDet, verifyNoHook);
    REG_B(SBXK_InjectDet, verifyNoDylib);
    REG_B(SBXK_InjectDet, verifyImageClean);
    REG_V1(SBXK_InjectDet, reportFrida);
    REG_V1(SBXK_InjectDet, reportSubstrate);
    REG_V1(SBXK_InjectDet, reportSubstitute);
    REG_V1(SBXK_InjectDet, reportElleKit);
    REG_V1(SBXK_InjectDet, reportLibhooker);
    REG_V1(SBXK_InjectDet, reportInjection);
    REG_V1(SBXK_InjectDet, reportHook);
    REG_V1(SBXK_InjectDet, reportDylib);
    REG_V1(SBXK_InjectDet, reportAttach);
    REG_V1(SBXK_InjectDet, reportPtrace);
    REG_V1(SBXK_InjectDet, reportExceptionPort);
    REG_V1(SBXK_InjectDet, reportNamedPipe);
    REG_V1(SBXK_InjectDet, reportEnvInject);
    REG_V1(SBXK_InjectDet, sendAlert);
    REG_V1(SBXK_InjectDet, sendReport);
    REG_V1(SBXK_InjectDet, uploadReport);
    REG_V1(SBXK_InjectDet, submitReport);
    REG_V1(SBXK_InjectDet, notifyServer);
    REG_V1(SBXK_InjectDet, alertUser);
    REG_V1(SBXK_InjectDet, blockGame);
    REG_V1(SBXK_InjectDet, kickPlayer);
}

// ============================================================================
// القسم 16: تسجيل الأصناف الحقيقية
// ============================================================================

static void SBXK_RegReal(void) {
    REG_B(QAPMReport, isEnabled);
    REG_B(QAPMReport, isRunning);
    REG_B(QAPMReport, shouldReport);
    REG_B(QAPMReport, hasReport);
    REG_V1(QAPMReport, report);
    REG_V1(QAPMReport, sendReport);
    REG_V1(QAPMReport, upload);
    REG_V1(QAPMReport, submit);
    REG_V1(QAPMReport, flush);
    REG_V1(QAPMReport, start);
    REG_V1(QAPMReport, stop);
    REG_V1(QAPMReport, setEnabled);
    REG_V1(QAPMReport, setUserId);
    REG_V1(QAPMReport, setUserValue);
    REG_V1(QAPMReport, trackEvent);
    REG_V1(QAPMReport, reportException);
    REG_V1(QAPMReport, reportCrash);
    REG_V1(QAPMReport, reportPerformance);
    REG_V1(QAPMReport, reportNetwork);
    REG_V1(QAPMReport, reportBattery);
    REG_ID0(QAPMReport, getState);
    REG_ID0(QAPMReport, getConfig);
    REG_ID0(QAPMReport, getReport);
    REG_ID0(QAPMReport, getDeviceId);
    REG_ID0(QAPMReport, getSessionId);
    REG_ID1(QAPMReport, updateConfig);
    REG_ID1(QAPMReport, setConfig);
    REG_ID1(QAPMReport, handleData);

    REG_B(MeemoUserManager, isGuest);
    REG_B(MeemoUserManager, isBanned);
    REG_B(MeemoUserManager, isBlocked);
    REG_B(MeemoUserManager, isUnderage);
    REG_ID0(MeemoUserManager, currentUser);
    REG_ID0(MeemoUserManager, currentToken);
    REG_ID0(MeemoUserManager, currentOpenId);
    REG_ID0(MeemoUserManager, currentAccountId);
    REG_ID0(MeemoUserManager, currentSession);
    REG_ID0(MeemoUserManager, userInfo);
    REG_ID0(MeemoUserManager, getInstance);
    REG_ID1(MeemoUserManager, setUser);
    REG_ID1(MeemoUserManager, setToken);
    REG_ID1(MeemoUserManager, updateUserInfo);

    REG_V1(MeemoLogUtil, log);
    REG_V1(MeemoLogUtil, logInfo);
    REG_V1(MeemoLogUtil, logDebug);
    REG_V1(MeemoLogUtil, logWarn);
    REG_V1(MeemoLogUtil, logError);
    REG_V1(MeemoLogUtil, logEvent);
    REG_V1(MeemoLogUtil, sendLog);
    REG_V1(MeemoLogUtil, uploadLog);
    REG_V1(MeemoLogUtil, flush);
    REG_V1(MeemoLogUtil, report);

    REG_ID0(MeemoUtils, getInstance);
    REG_ID0(MeemoUtils, getDeviceId);
    REG_ID0(MeemoUtils, getChannel);
    REG_ID0(MeemoUtils, getVersion);
    REG_ID0(MeemoUtils, getCountryCode);
    REG_ID0(MeemoUtils, getLanguage);
    REG_ID0(MeemoUtils, getPlatform);
    REG_ID0(MeemoUtils, getUUID);

    REG_B(PBConfigManager, isModified);
    REG_B(PBConfigManager, isTampered);
    REG_ID0(PBConfigManager, getConfig);
    REG_ID0(PBConfigManager, getInstance);
    REG_ID0(PBConfigManager, currentConfig);
    REG_ID1(PBConfigManager, updateConfig);
    REG_ID1(PBConfigManager, setConfig);
    REG_ID0(CdnConfigManager, getConfig);
    REG_ID0(CdnConfigManager, getInstance);
    REG_ID0(CdnConfigManager, currentConfig);
    REG_ID1(CdnConfigManager, updateConfig);

    REG_ID0(MeemoBundleUtils, getInstance);
    REG_ID0(MeemoBundleUtils, bundlePath);
    REG_ID0(MeemoBundleUtils, mainBundle);
    REG_ID0(MeemoSubPackageDownloadMgr, getInstance);
    REG_ID0(MeemoSubPackageDownloadMgr, state);
    REG_ID0(MeemoSubPackageInfoProvider, getInstance);
    REG_ID0(MeemoSubPackageInfoProvider, currentInfo);
    REG_ID0(MeemoSubPackageUtils, getInstance);
    REG_ID0(MeemoCoreInitalizer, getInstance);
    REG_ID0(MeemoCoreInitalizer, state);
    REG_V1(MeemoCoreInitalizer, initialize);
    REG_V1(MeemoCoreInitalizer, start);
    REG_ID0(MeemoFlutterViewController, getInstance);

    REG_B(HotfixPatchDownloadManager, isModified);
    REG_B(HotfixPatchDownloadManager, hasIllegalPatch);
    REG_B(HotfixPatchDownloadManager, isTampered);
    REG_ID0(HotfixPatchDownloadManager, getInstance);
    REG_ID0(HotfixPatchDownloadManager, state);
    REG_ID0(HotfixPatchDownloadManager, currentPatch);
    REG_ID1(HotfixPatchDownloadManager, checkPatch);
    REG_ID1(HotfixPatchDownloadManager, applyPatch);

    REG_ID0(DeviceInfoPlugin, getInstance);
    REG_ID0(DeviceInfoPlugin, deviceInfo);
    REG_ID0(DeviceInfoPlugin, model);
    REG_ID0(DeviceInfoPlugin, systemVersion);
    REG_ID0(DeviceInfoPlugin, identifierForVendor);
    REG_B(FlutterFlogPlugin, isEnabled);
    REG_V1(FlutterFlogPlugin, log);
    REG_V1(FlutterFlogPlugin, report);
    REG_B(FlutterQAPMPlugin, isEnabled);
    REG_V1(FlutterQAPMPlugin, report);
    REG_V1(FlutterQAPMPlugin, trackEvent);
}

// ============================================================================
// القسم 17: عارض سجل الأعطال
// ============================================================================

@interface SBXK_LogViewer : NSObject @end
@implementation SBXK_LogViewer
+ (void)installObserver {
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(onLaunched:)
        name:UIApplicationDidFinishLaunchingNotification object:nil];
}
+ (void)onLaunched:(NSNotification *)n {
    (void)n;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self show]; });
}
+ (void)show {
    NSString *p = [NSHomeDirectory()
                   stringByAppendingPathComponent:@"Documents/sbxk_crash_prev.log"];
    NSData *d = [NSData dataWithContentsOfFile:p];
    if (!d.length) { atomic_store(&g_viewer_done, true); return; }
    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (!s.length) { atomic_store(&g_viewer_done, true); return; }
    if (s.length > 2500) s = [[s substringToIndex:2500] stringByAppendingString:@"…"];

    UIWindow *w = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if (sc.activationState == UISceneActivationStateForegroundActive &&
                [sc isKindOfClass:[UIWindowScene class]]) {
                for (UIWindow *win in ((UIWindowScene *)sc).windows) {
                    if (win.isKeyWindow) { w = win; break; }
                }
                if (w) break;
            }
        }
    }
    if (!w) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        w = [UIApplication sharedApplication].keyWindow;
#pragma clang diagnostic pop
    }
    atomic_store(&g_viewer_done, true);

    if (!w || !w.rootViewController || w.rootViewController.presentedViewController) return;
    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:@"SBXK" message:s
        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"OK"
        style:UIAlertActionStyleDefault handler:nil]];
    [w.rootViewController presentViewController:a animated:YES completion:nil];
}
@end

// ============================================================================
// القسم 18: تنظيف ملفات
// ============================================================================

static NSArray<NSString *> *sbxk_cleanup_exact_paths(void) {
    NSString *home = NSHomeDirectory();
    NSString *docs = [home stringByAppendingPathComponent:@"Documents"];
    NSString *lib  = [home stringByAppendingPathComponent:@"Library"];
    return @[
        [docs stringByAppendingPathComponent:@"sbxk_crash.log"],
        [docs stringByAppendingPathComponent:@"sbxk_crash_prev.log"],
        [docs stringByAppendingPathComponent:@"ShadowTrackerExtra/Saved/Logs/UQMCrash"],
        [docs stringByAppendingPathComponent:@"ShadowTrackerExtra/Saved/Logs/CrashSight"],
        [docs stringByAppendingPathComponent:@"ShadowTrackerExtra/Saved/Logs/ano_crash.txt"],
        [lib  stringByAppendingPathComponent:@"Caches/com.tencent.uqm.crash"],
        [lib  stringByAppendingPathComponent:@"Caches/com.tencent.gcloud.crashsight"],
        [lib  stringByAppendingPathComponent:@"Caches/ano_log"],
    ];
}

static NSArray<NSString *> *sbxk_cleanup_dirs(void) {
    return @[
        [NSHomeDirectory() stringByAppendingPathComponent:
            @"Documents/ShadowTrackerExtra/Saved/Logs"],
    ];
}

static BOOL sbxk_should_skip(NSString *name) {
    if (!name.length) return YES;
    if ([name isEqualToString:@"MMKV"])         return YES;
    if ([name isEqualToString:@"Gamelet"])      return YES;
    if ([name isEqualToString:@"mmkv.default"]) return YES;
    if ([name isEqualToString:@"kvcache8.dat"]) return YES;
    if ([name hasSuffix:@".crc"])               return YES;
    if ([name hasSuffix:@".sig"])               return YES;
    if ([name hasSuffix:@".dat"])               return YES;
    if ([name hasSuffix:@".plist"])             return YES;
    return NO;
}

static void sbxk_do_cleanup(void) {
    @try {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSError *err = nil;

        for (NSString *p in sbxk_cleanup_exact_paths()) {
            if (!atomic_load(&g_viewer_done) &&
                [p hasSuffix:@"sbxk_crash_prev.log"]) continue;
            if ([fm fileExistsAtPath:p]) {
                [fm removeItemAtPath:p error:&err];
                err = nil;
            }
        }

        for (NSString *dir in sbxk_cleanup_dirs()) {
            if (![fm fileExistsAtPath:dir]) continue;
            NSArray *items = [fm contentsOfDirectoryAtPath:dir error:&err];
            err = nil;
            for (NSString *item in items) {
                if (sbxk_should_skip(item)) continue;
                if (![item hasSuffix:@".log"] &&
                    ![item hasSuffix:@".txt"] &&
                    ![item hasSuffix:@".dump"] &&
                    ![item hasSuffix:@".stack"]) continue;
                NSString *full = [dir stringByAppendingPathComponent:item];
                [fm removeItemAtPath:full error:&err];
                err = nil;
            }
        }
    } @catch (__unused NSException *e) {}
}

__attribute__((constructor))
static void sbxk_start_cleanup_timer(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        sbxk_do_cleanup();
        [NSTimer scheduledTimerWithTimeInterval:2.0
                                         repeats:YES
                                           block:^(NSTimer *t) {
            (void)t;
            sbxk_do_cleanup();
        }];
    });
}

// ============================================================================
// القسم 19: نقطة الدخول
// ============================================================================

static void sbxk_on_image_added(const struct mach_header *mh, intptr_t slide) {
    (void)mh; (void)slide;
    atomic_store(&g_pending, true);
}

static void SBXK_FullInstall(void) {
    @try { SBXK_RegBase();          } @catch (NSException *e) { NSLog(@"[SBXK] RegBase: %@", e); }
    @try { SBXK_RegExtended();      } @catch (NSException *e) { NSLog(@"[SBXK] RegExtended: %@", e); }
    @try { SBXK_RegInjectionKill(); } @catch (NSException *e) { NSLog(@"[SBXK] RegInject: %@", e); }
    @try { SBXK_RegReal();          } @catch (NSException *e) { NSLog(@"[SBXK] RegReal: %@", e); }
    @try { SBXK_RegAceClasses();    } @catch (NSException *e) { NSLog(@"[SBXK] RegAce: %@", e); }
    @try { SBXK_RegisterFishhook(); } @catch (NSException *e) { NSLog(@"[SBXK] Fishhook: %@", e); }
}

static void SBXK_Retry(void) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ SBXK_Retry(); });
        return;
    }
    SBXK_FullInstall();
}

static void SBXK_Run(void) {
    if (!sbxk_should_run()) return;
    atomic_store(&g_phase, 20);
    SBXK_FullInstall();
    atomic_store(&g_phase, 30);
    if (!sbxk_self_ok()) {
        NSLog(@"[SBXK] self-check fail — rollback");
        sbxk_disable_all();
        return;
    }
    sbxk_mark_ok();
    NSLog(@"[SBXK] v7.10.5 done=%lu skip=%lu",
          (unsigned long)g_done.count, (unsigned long)g_skip.count);
}

__attribute__((constructor))
static void SBXK_Boot(void) {
    @autoreleasepool {
        g_orig = [NSMutableDictionary dictionary];
        g_done = [NSMutableSet set];
        g_skip = [NSMutableSet set];
        SBXK_InitPaths();
        SBXK_InstallCrashHandlers();
        atomic_store(&g_phase, 1);
        SBXK_RotateCrashLog();
        atomic_store(&g_phase, 2);
        SBXK_ANTIDEBUG();
        NSLog(@"[SBXK] v7.10.5 boot");
        [SBXK_LogViewer installObserver];
        _dyld_register_func_for_add_image(sbxk_on_image_added);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool {
                SBXK_Run();
                [NSTimer scheduledTimerWithTimeInterval:3.0 repeats:YES block:^(NSTimer *t) {
                    (void)t;
                    if (atomic_exchange(&g_pending, false)) SBXK_Retry();
                }];
            }
        });
    }
}
